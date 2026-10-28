"""Opt-in v2 bootstrap, doctor, stdio launcher and shared-service CLI."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import secrets
import subprocess
import sys
import tempfile
import threading
from typing import Any

from .common import V2Error, require
from .configuration import (DOMAINS, DeploymentConfig, config_from_dict, initialize,
                            load_config, open_domain_key, read_key_fd)

MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_DOCUMENT_REQUEST_BYTES = 16 * 1024 * 1024


def _request_limit(domain: str | None, tool: str | None) -> int:
    # Only the explicit full-transcript operation needs a larger JSON envelope.
    return (MAX_DOCUMENT_REQUEST_BYTES if domain == "private-data"
            and tool == "save_document_text" else MAX_REQUEST_BYTES)


def _readonly_private_call(domain: str, action: str, tool: str | None) -> bool:
    from .runtime import READONLY_PRIVATE_TOOLS
    return domain == "private-data" and action == "call" and tool in READONLY_PRIVATE_TOOLS


def code_root() -> Path:
    """Source convenience root; installed code has no checkout scripts."""
    library = library_root()
    return library.parent if library.name == "src" else library


def library_root() -> Path:
    return Path(__file__).resolve().parents[2]


def entry_path() -> Path:
    return Path(__file__).resolve().with_name("entry.py")


def _pipe(data: bytes) -> int:
    read_fd, write_fd = os.pipe()
    if len(data) > 1024 * 1024:
        os.close(read_fd)
        os.close(write_fd)
        raise V2Error("configuration_invalid", "Inherited bootstrap payload exceeds bound")
    def write_payload() -> None:
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(write_fd, data[offset:])
        except BrokenPipeError:
            pass
        finally:
            os.close(write_fd)
    # Large multi-profile configs must not block bootstrap before the child
    # starts reading its pipe. No secrets are handed to argv or the environment.
    threading.Thread(target=write_payload, daemon=True).start()
    return read_fd


def _read_fd_json(fd: int, limit: int = 1024 * 1024) -> dict:
    try:
        pieces = []
        length = 0
        while length <= limit:
            block = os.read(fd, min(65536, limit + 1 - length))
            if not block:
                break
            pieces.append(block)
            length += len(block)
        data = b"".join(pieces)
    finally:
        os.close(fd)
    require(len(data) <= limit, "configuration_invalid", "Inherited configuration is too large")
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise V2Error("configuration_invalid", "Inherited configuration is not JSON") from exc
    require(isinstance(value, dict), "configuration_invalid", "Inherited configuration must be an object")
    return value


def _policy_path(path: Path) -> str:
    return json.dumps(str(path), ensure_ascii=False)


def sandbox_policy(config: DeploymentConfig, domain: str, *, interpreter: Path | None = None,
                   source_root: Path | None = None) -> str:
    """Allow code/system runtime reads and one domain; no archive writes.

    File metadata is readable for interpreter traversal; file contents and
    directory enumeration are allowed only under the listed read roots.
    Public outbound networking is enabled at the OS layer. Provider/content
    restrictions belong to adapters and are not a Seatbelt domain filter.
    """
    require(domain in DOMAINS, "zone_invalid", "Unknown v2 runtime zone")
    interpreter = (interpreter or Path(sys.executable)).resolve()
    source_root = (source_root or library_root()).resolve()
    code = source_root / "src" if (source_root / "src/health_analyzer/v2").is_dir() else source_root
    require(config.data_root != code and
            config.data_root not in code.parents and code not in config.data_root.parents,
            "configuration_invalid", "Runtime code and v2 state must not overlap")
    read_roots = {code, Path(sys.prefix).resolve(),
                  Path(sys.base_prefix).resolve(), Path("/System/Library"), Path("/usr/lib"),
                  Path("/Library/Apple/System/Library")}
    own = config.zone_root(domain)
    reads = [f"(subpath {_policy_path(p)})" for p in sorted(read_roots, key=str)]
    reads.extend([f"(literal {_policy_path(interpreter)})", f"(subpath {_policy_path(own)})"])
    if domain == "private-data":
        reads.extend(f"(subpath {_policy_path(item['path'])})" for item in config.archive_roots.values())
    lines = ["(version 1)", "(deny default)", "(allow process-fork)",
             f"(allow process-exec (literal {_policy_path(interpreter)}) (literal \"/usr/bin/sandbox-exec\"))",
             "(allow sysctl-read)", "(allow file-read-metadata)",
             # macOS Python/dyld aborts during startup without this exact
             # directory read. It grants root-directory enumeration only,
             # not a recursive read of all filesystem contents.
             '(allow file-read-data (literal "/"))',
             "(allow file-read* " + " ".join(reads) + ")",
             f"(allow file-write* (subpath {_policy_path(own)}))",
             '(allow file-read* (literal "/dev/random") (literal "/dev/urandom") (literal "/dev/null"))',
             '(allow file-write* (literal "/dev/null"))',
             "(allow ipc-posix-sem)"]
    if domain == "private-data":
        # Descriptor traversal needs directory opens on existing ancestors.
        # These are literal directory-data grants, never recursive grants to
        # sibling documents, archives, public data or domain key files.
        lines.extend(f"(allow file-read-data (literal {_policy_path(parent)}))"
                     for parent in own.parents if parent != Path("/"))
    if domain == "public-research":
        # urllib/OpenSSL must read the public system CA bundle to verify TLS.
        # Grant the certificate file only, never Keychain or all of /etc.
        import ssl
        ca_file = ssl.get_default_verify_paths().cafile
        if ca_file:
            certificate = Path(ca_file).resolve()
            require(certificate == Path("/private/etc/ssl/cert.pem"),
                    "isolation_unavailable", "Unexpected TLS CA bundle needs explicit policy review")
            lines.append(f"(allow file-read* (literal {_policy_path(certificate)}))")
        lines.append("(allow network-outbound)")
        forbidden = [config.data_root / "private", config.data_root / "keys",
                     Path.home() / "Library/Keychains"]
        forbidden += [item["path"] for item in config.archive_roots.values()]
        lines.extend(f"(deny file-read* file-write* (subpath {_policy_path(p)}))" for p in forbidden)
    else:
        lines.extend(["(deny network*)",
                      f"(deny file-read* file-write* (subpath {_policy_path(config.data_root / 'public')}))",
                      f"(deny file-read* file-write* (subpath {_policy_path(config.data_root / 'keys')}))",
                      f"(deny file-read* file-write* (subpath {_policy_path(Path.home() / 'Library/Keychains')}))"])
        lines.extend(f"(deny file-write* (subpath {_policy_path(item['path'])}))"
                     for item in config.archive_roots.values())
    return "\n".join(lines) + "\n"


def _sandbox_prefix(config: DeploymentConfig, domain: str, *, _policy_dir: Path | None = None) -> list[str]:
    if config.isolation == "host":
        return []
    require(platform.system() == "Darwin" and Path("/usr/bin/sandbox-exec").is_file(),
            "isolation_unavailable", "macos_enforced requires macOS sandbox-exec; no host fallback")
    # The override is bootstrap-internal only; no CLI/MCP/config path field.
    policy_dir = _policy_dir if _policy_dir is not None else config.data_root / "bootstrap"
    require(not policy_dir.is_symlink() and policy_dir.is_dir(), "deployment_invalid", "Bootstrap directory unavailable")
    policy = policy_dir / f"{domain}.sb"
    # Replaced policy is bootstrap-owned deployment output, not user source.
    temporary = policy_dir / f".{domain}-{secrets.token_hex(8)}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(descriptor, sandbox_policy(config, domain).encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, policy)
    return ["/usr/bin/sandbox-exec", "-f", str(policy)]


def launch_runtime(config: DeploymentConfig, domain: str, *, action: str,
                   tool: str | None = None, arguments: dict | None = None) -> int:
    """Trusted bootstrap reads one new key, then applies configured isolation."""
    readonly = _readonly_private_call(domain, action, tool)
    if readonly and config.isolation == "macos_enforced":
        # Reading a preview never overwrites existing deployment profiles or
        # prepares native helpers. Only this temporary policy is published.
        with tempfile.TemporaryDirectory(prefix="ha-v2-read-policy-") as temporary:
            return _launch_runtime(config, domain, action=action, tool=tool,
                                   arguments=arguments, readonly=True,
                                   _policy_dir=Path(temporary).resolve())
    return _launch_runtime(config, domain, action=action, tool=tool,
                           arguments=arguments, readonly=readonly)


def _launch_runtime(config: DeploymentConfig, domain: str, *, action: str,
                    tool: str | None, arguments: dict | None, readonly: bool,
                    _policy_dir: Path | None = None) -> int:
    prefix = (_sandbox_prefix(config, domain) if _policy_dir is None else
              _sandbox_prefix(config, domain, _policy_dir=_policy_dir))
    source_key_fd = open_domain_key(config, domain)
    try:
        key = read_key_fd(source_key_fd)
    except Exception:
        raise
    key_fd = _pipe(key)
    config_fd = _pipe(json.dumps(config.to_dict(domain=domain), ensure_ascii=False).encode())
    bridge = None
    if domain == "private-data" and config.isolation == "macos_enforced" and not readonly:
        from .pdf_bridge import PdfBridgeBootstrap
        bridge = PdfBridgeBootstrap()
        bridge.__enter__()
    command = prefix + [sys.executable, "-I", "-B", str(entry_path()),
                        "--_runtime-zone", domain, "--_config-fd", str(config_fd),
                        "--_key-fd", str(key_fd), "--_action", action]
    if bridge is not None:
        command += ["--_pdf-request-fd", str(bridge.client_fds[0]),
                    "--_pdf-response-fd", str(bridge.client_fds[1])]
    descriptors = (key_fd, config_fd) + (bridge.client_fds if bridge is not None else ())
    if tool is not None:
        command += ["--_tool", tool]
    env = {name: value for name, value in os.environ.items()
           if name in {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "SYSTEMROOT"}}
    env.update({"TMPDIR": str(config.temp_root(domain)), "PYTHONDONTWRITEBYTECODE": "1"})
    try:
        if action == "call":
            payload = json.dumps(arguments, ensure_ascii=False, allow_nan=False).encode()
            require(len(payload) <= _request_limit(domain, tool), "arguments_invalid", "Tool payload exceeds bound")
            completed = subprocess.run(command, input=payload, pass_fds=descriptors, env=env)
        else:
            completed = subprocess.run(command, pass_fds=descriptors, env=env)
        if completed.returncode != 0 and config.isolation == "macos_enforced":
            # Preserve the actual subprocess failure; do not fall back to host.
            print(json.dumps({"code": "isolated_runtime_failed", "message":
                              "Configured isolated runtime failed; host fallback was not attempted"}), file=sys.stderr)
        return completed.returncode
    finally:
        if bridge is not None:
            bridge.close()
        os.close(key_fd)
        os.close(config_fd)


def runtime_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--_runtime-zone", choices=DOMAINS, required=True)
    parser.add_argument("--_config-fd", type=int, required=True)
    parser.add_argument("--_key-fd", type=int, required=True)
    parser.add_argument("--_action", choices=("call", "serve"), required=True)
    parser.add_argument("--_tool")
    parser.add_argument("--_pdf-request-fd", type=int)
    parser.add_argument("--_pdf-response-fd", type=int)
    args = parser.parse_args(argv)
    config_data = _read_fd_json(args._config_fd)
    config = config_from_dict(config_data, path=Path("/v2-runtime-config.json"))
    readonly = _readonly_private_call(args._runtime_zone, args._action, args._tool)
    if args._runtime_zone == "public-research":
        require(not config.archive_roots, "scope_violation", "Public runtime cannot receive archive bindings")
        require(args._pdf_request_fd is None and args._pdf_response_fd is None,
                "scope_violation", "Public runtime cannot receive a PDF launch bridge")
    if args._pdf_request_fd is not None or args._pdf_response_fd is not None:
        require(not readonly, "scope_violation", "Readonly preview calls do not accept a PDF launch bridge")
        require(args._runtime_zone == "private-data" and args._pdf_request_fd is not None
                and args._pdf_response_fd is not None, "PDF_BRIDGE_INVALID", "Private PDF bridge needs both pipe FDs")
        from .pdf_bridge import configure_runtime_bridge
        configure_runtime_bridge(args._pdf_request_fd, args._pdf_response_fd)
    elif args._runtime_zone == "private-data" and config.isolation == "macos_enforced" and not readonly:
        raise V2Error("PDF_BRIDGE_REQUIRED", "Enforced private runtime requires its bootstrap PDF launch bridge")
    key = read_key_fd(args._key_fd)
    from .runtime import open_services, serve_stdio
    services = open_services(config, args._runtime_zone, key, readonly=readonly)
    try:
        if args._action == "serve":
            serve_stdio(services)
            return 0
        require(args._tool is not None, "arguments_invalid", "Tool name is required")
        request_limit = _request_limit(args._runtime_zone, args._tool)
        data = sys.stdin.buffer.read(request_limit + 1)
        require(len(data) <= request_limit, "arguments_invalid", "Tool payload exceeds bound")
        try:
            arguments = json.loads(data)
        except (ValueError, UnicodeError) as exc:
            raise V2Error("arguments_invalid", "Tool payload must be UTF-8 JSON") from exc
        print(json.dumps(services.call(args._tool, arguments), ensure_ascii=False, allow_nan=False))
        return 0
    finally:
        services.close()
        if args._runtime_zone == "private-data" and not readonly:
            from .pdf_bridge import close_runtime_bridge
            close_runtime_bridge()


def doctor(config: DeploymentConfig) -> dict:
    """Run synthetic OS probes only; never open a clinical archive or old DB."""
    result: dict[str, Any] = {"deployment_id": config.deployment_id, "isolation": config.isolation,
                             "status": "not_checked", "checks": [],
                             "legacy_state_opened": False, "clinical_archive_opened": False}
    if config.isolation == "host":
        result.update(status="logical_host_only", os_isolation="not_enforced")
        result["checks"].append({"check": "os_boundary", "status": "not_enforced",
                                 "reason": "Explicit host mode does not restrict process filesystem or network"})
        return result
    paths: list[Path] = []
    try:
        private_canary = config.zone_root("private-data") / f"doctor-{secrets.token_hex(8)}.txt"
        public_canary = config.zone_root("public-research") / f"doctor-{secrets.token_hex(8)}.txt"
        from .configuration import _exclusive_write
        for path in (private_canary, public_canary):
            _exclusive_write(path, b"synthetic v2 boundary canary")
            paths.append(path)
            paths.append(Path(str(path) + ".write"))
        for domain in DOMAINS:
            prefix = _sandbox_prefix(config, domain)
            owned = private_canary if domain == "private-data" else public_canary
            forbidden = public_canary if domain == "private-data" else private_canary
            script = """import errno,json,os,socket,sys
out={}
for name,path in [('own',sys.argv[1]),('other',sys.argv[2])]:
 try:
  with open(path,'rb') as f: f.read(1)
  out[name]='allowed'
 except OSError as e: out[name]='denied' if e.errno in (errno.EACCES,errno.EPERM) else 'inconclusive'
try:
 fd=os.open(sys.argv[1]+'.write',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try: os.write(fd,b'synthetic')
 finally: os.close(fd)
 out['own_write']='allowed'
except OSError as e: out['own_write']='denied' if e.errno in (errno.EACCES,errno.EPERM) else 'inconclusive'
try:
 s=socket.socket(); s.settimeout(.5); s.connect(('127.0.0.1',9)); s.close(); out['network']='allowed'
except OSError as e: out['network']='denied' if e.errno in (errno.EACCES,errno.EPERM) else 'not_permission_denied'
print(json.dumps(out))
"""
            completed = subprocess.run(prefix + [sys.executable, "-I", "-B", "-c", script,
                                                    str(owned), str(forbidden)], capture_output=True,
                                       text=True, timeout=10)
            if completed.returncode != 0:
                result["checks"].append({"zone": domain, "status": "unavailable",
                                         "code": "isolation_unavailable" if "Operation not permitted" in completed.stderr
                                         else "runtime_startup_failed" if completed.returncode < 0
                                         else "sandbox_probe_failed",
                                         "returncode": completed.returncode})
                continue
            try:
                observed = json.loads(completed.stdout)
            except ValueError:
                result["checks"].append({"zone": domain, "status": "failed", "code": "invalid_probe_output"})
                continue
            required = (observed.get("own") == "allowed" and observed.get("own_write") == "allowed"
                        and observed.get("other") == "denied")
            if domain == "private-data":
                required = required and observed.get("network") == "denied"
            result["checks"].append({"zone": domain, "status": "passed" if required else "failed",
                                     "observed": observed})
        result["status"] = ("partial" if all(item["status"] == "passed" for item in result["checks"])
                            else "unavailable" if all(item["status"] == "unavailable" for item in result["checks"])
                            else "failed")
        result["os_isolation"] = "tested_synthetic_boundaries" if result["status"] == "partial" else "unconfirmed"
        result["deployment_ready"] = False
        result["unimplemented_checks"] = ["nested_pdf_worker", "installed_plugin_cache", "Keychain_content_canary"]
        return result
    except V2Error as exc:
        result.update(status="unavailable", os_isolation="unconfirmed", error=exc.to_dict())
        return result
    except (OSError, subprocess.SubprocessError):
        result.update(status="failed", os_isolation="unconfirmed",
                      error={"code": "sandbox_probe_failed", "message": "Synthetic boundary probe could not complete"})
        return result
    finally:
        for path in paths:
            path.unlink(missing_ok=True)


def _input_json(path: str | Path, *, limit: int = MAX_REQUEST_BYTES) -> dict:
    from .configuration import _read_regular
    try:
        value = json.loads(_read_regular(Path(path), limit=limit))
    except (ValueError, UnicodeError) as exc:
        raise V2Error("arguments_invalid", "Arguments file must be UTF-8 JSON") from exc
    require(isinstance(value, dict), "arguments_invalid", "Arguments file must contain an object")
    return value


def deployment_assets(config: DeploymentConfig, output_dir: str | Path) -> dict:
    """Create reviewable MCP registration only, never activate/install it."""
    destination = Path(output_dir).expanduser().absolute()
    require(not destination.is_symlink() and not any(parent.is_symlink() for parent in destination.parents),
            "symlink_forbidden", "Deployment output cannot traverse symlinks")
    destination = destination.resolve(strict=False)
    for binding in config.archive_roots.values():
        archive = binding["path"]
        require(destination != archive and archive not in destination.parents and destination not in archive.parents,
                "scope_violation", "Deployment output must not overlap an archive")
    require(not destination.exists() or (destination.is_dir() and not any(destination.iterdir())),
            "deployment_exists", "Deployment output must be absent or empty")
    destination.mkdir(parents=True, mode=0o700, exist_ok=True)
    servers = {}
    for zone in DOMAINS:
        servers[f"health-analyzer-v2-{zone}"] = {
            "command": sys.executable,
            "args": ["-I", "-B", str(entry_path()), "--config", str(config.path),
                     "serve", "--zone", zone, "--transport", "stdio"]}
    assets = {".mcp.json": {"mcpServers": servers},
              "deployment-manifest.json": {"schema_version": "health-analyzer.assets/2.0",
                 "deployment_id": config.deployment_id, "runtime_library_root": str(library_root()),
                 "interpreter": sys.executable, "isolation": config.isolation,
                 "active_plugin_changed": False, "doctor_required_after_relocation": True}}
    from .configuration import _exclusive_write
    for name, payload in assets.items():
        _exclusive_write(destination / name, json.dumps(payload, indent=2, ensure_ascii=False).encode() + b"\n")
    return {"status": "generated_inactive", "output_dir": str(destination),
            "files": sorted(assets), "active_plugin_changed": False}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if "--_runtime-zone" in argv:
            return runtime_main(argv)
        parser = argparse.ArgumentParser(description="Parallel Health Analyzer v2; explicit new deployment only")
        parser.add_argument("--config", required=True, help="Explicit v2 configuration path")
        commands = parser.add_subparsers(dest="command", required=True)
        init = commands.add_parser("init", help="Create a new isolated data namespace; no migration")
        init.add_argument("--data-root", required=True)
        init.add_argument("--isolation", choices=("host", "macos_enforced"), required=True)
        init.add_argument("--deployment-id")
        init.add_argument("--archive-bindings", help="JSON object of explicitly authorized root/subject bindings")
        init.add_argument("--research-provider", choices=("pubmed",),
                          help="Enable the public PubMed adapter; private runtime stays offline")
        commands.add_parser("doctor", help="Synthetic checks without opening archive contents")
        describe = commands.add_parser("describe", help="Show capability status and configured paths")
        assets = commands.add_parser("deployment-assets", help="Generate inactive opt-in MCP registration")
        assets.add_argument("--output-dir", required=True)
        serve = commands.add_parser("serve", help="Run one stdio MCP zone")
        serve.add_argument("--zone", choices=DOMAINS, required=True)
        serve.add_argument("--transport", choices=("stdio",), default="stdio")
        call = commands.add_parser("call", help="Call the same scoped service using a JSON arguments file")
        call.add_argument("--zone", choices=DOMAINS, required=True)
        call.add_argument("--tool", required=True)
        call.add_argument("--arguments-file", required=True)
        args = parser.parse_args(argv)
        if args.command == "init":
            roots = _input_json(args.archive_bindings) if args.archive_bindings else {}
            config = initialize(args.config, args.data_root, isolation=args.isolation,
                                deployment_id=args.deployment_id, archive_roots=roots,
                                research_provider={"name": args.research_provider} if args.research_provider else None)
            output = {"status": "initialized", "deployment_id": config.deployment_id,
                      "config": str(config.path), "data_root": str(config.data_root),
                      "isolation": config.isolation, "legacy_state_opened": False}
        else:
            config = load_config(args.config)
            if args.command == "doctor":
                output = doctor(config)
                print(json.dumps(output, ensure_ascii=False))
                return 0 if output["status"] in {"passed", "logical_host_only"} else 2
            if args.command == "describe":
                output = {**config.to_dict(), "os_isolation": "not_enforced" if config.isolation == "host" else "requires_doctor",
                          "transports": ["stdio"], "active_plugin_changed": False,
                          "research_provider": config.research_provider or "not_configured"}
            elif args.command == "deployment-assets":
                output = deployment_assets(config, args.output_dir)
            else:
                return launch_runtime(config, args.zone, action="serve" if args.command == "serve" else "call",
                                      tool=getattr(args, "tool", None),
                                      arguments=_input_json(args.arguments_file,
                                          limit=_request_limit(args.zone, args.tool)) if args.command == "call" else None)
        print(json.dumps(output, ensure_ascii=False))
        return 0
    except V2Error as exc:
        print(json.dumps({"error": exc.to_dict()}, ensure_ascii=False), file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        # No raw filesystem path, argument object or secret in startup errors.
        print(json.dumps({"error": {"code": "runtime_failed", "message": "V2 operation failed before completion"}}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
