"""Local installation diagnostics that never print secret values."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import base64
import json
import os
from pathlib import Path
import sqlite3
import subprocess


@dataclass(frozen=True, slots=True)
class DiagnosticCheck:
    name: str
    status: str
    detail: str


def run_doctor(project_root: str | Path) -> dict[str, object]:
    root = Path(project_root).resolve()
    checks: list[DiagnosticCheck] = []

    schemas = sorted((root / "schemas").glob("*.schema.json"))
    try:
        for path in schemas:
            json.loads(path.read_text(encoding="utf-8"))
        checks.append(DiagnosticCheck("schemas", "pass", f"{len(schemas)} JSON schemas parsed"))
    except (OSError, json.JSONDecodeError) as error:
        checks.append(DiagnosticCheck("schemas", "fail", type(error).__name__))

    try:
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE VIRTUAL TABLE probe USING fts5(value)")
        connection.close()
        checks.append(DiagnosticCheck("sqlite_fts5", "pass", sqlite3.sqlite_version))
    except sqlite3.Error as error:
        checks.append(DiagnosticCheck("sqlite_fts5", "warn", str(error)))

    plugin_manifest = root / "plugins/human-science-workbench/.codex-plugin/plugin.json"
    marketplace = root / ".agents/plugins/marketplace.json"
    for name, path in (("plugin_manifest", plugin_manifest),):
        try:
            json.loads(path.read_text(encoding="utf-8"))
            checks.append(DiagnosticCheck(name, "pass", str(path)))
        except (OSError, json.JSONDecodeError) as error:
            checks.append(DiagnosticCheck(name, "fail", type(error).__name__))
    if marketplace.exists():
        try:
            json.loads(marketplace.read_text(encoding="utf-8"))
            checks.append(DiagnosticCheck("marketplace", "pass", str(marketplace)))
        except (OSError, json.JSONDecodeError) as error:
            checks.append(DiagnosticCheck("marketplace", "fail", type(error).__name__))
    else:
        checks.append(
            DiagnosticCheck(
                "marketplace",
                "warn",
                "not distributed with the public export",
            )
        )

    ncbi_email = os.environ.get("NCBI_EMAIL")
    checks.append(
        DiagnosticCheck(
            "ncbi_email",
            "pass" if ncbi_email and "@" in ncbi_email else "warn",
            "configured" if ncbi_email else "not configured; PubMed search will be disabled",
        )
    )

    private_roots_raw = os.environ.get("HEALTH_ANALYZER_PRIVATE_ROOTS")
    if private_roots_raw:
        try:
            private_roots = json.loads(private_roots_raw)
            invalid = [
                str(value)
                for value in private_roots.values()
                if not Path(str(value)).expanduser().resolve().is_dir()
            ]
            checks.append(
                DiagnosticCheck(
                    "private_roots",
                    "fail" if invalid else "pass",
                    "invalid paths present" if invalid else f"{len(private_roots)} root(s) configured",
                )
            )
        except (json.JSONDecodeError, AttributeError):
            checks.append(DiagnosticCheck("private_roots", "fail", "must be a JSON object"))
    else:
        checks.append(
            DiagnosticCheck("private_roots", "warn", "not configured; private scan will be disabled")
        )

    secret = os.environ.get("HEALTH_ANALYZER_PSEUDONYM_KEY")
    secret_source = "environment" if secret else None
    if not secret:
        security_command = Path("/usr/bin/security")
        login_keychain = Path.home() / "Library/Keychains/login.keychain-db"
        if security_command.is_file() and login_keychain.is_file():
            keychain_result = subprocess.run(
                [
                    str(security_command),
                    "find-generic-password",
                    "-a",
                    "health-analyzer-local",
                    "-s",
                    "health-analyzer-pseudonym-v1",
                    "-w",
                    str(login_keychain),
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
            )
            if keychain_result.returncode == 0:
                secret = keychain_result.stdout.strip()
                secret_source = "macOS Keychain"
    secret_valid = False
    if secret:
        try:
            decoded = bytes.fromhex(secret)
        except ValueError:
            try:
                decoded = base64.b64decode(secret, validate=True)
            except ValueError:
                decoded = b""
        secret_valid = len(decoded) >= 32
    checks.append(
        DiagnosticCheck(
            "pseudonym_key",
            "pass" if secret_valid else "fail" if secret else "warn",
            "configured and structurally valid"
            if secret_valid
            else "configured but invalid"
            if secret
            else "not configured; private scan will be disabled",
        )
    )
    if secret_valid and secret_source == "macOS Keychain":
        checks[-1] = DiagnosticCheck(
            "pseudonym_key",
            "pass",
            "available in macOS Keychain and structurally valid",
        )
    statuses = [check.status for check in checks]
    return {
        "status": "fail" if "fail" in statuses else "warn" if "warn" in statuses else "pass",
        "checks": [asdict(check) for check in checks],
    }
