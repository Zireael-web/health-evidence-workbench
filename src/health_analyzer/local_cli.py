"""Explicit local document operations without MCP, a database, or Keychain.

This module makes no network requests. The host mode retains the calling
environment's permissions; it does not claim OS-enforced network isolation.
The existing MCP and nested PDF-parser contracts remain unchanged.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets


def add_local_pdf_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        "local-pdf", help="Inspect or explicitly intake one local PDF, without MCP",
    )
    operations = parser.add_subparsers(dest="local_operation", required=True)
    for operation in ("inspect", "ingest"):
        command = operations.add_parser(operation)
        command.add_argument("source", type=Path)
        command.add_argument(
            "--isolation", choices=("seatbelt", "host"), default="seatbelt",
            help="host explicitly uses bounded workers under existing host permissions",
        )
        command.add_argument(
            "--output", type=Path,
            help="Create a new private JSON extraction file; never overwrites",
        )
        if operation == "ingest":
            command.add_argument("--archive-root", type=Path, required=True)
            command.add_argument("--destination", help="Relative filename in the confirmed patient archive")
    render = operations.add_parser("render", help="Render every PDF page into a fresh review directory")
    render.add_argument("source", type=Path)
    render.add_argument("--isolation", choices=("host",), required=True)
    render.add_argument("--render-parent", type=Path, required=True)
    render.add_argument("--dpi", type=int, default=120)
    render.add_argument("--output", type=Path, help="New JSON page manifest, without overwriting")


def _output_parent(path: Path) -> tuple[int, str]:
    """Open every parent without following symlinks; keep a stable parent FD."""
    if not path.is_absolute() or ".." in path.parts or not path.name:
        raise ValueError("output must be an absolute non-traversing file path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor, path.name
    except BaseException:
        os.close(descriptor)
        raise


def _write_new_json(path: Path, payload: dict) -> None:
    """Publish a complete private artifact atomically, never replacing a path."""
    content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    parent, name = _output_parent(path)
    temporary = ".local-pdf-" + secrets.token_hex(16) + ".tmp"
    created = False
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=parent,
        )
        created = True
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
    finally:
        if created:
            # Never unlink the final target; another process could replace it.
            os.unlink(temporary, dir_fd=parent)
        os.close(parent)


def _check_output_available(path: Path) -> None:
    parent, name = _output_parent(path)
    try:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise FileExistsError("Output already exists; no intake was attempted.")
    finally:
        os.close(parent)


def execute_local_pdf(args: argparse.Namespace) -> None:
    from .local_documents import inspect_local_pdf

    if args.output:
        _check_output_available(args.output)
    if args.local_operation == "render":
        from .local_documents import render_local_pdf

        result = render_local_pdf(
            args.source, args.render_parent, dpi=args.dpi, isolation=args.isolation,
        )
    else:
        result = inspect_local_pdf(
            args.source, isolation="nested" if args.isolation == "seatbelt" else "host",
        )
    if args.local_operation == "ingest":
        from .local_intake import copy_authorized_pdf

        intake = copy_authorized_pdf(
            args.source, args.archive_root, args.destination,
            expected_sha256=result["sha256"],
        )
        result = {
            **result,
            "intake": {
                "path": str(intake.path), "sha256": intake.sha256,
                "status": intake.status,
                "identity_assignment": "caller_confirmed_archive_root",
            },
        }
    if args.output:
        try:
            _write_new_json(args.output, result)
        except OSError as error:
            if "intake" in result:
                raise RuntimeError(
                    "Archive intake completed (" + result["intake"]["status"]
                    + "), but the separate JSON output could not be published. "
                    "The archive copy was retained; retrying the same intake is idempotent."
                ) from error
            raise
        # Console summary excludes the clinical text and direct identifiers.
        print(json.dumps({
            "status": "written", "page_count": result["page_count"],
            "sha256": result["sha256"], "review_status": result["review_status"],
            "intake_status": result.get("intake", {}).get("status"),
        }, ensure_ascii=False, sort_keys=True))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
