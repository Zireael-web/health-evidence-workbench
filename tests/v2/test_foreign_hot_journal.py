"""A rejected legacy SQLite file must not be recovered as a side effect."""
from __future__ import annotations

import sqlite3
import subprocess
import sys

import pytest

from health_analyzer.v2.common import SignedStore, V2Error


def test_foreign_hot_rollback_journal_is_preserved_byte_for_byte(tmp_path):
    root = tmp_path.resolve()
    path = root / "foreign.sqlite3"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA journal_mode=DELETE")
    connection.execute("CREATE TABLE legacy (value TEXT)")
    connection.executemany("INSERT INTO legacy VALUES (?)", [("x" * 1000,) for _ in range(1000)])
    connection.commit()
    connection.close()

    # Flush uncommitted pages, then emulate a process crash. SQLite leaves a
    # genuinely hot rollback journal; a subsequent read/write connection would
    # recover it before reporting that the v2 identity table is absent.
    child = """import os,sqlite3,sys
c=sqlite3.connect(sys.argv[1])
c.execute('PRAGMA cache_size=1')
c.execute('BEGIN IMMEDIATE')
c.execute("UPDATE legacy SET value='uncommitted synthetic replacement'")
os._exit(0)
"""
    subprocess.run([sys.executable, "-I", "-B", "-c", child, str(path)], check=True, timeout=10)
    journal = path.with_name(path.name + "-journal")
    assert journal.is_file() and journal.stat().st_size > 512
    assert journal.read_bytes()[:8] != b"\x00" * 8, "The fixture must contain a hot, not empty, journal header"
    before = {item.name: item.read_bytes() for item in root.iterdir() if item.is_file()}

    with pytest.raises(V2Error) as caught:
        SignedStore(path, b"synthetic-foreign-key-never-read!!", "private-data")
    assert caught.value.code in {"FOREIGN_STORE", "FOREIGN_OR_CORRUPT_STORE"}
    after = {item.name: item.read_bytes() for item in root.iterdir() if item.is_file()}
    unchanged = after == before
    assert unchanged, "Rejecting a foreign store changed its SQLite database or hot journal"
