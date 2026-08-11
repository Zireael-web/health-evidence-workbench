from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3

import pytest

from health_analyzer.contracts import ProvenanceLocator as ContractProvenanceLocator
from health_analyzer.vault import (
    CrossSubjectDocumentError,
    LocationHint,
    ProvenanceLocator,
    SourceChangedDuringReadError,
    SourceOutsideVaultError,
    SubjectPseudonymizer,
    VaultIndex,
)
from health_analyzer.vault import store as vault_store


FIXTURES = Path(__file__).parents[1] / "fixtures" / "private"
SECRET = b"synthetic-test-secret-material-32b!"


@pytest.mark.parametrize(
    "overrides",
    (
        {"source_id": ""},
        {"sha256": "bad"},
        {"page": -1},
        {"bbox": (0.0, 0.0, float("nan"), 1.0)},
        {"line_end": 2},
        {"char_end": 2},
        {"locator": " "},
    ),
)
def test_shared_provenance_locator_rejects_invalid_identity_and_location(
    overrides: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "source_id": "src_synthetic",
        "sha256": "a" * 64,
    }
    values.update(overrides)

    assert ContractProvenanceLocator is ProvenanceLocator
    with pytest.raises(ValueError):
        ProvenanceLocator(**values)  # type: ignore[arg-type]


def _vault(tmp_path: Path) -> VaultIndex:
    return VaultIndex(
        tmp_path / "vault.sqlite3",
        roots={"synthetic": FIXTURES},
        pseudonymizer=SubjectPseudonymizer(SECRET, namespace="tests"),
    )


def _mutable_vault(tmp_path: Path) -> tuple[VaultIndex, Path]:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    return (
        VaultIndex(
            tmp_path / "vault.sqlite3",
            roots={"source": source_root},
            pseudonymizer=SubjectPseudonymizer(SECRET, namespace="tests"),
        ),
        source_root,
    )


def test_import_is_read_only_and_manifest_is_content_addressed(tmp_path: Path) -> None:
    source = FIXTURES / "subject-alpha" / "lab-report.txt"
    before_bytes = source.read_bytes()
    before_stat = source.stat()

    with _vault(tmp_path) as vault:
        subject_id = vault.register_subject("alpha")
        document = vault.import_file(
            subject_id,
            source,
            locations=(
                LocationHint(page=1, bbox=(10.0, 20.0, 300.0, 60.0), line_start=6, line_end=7),
            ),
        )
        manifest = vault.manifest(subject_id)

        assert document.sha256 == hashlib.sha256(before_bytes).hexdigest()
        assert document.provenance[0].page == 1
        assert document.provenance[0].bbox == (10.0, 20.0, 300.0, 60.0)
        assert document.provenance[0].line_start == 6
        assert manifest.to_dict()["manifest_sha256"] == manifest.manifest_sha256
        assert manifest.to_json(indent=None) == manifest.to_json(indent=None)
        assert vault.verify_manifest(subject_id)[0].status == "ok"

    after_stat = source.stat()
    assert source.read_bytes() == before_bytes
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
    assert after_stat.st_size == before_stat.st_size


def test_patient_vaults_are_always_subject_scoped(tmp_path: Path) -> None:
    source = FIXTURES / "subject-alpha" / "lab-report.txt"

    with _vault(tmp_path) as vault:
        alpha = vault.register_subject("alpha")
        beta = vault.register_subject("beta")
        document = vault.import_file(alpha, source)

        assert vault.list_documents(alpha) == (document,)
        assert vault.list_documents(beta) == ()
        with pytest.raises(KeyError):
            vault.get_document(beta, document.source_id)
        with pytest.raises(CrossSubjectDocumentError):
            vault.import_file(beta, source)


def test_same_path_content_change_retains_old_version_and_selects_new_current(
    tmp_path: Path,
) -> None:
    vault, source_root = _mutable_vault(tmp_path)
    source = source_root / "report.txt"
    source.write_text("version one", encoding="utf-8")

    with vault:
        subject_id = vault.register_subject("alpha")
        first = vault.import_file(
            subject_id,
            source,
            locations=(LocationHint(page=1, line_start=1, line_end=1),),
        )
        source.write_text("version two is different", encoding="utf-8")
        second = vault.import_file(
            subject_id,
            source,
            locations=(LocationHint(page=2, line_start=3, line_end=4),),
        )

        assert first.source_id != second.source_id
        assert first.sha256 != second.sha256
        assert vault.list_documents(subject_id) == (second,)
        assert vault.get_document(subject_id, first.source_id) == first
        assert vault.list_document_versions(subject_id, second.source_id) == (
            first,
            second,
        )
        assert vault.manifest(subject_id).documents == (second,)
        assert vault.verify_manifest(subject_id)[0].status == "ok"


def test_unchanged_reimport_reuses_content_version(tmp_path: Path) -> None:
    vault, source_root = _mutable_vault(tmp_path)
    source = source_root / "report.txt"
    source.write_text("same bytes", encoding="utf-8")

    with vault:
        subject_id = vault.register_subject("alpha")
        first = vault.import_file(subject_id, source)
        source.write_text("same bytes", encoding="utf-8")
        second = vault.import_file(
            subject_id,
            source,
            locations=(LocationHint(line_start=2, line_end=2),),
        )

        assert second.source_id == first.source_id
        assert second.indexed_at == first.indexed_at
        assert second.provenance[0].line_start == 2
        assert vault.list_document_versions(subject_id, first.source_id) == (second,)


def test_duplicate_content_at_distinct_paths_has_distinct_logical_identity(
    tmp_path: Path,
) -> None:
    vault, source_root = _mutable_vault(tmp_path)
    first_path = source_root / "first.txt"
    second_path = source_root / "second.txt"
    first_path.write_text("same bytes", encoding="utf-8")
    second_path.write_text("same bytes", encoding="utf-8")

    with vault:
        subject_id = vault.register_subject("alpha")
        first = vault.import_file(subject_id, first_path)
        second = vault.import_file(subject_id, second_path)

        assert first.sha256 == second.sha256
        assert first.source_id != second.source_id
        assert vault.list_documents(subject_id) == (first, second)
        assert vault.list_document_versions(subject_id, first.source_id) == (first,)
        assert vault.list_document_versions(subject_id, second.source_id) == (second,)


def test_tree_sync_tombstones_missing_paths_and_reappearance_is_deterministic(
    tmp_path: Path,
) -> None:
    vault, source_root = _mutable_vault(tmp_path)
    source = source_root / "report.txt"
    source.write_text("stable bytes", encoding="utf-8")

    with vault:
        subject_id = vault.register_subject("alpha")
        first_snapshot = vault.sync_tree(subject_id, "source")
        first = vault.load_snapshot_page(
            subject_id, first_snapshot.snapshot_id
        ).documents[0]

        source.unlink()
        empty_snapshot = vault.sync_tree(subject_id, "source")
        tombstoned = vault.get_document_state(subject_id, first.source_id)

        assert empty_snapshot.source_count == 0
        assert vault.list_documents(subject_id) == ()
        assert tombstoned.presence_state == "tombstoned"
        assert tombstoned.tombstoned_at is not None
        assert vault.get_document(subject_id, first.source_id) == first
        assert vault.list_document_versions(subject_id, first.source_id) == (first,)

        source.write_text("stable bytes", encoding="utf-8")
        revived_snapshot = vault.sync_tree(subject_id, "source")
        revived = vault.load_snapshot_page(
            subject_id, revived_snapshot.snapshot_id
        ).documents[0]
        present = vault.get_document_state(subject_id, revived.source_id)

        assert revived.source_id == first.source_id
        assert revived_snapshot.snapshot_id == first_snapshot.snapshot_id
        assert present.document_id == tombstoned.document_id
        assert present.presence_state == "present"
        assert present.tombstoned_at is None
        assert vault.list_document_versions(subject_id, revived.source_id) == (first,)
        assert len(vault.list_snapshots(subject_id)) == 2

        source.unlink()
        vault.sync_tree(subject_id, "source")
        source.write_text("changed after return", encoding="utf-8")
        changed_snapshot = vault.sync_tree(subject_id, "source")
        changed = vault.load_snapshot_page(
            subject_id, changed_snapshot.snapshot_id
        ).documents[0]

        assert changed.source_id != first.source_id
        assert vault.get_document_state(
            subject_id, changed.source_id
        ).document_id == tombstoned.document_id
        assert vault.list_document_versions(subject_id, changed.source_id) == (
            first,
            changed,
        )


def test_rename_is_tombstone_plus_new_document_with_both_histories_retained(
    tmp_path: Path,
) -> None:
    vault, source_root = _mutable_vault(tmp_path)
    old_path = source_root / "old-name.txt"
    new_path = source_root / "new-name.txt"
    old_path.write_text("same clinical bytes", encoding="utf-8")

    with vault:
        subject_id = vault.register_subject("alpha")
        original = vault.import_tree(subject_id, "source")[0]
        old_path.rename(new_path)
        renamed = vault.import_tree(subject_id, "source")[0]

        old_state = vault.get_document_state(subject_id, original.source_id)
        new_state = vault.get_document_state(subject_id, renamed.source_id)

        assert original.sha256 == renamed.sha256
        assert original.source_id != renamed.source_id
        assert old_state.document_id != new_state.document_id
        assert old_state.presence_state == "tombstoned"
        assert new_state.presence_state == "present"
        assert vault.get_document(subject_id, original.source_id) == original
        assert vault.list_document_versions(subject_id, original.source_id) == (
            original,
        )
        assert vault.list_document_versions(subject_id, renamed.source_id) == (
            renamed,
        )


def test_snapshot_cursor_reads_frozen_order_after_live_tree_changes(
    tmp_path: Path,
) -> None:
    vault, source_root = _mutable_vault(tmp_path)
    for name in ("a.txt", "b.txt", "c.txt"):
        (source_root / name).write_text(name, encoding="utf-8")

    with vault:
        alpha = vault.register_subject("alpha")
        beta = vault.register_subject("beta")
        original_snapshot = vault.sync_tree(alpha, "source")
        first_page = vault.load_snapshot_page(
            alpha, original_snapshot.snapshot_id, limit=1
        )
        assert tuple(item.relative_path for item in first_page.documents) == (
            "a.txt",
        )
        assert first_page.next_cursor is not None

        (source_root / "b.txt").write_text("changed b", encoding="utf-8")
        (source_root / "c.txt").unlink()
        (source_root / "d.txt").write_text("new d", encoding="utf-8")
        current_snapshot = vault.sync_tree(alpha, "source")

        second_page = vault.load_snapshot_page(
            alpha,
            original_snapshot.snapshot_id,
            cursor=first_page.next_cursor,
            limit=1,
        )
        third_page = vault.load_snapshot_page(
            alpha,
            original_snapshot.snapshot_id,
            cursor=second_page.next_cursor,
            limit=1,
        )
        assert tuple(item.relative_path for item in second_page.documents) == (
            "b.txt",
        )
        assert tuple(item.relative_path for item in third_page.documents) == (
            "c.txt",
        )
        assert third_page.next_cursor is None
        assert tuple(
            item.relative_path
            for item in vault.load_snapshot_page(
                alpha, current_snapshot.snapshot_id
            ).documents
        ) == ("a.txt", "b.txt", "d.txt")

        with pytest.raises(ValueError, match="does not match"):
            vault.load_snapshot_page(
                alpha,
                current_snapshot.snapshot_id,
                cursor=first_page.next_cursor,
            )
        with pytest.raises(KeyError):
            vault.get_snapshot(beta, original_snapshot.snapshot_id)
        with pytest.raises(ValueError, match="between 1 and"):
            vault.load_snapshot_page(alpha, original_snapshot.snapshot_id, limit=501)
        with pytest.raises(ValueError, match="size limit"):
            vault.load_snapshot_page(
                alpha,
                original_snapshot.snapshot_id,
                cursor="A" * (vault_store.MAX_SNAPSHOT_CURSOR_CHARS + 1),
            )


def test_snapshot_freezes_provenance_for_unchanged_source_version(
    tmp_path: Path,
) -> None:
    vault, source_root = _mutable_vault(tmp_path)
    source = source_root / "report.txt"
    source.write_text("same immutable bytes", encoding="utf-8")

    with vault:
        subject_id = vault.register_subject("alpha")
        original = vault.import_file(
            subject_id,
            source,
            locations=(LocationHint(page=1, line_start=2, line_end=3),),
        )
        snapshot = vault.sync_tree(subject_id, "source")

        updated = vault.import_file(
            subject_id,
            source,
            locations=(LocationHint(page=9, line_start=20, line_end=30),),
        )
        frozen = vault.load_snapshot_page(
            subject_id, snapshot.snapshot_id
        ).documents[0]

        assert updated.source_id == original.source_id
        assert updated.provenance[0].page == 9
        assert frozen.provenance[0].page == 1
        assert frozen.provenance[0].line_start == 2


def test_new_sync_binds_current_provenance_without_mutating_old_snapshot(
    tmp_path: Path,
) -> None:
    vault, source_root = _mutable_vault(tmp_path)
    source = source_root / "report.txt"
    source.write_text("same immutable bytes", encoding="utf-8")

    with vault:
        subject_id = vault.register_subject("alpha")
        vault.import_file(
            subject_id,
            source,
            locations=(LocationHint(page=1, line_start=2, line_end=3),),
        )
        original_snapshot = vault.sync_tree(subject_id, "source")

        vault.import_file(
            subject_id,
            source,
            locations=(LocationHint(page=9, line_start=20, line_end=30),),
        )
        current_snapshot = vault.sync_tree(subject_id, "source")

        assert current_snapshot.snapshot_id != original_snapshot.snapshot_id
        assert vault.load_snapshot_page(
            subject_id, original_snapshot.snapshot_id
        ).documents[0].provenance[0].page == 1
        current = vault.load_snapshot_page(
            subject_id, current_snapshot.snapshot_id
        ).documents[0]
        assert current.provenance[0].page == 9
        assert current.provenance[0].line_start == 20


def test_published_snapshot_rows_and_entries_are_immutable(tmp_path: Path) -> None:
    vault, source_root = _mutable_vault(tmp_path)
    (source_root / "report.txt").write_text("immutable", encoding="utf-8")

    with vault:
        subject_id = vault.register_subject("alpha")
        snapshot = vault.sync_tree(subject_id, "source")

        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            vault._connection.execute(
                "UPDATE vault_snapshots SET source_count = 9 WHERE snapshot_id = ?",
                (snapshot.snapshot_id,),
            )
        vault._connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            vault._connection.execute(
                """
                UPDATE vault_snapshot_entries SET ordinal = 2
                WHERE snapshot_id = ? AND ordinal = 0
                """,
                (snapshot.snapshot_id,),
            )
        vault._connection.rollback()


def test_sync_rolls_back_imports_and_does_not_publish_partial_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault, source_root = _mutable_vault(tmp_path)
    original_bytes = {
        "a.txt": b"first",
        "b.txt": b"second",
    }
    for name, content in original_bytes.items():
        (source_root / name).write_bytes(content)

    with vault:
        subject_id = vault.register_subject("alpha")
        original_upsert = vault._upsert_prepared
        calls = 0

        def fail_after_first_upsert(*args: object, **kwargs: object) -> str:
            nonlocal calls
            source_id = original_upsert(*args, **kwargs)  # type: ignore[arg-type]
            calls += 1
            if calls == 2:
                raise RuntimeError("synthetic transaction failure")
            return source_id

        monkeypatch.setattr(vault, "_upsert_prepared", fail_after_first_upsert)
        with pytest.raises(RuntimeError, match="synthetic transaction failure"):
            vault.sync_tree(subject_id, "source")

        assert vault.list_documents(subject_id) == ()
        assert vault.list_document_states(subject_id) == ()
        assert vault.list_snapshots(subject_id) == ()

    assert {
        path.name: path.read_bytes() for path in sorted(source_root.iterdir())
    } == original_bytes


def test_sync_revalidates_sources_after_snapshot_staging_and_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault, source_root = _mutable_vault(tmp_path)
    source = source_root / "report.txt"
    source.write_bytes(b"bytes hashed before the transaction")

    with vault:
        subject_id = vault.register_subject("alpha")
        original_publish = vault._publish_snapshot

        def mutate_after_snapshot_staging(
            *args: object,
            **kwargs: object,
        ) -> str:
            snapshot_id = original_publish(*args, **kwargs)  # type: ignore[arg-type]
            source.write_bytes(b"different bytes after snapshot staging")
            return snapshot_id

        monkeypatch.setattr(vault, "_publish_snapshot", mutate_after_snapshot_staging)

        with pytest.raises(SourceChangedDuringReadError, match="changed"):
            vault.sync_tree(subject_id, "source")

        assert vault.list_documents(subject_id) == ()
        assert vault.list_document_states(subject_id) == ()
        assert vault.list_snapshots(subject_id) == ()


def test_import_file_revalidates_source_before_commit_and_rolls_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault, source_root = _mutable_vault(tmp_path)
    source = source_root / "report.txt"
    source.write_bytes(b"initial bytes")

    with vault:
        subject_id = vault.register_subject("alpha")
        original_upsert = vault._upsert_prepared

        def mutate_after_upsert(*args: object, **kwargs: object) -> str:
            source_id = original_upsert(*args, **kwargs)  # type: ignore[arg-type]
            source.write_bytes(b"mutated bytes with a different length")
            return source_id

        monkeypatch.setattr(vault, "_upsert_prepared", mutate_after_upsert)

        with pytest.raises(SourceChangedDuringReadError, match="changed"):
            vault.import_file(subject_id, source)

        assert vault.list_documents(subject_id) == ()
        assert vault.list_document_states(subject_id) == ()


def test_v1_database_migrates_and_accepts_changed_bytes(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    source = source_root / "report.txt"
    source.write_text("legacy bytes", encoding="utf-8")
    database = tmp_path / "vault.sqlite3"
    pseudonymizer = SubjectPseudonymizer(SECRET, namespace="tests")
    subject_id = pseudonymizer.subject_id("alpha")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    source_id = "src_" + hashlib.sha256(
        "\0".join((subject_id, "source", "report.txt", digest)).encode("utf-8")
    ).hexdigest()[:32]
    indexed_at = "2026-01-01T00:00:00+00:00"

    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE subjects (
                subject_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );
            CREATE TABLE documents (
                source_id TEXT PRIMARY KEY,
                subject_id TEXT NOT NULL REFERENCES subjects(subject_id),
                absolute_path TEXT NOT NULL UNIQUE,
                root_id TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                media_type TEXT NOT NULL,
                indexed_at TEXT NOT NULL,
                UNIQUE(subject_id, root_id, relative_path)
            );
            CREATE TABLE provenance_locators (
                locator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL REFERENCES documents(source_id) ON DELETE CASCADE,
                page INTEGER,
                bbox_x0 REAL,
                bbox_y0 REAL,
                bbox_x1 REAL,
                bbox_y1 REAL,
                line_start INTEGER,
                line_end INTEGER,
                char_start INTEGER,
                char_end INTEGER
            );
            """
        )
        connection.execute(
            "INSERT INTO subjects(subject_id, created_at) VALUES (?, ?)",
            (subject_id, indexed_at),
        )
        connection.execute(
            """
            INSERT INTO documents(
                source_id, subject_id, absolute_path, root_id, relative_path,
                sha256, size_bytes, mtime_ns, media_type, indexed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                source_id,
                subject_id,
                str(source.resolve()),
                "source",
                "report.txt",
                digest,
                source.stat().st_size,
                source.stat().st_mtime_ns,
                "text/plain",
                indexed_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO provenance_locators(source_id, page, line_start, line_end)
            VALUES (?, 1, 1, 1)
            """,
            (source_id,),
        )

    with VaultIndex(
        database,
        roots={"source": source_root},
        pseudonymizer=pseudonymizer,
    ) as vault:
        migrated = vault.get_document(subject_id, source_id)
        assert migrated.provenance[0].page == 1
        assert vault._connection.execute("PRAGMA user_version").fetchone()[0] == 3

        source.write_text("new bytes", encoding="utf-8")
        current = vault.import_file(subject_id, source)

        assert current.source_id != source_id
        assert vault.list_documents(subject_id) == (current,)
        assert vault.list_document_versions(subject_id, current.source_id) == (
            migrated,
            current,
        )


def test_v2_database_migrates_existing_documents_as_present(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    source = source_root / "report.txt"
    source.write_text("v2 bytes", encoding="utf-8")
    database = tmp_path / "vault.sqlite3"
    pseudonymizer = SubjectPseudonymizer(SECRET, namespace="tests")
    subject_id = pseudonymizer.subject_id("alpha")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    document_id = VaultIndex._logical_document_id(
        subject_id, "source", "report.txt"
    )
    source_id = "src_" + hashlib.sha256(
        "\0".join((subject_id, "source", "report.txt", digest)).encode("utf-8")
    ).hexdigest()[:32]
    indexed_at = "2026-01-01T00:00:00+00:00"

    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            PRAGMA user_version = 2;
            CREATE TABLE subjects (
                subject_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );
            CREATE TABLE documents (
                document_id TEXT PRIMARY KEY,
                subject_id TEXT NOT NULL REFERENCES subjects(subject_id),
                absolute_path TEXT NOT NULL UNIQUE,
                root_id TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                current_source_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(subject_id, root_id, relative_path),
                FOREIGN KEY(document_id, current_source_id)
                    REFERENCES document_versions(document_id, source_id)
                    DEFERRABLE INITIALLY DEFERRED
            );
            CREATE TABLE document_versions (
                source_id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL REFERENCES documents(document_id),
                version_number INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                media_type TEXT NOT NULL,
                indexed_at TEXT NOT NULL,
                UNIQUE(document_id, version_number),
                UNIQUE(document_id, sha256),
                UNIQUE(document_id, source_id)
            );
            CREATE TABLE provenance_locators (
                locator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL REFERENCES document_versions(source_id),
                page INTEGER,
                bbox_x0 REAL,
                bbox_y0 REAL,
                bbox_x1 REAL,
                bbox_y1 REAL,
                line_start INTEGER,
                line_end INTEGER,
                char_start INTEGER,
                char_end INTEGER
            );
            """
        )
        connection.execute(
            "INSERT INTO subjects(subject_id, created_at) VALUES (?, ?)",
            (subject_id, indexed_at),
        )
        connection.execute(
            """
            INSERT INTO documents(
                document_id, subject_id, absolute_path, root_id, relative_path,
                current_source_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                document_id,
                subject_id,
                str(source.resolve()),
                "source",
                "report.txt",
                source_id,
                indexed_at,
                indexed_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO document_versions(
                source_id, document_id, version_number, sha256, size_bytes,
                mtime_ns, media_type, indexed_at
            ) VALUES (?, ?, 1, ?, ?, ?, 'text/plain', ?)
            """,
            (
                source_id,
                document_id,
                digest,
                source.stat().st_size,
                source.stat().st_mtime_ns,
                indexed_at,
            ),
        )

    with VaultIndex(
        database,
        roots={"source": source_root},
        pseudonymizer=pseudonymizer,
    ) as vault:
        state = vault.get_document_state(subject_id, source_id)
        snapshot = vault.sync_tree(subject_id, "source")

        assert vault._connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert state.presence_state == "present"
        assert state.tombstoned_at is None
        assert snapshot.source_count == 1
        assert vault.load_snapshot_page(
            subject_id, snapshot.snapshot_id
        ).documents[0].source_id == source_id


def test_corrupt_v1_migration_rolls_back_and_retry_still_fails(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    source = source_root / "report.txt"
    source.write_text("legacy", encoding="utf-8")
    database = tmp_path / "vault.sqlite3"
    pseudonymizer = SubjectPseudonymizer(SECRET, namespace="tests")
    subject_id = pseudonymizer.subject_id("alpha")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    source_id = "src_valid"
    indexed_at = "2026-01-01T00:00:00+00:00"

    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE subjects (
                subject_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );
            CREATE TABLE documents (
                source_id TEXT PRIMARY KEY,
                subject_id TEXT NOT NULL REFERENCES subjects(subject_id),
                absolute_path TEXT NOT NULL UNIQUE,
                root_id TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                media_type TEXT NOT NULL,
                indexed_at TEXT NOT NULL,
                UNIQUE(subject_id, root_id, relative_path)
            );
            CREATE TABLE provenance_locators (
                locator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL REFERENCES documents(source_id),
                page INTEGER,
                bbox_x0 REAL,
                bbox_y0 REAL,
                bbox_x1 REAL,
                bbox_y1 REAL,
                line_start INTEGER,
                line_end INTEGER,
                char_start INTEGER,
                char_end INTEGER
            );
            """
        )
        connection.execute(
            "INSERT INTO subjects(subject_id, created_at) VALUES (?, ?)",
            (subject_id, indexed_at),
        )
        connection.execute(
            """
            INSERT INTO documents(
                source_id, subject_id, absolute_path, root_id, relative_path,
                sha256, size_bytes, mtime_ns, media_type, indexed_at
            ) VALUES (?, ?, ?, 'source', 'report.txt', ?, ?, ?, 'text/plain', ?)
            """,
            (
                source_id,
                subject_id,
                str(source.resolve()),
                digest,
                source.stat().st_size,
                source.stat().st_mtime_ns,
                indexed_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO provenance_locators(source_id, page)
            VALUES ('src_dangling', 1)
            """
        )

    for _ in range(2):
        with pytest.raises(sqlite3.IntegrityError, match="foreign-key"):
            VaultIndex(
                database,
                roots={"source": source_root},
                pseudonymizer=pseudonymizer,
            )
        with sqlite3.connect(database) as connection:
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(documents)")
            }
            assert "source_id" in columns
            assert "document_id" not in columns
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
            assert connection.execute(
                "SELECT source_id FROM provenance_locators"
            ).fetchall() == [("src_dangling",)]


def test_corrupt_v2_migration_rolls_back_without_version_change(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    database = tmp_path / "vault.sqlite3"
    pseudonymizer = SubjectPseudonymizer(SECRET, namespace="tests")
    subject_id = pseudonymizer.subject_id("alpha")
    indexed_at = "2026-01-01T00:00:00+00:00"

    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            PRAGMA user_version = 2;
            CREATE TABLE subjects (
                subject_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );
            CREATE TABLE documents (
                document_id TEXT PRIMARY KEY,
                subject_id TEXT NOT NULL REFERENCES subjects(subject_id),
                absolute_path TEXT NOT NULL UNIQUE,
                root_id TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                current_source_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(subject_id, root_id, relative_path),
                FOREIGN KEY(document_id, current_source_id)
                    REFERENCES document_versions(document_id, source_id)
                    DEFERRABLE INITIALLY DEFERRED
            );
            CREATE TABLE document_versions (
                source_id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL REFERENCES documents(document_id),
                version_number INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL,
                media_type TEXT NOT NULL,
                indexed_at TEXT NOT NULL,
                UNIQUE(document_id, version_number),
                UNIQUE(document_id, sha256),
                UNIQUE(document_id, source_id)
            );
            CREATE TABLE provenance_locators (
                locator_id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id TEXT NOT NULL REFERENCES document_versions(source_id),
                page INTEGER,
                bbox_x0 REAL,
                bbox_y0 REAL,
                bbox_x1 REAL,
                bbox_y1 REAL,
                line_start INTEGER,
                line_end INTEGER,
                char_start INTEGER,
                char_end INTEGER
            );
            """
        )
        connection.execute(
            "INSERT INTO subjects(subject_id, created_at) VALUES (?, ?)",
            (subject_id, indexed_at),
        )
        connection.execute(
            """
            INSERT INTO documents(
                document_id, subject_id, absolute_path, root_id, relative_path,
                current_source_id, created_at, updated_at
            ) VALUES ('doc_dangling', ?, ?, 'source', 'missing.txt',
                      'src_dangling', ?, ?)
            """,
            (subject_id, str(source_root / "missing.txt"), indexed_at, indexed_at),
        )

    with pytest.raises(sqlite3.IntegrityError, match="foreign-key"):
        VaultIndex(
            database,
            roots={"source": source_root},
            pseudonymizer=pseudonymizer,
        )

    with sqlite3.connect(database) as connection:
        columns = {
            row[1] for row in connection.execute("PRAGMA table_info(documents)")
        }
        assert "presence_state" not in columns
        assert "tombstoned_at" not in columns
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert connection.execute(
            "SELECT current_source_id FROM documents"
        ).fetchall() == [("src_dangling",)]


def test_future_schema_version_is_rejected_without_downgrade(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    database = tmp_path / "vault.sqlite3"
    future_version = 4
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
        connection.execute("INSERT INTO sentinel(value) VALUES ('unchanged')")
        connection.execute(f"PRAGMA user_version = {future_version}")

    with pytest.raises(RuntimeError, match="newer than supported version 3"):
        VaultIndex(
            database,
            roots={"source": source_root},
            pseudonymizer=SubjectPseudonymizer(SECRET, namespace="tests"),
        )

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == future_version
        assert connection.execute("SELECT value FROM sentinel").fetchall() == [
            ("unchanged",)
        ]
        assert connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name != 'sentinel'
            """
        ).fetchall() == []


def test_sources_outside_allowlist_are_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("synthetic", encoding="utf-8")

    with _vault(tmp_path) as vault:
        subject_id = vault.register_subject("alpha")
        with pytest.raises(SourceOutsideVaultError):
            vault.import_file(subject_id, outside)


def test_database_cannot_live_inside_source_root(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    with pytest.raises(ValueError, match="outside read-only source roots"):
        VaultIndex(
            source_root / "vault.sqlite3",
            roots={"source": source_root},
            pseudonymizer=SubjectPseudonymizer(SECRET),
        )


def test_database_hardlink_alias_into_source_root_is_rejected_before_write(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    source_alias = source_root / "archive.sqlite3"
    source_alias.write_bytes(b"source bytes must stay unchanged")
    outside_database = tmp_path / "sidecar.sqlite3"
    outside_database.hardlink_to(source_alias)
    before = source_alias.read_bytes()

    with pytest.raises(ValueError, match="singly linked regular file"):
        VaultIndex(
            outside_database,
            roots={"source": source_root},
            pseudonymizer=SubjectPseudonymizer(SECRET),
        )

    assert source_alias.read_bytes() == before
    assert outside_database.read_bytes() == before


def test_manifest_verification_rejects_post_index_symlink(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    source = source_root / "source.txt"
    source.write_text("original", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")

    with VaultIndex(
        tmp_path / "vault.sqlite3",
        roots={"source": source_root},
        pseudonymizer=SubjectPseudonymizer(SECRET),
    ) as vault:
        subject_id = vault.register_subject("alpha")
        vault.import_file(subject_id, source)
        source.unlink()
        source.symlink_to(outside)

        result = vault.verify_manifest(subject_id)[0]

    assert result.status == "unsafe_or_missing"


def test_tree_import_is_file_format_independent_by_default(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    (source_root / "unknown.payload").write_bytes(b"opaque")

    with VaultIndex(
        tmp_path / "vault.sqlite3",
        roots={"source": source_root},
        pseudonymizer=SubjectPseudonymizer(SECRET),
    ) as vault:
        subject_id = vault.register_subject("alpha")
        documents = vault.import_tree(subject_id, "source")

    assert len(documents) == 1
    assert documents[0].media_type == "application/octet-stream"


def test_descriptor_indexing_rejects_hardlinked_sources(tmp_path: Path) -> None:
    source_root = tmp_path / "sources"
    source_root.mkdir()
    original = source_root / "original.txt"
    original.write_text("synthetic", encoding="utf-8")
    linked = source_root / "linked.txt"
    linked.hardlink_to(original)

    with VaultIndex(
        tmp_path / "vault.sqlite3",
        roots={"source": source_root},
        pseudonymizer=SubjectPseudonymizer(SECRET),
    ) as vault:
        subject_id = vault.register_subject("alpha")
        with pytest.raises(SourceOutsideVaultError, match="multiply linked"):
            vault.import_file(subject_id, original)
        with pytest.raises(SourceOutsideVaultError, match="unsafe file"):
            vault.import_tree(subject_id, "source")
