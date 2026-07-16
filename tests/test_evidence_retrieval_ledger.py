from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sqlite3

import pytest

from health_analyzer.contracts import EvidenceItem, RiskEnvelope, RiskIntent
from health_analyzer.evidence.query import EvidenceQuery
from health_analyzer.evidence.query import retrieval_execution_descriptor
from health_analyzer.evidence.retrieval_ledger import (
    DuplicateRetrievalReceiptError,
    RetrievalLedger,
    RetrievalLedgerIntegrityError,
    UnknownRetrievalReceiptError,
)


LEDGER_KEY = b"synthetic-retrieval-ledger-key-32b"
OTHER_KEY = b"different-retrieval-ledger-key-32"
EDUCATION_RISK = RiskEnvelope(intent=RiskIntent.EDUCATION)


def _query(
    *,
    max_results: int = 2,
    risk_envelope: RiskEnvelope = EDUCATION_RISK,
) -> EvidenceQuery:
    return EvidenceQuery(
        question="Does a synthetic intervention change a synthetic outcome?",
        risk_envelope=risk_envelope,
        population="synthetic adults",
        intervention="synthetic intervention",
        outcomes=("synthetic outcome",),
        max_results=max_results,
    )


def _pubmed_item(pmid: str = "42", *, title: str = "Synthetic trial") -> EvidenceItem:
    return EvidenceItem(
        evidence_id=f"pmid:{pmid}",
        title=title,
        source_type="randomized_trial",
        url=f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/",
        published_at="2026",
        organization="Synthetic Journal",
        identifiers={"pmid": pmid, "doi": f"10.1000/test-{pmid}"},
        content_hash=hashlib.sha256(f"remote-pubmed-{pmid}".encode()).hexdigest(),
    )


def _crossref_item(doi: str = "10.1000/test") -> EvidenceItem:
    return EvidenceItem(
        evidence_id=f"doi:{doi}",
        title="Synthetic Crossref record",
        source_type="journal_article",
        url=f"https://doi.org/{doi}",
        identifiers={"doi": doi},
        content_hash=hashlib.sha256(f"remote-crossref-{doi}".encode()).hexdigest(),
    )


def test_register_and_load_exact_server_snapshot_with_private_modes(tmp_path: Path) -> None:
    database = tmp_path / "public-state" / "retrieval" / "ledger.sqlite3"
    query = _query()
    items = (_pubmed_item("42"), _pubmed_item("43"))
    ledger = RetrievalLedger(database, integrity_key=LEDGER_KEY)

    receipt = ledger.register("pubmed", query, items)
    loaded = ledger.load_receipt(receipt.receipt_id)

    assert receipt.receipt_id.startswith("retr_")
    assert query.query_id not in receipt.receipt_id
    assert receipt.item_count == 2
    assert receipt.risk_envelope == EDUCATION_RISK
    assert receipt.query_sha256 == loaded.receipt.query_sha256
    assert receipt.results_sha256 == loaded.receipt.results_sha256
    assert receipt.item_sha256s == loaded.receipt.item_sha256s
    assert loaded.query == query
    assert loaded.receipt.risk_envelope == EDUCATION_RISK
    assert loaded.items == items
    assert database.stat().st_mode & 0o777 == 0o600
    assert database.parent.stat().st_mode & 0o777 == 0o700

    with sqlite3.connect(database) as connection:
        stored_query, stored_item = connection.execute(
            """
            SELECT r.query_json, i.item_json
            FROM retrieval_run r
            JOIN retrieval_item i ON i.receipt_id = r.receipt_id
            WHERE r.receipt_id = ? AND i.ordinal = 0
            """,
            (receipt.receipt_id,),
        ).fetchone()
    assert json.loads(stored_query) == asdict(query) | {
        "outcomes": list(query.outcomes),
        "source_types": list(query.source_types),
        "jurisdictions": list(query.jurisdictions),
    }
    assert json.loads(stored_item)["title"] == "Synthetic trial"


def test_register_snapshots_mutable_identifier_mapping(tmp_path: Path) -> None:
    item = _pubmed_item()
    database = tmp_path / "retrieval" / "ledger.sqlite3"
    ledger = RetrievalLedger(database, integrity_key=LEDGER_KEY)
    receipt = ledger.register("pubmed", _query(max_results=1), (item,))

    item.identifiers["pmid"] = "999"
    loaded = ledger.load_receipt(receipt.receipt_id)

    assert loaded.items[0].identifiers["pmid"] == "42"


def test_query_id_and_receipt_bind_the_explicit_risk_envelope(tmp_path: Path) -> None:
    personal_risk = RiskEnvelope(intent=RiskIntent.PERSONAL_CONTEXT)
    education_query = _query(max_results=1)
    personal_query = _query(max_results=1, risk_envelope=personal_risk)
    assert education_query.query_id != personal_query.query_id

    database = tmp_path / "retrieval" / "ledger.sqlite3"
    ledger = RetrievalLedger(database, integrity_key=LEDGER_KEY)
    receipt = ledger.register("pubmed", personal_query, (_pubmed_item(),))

    with sqlite3.connect(database) as connection:
        raw = connection.execute(
            "SELECT query_json FROM retrieval_run WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone()[0]
        payload = json.loads(raw)
        payload["risk_envelope"] = asdict(EDUCATION_RISK)
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        connection.execute(
            "UPDATE retrieval_run SET query_json = ?, query_sha256 = ? WHERE receipt_id = ?",
            (
                canonical,
                hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                receipt.receipt_id,
            ),
        )

    with pytest.raises(RetrievalLedgerIntegrityError, match="canonical binding"):
        ledger.load_receipt(receipt.receipt_id)


def test_load_rejects_unknown_and_duplicate_receipts(tmp_path: Path) -> None:
    ledger = RetrievalLedger(
        tmp_path / "retrieval" / "ledger.sqlite3",
        integrity_key=LEDGER_KEY,
    )
    receipt = ledger.register("crossref", _query(max_results=1), (_crossref_item(),))

    with pytest.raises(UnknownRetrievalReceiptError, match="not present"):
        ledger.load_receipt("retr_" + "0" * 32)
    with pytest.raises(DuplicateRetrievalReceiptError, match="duplicate"):
        ledger.load_receipts([receipt.receipt_id, receipt.receipt_id])


def test_load_rejects_item_tampering_even_when_public_hash_is_recomputed(
    tmp_path: Path,
) -> None:
    database = tmp_path / "retrieval" / "ledger.sqlite3"
    ledger = RetrievalLedger(database, integrity_key=LEDGER_KEY)
    receipt = ledger.register("pubmed", _query(max_results=1), (_pubmed_item(),))

    with sqlite3.connect(database) as connection:
        raw = connection.execute(
            "SELECT item_json FROM retrieval_item WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone()[0]
        payload = json.loads(raw)
        payload["title"] = "Tampered title"
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        connection.execute(
            """
            UPDATE retrieval_item
            SET item_json = ?, item_sha256 = ?
            WHERE receipt_id = ?
            """,
            (
                canonical,
                hashlib.sha256(canonical.encode()).hexdigest(),
                receipt.receipt_id,
            ),
        )

    with pytest.raises(RetrievalLedgerIntegrityError, match="canonical binding"):
        ledger.load_receipt(receipt.receipt_id)


def test_load_rejects_deleted_items_and_wrong_integrity_key(tmp_path: Path) -> None:
    database = tmp_path / "retrieval" / "ledger.sqlite3"
    ledger = RetrievalLedger(database, integrity_key=LEDGER_KEY)
    first = ledger.register("pubmed", _query(max_results=1), (_pubmed_item("42"),))
    second = ledger.register("pubmed", _query(max_results=1), (_pubmed_item("43"),))

    wrong_key_ledger = RetrievalLedger(database, integrity_key=OTHER_KEY)
    with pytest.raises(RetrievalLedgerIntegrityError, match="canonical binding"):
        wrong_key_ledger.load_receipt(first.receipt_id)

    with sqlite3.connect(database) as connection:
        connection.execute(
            "DELETE FROM retrieval_item WHERE receipt_id = ?",
            (second.receipt_id,),
        )
    with pytest.raises(RetrievalLedgerIntegrityError, match="canonical binding"):
        ledger.load_receipt(second.receipt_id)


@pytest.mark.parametrize(
    ("source", "items", "message"),
    [
        ("crossref", (_pubmed_item(),), "Crossref"),
        ("pubmed", (_crossref_item(),), "PubMed"),
        ("crossref", (_crossref_item("not-a-doi"),), "canonical DOI"),
        ("crossref", (_crossref_item("10.1000/test#fragment"),), "canonical DOI"),
        ("pubmed", (_pubmed_item("1" * 17),), "invalid PMID"),
        ("unknown", (_pubmed_item(),), "source"),
    ],
)
def test_register_rejects_source_inconsistent_or_unknown_items(
    tmp_path: Path,
    source: str,
    items: tuple[EvidenceItem, ...],
    message: str,
) -> None:
    ledger = RetrievalLedger(
        tmp_path / source / "ledger.sqlite3",
        integrity_key=LEDGER_KEY,
    )
    with pytest.raises(ValueError, match=message):
        ledger.register(source, _query(max_results=1), items)


def test_register_rejects_duplicate_or_caller_modified_results(tmp_path: Path) -> None:
    ledger = RetrievalLedger(
        tmp_path / "retrieval" / "ledger.sqlite3",
        integrity_key=LEDGER_KEY,
    )
    item = _pubmed_item()

    with pytest.raises(ValueError, match="duplicate evidence"):
        ledger.register("pubmed", _query(), (item, item))

    modified = _pubmed_item()
    modified.identifiers["pmid"] = "999"
    with pytest.raises(ValueError, match="does not match"):
        ledger.register("pubmed", _query(max_results=1), (modified,))


def test_database_symlink_and_hardlink_are_rejected(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    parent_link = tmp_path / "parent-link"
    parent_link.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(ValueError, match="parent must not be a symbolic link"):
        RetrievalLedger(parent_link / "ledger.sqlite3", integrity_key=LEDGER_KEY)

    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"")
    database_link = tmp_path / "database-link.sqlite3"
    database_link.symlink_to(target)
    with pytest.raises(ValueError, match="database must not be a symbolic link"):
        RetrievalLedger(database_link, integrity_key=LEDGER_KEY)

    database = tmp_path / "hardlinks" / "ledger.sqlite3"
    ledger = RetrievalLedger(database, integrity_key=LEDGER_KEY)
    receipt = ledger.register("pubmed", _query(max_results=1), (_pubmed_item(),))
    os.link(database, tmp_path / "hardlinks" / "second-name.sqlite3")
    with pytest.raises(ValueError, match="private regular file"):
        ledger.load_receipt(receipt.receipt_id)


def test_empty_retrieval_is_still_receipted_exactly(tmp_path: Path) -> None:
    ledger = RetrievalLedger(
        tmp_path / "retrieval" / "ledger.sqlite3",
        integrity_key=LEDGER_KEY,
    )
    receipt = ledger.register("pubmed", _query(max_results=1), ())
    loaded = ledger.load_receipt(receipt.receipt_id)

    assert receipt.item_count == 0
    assert receipt.item_sha256s == ()
    assert loaded.items == ()


def test_pubmed_receipt_binds_esummary_ordered_ids(tmp_path: Path) -> None:
    ledger = RetrievalLedger(
        tmp_path / "retrieval" / "ledger.sqlite3",
        integrity_key=LEDGER_KEY,
    )
    query = _query(max_results=2)
    item = _pubmed_item("42")
    execution = retrieval_execution_descriptor(
        "pubmed",
        query,
        pubmed_summary_ids=("43",),
    )

    with pytest.raises(ValueError, match="summary request"):
        ledger.register("pubmed", query, (item,), execution=execution)
