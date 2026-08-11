from __future__ import annotations

from health_analyzer.vault import SubjectPseudonymizer


SECRET = b"synthetic-test-secret-material-32b!"


def test_subject_ids_are_deterministic_and_keyed() -> None:
    first = SubjectPseudonymizer(SECRET, namespace="private-archive")
    second = SubjectPseudonymizer(SECRET, namespace="private-archive")

    assert first.subject_id("local-record-alpha") == second.subject_id("local-record-alpha")
    assert first.subject_id("local-record-alpha") != first.subject_id("local-record-beta")
    assert "local-record-alpha" not in first.subject_id("local-record-alpha")


def test_subject_namespace_is_part_of_pseudonym() -> None:
    one = SubjectPseudonymizer(SECRET, namespace="one")
    two = SubjectPseudonymizer(SECRET, namespace="two")

    assert one.subject_id("same-local-key") != two.subject_id("same-local-key")
