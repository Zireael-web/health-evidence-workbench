import pytest

from health_analyzer.privacy import PrivacyGate, PrivacyViolation, pseudonymous_subject_id


def test_public_gate_rejects_direct_identifiers_without_leaking_value() -> None:
    gate = PrivacyGate()
    with pytest.raises(PrivacyViolation) as error:
        gate.assert_public_query("Пациент: Тестов Алексей Сергеевич, телефон +7 999 123-45-67")
    assert "Тестов" not in str(error.value)
    assert "direct identifiers" in str(error.value)


def test_redaction_is_explicit_and_deterministic() -> None:
    gate = PrivacyGate()
    redacted, findings = gate.redact_for_review("email me at patient@example.org")
    assert redacted == "email me at [REDACTED:email]"
    assert [finding.kind for finding in findings] == ["email"]


def test_pseudonym_is_stable_but_secret_scoped() -> None:
    first = pseudonymous_subject_id("Test Person", b"a" * 32)
    second = pseudonymous_subject_id(" test person ", b"a" * 32)
    other_secret = pseudonymous_subject_id("Test Person", b"b" * 32)
    assert first == second
    assert first != other_secret
    assert "person" not in first


@pytest.mark.parametrize(
    "text",
    [
        '{"subject_id":"subj_abcdef1234567890","raw_value":"7.1"}',
        "/" + "Users/" + "example/record.txt",
    ],
)
def test_public_gate_rejects_minimal_private_packet_or_local_path(text: str) -> None:
    with pytest.raises(PrivacyViolation):
        PrivacyGate().assert_public_query(text)


def test_public_gate_recursively_rejects_identifiers_in_nested_payload() -> None:
    payload = {
        "claims": [
            {
                "text": "population result",
                "caveats": ["Дата рождения: 17.04.1988"],
            }
        ]
    }

    with pytest.raises(PrivacyViolation) as error:
        PrivacyGate().assert_public_payload(payload)

    assert "1988" not in str(error.value)
    assert "birth_date" in str(error.value)


def test_public_gate_allows_typed_public_metadata_dates() -> None:
    PrivacyGate().assert_public_payload(
        {
            "as_of": "2026-08-07",
            "items": [
                {
                    "title": "Synthetic public guideline",
                    "published_at": "2025-01-31",
                    "retrieved_at": "2026-08-07T12:30:00+00:00",
                }
            ],
        }
    )


def test_public_gate_does_not_exempt_date_in_free_text_field() -> None:
    with pytest.raises(PrivacyViolation):
        PrivacyGate().assert_public_payload(
            {"question": "мужчина 38 лет, обследование 17.04.1988"}
        )


def test_public_gate_exempts_only_typed_public_hashes_and_receipts() -> None:
    digit_heavy_hash = "12345678901" + "a" * 53
    PrivacyGate().assert_public_payload(
        {
            "source_document_sha256": digit_heavy_hash,
            "retrieval_receipt_id": "retr_" + "12345678901" + "a" * 21,
        }
    )

    with pytest.raises(PrivacyViolation):
        PrivacyGate().assert_public_payload({"question": digit_heavy_hash})


def test_public_semantic_gate_rejects_unlabelled_long_identifier() -> None:
    with pytest.raises(PrivacyViolation, match="quasi-identifiers"):
        PrivacyGate().assert_public_semantic_payload(
            {"text": "Patient record 654321 shows a response."}
        )


def test_confirmed_review_digests_are_typed_not_scanned_as_phone_numbers() -> None:
    digit_heavy_hash = ("12345678901" * 6)[:64]

    PrivacyGate().assert_public_payload(
        {
            "confirmed_source_snapshot_sha256": digit_heavy_hash,
            "confirmed_source_document_sha256": digit_heavy_hash,
        }
    )


def test_bounded_offline_payload_allows_opaque_case_packet_id() -> None:
    PrivacyGate().assert_bounded_payload(
        {"case_packet_id": "case_" + "a" * 24, "question": "Synthetic question"}
    )


def test_bounded_offline_payload_rejects_oversized_text() -> None:
    with pytest.raises(PrivacyViolation, match="text inspection limit"):
        PrivacyGate().assert_bounded_payload({"question": "x" * 250_001})


@pytest.mark.parametrize(
    "text",
    [
        "Тестов Алексей Сергеевич артериальное давление",
        "мужчина 38 лет, обследование 17.04.1988",
        "Адрес: Лабораторная 17, рекомендации",
    ],
)
def test_public_gate_rejects_unlabelled_name_date_and_labelled_address(text: str) -> None:
    with pytest.raises(PrivacyViolation):
        PrivacyGate().assert_public_query(text)


@pytest.mark.parametrize(
    "text",
    [
        "Тестов Алексей давление",
        "Testov Alexey blood pressure",
        "номер исследования 654321",
        "Лабораторная 17 давление",
    ],
)
def test_public_query_rejects_probable_quasi_identifiers(text: str) -> None:
    with pytest.raises(PrivacyViolation, match="quasi-identifiers"):
        PrivacyGate().assert_public_query(text)


@pytest.mark.parametrize(
    "text",
    [
        "blood pressure treatment",
        "systematic review exercise",
        "Does aerobic training reduce ambulatory blood pressure?",
        "Systematic Review Exercise",
        "Aerobic Exercise",
    ],
)
def test_public_query_name_heuristic_does_not_block_scientific_phrases(text: str) -> None:
    PrivacyGate().assert_public_query(text)


@pytest.mark.parametrize(
    "text",
    [
        "Name: alex morgan",
        "Full name: alex morgan",
        "phone +1 (202) 555-0198",
        "phone: 202-555-0198",
    ],
)
def test_public_query_rejects_labelled_lowercase_name_and_international_phone(
    text: str,
) -> None:
    with pytest.raises(PrivacyViolation):
        PrivacyGate().assert_public_query(text)
