"""Private, standalone whole-row preview; no records writes or source reads.

The caller retrieves snapshots through its verified store and supplies bounded,
source-bound assets. SHA verification below binds content; it does not verify a
store MAC, pixel derivation, clinical correctness, or the origin of a decision.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import html
import json
import os
from pathlib import Path
import stat
from typing import Any
import zlib

from .common import V2Error, canonical, digest, require
from .contracts import SCHEMA_VERSION, SHA256_RE, identifier, iso_timestamp, lab_observation, text

PREVIEW_SCHEMA = "health-analyzer.private-preview/1.0"
DECISION_SCHEMA = "health-analyzer.preview-decisions/1.0"
MAX_BUNDLES = 1000
MAX_ASSET_BYTES = 5 * 1024 * 1024
MAX_IMAGE_DIMENSION = 12000
MAX_IMAGE_PIXELS = 40_000_000
MAX_PREVIEW_BYTES = 64 * 1024 * 1024
MATERIAL_FIELDS = ("analyte_raw", "result", "unit_raw", "clinical_time", "reference_intervals")
SNAPSHOT_KEYS = {"schema_version", "subject_id", "snapshot_id", "version_id", "source_sha256", "run_id", "selection_token", "panel_id", "rows", "displayed_draft_ids", "review_tokens", "observation_tokens", "coverage", "offset", "limit", "total_in_selection", "recorded_at", "snapshot_sha256"}
LABELS = {
    "analyte_raw": "Показатель — исходное название", "result": "Результат",
    "unit_raw": "Единица — как напечатана", "clinical_time": "Клиническая дата / время",
    "reference_intervals": "Референсы этого результата", "specimen": "Биоматериал",
    "method": "Метод / анализатор", "lab_flag_raw": "Флаг лаборатории",
    "analyte_key": "Ключ показателя", "mapping_status": "Статус сопоставления",
    "measurement_property": "Измеряемое свойство", "subtype": "Подтип", "loinc": "LOINC",
    "unit_code": "Код единицы", "device": "Прибор", "panel_key": "Панель",
    "extraction_method": "Способ извлечения", "field_status": "Статусы полей",
    "missing_reasons": "Причины отсутствия", "field_anchors": "Все якоря источника",
}
STATUSES = {"proposed": "предложено извлечением", "extracted": "извлечено; не подтверждено",
            "ambiguous": "неоднозначно", "unknown": "неизвестно", "not_reported": "не указано",
            "not_applicable": "не применимо", "review_corrected": "исправление в данных snapshot"}


def _sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(SHA256_RE.fullmatch(value)), "preview_hash", f"Invalid {label}")
    return value


def _bounded_list(value: Any, limit: int, code: str) -> list:
    require(isinstance(value, list) and len(value) <= limit, code, "List exceeds preview limits")
    return value


def _anchors(row: dict, field: str) -> list[dict]:
    value = row["field_anchors"].get(field)
    return value if isinstance(value, list) else [value] if value is not None else []


def _material_anchors(row: dict) -> list[tuple[str, int]]:
    return [(field, index) for field in MATERIAL_FIELDS for index, _ in enumerate(_anchors(row, field))]


def _validate_snapshot(snapshot: dict, subject_id: str) -> None:
    require(isinstance(snapshot, dict) and set(snapshot) <= SNAPSHOT_KEYS, "preview_snapshot", "Expected a frozen prepare_review snapshot")
    require(snapshot.get("schema_version") == SCHEMA_VERSION, "preview_schema", "Unsupported record schema")
    require(snapshot.get("subject_id") == subject_id, "preview_subject", "Snapshot belongs to another profile")
    for key in ("snapshot_id", "version_id", "run_id"):
        identifier(snapshot.get(key), key)
    _sha(snapshot.get("source_sha256"), "source SHA")
    _sha(snapshot.get("snapshot_sha256"), "snapshot SHA")
    require(digest({k: v for k, v in snapshot.items() if k != "snapshot_sha256"}) == snapshot["snapshot_sha256"], "preview_snapshot_hash", "Frozen snapshot content differs from its SHA")
    rows = _bounded_list(snapshot.get("rows"), 100, "preview_limit")
    require(bool(rows), "preview_snapshot", "Snapshot has no rows")
    ids = snapshot.get("displayed_draft_ids")
    require(isinstance(ids, list) and len(ids) == len(rows) and len(set(ids)) == len(ids), "preview_rows", "Snapshot row IDs are inconsistent")
    limit, offset, total = (snapshot.get(k) for k in ("limit", "offset", "total_in_selection"))
    require(type(limit) is int and 1 <= limit <= 100 and len(rows) <= limit and type(offset) is int and offset >= 0 and type(total) is int and total >= offset + len(rows), "preview_limit", "Snapshot pagination is invalid")
    require(isinstance(snapshot.get("coverage"), dict), "preview_coverage", "Snapshot coverage is required")
    coverage = snapshot["coverage"]
    require(coverage.get("run_id") == snapshot["run_id"] and coverage.get("version_id") == snapshot["version_id"], "preview_version", "Coverage belongs to another extraction/version")
    require(coverage.get("expected_count_basis") in {"unknown", "source_count", "extractor_count"} and not (coverage.get("expected_count_basis") == "unknown" and coverage.get("expected_count") is not None), "preview_coverage", "Unknown source counts must stay unknown")
    require(isinstance(snapshot.get("review_tokens"), dict) and set(snapshot["review_tokens"]) == set(ids), "preview_rows", "Review token scope differs from displayed rows")
    require(isinstance(snapshot.get("observation_tokens"), dict), "preview_rows", "Observation tokens are required")
    observations = []
    for draft, draft_id in zip(rows, ids):
        require(isinstance(draft, dict) and draft.get("draft_id") == draft_id, "preview_rows", "Displayed row order differs from snapshot IDs")
        require(draft.get("subject_id") == subject_id, "preview_subject", "A draft belongs to another profile")
        require(draft.get("schema_version") == SCHEMA_VERSION and draft.get("source_version_id") == snapshot["version_id"] and draft.get("source_sha256") == snapshot["source_sha256"] and draft.get("extraction_run_id") == snapshot["run_id"], "preview_version", "Draft lineage differs from frozen snapshot")
        observations.append(identifier(draft.get("observation_id"), "observation_id"))
        identifier(draft_id, "draft_id")
        lab_observation(draft.get("row"), snapshot["version_id"], snapshot["source_sha256"])
    require(set(snapshot["observation_tokens"]) == set(observations), "preview_rows", "Observation token scope differs from displayed rows")


def _validate_source_state(state: Any, snapshot: dict) -> None:
    require(isinstance(state, dict) and set(state) <= {"subject_id", "version_id", "source_sha256", "status", "observed_source_sha256", "checked_at", "archive_drift"}, "preview_source_state", "Source state must be explicit and bounded")
    for key in ("subject_id", "version_id", "source_sha256"):
        require(state.get(key) == snapshot[key], "preview_source_binding", "Source state refers to another snapshot scope")
    status = state.get("status")
    require(status in {"unchanged", "changed", "unavailable", "unverified"}, "preview_source_state", "Unknown saved-source integrity state")
    observed = state.get("observed_source_sha256")
    if observed is not None:
        _sha(observed, "observed source SHA")
    if state.get("checked_at") is not None:
        iso_timestamp(state["checked_at"], "source checked_at")
    if status in {"unchanged", "changed"}:
        require(observed is not None and state.get("checked_at") is not None, "preview_source_state", "A byte-integrity check needs its observed SHA and time")
        require((observed == snapshot["source_sha256"]) == (status == "unchanged"), "preview_source_state", "Saved-source state contradicts its observed SHA")
    require(state.get("archive_drift", "not_checked") in {"unchanged", "changed", "unavailable", "not_checked"}, "preview_source_state", "Unknown archive drift state")


def _validate_snapshot_verification(value: Any, snapshot: dict) -> None:
    if value is None:
        return
    keys = {"method", "checked_at", "state", "reasons", "snapshot_sha256", "source_bytes_checked", "clinical_validation"}
    require(isinstance(value, dict) and set(value) == keys, "preview_verification", "Expected the read-only backend verification wrapper")
    require(value["method"] == "signed_store_hmac" and value["snapshot_sha256"] == snapshot["snapshot_sha256"], "preview_verification", "Backend verification must bind this exact frozen snapshot SHA")
    iso_timestamp(value["checked_at"], "snapshot verification checked_at")
    require(value["state"] in {"current", "stale"} and value["source_bytes_checked"] is False and value["clinical_validation"] == "not_provided", "preview_verification", "Snapshot freshness does not validate source pixels or clinical meaning")
    reasons = _bounded_list(value["reasons"], 4, "preview_verification")
    allowed = {"extraction_run_changed", "extraction_selection_changed", "review_state_changed", "observation_revision_changed"}
    require(all(isinstance(reason, str) and reason in allowed for reason in reasons) and len(set(reasons)) == len(reasons) and bool(reasons) == (value["state"] == "stale"), "preview_verification", "Backend freshness state contradicts its reasons")


def _image_dimensions(raw: bytes, mime: str) -> tuple[int, int]:
    if mime == "image/png":
        require(len(raw) >= 45 and raw[:8] == b"\x89PNG\r\n\x1a\n" and raw[8:16] == b"\x00\x00\x00\rIHDR" and raw[-12:] == b"\x00\x00\x00\x00IEND\xaeB`\x82", "preview_asset", "PNG needs an actual bounded IHDR and final IEND")
        require(int.from_bytes(raw[29:33], "big") == zlib.crc32(raw[12:29]), "preview_asset", "PNG IHDR checksum differs")
        depth, color, compression, filtering, interlace = raw[24:29]
        depths = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}
        require(color in depths and depth in depths[color] and compression == filtering == 0 and interlace in {0, 1}, "preview_asset", "Unsupported PNG header")
        position, chunks, has_pixels, ended_pixels = 8, 0, False, False
        while position < len(raw):
            chunks += 1
            require(chunks <= 4096 and position + 12 <= len(raw), "preview_asset", "PNG chunks are truncated or exceed structural limits")
            length = int.from_bytes(raw[position:position + 4], "big")
            end = position + length + 12
            require(end <= len(raw), "preview_asset", "PNG chunk exceeds supplied bytes")
            kind = raw[position + 4:position + 8]
            require(all(65 <= n <= 90 or 97 <= n <= 122 for n in kind), "preview_asset", "Invalid PNG chunk type")
            require(kind not in {b"acTL", b"fcTL", b"fdAT"}, "preview_asset", "Animated PNG is not a bounded static source crop")
            require(int.from_bytes(raw[end - 4:end], "big") == zlib.crc32(raw[position + 4:end - 4]), "preview_asset", "PNG chunk checksum differs")
            require(kind != b"IHDR" or chunks == 1 and length == 13, "preview_asset", "PNG cannot contain a second frame header")
            require(not (65 <= kind[0] <= 90) or kind in {b"IHDR", b"PLTE", b"IDAT", b"IEND"}, "preview_asset", "Unsupported critical PNG chunk")
            if kind == b"IDAT":
                require(not ended_pixels, "preview_asset", "PNG image-data chunks must be consecutive")
                has_pixels = has_pixels or length > 0
            elif has_pixels:
                ended_pixels = True
            if kind == b"IEND":
                require(length == 0 and end == len(raw) and has_pixels, "preview_asset", "PNG requires pixel data and exactly one final IEND")
            position = end
        return int.from_bytes(raw[16:20], "big"), int.from_bytes(raw[20:24], "big")
    require(raw.startswith(b"\xff\xd8") and raw.endswith(b"\xff\xd9"), "preview_asset", "JPEG needs SOI and EOI markers")
    position = 2
    sof = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
    while position < len(raw) - 2:
        require(raw[position] == 0xFF, "preview_asset", "Malformed JPEG marker header")
        while position < len(raw) and raw[position] == 0xFF:
            position += 1
        require(position < len(raw), "preview_asset", "Truncated JPEG marker")
        marker = raw[position]
        position += 1
        require(marker not in {0x00, 0xD8, 0xD9, 0xDA}, "preview_asset", "JPEG must declare dimensions before scan data")
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        require(position + 2 <= len(raw), "preview_asset", "Truncated JPEG segment")
        length = int.from_bytes(raw[position:position + 2], "big")
        require(length >= 2 and position + length <= len(raw), "preview_asset", "JPEG segment exceeds supplied bytes")
        if marker in sof:
            require(length >= 11 and raw[position + 2] in {8, 12, 16}, "preview_asset", "Malformed JPEG frame header")
            components = raw[position + 7]
            require(1 <= components <= 4 and length == 8 + 3 * components, "preview_asset", "JPEG frame components are inconsistent")
            return int.from_bytes(raw[position + 5:position + 7], "big"), int.from_bytes(raw[position + 3:position + 5], "big")
        position += length
    require(False, "preview_asset", "JPEG has no dimension-bearing frame header")
    raise AssertionError("unreachable")


def _image_sha(fragment: dict) -> str:
    require(fragment.get("kind") == "image_crop" and fragment.get("mime") in {"image/png", "image/jpeg"}, "preview_asset", "Only declared PNG/JPEG crops are supported")
    encoded = fragment.get("data_base64")
    require(isinstance(encoded, str) and len(encoded) <= 4 * ((MAX_ASSET_BYTES + 2) // 3), "preview_asset_limit", "Crop exceeds preview size limit")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise V2Error("preview_asset", "Invalid crop base64") from exc
    require(0 < len(raw) <= MAX_ASSET_BYTES and base64.b64encode(raw).decode("ascii") == encoded, "preview_asset", "Crop bytes must be bounded canonical base64")
    width, height = _image_dimensions(raw, fragment["mime"])
    require(1 <= width <= MAX_IMAGE_DIMENSION and 1 <= height <= MAX_IMAGE_DIMENSION and width * height <= MAX_IMAGE_PIXELS, "preview_asset_limit", "Crop dimensions exceed bounded browser decoding limits")
    return hashlib.sha256(raw).hexdigest()


def _validate_document_fragment(fragment: Any, snapshot: dict) -> dict:
    allowed = {"subject_id", "version_id", "source_sha256", "snapshot_id", "snapshot_sha256", "page", "region", "purpose", "kind", "mime", "data_base64", "provenance", "quality", "asset_sha256"}
    require(isinstance(fragment, dict) and set(fragment) <= allowed, "preview_asset", "Document context cannot contain row anchors, paths or URLs")
    for key in ("subject_id", "version_id", "source_sha256", "snapshot_id", "snapshot_sha256"):
        require(fragment.get(key) == snapshot[key], "preview_fragment_binding", "Document context does not bind this exact profile/version/snapshot")
    require(type(fragment.get("page")) is int and 1 <= fragment["page"] <= 500, "preview_asset", "Document context page must be one-based and bounded")
    region = fragment.get("region")
    require(isinstance(region, list) and len(region) == 4 and all(type(n) in {int, float} and 0 <= n <= 1 for n in region) and region[0] < region[2] and region[1] < region[3], "preview_asset", "Document context region must be normalized source coordinates")
    require(fragment.get("purpose") in {"identity_header", "document_header"}, "preview_asset", "Document context purpose must remain explicit")
    provenance = fragment.get("provenance")
    require(isinstance(provenance, dict) and set(provenance) <= {"kind", "receipt_id"} and provenance.get("kind") in {"local_source_render", "model_reported"}, "preview_asset", "Image provenance is declared, never authenticated here")
    if provenance.get("receipt_id") is not None:
        text(provenance["receipt_id"], "render receipt", maximum=1000)
    quality = fragment.get("quality", {"status": "unknown"})
    require(isinstance(quality, dict) and set(quality) <= {"status", "notes"} and quality.get("status") in {"readable", "degraded", "unknown"}, "preview_asset", "Document quality must be categorical")
    if quality.get("notes") is not None:
        text(quality["notes"], "quality notes", maximum=2000)
    normalized = {**copy.deepcopy(fragment), "quality": copy.deepcopy(quality), "asset_sha256": _image_sha(fragment)}
    require("asset_sha256" not in fragment or fragment["asset_sha256"] == normalized["asset_sha256"], "preview_asset", "Document asset SHA differs from supplied bytes")
    return normalized


def _validate_fragment(fragment: Any, snapshot: dict, drafts: dict) -> dict:
    fields = {"subject_id", "version_id", "source_sha256", "snapshot_id", "snapshot_sha256", "draft_id", "field", "anchor_index", "locator", "kind", "text", "mime", "data_base64", "provenance", "quality", "asset_sha256"}
    require(isinstance(fragment, dict) and set(fragment) <= fields, "preview_asset", "Fragments cannot contain paths, URLs, scripts or extra fields")
    for key in ("subject_id", "version_id", "source_sha256", "snapshot_id", "snapshot_sha256"):
        require(fragment.get(key) == snapshot[key], "preview_fragment_binding", "Fragment does not bind this exact profile/version/snapshot")
    draft_id, field, index = (fragment.get(key) for key in ("draft_id", "field", "anchor_index"))
    require(draft_id in drafts and type(index) is int and index >= 0 and isinstance(field, str), "preview_fragment_binding", "Fragment needs a displayed field anchor")
    anchors = _anchors(drafts[draft_id]["row"], field)
    require(index < len(anchors), "preview_fragment_binding", "Fragment anchor does not exist")
    anchor = anchors[index]
    require(fragment.get("locator") == anchor["locator"], "preview_fragment_binding", "Fragment locator differs from frozen field anchor")
    provenance = fragment.get("provenance")
    require(isinstance(provenance, dict) and set(provenance) <= {"kind", "receipt_id"} and provenance.get("kind") in {"local_source_render", "source_anchor", "model_reported"}, "preview_asset", "Fragment provenance must state its actual evidence kind")
    if provenance.get("receipt_id") is not None:
        text(provenance["receipt_id"], "render receipt", maximum=1000)
    quality = fragment.get("quality", {"status": "unknown"})
    require(isinstance(quality, dict) and set(quality) <= {"status", "notes"} and quality.get("status") in {"readable", "degraded", "unknown"}, "preview_asset", "Source quality is categorical, not a correctness probability")
    if quality.get("notes") is not None:
        text(quality["notes"], "quality notes", maximum=2000)
    normalized = copy.deepcopy(fragment)
    normalized["quality"] = copy.deepcopy(quality)
    if fragment.get("kind") == "literal_anchor_excerpt":
        require(set(fragment).isdisjoint({"mime", "data_base64"}) and fragment.get("text") == anchor["excerpt"] and provenance["kind"] == "source_anchor", "preview_asset", "Text fragments must preserve the exact literal anchor excerpt")
        normalized["asset_sha256"] = hashlib.sha256(fragment["text"].encode("utf-8")).hexdigest()
    else:
        require("text" not in fragment and provenance["kind"] in {"local_source_render", "model_reported"}, "preview_asset", "Image crops cannot masquerade as literal text")
        normalized["asset_sha256"] = _image_sha(fragment)
    if "asset_sha256" in fragment:
        require(fragment["asset_sha256"] == normalized["asset_sha256"], "preview_asset", "Fragment asset SHA differs from supplied bytes")
    return normalized


def validate_bundles(bundles: list[dict], *, page_size: int = 25) -> list[dict]:
    """Validate content/scope without reading any store, file or network resource."""
    require(type(page_size) is int and 1 <= page_size <= 100, "preview_limit", "Preview page must show 1–100 whole rows")
    _bounded_list(bundles, MAX_BUNDLES, "preview_limit")
    require(bool(bundles), "preview_empty", "At least one snapshot bundle is required")
    require(len(canonical(bundles)) <= MAX_PREVIEW_BYTES, "preview_size", "Private preview exceeds total size limit; narrow the scope")
    result, snapshots, profile_labels, group_labels, documents = [], set(), {}, {}, {}
    for bundle in bundles:
        required_keys = {"profile", "document", "snapshot", "source_state", "fragments"}
        require(isinstance(bundle, dict) and required_keys <= set(bundle) <= required_keys | {"review_flags", "document_fragments", "snapshot_verification"}, "preview_bundle", "Expected profile, document, snapshot, source_state and fragments")
        profile, document, snapshot = (bundle[key] for key in ("profile", "document", "snapshot"))
        require(isinstance(profile, dict) and {"subject_id", "label"} <= set(profile) <= {"subject_id", "label", "group_id"}, "preview_profile", "Profile needs its own ID and label; grouping is an explicit UI tag only")
        subject = identifier(profile["subject_id"], "subject_id")
        text(profile["label"], "profile label", maximum=500)
        require(subject not in profile_labels or profile_labels[subject] == profile["label"], "preview_profile", "One profile ID cannot have conflicting labels")
        profile_labels[subject] = profile["label"]
        group = identifier(profile.get("group_id", subject), "profile group_id")
        require(group not in group_labels or group_labels[group] == profile["label"], "preview_profile", "One UI profile group cannot have conflicting labels")
        group_labels[group] = profile["label"]
        require(isinstance(document, dict) and set(document) == {"document_id", "label"}, "preview_document", "Document needs an opaque ID and label")
        identifier(document["document_id"], "document_id")
        text(document["label"], "document label", maximum=1000)
        _validate_snapshot(snapshot, subject)
        key = (subject, snapshot["snapshot_id"])
        require(key not in snapshots, "preview_duplicate", "Duplicate snapshot in preview")
        snapshots.add(key)
        version_key = (subject, snapshot["version_id"])
        require(version_key not in documents or documents[version_key] == document, "preview_document", "A source version cannot move to another document")
        documents[version_key] = document
        _validate_source_state(bundle["source_state"], snapshot)
        _validate_snapshot_verification(bundle.get("snapshot_verification"), snapshot)
        drafts = {draft["draft_id"]: draft for draft in snapshot["rows"]}
        fragments, used = [], set()
        for fragment in _bounded_list(bundle["fragments"], 10000, "preview_asset_limit"):
            fragment = _validate_fragment(fragment, snapshot, drafts)
            key = (fragment["draft_id"], fragment["field"], fragment["anchor_index"])
            require(key not in used, "preview_duplicate", "A field anchor has duplicate fragments")
            used.add(key)
            fragments.append(fragment)
        review_flags = _bounded_list(bundle.get("review_flags", []), 1000, "preview_limit")
        for flag in review_flags:
            require(isinstance(flag, dict) and set(flag) == {"draft_id", "field", "code", "note"}, "preview_flag", "Review flags must be bounded source-review annotations")
            require(flag["draft_id"] is None or flag["draft_id"] in drafts, "preview_flag", "Review flag belongs to an unshown row")
            require(flag["field"] is None or isinstance(flag["field"], str) and (flag["field"] in drafts[flag["draft_id"]]["row"] if flag["draft_id"] is not None else flag["field"] in LABELS), "preview_flag", "Review flag field is outside frozen row")
            require(flag["code"] in {"identity_conflict", "not_visually_supported", "unresolved_reading"}, "preview_flag", "Unsupported source-review flag")
            text(flag["note"], "source-review flag note", maximum=2000)
        document_fragments = [_validate_document_fragment(f, snapshot) for f in _bounded_list(bundle.get("document_fragments", []), 20, "preview_asset_limit")]
        result.append({**copy.deepcopy(bundle), "fragments": fragments, "review_flags": copy.deepcopy(review_flags), "document_fragments": document_fragments})
    return result


def confirmation_blockers(bundle: dict, draft_id: str) -> list[str]:
    """Explain why an unchanged frozen row cannot be proposed for confirmation."""
    draft = next((d for d in bundle["snapshot"]["rows"] if d["draft_id"] == draft_id), None)
    require(draft is not None, "preview_unshown", "Row is outside this snapshot")
    row, blocked = draft["row"], []
    verification = bundle.get("snapshot_verification")
    if verification is None:
        blocked.append("Актуальность сохранённого набора строк ещё не проверена backend.")
    elif verification["state"] != "current":
        blocked.append("Сохранённый набор строк устарел. Нужна повторная проверка; подробные причины сохранены в данных набора.")
    for flag in bundle.get("review_flags", []):
        if flag["draft_id"] is None or flag["draft_id"] == draft_id:
            code = {"identity_conflict": "принадлежность документа не установлена", "not_visually_supported": "значение не подтверждено изображением", "unresolved_reading": "чтение не удалось уточнить"}[flag["code"]]
            blocked.append("Замечание сверки источника — " + code + ": " + flag["note"])
    if bundle["source_state"]["status"] != "unchanged":
        blocked.append("Целостность сохранённой версии источника не проверена либо источник изменён / недоступен.")
    if row["result"]["kind"] == "text_unparsed" or (row["result"]["kind"] == "no_result" and not row["result"]["raw"].strip()):
        blocked.append("Результат не разобран или пустая ячейка не доказывает отсутствие результата.")
    for field, state in row.get("field_status", {}).items():
        if state == "ambiguous":
            blocked.append(f"Неоднозначное поле: {LABELS.get(field, field)}.")
    for field, state in row.get("missing_reasons", {}).items():
        if state == "ambiguous":
            blocked.append(f"Неоднозначное отсутствие: {LABELS.get(field, field)}.")
    if row["mapping_status"] == "ambiguous":
        blocked.append("Сопоставление показателя неоднозначно.")
    fragments = {(f["field"], f["anchor_index"]): f for f in bundle["fragments"] if f["draft_id"] == draft_id}
    for field, index in _material_anchors(row):
        fragment = fragments.get((field, index))
        if fragment is None:
            blocked.append(f"Не передан фрагмент для поля: {LABELS[field]} (якорь {index + 1}).")
        elif fragment["quality"]["status"] == "degraded":
            blocked.append(f"Фрагмент поля плохо читается: {LABELS[field]}.")
    return blocked


def prepare_decisions(bundle: dict, decisions: list[dict], *, visible_draft_ids: list[str]) -> dict:
    """Prepare proposals only. The backend must revalidate any later chat decision."""
    normalized = validate_bundles([bundle])[0]
    snapshot = normalized["snapshot"]
    shown = snapshot["displayed_draft_ids"]
    require(isinstance(visible_draft_ids, list) and 0 < len(visible_draft_ids) <= 100 and all(isinstance(item, str) for item in visible_draft_ids) and len(set(visible_draft_ids)) == len(visible_draft_ids) and set(visible_draft_ids) <= set(shown), "preview_unshown", "Visible scope must be a subset of the frozen snapshot")
    _bounded_list(decisions, 100, "preview_limit")
    require(bool(decisions), "preview_empty", "Select rows explicitly before preparing a decision")
    used = set()
    for decision in decisions:
        require(isinstance(decision, dict) and set(decision) <= {"draft_id", "action", "reason", "correction_note"}, "preview_decision", "Unexpected decision or assurance field")
        draft_id, action = decision.get("draft_id"), decision.get("action")
        require(draft_id in visible_draft_ids and draft_id not in used, "preview_unshown", "Only explicitly selected visible rows may receive a proposal")
        used.add(draft_id)
        require(action in {"confirm", "reject", "defer", "request_correction"}, "preview_decision", "Unsupported proposed action")
        if action == "confirm":
            require(not confirmation_blockers(normalized, draft_id), "preview_confirmation_blocked", "Resolve source/field uncertainty before proposing confirmation")
        if action == "request_correction":
            text(decision.get("correction_note"), "correction proposal", maximum=2000)
        else:
            require("correction_note" not in decision, "preview_decision", "Only correction requests may carry a correction note")
        if decision.get("reason") is not None:
            text(decision["reason"], "decision reason", maximum=2000)
    return {"schema_version": DECISION_SCHEMA, "state": "PROPOSED", "confirmation_assurance": "none",
            "subject_id": snapshot["subject_id"], "profile_group_id": normalized["profile"].get("group_id", snapshot["subject_id"]), "document_id": normalized["document"]["document_id"],
            "snapshot_id": snapshot["snapshot_id"], "snapshot_sha256": snapshot["snapshot_sha256"],
            "source_version_id": snapshot["version_id"], "source_sha256": snapshot["source_sha256"],
            "run_id": snapshot["run_id"], "selection_token": snapshot.get("selection_token"),
            "visible_draft_ids": copy.deepcopy(visible_draft_ids), "selected_draft_ids": [d["draft_id"] for d in decisions],
            "decisions": copy.deepcopy(decisions), "source_state": copy.deepcopy(normalized["source_state"]),
            "review_flags": copy.deepcopy(normalized["review_flags"]),
            "snapshot_verification": copy.deepcopy(normalized.get("snapshot_verification")),
            "limitations": ["not_record_confirmation", "source_recheck_required", "no_human_authentication"]}


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)


def _display(value: Any) -> str:
    if value is None:
        return '<span class="missing">не указано / неизвестно — см. причину</span>'
    return '<pre>' + _e(value if isinstance(value, str) else _json(value)) + '</pre>'


def _field(row: dict, field: str) -> str:
    state = row.get("field_status", {}).get(field)
    reason = row.get("missing_reasons", {}).get(field)
    statuses = [STATUSES.get(state, state) if state else "не подтверждено"]
    if reason:
        statuses.append("причина: " + STATUSES.get(reason, reason))
    if any(anchor.get("inherited") for anchor in _anchors(row, field)):
        statuses.append("унаследовано из заголовка / контекста; якорь сохранён")
    value = row.get(field)
    display = _display(value)
    if field == "result":
        kinds = {"numeric_exact": "точное число", "numeric_censored": "граница, не точное измерение", "qualitative": "качественный результат", "semiquantitative": "полуколичественный результат", "text_unparsed": "неразобранный текст", "no_result": "без результата"}
        display = '<pre>' + _e(value["raw"] if value["raw"] else "[исходная ячейка пуста]") + '</pre><p>Тип: ' + _e(kinds[value["kind"]]) + '</p>'
        if "decimal" in value:
            display += '<p>Число для расчётов: <code>' + _e(value.get("operator", "") + value["decimal"]) + '</code></p>'
        if value.get("value") is not None:
            display += '<p>Типизированное значение: ' + _e(value["value"]) + '</p>'
        if value.get("reason") is not None:
            display += '<p>Причина: ' + _e(value["reason"]) + '</p>'
    elif field == "clinical_time":
        roles = {"collected": "забор материала", "performed": "проведение исследования", "reported": "выдача отчёта", "unknown": "роль неизвестна"}
        precision = {"datetime": "дата и время", "date": "день", "month": "месяц", "year": "год", "interval": "интервал", "unknown": "неизвестная"}
        display = _display(value.get("raw")) + '<p>Роль: ' + _e(roles[value["role"]]) + ' · точность: ' + _e(precision[value["precision"]]) + '</p>'
        normalized = {k: v for k, v in value.items() if k not in {"raw", "role", "precision"}}
        if normalized:
            display += '<small>Нормализованные границы / значение, без уточнения исходной точности:</small>' + _display(normalized)
    elif field == "reference_intervals":
        kinds = {"laboratory_reference": "референс лаборатории", "diagnostic_decision_limit": "диагностический порог", "therapeutic_target": "терапевтическая цель"}
        display = ''.join('<div><pre>' + _e(reference["raw"]) + '</pre><small>' + _e(kinds[reference["kind"]]) + '</small>' + _display({k: v for k, v in reference.items() if k not in {"raw", "kind"}}) + '</div>' for reference in value) if value else '<span class="missing">Референс не указан — см. причину.</span>'
    return '<div class="field' + (' uncertain' if state == "ambiguous" or reason == "ambiguous" else '') + '"><dt>' + _e(LABELS.get(field, field)) + '</dt><dd>' + display + '<small>' + _e(" · ".join(statuses)) + '</small></dd></div>'


def _coverage_summary(coverage: dict) -> str:
    expected = coverage.get("expected_count")
    basis = {"unknown": "неизвестно", "source_count": "число из источника", "extractor_count": "число экстрактора"}.get(coverage.get("expected_count_basis"), "неизвестно")
    counts = ' · '.join(label + ': ' + str(coverage[key]) for key, label in (("reviewed", "принято ранее"), ("unreviewed", "не проверено"), ("rejected", "отклонено"), ("deferred", "отложено")) if key in coverage)
    status = {"complete": "извлечение завершено", "partial": "частичное извлечение", "visual_required": "нужна визуальная сверка", "error": "ошибка извлечения"}.get(coverage.get("status"), "состояние неизвестно")
    scope = 'Полный объём документа неизвестен.' if expected is None else 'Ожидаемое число строк: ' + str(expected) + ' (' + basis + ').'
    return '<p><strong>Покрытие: ' + _e(status) + '</strong> · ' + _e(scope) + '</p><p>' + _e(counts) + '</p><p>Обработанные страницы: ' + _e(coverage.get("processed_pages", [])) + ' · необработанные: ' + _e(coverage.get("unprocessed_pages", [])) + '</p>'


def _fragment_html(fragment: dict) -> str:
    label = LABELS.get(fragment["field"], fragment["field"])
    if fragment["kind"] == "literal_anchor_excerpt":
        content = '<strong>Извлечённый текст</strong><small>Дословная выдержка сохранённого текста; это не пиксели оригинала.</small><pre>' + _e(fragment["text"]) + '</pre>'
    else:
        content = '<strong>Фрагмент оригинала</strong><img loading="lazy" decoding="async" data-material="' + ('1' if fragment["field"] in MATERIAL_FIELDS else '0') + '" alt="' + _e(label) + '" src="data:' + fragment["mime"] + ';base64,' + fragment["data_base64"] + '">'
    provenance = fragment["provenance"]
    kind = {"source_anchor": "выдержка из сохранённого якоря", "local_source_render": "заявлен локальный рендер источника", "model_reported": "происхождение заявлено моделью"}[provenance["kind"]]
    quality = fragment["quality"]
    quality_text = {"readable": "читаемый", "degraded": "плохо читаемый", "unknown": "качество не установлено"}[quality["status"]]
    return '<figure><figcaption>' + _e(label) + ' · фрагмент ' + str(fragment["anchor_index"] + 1) + '</figcaption>' + content + '<small>' + _e(quality_text + "; медицинская достоверность не проверена") + '</small>' + (('<p>' + _e(quality["notes"]) + '</p>') if quality.get("notes") else '') + '<details><summary>Источник, привязка и целостность</summary><p>' + _e(kind) + '</p><pre>' + _e(_json({key: value for key, value in fragment.items() if key not in {"text", "data_base64"}})) + '</pre></details></figure>'


def _document_context(bundle: dict) -> str:
    fragments = bundle.get("document_fragments", [])
    if not fragments:
        return ''
    figures = ''.join('<figure><figcaption>Шапка оригинала · страница ' + str(f["page"]) + '</figcaption><img loading="lazy" decoding="async" alt="Фрагмент шапки документа" src="data:' + f["mime"] + ';base64,' + f["data_base64"] + '"><small>Контекст документа; не типизированный факт о личности и не подтверждение совпадения профиля.</small><details><summary>Привязка, координаты и заявленное происхождение</summary><pre>' + _e(_json({k: v for k, v in f.items() if k != "data_base64"})) + '</pre></details></figure>' for f in fragments)
    return '<details><summary>Шапка оригинала — контекст для сверки документа / личности</summary>' + figures + '</details>'


def _source_context(bundle: dict) -> str:
    state = bundle["source_state"]
    statuses = {"unchanged": "Сохранённая копия источника целая.", "changed": "Сохранённая копия источника изменена — предложение принять заблокировано.", "unavailable": "Сохранённый источник недоступен — предложение принять заблокировано.", "unverified": "Целостность сохранённой копии не проверена — предложение принять заблокировано."}
    css = "notice" if state["status"] == "unchanged" else "warning"
    output = '<p class="' + css + '">' + _e(statuses[state["status"]]) + '</p>'
    if state.get("archive_drift") == "changed":
        output += '<p class="notice">Файл в архиве изменён. Проверяется отдельно сохранённая версия документа.</p>'
    verification = bundle.get("snapshot_verification")
    if verification is None or verification["state"] != "current":
        output += '<p class="warning">Сохранённый набор строк не проверен на актуальность либо устарел. Предложение принять заблокировано.</p>'
    return output + '<details><summary>Проверки источника и набора строк</summary><p>Результаты локальной проверки переданы вызывающей стороной. Проверка набора строк, если она приложена, получена от backend. Эта страница проверяет привязку данных, но сама не проверяет подпись хранилища, происхождение человека или медицинскую достоверность.</p><pre>' + _e(_json(state)) + '</pre><pre>' + _e(_json(verification)) + '</pre></details>'


def _card(bundle: dict, draft: dict, number: int) -> str:
    row = draft["row"]
    blockers = confirmation_blockers(bundle, draft["draft_id"])
    pages = sorted({a["locator"]["page"] for field in row["field_anchors"] for a in _anchors(row, field) if "page" in a["locator"]})
    primary = ("analyte_raw", "result", "unit_raw", "clinical_time", "reference_intervals", "specimen", "method", "lab_flag_raw")
    fragments = [f for f in bundle["fragments"] if f["draft_id"] == draft["draft_id"]]
    sources = ''.join(_fragment_html(f) for f in fragments)
    if not sources:
        sources = '<p class="warning">Фрагменты источника не переданы. Целая строка доступна; предложение принять заблокировано.</p>'
    return '<article class="row-card" data-draft="' + _e(draft["draft_id"]) + '" data-pages="' + _e(json.dumps(pages)) + '" data-blocked="' + ('1' if blockers else '0') + '"><header><label><input type="checkbox" class="row-select"> Выбрать строку ' + str(number) + '</label><span>' + _e({"unreviewed": "не подтверждено"}.get(draft["review_status"], draft["review_status"])) + '</span></header><div class="row-columns"><section><h3>Полная строка анализа</h3><dl>' + ''.join(_field(row, f) for f in primary) + '</dl><details><summary>Остальные поля и все якоря</summary><dl>' + ''.join(_field(row, f) for f in row if f not in primary) + '</dl></details><details><summary>Точный замороженный объект строки</summary><pre>' + _e(_json(draft)) + '</pre></details></section><section><h3>Фрагменты для сверки</h3>' + sources + '<details><summary>Ограничения проверки фрагментов</summary><p class="notice">SHA связывает байты с объектом. Происхождение изображения передаёт вызывающая сторона; клиническая проверка и удостоверение человека здесь не выполняются.</p></details></section></div>' + ('<div class="warning"><strong>Предложение принять заблокировано</strong><ul>' + ''.join('<li>' + _e(item) + '</li>' for item in blockers) + '</ul></div>' if blockers else '<p class="notice">Можно предложить принять после самостоятельной сверки целой строки и фрагментов.</p>') + '<label class="correction">Предложение исправления этой строки<textarea maxlength="2000" class="correction-note" placeholder="Укажите поле и правильное значение; это предложение для следующего review"></textarea></label></article>'


STYLE = """
:root{font-family:system-ui,sans-serif;color:#152936;background:#f4f7f9;font-size:16px}*{box-sizing:border-box}body{margin:0}main{max-width:1480px;margin:auto;padding:24px}h1{font-size:1.8rem}h2{font-size:1.25rem}h3{font-size:1.05rem;margin-top:0}.notice,small{color:#536674}small{display:block;margin-top:6px}.privacy,.warning{padding:14px;border-radius:6px;margin:14px 0}.privacy{background:#dfeef8}.warning{background:#fff0d6;border-left:4px solid #bb7722}.controls{display:flex;gap:12px;flex-wrap:wrap;align-items:end;background:white;border:1px solid #d2dce3;padding:16px;border-radius:8px;position:sticky;top:0;z-index:2}.controls label{display:flex;flex-direction:column;gap:5px}button,select,textarea{font:inherit;border:1px solid #a3b6c4;border-radius:5px;padding:8px;background:white}button{cursor:pointer}button:disabled{cursor:default;opacity:.5}.row-card{background:#fff;border:1px solid #cfdae2;border-radius:8px;margin:18px 0;padding:18px}.row-card>header{display:flex;justify-content:space-between;gap:10px;padding-bottom:14px;border-bottom:1px solid #d9e1e6}.row-columns{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:18px}dl{margin:0}.field{padding:10px 0;border-bottom:1px solid #e4eaee}.field.uncertain{background:#fff0d6;padding:10px}dt{font-weight:650}dd{margin:6px 0 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-family:ui-monospace,monospace;font-size:.89rem;margin:6px 0;padding:9px;background:#f1f5f8;line-height:1.45}figure{margin:0 0 14px;padding:12px;border:1px solid #dae3e9;border-radius:5px}figcaption{font-weight:650;margin-bottom:9px}img{display:block;max-width:100%;height:auto;margin:10px 0}details{margin:12px 0}summary{cursor:pointer;color:#245e7d}.correction{display:block;margin-top:12px}.correction textarea{display:block;width:100%;min-height:65px;margin-top:6px}.decision-panel{background:white;padding:18px;border:1px solid #b6cbd8;border-radius:8px;margin-top:22px}.missing{color:#775c26}.identity{overflow-wrap:anywhere}.hidden,[hidden]{display:none!important}#status{min-height:1.4em;color:#884513}#packet{max-height:450px;overflow:auto}@media(max-width:850px){.row-columns{grid-template-columns:1fr}.controls{position:static}main{padding:14px}}@media print{.controls,.decision-panel,.row-select,.correction{display:none}.row-columns{display:block}.row-card{break-inside:avoid}}
"""

SCRIPT = r"""
'use strict';
const manifest = JSON.parse(document.getElementById('preview-manifest').textContent);
const $ = id => document.getElementById(id);
const bundles = manifest.bundles;
let page = 0, packet = null;
const sections = Array.from(document.querySelectorAll('.bundle'));
function options(select, items) { select.replaceChildren(); for (const [value,label] of items) { const option=document.createElement('option'); option.value=value; option.textContent=label; select.append(option); } }
const profileGroup = b => b.profile.group_id ?? b.profile.subject_id;
const documentKey = b => b.snapshot.subject_id+'|'+b.document.document_id+'|'+b.snapshot.version_id;
const profiles = [...new Map(bundles.map(b => [profileGroup(b),b.profile.label])).entries()];
options($('profile'), profiles);
function populateDocuments() { const group=$('profile').value; const docs=new Map(); bundles.forEach((b,i)=>{if(profileGroup(b)===group) docs.set(documentKey(b),b.document.label);}); options($('document'),[...docs.entries()]); populateSnapshots(); }
function populateSnapshots() { const group=$('profile').value, doc=$('document').value; options($('snapshot'),bundles.map((b,i)=>[i,b]).filter(([i,b])=>profileGroup(b)===group && documentKey(b)===doc).map(([i,b])=>[String(i),'Строки '+(b.snapshot.offset+1)+'–'+(b.snapshot.offset+b.snapshot.rows.length)+' из '+b.snapshot.total_in_selection])); populatePages(); }
function populatePages() { const section=sections[Number($('snapshot').value)], pages=new Set(); section.querySelectorAll('.row-card').forEach(card=>JSON.parse(card.dataset.pages).forEach(p=>pages.add(p))); options($('source-page'),[['all','Все переданные страницы'],...Array.from(pages).sort((a,b)=>a-b).map(p=>[String(p),'Страница источника '+p])]); page=0; refresh(); }
function matchingCards() { const section=sections[Number($('snapshot').value)], sourcePage=$('source-page').value; return Array.from(section.querySelectorAll('.row-card')).filter(card=>sourcePage==='all'||JSON.parse(card.dataset.pages).includes(Number(sourcePage))); }
function visibleCards() { return matchingCards().slice(page*manifest.page_size,(page+1)*manifest.page_size); }
function resetPacket() { packet=null; $('packet').textContent='Предложение ещё не подготовлено.'; $('export').disabled=true; $('status').textContent=''; }
function refresh() { const index=Number($('snapshot').value), matches=matchingCards(), pages=Math.max(1,Math.ceil(matches.length/manifest.page_size)); page=Math.min(page,pages-1); sections.forEach((section,i)=>{section.hidden=i!==index; section.querySelectorAll('.row-card').forEach(card=>{card.hidden=true; card.querySelector('.row-select').checked=false;});}); visibleCards().forEach(card=>card.hidden=false); const snap=bundles[index].snapshot; $('page-label').textContent='Экран '+(page+1)+' / '+pages+' · показано '+visibleCards().length+' целых строк · в наборе '+snap.rows.length+' · в выборе '+snap.total_in_selection; $('previous').disabled=page===0; $('next').disabled=page>=pages-1; resetPacket(); }
$('profile').addEventListener('change',populateDocuments); $('document').addEventListener('change',populateSnapshots); $('snapshot').addEventListener('change',populatePages); $('source-page').addEventListener('change',()=>{page=0;refresh();}); $('previous').addEventListener('click',()=>{page--;refresh();}); $('next').addEventListener('click',()=>{page++;refresh();});
$('select-visible').addEventListener('click',()=>{visibleCards().forEach(card=>card.querySelector('.row-select').checked=true);resetPacket();}); $('clear-selection').addEventListener('click',()=>{visibleCards().forEach(card=>card.querySelector('.row-select').checked=false);resetPacket();});
document.querySelectorAll('.row-select,.correction-note').forEach(input=>input.addEventListener('input',resetPacket)); $('action').addEventListener('change',resetPacket);
$('prepare').addEventListener('click',()=>{resetPacket(); const cards=visibleCards(), chosen=cards.filter(card=>card.querySelector('.row-select').checked), action=$('action').value; if(!chosen.length){$('status').textContent='Сначала явно выберите показанные строки.';return;} if(action==='confirm' && chosen.some(card=>card.dataset.blocked==='1')){$('status').textContent='Предложение принять заблокировано: в выбранных строках есть нерешённые поля или источники. Исправьте, отложите или исключите эти строки из выбора.';return;} if(action==='confirm' && !confirmationImagesReady(chosen)){ $('status').textContent='Нужные фрагменты ещё загружаются или не открылись. Дождитесь изображения каждого выбранного результата и шапки документа, затем повторите подготовку.';return;} const decisions=[]; for(const card of chosen){const decision={draft_id:card.dataset.draft,action}; if(action==='request_correction'){const note=card.querySelector('.correction-note').value; if(!note.trim()){$('status').textContent='Введите предложение исправления для каждой выбранной строки.';return;} decision.correction_note=note;} decisions.push(decision);} const b=bundles[Number($('snapshot').value)],s=b.snapshot; packet={schema_version:'health-analyzer.preview-decisions/1.0',state:'PROPOSED',confirmation_assurance:'none',subject_id:s.subject_id,profile_group_id:profileGroup(b),document_id:b.document.document_id,snapshot_id:s.snapshot_id,snapshot_sha256:s.snapshot_sha256,source_version_id:s.version_id,source_sha256:s.source_sha256,run_id:s.run_id,selection_token:s.selection_token??null,visible_draft_ids:cards.map(card=>card.dataset.draft),selected_draft_ids:decisions.map(d=>d.draft_id),decisions,source_state:b.source_state,review_flags:b.review_flags,snapshot_verification:b.snapshot_verification??null,limitations:['not_record_confirmation','source_recheck_required','no_human_authentication']}; $('packet').textContent=JSON.stringify(packet,null,2); $('export').disabled=false; $('status').textContent='Подготовлено только предложение. Записи и история не изменены; решение требует последующего подтверждения в чате.';});
$('export').addEventListener('click',()=>{if(!packet)return; const blob=new Blob([JSON.stringify(packet,null,2)],{type:'application/json;charset=utf-8'}),url=URL.createObjectURL(blob),link=document.createElement('a'); link.href=url; link.download='PROPOSED-review-decisions.json'; document.body.append(link);link.click();link.remove();URL.revokeObjectURL(url);});
function confirmationImagesReady(cards) { const bundle=sections[Number($('snapshot').value)]; const required=cards.flatMap(card=>Array.from(card.querySelectorAll('img')).filter(image=>image.dataset.material==='1')).concat(Array.from(bundle.querySelectorAll('img')).filter(image=>!image.closest('.row-card'))); const pending=required.filter(image=>!image.complete || image.naturalWidth===0);pending.forEach(image=>image.loading='eager');return pending.length===0; }
function imageFailed(image) { if(image.dataset.failed==='1')return; image.dataset.failed='1'; const card=image.closest('.row-card'),bundle=image.closest('.bundle'); if(card && image.dataset.material==='1')card.dataset.blocked='1'; if(!card && bundle)bundle.querySelectorAll('.row-card').forEach(row=>row.dataset.blocked='1'); const warning=document.createElement('p');warning.className='warning';warning.textContent='Браузер не смог открыть этот фрагмент изображения. Сверка по нему недоступна.';image.parentElement.append(warning);resetPacket();$('status').textContent='Фрагмент изображения не открылся. Подготовленное предложение отменено; принятие затронутых строк заблокировано.'; }
document.querySelectorAll('img').forEach(image=>{image.addEventListener('error',()=>imageFailed(image));image.addEventListener('load',()=>{const card=image.closest('.row-card'),bundle=image.closest('.bundle');if(packet && bundle===sections[Number($('snapshot').value)] && (!card || image.dataset.material==='1' && packet.selected_draft_ids.includes(card.dataset.draft)))resetPacket();});if(image.complete && image.naturalWidth===0)imageFailed(image);});
populateDocuments();
"""


def render_preview(bundles: list[dict], *, title: str = "Проверка анализов", page_size: int = 25) -> str:
    """Return standalone HTML with inline, escaped data and no remote resources."""
    text(title, "preview title", maximum=1000)
    normalized = validate_bundles(bundles, page_size=page_size)
    # Pixel bytes are already inline in their <img data:> element. Preserve their
    # scope/provenance/SHA in the UI manifest without duplicating large base64.
    ui_bundles = [{**bundle,
                   "fragments": [{key: value for key, value in f.items() if key != "data_base64"} for f in bundle["fragments"]],
                   "document_fragments": [{key: value for key, value in f.items() if key != "data_base64"} for f in bundle["document_fragments"]]}
                  for bundle in normalized]
    manifest = {"schema_version": PREVIEW_SCHEMA, "page_size": page_size, "image_bytes_location": "inline_img_data_url", "bundles": ui_bundles}
    encoded = _json(manifest).replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    style_hash = base64.b64encode(hashlib.sha256(STYLE.encode()).digest()).decode()
    script_hash = base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    csp = f"default-src 'none'; script-src 'sha256-{script_hash}'; style-src 'sha256-{style_hash}'; img-src data:; connect-src 'none'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'"
    sections = []
    for index, bundle in enumerate(normalized):
        snapshot = bundle["snapshot"]
        state = bundle["source_state"]
        status = {"unchanged": "SHA сохранённых байтов совпадает с версией snapshot", "changed": "сохранённые байты изменились — предложение принять заблокировано", "unavailable": "сохранённый источник недоступен — предложение принять заблокировано", "unverified": "целостность сохранённой версии не проверена — предложение принять заблокировано"}[state["status"]]
        binding = {key: snapshot.get(key) for key in ("subject_id", "version_id", "source_sha256", "snapshot_id", "snapshot_sha256", "run_id", "selection_token", "panel_id", "offset", "limit", "total_in_selection", "recorded_at")}
        sections.append('<section class="bundle" hidden data-bundle="' + str(index) + '"><h2>' + _e(bundle["profile"]["label"]) + ' · ' + _e(bundle["document"]["label"]) + '</h2>' + _source_context(bundle) + '<details><summary>Привязка к профилю, версии и сохранённым данным</summary><pre>' + _e(_json(binding)) + '</pre><pre>' + _e(_json(state)) + '</pre></details>' + _document_context(bundle) + _coverage_summary(snapshot["coverage"]) + '<details><summary>Точное покрытие документа — frozen coverage</summary><pre>' + _e(_json(snapshot["coverage"])) + '</pre><p class="notice">Все строки этого экрана не означают полный просмотр документа. Неизвестное ожидаемое число остаётся неизвестным; необработанные страницы показаны в coverage.</p></details>' + ''.join(_card(bundle, draft, snapshot["offset"] + number + 1) for number, draft in enumerate(snapshot["rows"])) + '<details><summary>Точный frozen snapshot целиком</summary><pre>' + _e(_json(snapshot)) + '</pre></details></section>')
    controls = '<nav class="controls" aria-label="Навигация по приватным строкам"><label>Профиль<select id="profile"></select></label><label>Документ<select id="document"></select></label><label>Набор строк<select id="snapshot"></select></label><label>Страница источника<select id="source-page"></select></label><button id="previous">Предыдущие строки</button><button id="next">Следующие строки</button><span id="page-label"></span></nav>'
    decisions = '<section class="decision-panel"><h2>Подготовить предложение решения</h2><p>Выбранные строки относятся к одному видимому экрану и одному сохранённому набору. Предложение не является подтверждением записи. Исправления сначала проходят новый review.</p><button id="select-visible">Выбрать только показанные строки</button> <button id="clear-selection">Снять выбор</button> <label>Предлагаемое действие <select id="action"><option value="confirm">Предложить принять целую строку</option><option value="request_correction">Предложить исправление</option><option value="defer">Отложить решение</option><option value="reject">Предложить отклонить</option></select></label> <button id="prepare">Подготовить решение</button><p id="status" role="status"></p><pre id="packet">Предложение ещё не подготовлено.</pre><button id="export" disabled>Экспортировать предложение JSON</button><p class="notice">Экспорт содержит приватные строки / идентификаторы. Передайте его в приватный чат для отдельного решения. Здесь нет доступа к базе, подтверждения человеком или записи в историю.</p></section>'
    output = '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="' + _e(csp) + '"><title>' + _e(title) + '</title><style>' + STYLE + '</style></head><body><main><h1>' + _e(title) + '</h1><p class="privacy"><strong>Черновики.</strong> В историю ничего не записано; сохранение требует вашего решения.</p><noscript><p class="warning">Для навигации нужен JavaScript. Все данные находятся в этом локальном HTML; сетевых запросов нет.</p></noscript>' + controls + ''.join(sections) + decisions + '</main><script id="preview-manifest" type="application/json">' + encoded + '</script><script>' + SCRIPT + '</script></body></html>'
    require(len(output.encode("utf-8")) <= MAX_PREVIEW_BYTES, "preview_size", "Rendered preview exceeds size limit; narrow the scope")
    return output


def export_preview(bundles: list[dict], output_path: str | Path, *, title: str = "Проверка анализов", page_size: int = 25) -> dict:
    """Create a new private HTML file, mode 0600, without replacing any file."""
    output = render_preview(bundles, title=title, page_size=page_size).encode("utf-8")
    path = Path(output_path).absolute()
    require(path.suffix.lower() == ".html", "preview_output", "Preview export must be an HTML file")
    require(not path.is_symlink() and not any(parent.is_symlink() for parent in path.parents), "preview_output", "Export path and parents cannot be symlinks")
    require(path.parent.is_dir(), "preview_output", "Export parent must already exist")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "preview_output", "Export must be a regular file")
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(output)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)
    return {"schema_version": PREVIEW_SCHEMA, "path": str(path), "sha256": hashlib.sha256(output).hexdigest(), "bytes": len(output), "profiles": len({b["profile"].get("group_id", b["profile"]["subject_id"]) for b in bundles}), "subject_namespaces": len({b["profile"]["subject_id"] for b in bundles}), "snapshots": len(bundles), "confirmed_records": 0}
