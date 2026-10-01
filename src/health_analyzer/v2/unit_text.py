"""Source-preserving unit recognition; no conversions or analyte-based guesses."""
from __future__ import annotations

import re
import unicodedata


def _key(value: str) -> str:
    # Typography changes only: case and prefix characters are significant.
    superscripts = str.maketrans("⁰¹²³⁴⁵⁶⁷⁸⁹", "0123456789")
    value = re.sub(r"[⁰¹²³⁴⁵⁶⁷⁸⁹]+", lambda m: "^" + m.group().translate(superscripts), value)
    value = unicodedata.normalize("NFKC", value).replace("μ", "µ")
    return re.sub(r"\s+", "", value).strip()


_ALIASES = {
    "[arb'U]": ("u", "a.u.", "у.е.", "усл.ед."),
    "U": ("U", "Ед", "ед", "Ед.", "ед."),
    "[IU]": ("IU", "МЕ"),
    "m[IU]": ("mIU", "мМЕ"),
    "%": ("%", "проц.", "процент"),
    "g/L": ("g/L", "g/l", "г/л", "г/Л"),
    "g/dL": ("g/dL", "g/dl", "г/дл"),
    "mg/L": ("mg/L", "mg/l", "мг/л"),
    "mg/dL": ("mg/dL", "mg/dl", "мг/дл"),
    "ug/L": ("µg/L", "µg/l", "μg/L", "ug/L", "ug/l", "мкг/л"),
    "ug/dL": ("µg/dL", "μg/dL", "ug/dL", "мкг/дл"),
    "ng/mL": ("ng/mL", "ng/ml", "нг/мл"),
    "ng/L": ("ng/L", "ng/l", "нг/л"),
    "pg/mL": ("pg/mL", "pg/ml", "пг/мл"),
    "mmol/L": ("mmol/L", "mmol/l", "ммоль/л"),
    "umol/L": ("µmol/L", "μmol/L", "umol/L", "umol/l", "мкмоль/л"),
    "nmol/L": ("nmol/L", "nmol/l", "нмоль/л"),
    "pmol/L": ("pmol/L", "pmol/l", "пмоль/л"),
    "10*9/L": ("10^9/L", "10^9/l", "10^9/л", "10⁹/л", "10⁹/L", "10*9/L", "×10^9/л", "х10^9/л"),
    "10*12/L": ("10^12/L", "10^12/l", "10^12/л", "10¹²/л", "10¹²/L", "10*12/L", "×10^12/л", "х10^12/л"),
    "fL": ("fL", "fl", "фл"),
    "pg": ("pg", "пг"),
    "s": ("s", "sec", "с", "сек", "сек."),
    "ms": ("ms", "мс", "мсек"),
    "mm/h": ("mm/h", "мм/ч", "мм/час"),
    "mm[Hg]": ("mmHg", "mm[Hg]", "ммрт.ст.", "мм рт. ст."),
    "U/L": ("U/L", "U/l", "Ед/л", "ед/л", "Ед./л", "ЕД/Л"),
    "[IU]/L": ("IU/L", "IU/l", "МЕ/л", "МЕ/Л"),
    "[IU]/mL": ("IU/mL", "IU/ml", "МЕ/мл"),
    "m[IU]/L": ("mIU/L", "mIU/l", "мМЕ/л", "мМЕ/Л"),
    "m[IU]/mL": ("mIU/mL", "mIU/ml", "мМЕ/мл"),
}
_LOOKUP = {_key(alias): code for code, aliases in _ALIASES.items() for alias in aliases}


def _recognized(value: str) -> str | None:
    code = _LOOKUP.get(_key(value))
    if code:
        return code
    # Case variation of the word 'mol' does not alter a prefix. Prefix case
    # itself is never folded: Mmol and mmol must not become the same unit.
    compact = _key(value)
    m = re.fullmatch(r"(м|мк|н|п)моль/([лЛ])", compact, re.I)
    if m and compact.startswith(m.group(1).lower()):
        return {"м": "mmol/L", "мк": "umol/L", "н": "nmol/L", "п": "pmol/L"}[m.group(1).lower()]
    return None


def inspect_unit(raw: str | None, candidates: list[dict] | None = None) -> dict:
    """Recognize exact explicit aliases; competing readings stay hypotheses.

    `unit_code` is a proposed notation, not an authenticated source reading.
    Numeric values and `raw` never change. Candidate or character-confusion
    alternatives cannot make an unknown primary OCR unit known.
    """
    if raw is None or not raw.strip():
        return {"raw": raw, "status": "missing", "unit_code": None,
                "alternatives": [], "reason_codes": []}
    primary = _recognized(raw)
    alternatives = []
    seen = {raw}
    for item in candidates or []:
        value = item.get("text") if isinstance(item, dict) else None
        if not isinstance(value, str) or not value or value in seen:
            continue
        seen.add(value)
        alternatives.append({"text": value, "unit_code": _recognized(value), "basis": "ocr_candidate"})
    # At most a small set of transparent source-character hypotheses, never
    # selected as corrected source text. A digit/letter substitution is unsafe
    # without the original: ng/m1 and mmol/1 therefore stay ambiguous.
    for a, b in (("1", "l"), ("|", "l"), ("О", "о")):
        if a not in raw:
            continue
        value = raw.replace(a, b)
        code = _recognized(value)
        if code and value not in seen:
            seen.add(value)
            alternatives.append({"text": value, "unit_code": code, "basis": "glyph_confusion_requires_source_review"})
    codes = {item["unit_code"] for item in alternatives if item["unit_code"]}
    conflicts = bool(primary and any(code != primary for code in codes))
    unknown_competing = bool(primary and any(item["basis"] == "ocr_candidate" and not item["unit_code"] for item in alternatives))
    if conflicts or unknown_competing:
        status, reasons = "ambiguous", ["OCR_UNIT_CANDIDATES_CONFLICT"]
    elif primary:
        status, reasons = "known", []
    elif alternatives:
        status, reasons = "ambiguous", ["UNIT_GLYPHS_REQUIRE_SOURCE_REVIEW"]
    else:
        status, reasons = "unknown", ["UNIT_NOT_IN_ALLOWLIST"]
    return {"raw": raw, "status": status, "unit_code": primary if status == "known" else None,
            "alternatives": alternatives, "reason_codes": reasons}
