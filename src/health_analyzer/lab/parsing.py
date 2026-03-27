"""Strict parsing of numeric laboratory result tokens."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, DecimalException
import re


class NumericParseError(ValueError):
    """Raised when a raw result is not an unambiguous numeric token."""


_NUMERIC_RE = re.compile(
    r"^\s*(?P<comparator><=|>=|<|>|=|≤|≥)?\s*"
    r"(?P<number>[+\-−]?(?:\d+(?:[.,]\d+)?|[.,]\d+)(?:[eE][+\-]?\d+)?)\s*$"
)
_DECIMAL_TOKEN_RE = re.compile(
    r"(?P<sign>[+\-])?(?P<mantissa>(?:\d+(?:\.\d+)?|\.\d+))"
    r"(?:[eE](?P<exponent>[+\-]?\d+))?\Z"
)
MAX_DECIMAL_TOKEN_CHARS = 256
MAX_DECIMAL_DIGITS = 128
MAX_DECIMAL_ABS_EXPONENT = 1_000


@dataclass(frozen=True, slots=True)
class ParsedNumeric:
    raw: str
    value: Decimal
    comparator: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.raw, str)
            or not self.raw.strip()
            or "\0" in self.raw
            or len(self.raw) > MAX_DECIMAL_TOKEN_CHARS
        ):
            raise ValueError("raw numeric token is invalid or oversized")
        if not is_bounded_decimal(self.value):
            raise ValueError("parsed numeric value must be a bounded Decimal")
        if self.comparator not in {None, "<", "<=", ">", ">="}:
            raise ValueError("parsed numeric comparator is unsupported")


def is_bounded_decimal(value: object) -> bool:
    if not isinstance(value, Decimal) or not value.is_finite():
        return False
    parts = value.as_tuple()
    return (
        len(parts.digits) <= MAX_DECIMAL_DIGITS
        and abs(parts.exponent) <= MAX_DECIMAL_ABS_EXPONENT
        and (
            value.is_zero()
            or abs(value.adjusted()) <= MAX_DECIMAL_ABS_EXPONENT
        )
    )


def parse_bounded_decimal_token(raw: str, *, name: str = "decimal value") -> Decimal:
    """Parse a bounded ASCII decimal token and normalize decimal errors."""

    if (
        not isinstance(raw, str)
        or not raw.strip()
        or "\0" in raw
        or len(raw) > MAX_DECIMAL_TOKEN_CHARS
    ):
        raise ValueError(f"{name} must be a bounded decimal token")
    token = raw.strip()
    match = _DECIMAL_TOKEN_RE.fullmatch(token)
    if match is None:
        raise ValueError(f"{name} must be a bounded decimal token")
    digit_count = sum(character.isdigit() for character in match.group("mantissa"))
    exponent_text = match.group("exponent")
    if digit_count > MAX_DECIMAL_DIGITS or (
        exponent_text is not None
        and (
            len(exponent_text.lstrip("+-")) > 4
            or abs(int(exponent_text)) > MAX_DECIMAL_ABS_EXPONENT
        )
    ):
        raise ValueError(f"{name} exceeds decimal size limits")
    try:
        value = Decimal(token)
    except (DecimalException, ValueError):
        raise ValueError(f"{name} must be a bounded decimal token") from None
    if not is_bounded_decimal(value):
        raise ValueError(f"{name} exceeds decimal size limits")
    return value


def parse_numeric(raw: str) -> ParsedNumeric:
    """Parse a single exact/comparator-prefixed number without losing raw text.

    Both decimal comma and decimal point are accepted.  Thousands separators,
    ranges, units, and qualitative text are deliberately rejected so a table
    row cannot silently collapse into a wrong scalar.
    """

    if not isinstance(raw, str) or len(raw) > MAX_DECIMAL_TOKEN_CHARS:
        raise NumericParseError("laboratory numeric token exceeds size limits")
    match = _NUMERIC_RE.fullmatch(raw)
    if match is None:
        raise NumericParseError(f"ambiguous or non-numeric result: {raw!r}")

    number = match.group("number").replace("−", "-")
    if "," in number and "." in number:
        raise NumericParseError(f"mixed decimal separators: {raw!r}")
    number = number.replace(",", ".")
    try:
        value = parse_bounded_decimal_token(
            number,
            name="laboratory numeric result",
        )
    except ValueError as error:
        raise NumericParseError(str(error)) from None

    comparator = match.group("comparator")
    comparator = {"≤": "<=", "≥": ">=", "=": None}.get(comparator, comparator)
    return ParsedNumeric(raw=raw, value=value, comparator=comparator)
