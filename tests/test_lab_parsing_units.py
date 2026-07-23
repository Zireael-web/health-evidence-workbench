from __future__ import annotations

from decimal import Decimal, localcontext

import pytest

from health_analyzer.lab import (
    ConversionRule,
    CuratedUnitRegistry,
    NumericParseError,
    ParsedNumeric,
    UnsafeUnitConversionError,
    UnitDefinition,
    parse_bounded_decimal_token,
    parse_numeric,
)


@pytest.mark.parametrize(
    ("raw", "value", "comparator"),
    [
        ("<0,7", Decimal("0.7"), "<"),
        (">= 1.25", Decimal("1.25"), ">="),
        ("−2,50", Decimal("-2.50"), None),
        ("≤ .5", Decimal("0.5"), "<="),
    ],
)
def test_numeric_parser_is_lossless_and_comma_aware(
    raw: str,
    value: Decimal,
    comparator: str | None,
) -> None:
    parsed = parse_numeric(raw)
    assert parsed.raw == raw
    assert parsed.value == value
    assert parsed.comparator == comparator


@pytest.mark.parametrize("raw", ["0,7-1,2", "отрицательно", "1 234,5", "0.7 mg/dL"])
def test_numeric_parser_rejects_ambiguous_tokens(raw: str) -> None:
    with pytest.raises(NumericParseError):
        parse_numeric(raw)


@pytest.mark.parametrize(
    "raw",
    (
        "9" * 129,
        "9" * 257,
        "1e1001",
        "1e-1001",
    ),
)
def test_numeric_parser_rejects_oversized_digits_tokens_and_exponents(
    raw: str,
) -> None:
    with pytest.raises(NumericParseError):
        parse_numeric(raw)


@pytest.mark.parametrize(
    "raw",
    ("not-a-number", "NaN", "Infinity", "9" * 129, "1e1001"),
)
def test_bounded_decimal_parser_normalizes_decimal_failures(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_bounded_decimal_token(raw, name="synthetic")


def test_parsed_numeric_direct_construction_enforces_decimal_bounds() -> None:
    with pytest.raises(ValueError, match="bounded Decimal"):
        ParsedNumeric(raw="NaN", value=Decimal("NaN"))


def test_curated_conversion_retains_original_value_and_unit() -> None:
    registry = CuratedUnitRegistry()
    parsed = parse_numeric("15,9")
    quantity = registry.normalize(parsed, "г/дл", target_ucum="g/L")

    assert quantity.raw_value == "15,9"
    assert quantity.original_value == Decimal("15.9")
    assert quantity.original_unit == "г/дл"
    assert quantity.normalized_value == Decimal("159.0")
    assert quantity.ucum_unit == "g/L"
    assert quantity.conversion_rule_id == "mass:g/dL-to-g/L:v1"


def test_mass_to_molar_conversion_is_not_inferred() -> None:
    registry = CuratedUnitRegistry()
    with pytest.raises(UnsafeUnitConversionError):
        registry.normalize(parse_numeric("100"), "мг/дл", target_ucum="mmol/L")


@pytest.mark.parametrize(
    "rule",
    (
        ConversionRule("cross-dimension", "mmol/L", "mm[Hg]", Decimal("1")),
        ConversionRule("duplicate-pair", "mg/dL", "g/L", Decimal("1")),
    ),
)
def test_custom_registry_rejects_cross_dimension_and_duplicate_conversion_pairs(
    rule: ConversionRule,
) -> None:
    definitions = (
        UnitDefinition("mg/dL", "mass_concentration", ("мг/дл",)),
        UnitDefinition("g/L", "mass_concentration", ("г/л",)),
        UnitDefinition("mmol/L", "substance_concentration", ("ммоль/л",)),
        UnitDefinition("mm[Hg]", "pressure", ("mmhg",)),
    )
    conversions = (
        ConversionRule("existing", "mg/dL", "g/L", Decimal("0.01")),
        rule,
    )

    with pytest.raises(ValueError):
        CuratedUnitRegistry(definitions=definitions, conversions=conversions)


@pytest.mark.parametrize("factor", (Decimal("0"), Decimal("-2"), Decimal("Infinity")))
def test_conversion_rule_requires_finite_positive_factor(factor: Decimal) -> None:
    with pytest.raises(ValueError, match="finite positive"):
        ConversionRule("invalid-factor", "mg/dL", "g/L", factor)


@pytest.mark.parametrize("precision", (3, 28))
def test_unit_conversion_is_exact_independent_of_ambient_precision(precision: int) -> None:
    raw = "123456789012345678901234567890.123456789"
    parsed = parse_numeric(raw)
    registry = CuratedUnitRegistry()
    with localcontext() as context:
        context.prec = precision
        same_unit = registry.normalize(parsed, "mg/dL")
        converted = registry.normalize(parsed, "mg/dL", target_ucum="g/L")
        assert context.prec == precision
    assert same_unit.normalized_value == Decimal(raw)
    assert converted.normalized_value == Decimal("1234567890123456789012345678.90123456789")
    assert converted.raw_value == raw


def test_unit_conversion_fails_closed_on_out_of_bounds_result_or_factor() -> None:
    with pytest.raises(ValueError, match="numeric bounds"):
        ConversionRule("huge-factor", "g/L", "mg/dL", Decimal("1e1001"))
    with pytest.raises(UnsafeUnitConversionError, match="numeric bounds"):
        CuratedUnitRegistry().normalize(parse_numeric("1e1000"), "g/L", target_ucum="mg/dL")


def test_custom_registry_rejects_duplicate_unit_definitions_and_rule_ids() -> None:
    duplicate_definitions = (
        UnitDefinition("mg/dL", "mass_concentration", ("мг/дл",)),
        UnitDefinition("mg/dL", "mass_concentration", ("milligrams",)),
    )
    with pytest.raises(ValueError, match="duplicate unit definition"):
        CuratedUnitRegistry(definitions=duplicate_definitions, conversions=())

    definitions = (
        UnitDefinition("mg/dL", "mass_concentration", ("мг/дл",)),
        UnitDefinition("g/L", "mass_concentration", ("г/л",)),
    )
    with pytest.raises(ValueError, match="duplicate conversion rule ID"):
        CuratedUnitRegistry(
            definitions=definitions,
            conversions=(
                ConversionRule("duplicate", "mg/dL", "g/L", Decimal("0.01")),
                ConversionRule("duplicate", "g/L", "mg/dL", Decimal("100")),
            ),
        )
