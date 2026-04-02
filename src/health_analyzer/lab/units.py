"""Curated UCUM normalization with explicit conversion rules only."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext
import unicodedata

from .parsing import MAX_DECIMAL_ABS_EXPONENT, MAX_DECIMAL_DIGITS, ParsedNumeric, is_bounded_decimal


class UnsupportedUnitError(ValueError):
    """Raised when a source unit is not in the curated registry."""


class UnsafeUnitConversionError(ValueError):
    """Raised when no exact, curated conversion rule exists."""


@dataclass(frozen=True, slots=True)
class UnitDefinition:
    ucum_code: str
    dimension: str
    aliases: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.ucum_code, str) or not self.ucum_code.strip():
            raise ValueError("unit UCUM code is required")
        if not isinstance(self.dimension, str) or not self.dimension.strip():
            raise ValueError("unit dimension is required")
        if not isinstance(self.aliases, tuple) or not all(
            isinstance(alias, str) and alias.strip() for alias in self.aliases
        ):
            raise ValueError("unit aliases must be non-empty strings")


@dataclass(frozen=True, slots=True)
class ConversionRule:
    rule_id: str
    source_ucum: str
    target_ucum: str
    factor: Decimal

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value.strip()
            for value in (self.rule_id, self.source_ucum, self.target_ucum)
        ):
            raise ValueError("conversion identifiers and units are required")
        if (
            not is_bounded_decimal(self.factor)
            or self.factor <= 0
        ):
            raise ValueError("conversion factor must be a finite positive Decimal within numeric bounds")


@dataclass(frozen=True, slots=True)
class NormalizedQuantity:
    raw_value: str
    original_value: Decimal
    original_unit: str
    comparator: str | None
    normalized_value: Decimal
    ucum_unit: str
    conversion_rule_id: str


def _unit_key(unit: str) -> str:
    normalized = unicodedata.normalize("NFKC", unit).strip()
    normalized = normalized.replace("µ", "u").replace("μ", "u")
    return "".join(normalized.split()).casefold()


class CuratedUnitRegistry:
    """An allowlist, not a dimensional-analysis inference engine."""

    def __init__(
        self,
        definitions: tuple[UnitDefinition, ...] | None = None,
        conversions: tuple[ConversionRule, ...] | None = None,
    ) -> None:
        definitions = (
            DEFAULT_UNIT_DEFINITIONS if definitions is None else definitions
        )
        conversions = DEFAULT_CONVERSIONS if conversions is None else conversions
        if not definitions:
            raise ValueError("at least one curated unit definition is required")
        self._aliases: dict[str, UnitDefinition] = {}
        definitions_by_ucum: dict[str, UnitDefinition] = {}
        for definition in definitions:
            if not isinstance(definition, UnitDefinition):
                raise TypeError("definitions must contain UnitDefinition values")
            if definition.ucum_code in definitions_by_ucum:
                raise ValueError(
                    f"duplicate unit definition: {definition.ucum_code}"
                )
            definitions_by_ucum[definition.ucum_code] = definition
            for alias in (*definition.aliases, definition.ucum_code):
                key = _unit_key(alias)
                previous = self._aliases.get(key)
                if previous is not None and previous.ucum_code != definition.ucum_code:
                    raise ValueError(f"unit alias collision: {alias}")
                self._aliases[key] = definition
        self._conversions: dict[tuple[str, str], ConversionRule] = {}
        rule_ids: set[str] = set()
        for rule in conversions:
            if not isinstance(rule, ConversionRule):
                raise TypeError("conversions must contain ConversionRule values")
            if rule.rule_id in rule_ids:
                raise ValueError(f"duplicate conversion rule ID: {rule.rule_id}")
            pair = (rule.source_ucum, rule.target_ucum)
            if pair in self._conversions:
                raise ValueError(
                    f"duplicate conversion pair: {rule.source_ucum} to {rule.target_ucum}"
                )
            try:
                source_definition = definitions_by_ucum[rule.source_ucum]
                target_definition = definitions_by_ucum[rule.target_ucum]
            except KeyError as error:
                raise ValueError(
                    "conversion rule references an undefined UCUM code"
                ) from error
            if source_definition.dimension != target_definition.dimension:
                raise ValueError(
                    "conversion rule crosses incompatible unit dimensions: "
                    f"{source_definition.dimension} to {target_definition.dimension}"
                )
            rule_ids.add(rule.rule_id)
            self._conversions[pair] = rule

    def resolve(self, original_unit: str) -> UnitDefinition:
        try:
            return self._aliases[_unit_key(original_unit)]
        except KeyError as error:
            raise UnsupportedUnitError(original_unit) from error

    def normalize(
        self,
        parsed: ParsedNumeric,
        original_unit: str,
        *,
        target_ucum: str | None = None,
    ) -> NormalizedQuantity:
        source = self.resolve(original_unit)
        target = target_ucum or source.ucum_code
        if target == source.ucum_code:
            rule = ConversionRule(
                f"identity:{source.ucum_code}",
                source.ucum_code,
                source.ucum_code,
                Decimal("1"),
            )
        else:
            try:
                rule = self._conversions[(source.ucum_code, target)]
            except KeyError as error:
                raise UnsafeUnitConversionError(
                    f"no curated conversion from {source.ucum_code} to {target}"
                ) from error

        # Decimal arithmetic otherwise inherits the caller's ambient precision
        # (28 by default) and can silently round even an identity conversion.
        if rule.factor == 1:
            normalized = parsed.value
        else:
            with localcontext() as context:
                context.prec = len(parsed.value.as_tuple().digits) + len(rule.factor.as_tuple().digits)
                context.Emax = 2 * (MAX_DECIMAL_ABS_EXPONENT + MAX_DECIMAL_DIGITS)
                context.Emin = -context.Emax
                normalized = (parsed.value * rule.factor).normalize()
        if not is_bounded_decimal(normalized):
            raise UnsafeUnitConversionError("converted quantity exceeds numeric bounds")

        return NormalizedQuantity(
            raw_value=parsed.raw,
            original_value=parsed.value,
            original_unit=original_unit,
            comparator=parsed.comparator,
            normalized_value=normalized,
            ucum_unit=target,
            conversion_rule_id=rule.rule_id,
        )


DEFAULT_UNIT_DEFINITIONS = (
    UnitDefinition("mg/dL", "mass_concentration", ("мг/дл",)),
    UnitDefinition("g/dL", "mass_concentration", ("г/дл",)),
    UnitDefinition("mg/L", "mass_concentration", ("мг/л",)),
    UnitDefinition("g/L", "mass_concentration", ("г/л",)),
    UnitDefinition("ug/L", "mass_concentration", ("мкг/л", "ng/mL", "нг/мл")),
    UnitDefinition("ng/L", "mass_concentration", ("нг/л", "pg/mL", "пг/мл")),
    UnitDefinition("mmol/L", "substance_concentration", ("ммоль/л",)),
    UnitDefinition("umol/L", "substance_concentration", ("мкмоль/л", "umol/l")),
    UnitDefinition("nmol/L", "substance_concentration", ("нмоль/л",)),
    UnitDefinition("10*9/L", "number_concentration", ("тыс/мкл", "10^9/л", "10^9/L")),
    UnitDefinition("10*12/L", "number_concentration", ("млн/мкл", "10^12/л", "10^12/L")),
    UnitDefinition("%", "fraction", ("проц.",)),
    UnitDefinition("fL", "volume", ("фл",)),
    UnitDefinition("pg", "mass", ("пг",)),
    UnitDefinition("s", "time", ("сек", "с", "sec")),
    UnitDefinition("ms", "time", ("мсек", "msec")),
    UnitDefinition("mm/h", "velocity", ("мм/ч",)),
    UnitDefinition("mm[Hg]", "pressure", ("ммрт.ст.", "мм рт. ст.", "mmhg")),
    UnitDefinition("/min", "frequency", ("уд/мин", "1/мин")),
)


DEFAULT_CONVERSIONS = (
    ConversionRule("mass:mg/dL-to-g/L:v1", "mg/dL", "g/L", Decimal("0.01")),
    ConversionRule("mass:g/L-to-mg/dL:v1", "g/L", "mg/dL", Decimal("100")),
    ConversionRule("mass:g/dL-to-g/L:v1", "g/dL", "g/L", Decimal("10")),
    ConversionRule("mass:g/L-to-g/dL:v1", "g/L", "g/dL", Decimal("0.1")),
    ConversionRule("mass:mg/L-to-g/L:v1", "mg/L", "g/L", Decimal("0.001")),
    ConversionRule("mass:g/L-to-mg/L:v1", "g/L", "mg/L", Decimal("1000")),
    ConversionRule("mass:ug/L-to-mg/L:v1", "ug/L", "mg/L", Decimal("0.001")),
    ConversionRule("mass:mg/L-to-ug/L:v1", "mg/L", "ug/L", Decimal("1000")),
    ConversionRule("mass:ng/L-to-ug/L:v1", "ng/L", "ug/L", Decimal("0.001")),
    ConversionRule("mass:ug/L-to-ng/L:v1", "ug/L", "ng/L", Decimal("1000")),
)
