"""Conservative LOINC candidate generation and explicit confirmation."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
import hashlib
import json
import unicodedata


class MappingStatus(StrEnum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"


@dataclass(frozen=True, slots=True)
class LoincAxes:
    component: str
    property: str
    time: str
    system: str
    scale: str
    method: str | None = None

    def __post_init__(self) -> None:
        for name in ("component", "property", "time", "system", "scale"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or "\0" in value:
                raise ValueError(f"LOINC axis {name} must be non-empty text")
        if self.method is not None and (
            not isinstance(self.method, str)
            or not self.method.strip()
            or "\0" in self.method
        ):
            raise ValueError("LOINC method axis must be non-empty text or null")


@dataclass(frozen=True, slots=True)
class LoincCatalogEntry:
    code: str
    display: str
    version: str
    axes: LoincAxes
    aliases: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("code", "display", "version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or "\0" in value:
                raise ValueError(f"LOINC {name} must be non-empty text")
        if not isinstance(self.axes, LoincAxes):
            raise ValueError("LOINC axes must be a LoincAxes snapshot")
        object.__setattr__(self, "aliases", tuple(self.aliases))
        if not self.aliases or any(
            not isinstance(alias, str) or not alias.strip() or "\0" in alias
            for alias in self.aliases
        ):
            raise ValueError("LOINC aliases must contain non-empty text")
        normalized = tuple(_term_key(alias) for alias in self.aliases)
        if len(set(normalized)) != len(normalized):
            raise ValueError("LOINC aliases must be unique after normalization")


@dataclass(frozen=True, slots=True)
class LoincMapping:
    code: str
    display: str
    version: str
    catalog_sha256: str
    entry_sha256: str
    status: MappingStatus
    matched_alias: str
    verified_axes: tuple[str, ...] = ()
    confirmed_by: str | None = None

    def __post_init__(self) -> None:
        for name in ("code", "display", "version", "matched_alias"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or "\0" in value:
                raise ValueError(f"LOINC mapping {name} must be non-empty text")
        for name in ("catalog_sha256", "entry_sha256"):
            value = getattr(self, name)
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if not isinstance(self.status, MappingStatus):
            raise ValueError("LOINC mapping status must be a MappingStatus")
        object.__setattr__(self, "verified_axes", tuple(self.verified_axes))
        if self.status is MappingStatus.CANDIDATE and (
            self.verified_axes or self.confirmed_by is not None
        ):
            raise ValueError("candidate mappings cannot carry confirmation fields")
        if self.status is MappingStatus.CONFIRMED and (
            not self.verified_axes
            or not isinstance(self.confirmed_by, str)
            or not self.confirmed_by.strip()
        ):
            raise ValueError("confirmed mappings require axes and reviewer attribution")


def _term_key(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def _entry_payload(entry: LoincCatalogEntry) -> dict[str, object]:
    return {
        "code": entry.code,
        "display": entry.display,
        "version": entry.version,
        "axes": {
            "component": entry.axes.component,
            "property": entry.axes.property,
            "time": entry.axes.time,
            "system": entry.axes.system,
            "scale": entry.axes.scale,
            "method": entry.axes.method,
        },
        "aliases": sorted(_term_key(alias) for alias in entry.aliases),
    }


def _snapshot_sha256(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


class LoincMapper:
    """Exact alias matching only; no fuzzy or model-only confirmation."""

    BASE_AXES = frozenset({"component", "property", "time", "system", "scale"})

    def __init__(self, entries: tuple[LoincCatalogEntry, ...] = ()) -> None:
        codes = tuple(entry.code for entry in entries)
        if len(set(codes)) != len(codes):
            raise ValueError("LOINC catalog codes must be unique")
        self._entries = {entry.code: entry for entry in entries}
        self._entry_sha256 = {
            entry.code: _snapshot_sha256(_entry_payload(entry)) for entry in entries
        }
        self.catalog_sha256 = _snapshot_sha256(
            {
                "schema": "loinc-catalog-snapshot-v1",
                "entries": [
                    _entry_payload(entry)
                    for entry in sorted(entries, key=lambda item: item.code)
                ],
            }
        )
        self._aliases: dict[str, list[LoincCatalogEntry]] = {}
        for entry in entries:
            for alias in entry.aliases:
                self._aliases.setdefault(_term_key(alias), []).append(entry)

    def propose(self, source_name: str) -> tuple[LoincMapping, ...]:
        entries = self._aliases.get(_term_key(source_name), [])
        return tuple(
            LoincMapping(
                code=entry.code,
                display=entry.display,
                version=entry.version,
                catalog_sha256=self.catalog_sha256,
                entry_sha256=self._entry_sha256[entry.code],
                status=MappingStatus.CANDIDATE,
                matched_alias=source_name,
            )
            for entry in sorted(entries, key=lambda item: item.code)
        )

    def confirm(
        self,
        mapping: LoincMapping,
        *,
        verified_axes: set[str] | frozenset[str],
        reviewer_id: str,
    ) -> LoincMapping:
        if mapping.status is not MappingStatus.CANDIDATE:
            raise ValueError("only a candidate mapping can be confirmed")
        if not isinstance(reviewer_id, str) or not reviewer_id.strip():
            raise ValueError("reviewer_id is required")
        entry = self._entries.get(mapping.code)
        if entry is None or mapping not in self.propose(mapping.matched_alias):
            raise ValueError("mapping does not belong to this pinned catalog")
        required = set(self.BASE_AXES)
        if entry.axes.method is not None:
            required.add("method")
        supplied = set(verified_axes)
        unknown = supplied - required
        if unknown:
            raise ValueError(
                f"unknown LOINC axes: {', '.join(sorted(unknown))}"
            )
        missing = required - supplied
        if missing:
            raise ValueError(f"LOINC axes not verified: {', '.join(sorted(missing))}")
        return replace(
            mapping,
            status=MappingStatus.CONFIRMED,
            verified_axes=tuple(sorted(required)),
            confirmed_by=reviewer_id,
        )
