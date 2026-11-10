"""Conservative, local laboratory layout proposals, never accepted observations.

``propose_lab_rows(pages, version, locator_kind="pdf")`` accepts page dictionaries
with page/text/blocks/width/height/source. Blocks use top-left x/y/width/height;
source is pdf_text or vision_ocr. Confidence is optional and never assurance.
For rotated OCR, readable_box and metadata.readable_width/readable_height are
used for grouping; the original block boxes remain the source anchors.

The result has contract-ready rows, separately reviewable whole-source-row
issues, and contract-ready extraction coverage. Issues retain all raw cells and
anchors, including prior-result columns and comments that the observation
contract cannot represent. No analyte mapping, patient identity, timezone,
collection date from another page, or absent result is inferred.

Transposed tables need source analyte headers above an explicit date column or
a blank corner followed by an actual date/result row. Separate sections do not
inherit analytes or units. Units may be explicit header suffixes, unit rows, or
the adjacent continuation of one source result cell. Unknown years/date roles,
missing cells, conflicting units, and unseparated source boxes remain issues
or ambiguous drafts. Native transposed cells use ``line="N;chars=A:B"``: N is
the one-based extracted source line; A:B is its literal zero-based Python
character slice, including the original tab positions. This describes source
text, never inferred physical PDF coordinates.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import date, datetime
from decimal import Decimal
import math
import re
from statistics import median
from typing import Any

from .common import V2Error, canonical, digest, require
from .contracts import SHA256_RE, identifier, lab_observation
from .unit_text import inspect_unit

MAX_PAGES = 500
MAX_BLOCKS = 50000
MAX_ROWS = 1000
MAX_TEXT = 16 * 1024 * 1024
MAX_ISSUES = 1000
MAX_ISSUE_TEXT = 8000
MAX_ISSUE_BYTES = 64 * 1024
FRAGMENT_CHARS = 2000
NUMBER = r"[+-]?(?:\d+(?:[.,]\d+)?|[.,]\d+)"
SCALAR = re.compile(rf"^(<=|>=|<|>|≤|≥)?\s*({NUMBER})$")
RANGE = re.compile(rf"^({NUMBER})\s*[-–—]\s*({NUMBER})$")
INLINE_SCALAR = re.compile(rf"^(<=|>=|<|>|≤|≥)?\s*({NUMBER})(?:\s*([*↑↓]+|[HL]))?(?:\s+(.+))?$")
COMMENT = re.compile(r"^(?:комментарий|примечани[ея]|comment|note|interpretation)\s*[:：]", re.I)
FOOTER = re.compile(r"^(?:исполнитель|врач|подпись|страница|page\s+\d|www\.|https?://|результаты исследований не|лабораторные исследования не)", re.I)
UNIT = re.compile(r"^(?:%|‰|[a-zа-яёµμ][a-zа-яёµμ0-9^*·./()−⁻²³]*|(?:10|\d+)\s*\^\s*\d+\s*/\s*[a-zа-яёµμ]+)$", re.I)
DATE_TOKEN = re.compile(r"(?<!\d)(?:\d{2}\.\d{2}\.\d{4}|\d{4}-\d{2}-\d{2})(?:[ T]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})?)?(?!\d)")
TIME_LABELS = (
    ("collected", r"дата\s+(?:и\s+время\s+)?(?:взятия|забора|сбора)(?:\s+(?:образца|биоматериала|материала))?|(?:specimen\s+)?collect(?:ed|ion)(?:\s+(?:date|time|datetime|at))?|sample\s+date"),
    ("performed", r"дата\s+(?:и\s+время\s+)?(?:выполнения|исследования)|performed(?:\s+(?:date|time))?|test\s+date"),
    ("reported", r"дата\s+(?:и\s+время\s+)?(?:отч[её]та|печати|выдачи)|reported(?:\s+(?:date|time))?|report\s+date"),
    ("unknown", r"дата|date"),
)
META_LABEL = re.compile("|".join(f"(?:{pattern})" for _, pattern in TIME_LABELS) + r"|биоматериал|материал(?=\s*[:：])|specimen|метод|method", re.I)


@dataclass
class _Box:
    text: str
    x: float
    y: float
    width: float
    height: float
    source_rect: tuple[float, float, float, float] | None
    line: int | None
    confidence: float | None = None
    source_text: str | None = None
    source_span: tuple[int, int] | None = None
    cell_locator: bool = False
    matrix_column: int | None = None


@dataclass
class _Line:
    boxes: list[_Box]
    y: float
    height: float

    @property
    def text(self) -> str:
        return " ".join(box.text for box in self.boxes)


@dataclass
class _Column:
    label: str
    role: str
    x: float
    end: float
    boxes: list[_Box]


@dataclass
class _Candidate:
    cells: dict[int, list[_Box]] = field(default_factory=dict)
    lines: list[_Line] = field(default_factory=list)
    comments: list[_Box] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    inherited_roles: set[str] = field(default_factory=set)
    unit_hypotheses: list[tuple[str, list[_Box]]] = field(default_factory=list)


@dataclass
class _Table:
    columns: list[_Column]
    header_end: int
    start: float = 0.0
    end: float | None = None


@dataclass
class _Matrix:
    """A source-labelled date column followed by source analyte columns."""
    columns: list[_Column]
    header_end: int
    start: float
    end: float | None
    units: dict[int, list[tuple[str, list[_Box]]]] = field(default_factory=dict)
    references: dict[int, list[_Box]] = field(default_factory=dict)
    context: list[_Line] = field(default_factory=list)


def _fold(text: str) -> str:
    return re.sub(r"[\s.:()]+", " ", text.casefold()).strip()


def _role(label: str) -> str | None:
    token = _fold(label)
    if re.search(r"предыдущ|предшеств|previous|prior|historical", token):
        return "prior_result"
    if DATE_TOKEN.fullmatch(label.strip()):
        return "prior_result"
    if token in {"исследование", "исследования", "показатель", "анализ", "анализы", "наименование", "наименование исследования", "наименование показателя", "test", "tests", "analyte", "analyte raw", "name", "test name"}:
        return "analyte_raw"
    if token in {"результат", "результаты", "значение", "result", "results", "value", "current result", "текущий результат"}:
        return "result"
    if token in {"ед", "ед изм", "ед измер", "ед измерения", "единица", "единицы", "единицы измерения", "единица измерения", "unit", "units", "unit raw"}:
        return "unit_raw"
    if re.fullmatch(r"(?:референс(?:ы|ные|ный)?(?: значения| интервал| пределы)?|норма|нормы|нормальные значения|reference(?: values| range| interval| limits)?|ref|range|limits)", token):
        return "reference_intervals"
    if token in {"флаг", "flag", "flags", "отклонение"}:
        return "lab_flag_raw"
    if token in {"биоматериал", "материал", "образец", "specimen", "sample"}:
        return "specimen"
    if token in {"метод", "method"}:
        return "method"
    if any(re.fullmatch(pattern, token, re.I) for _, pattern in TIME_LABELS):
        return "clinical_time"
    return None


def _finite(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _pages(pages: list[dict]) -> list[dict]:
    require(isinstance(pages, list) and 1 <= len(pages) <= MAX_PAGES, "LAYOUT_INPUT_LIMIT", "Layout accepts 1 to 500 pages")
    normalized = []
    page_ids: set[int] = set()
    total_text = total_blocks = 0
    for page in pages:
        require(isinstance(page, dict), "INVALID_LAYOUT", "Each layout page must be an object")
        number = page.get("page")
        require(isinstance(number, int) and not isinstance(number, bool) and 1 <= number <= MAX_PAGES and number not in page_ids,
                "INVALID_LAYOUT", "Layout pages need distinct bounded one-based IDs")
        page_ids.add(number)
        require(page.get("source") in {"pdf_text", "vision_ocr"}, "INVALID_LAYOUT", "Layout source must identify text or OCR")
        raw_text = page.get("text", "")
        blocks = page.get("blocks", [])
        require(isinstance(raw_text, str) and isinstance(blocks, list), "INVALID_LAYOUT", "Page text and blocks must have explicit shapes")
        total_text += len(raw_text.encode("utf-8"))
        total_blocks += len(blocks)
        require(total_text <= MAX_TEXT and total_blocks <= MAX_BLOCKS, "LAYOUT_INPUT_LIMIT", "Layout exceeds bounded text/block limits")
        copy = dict(page)
        copy["text"] = raw_text
        if blocks:
            width, height = page.get("width"), page.get("height")
            require(_finite(width) and _finite(height) and width > 0 and height > 0,
                    "INVALID_LAYOUT", "Geometry pages require positive width/height")
            for block in blocks:
                require(isinstance(block, dict) and isinstance(block.get("text"), str), "INVALID_LAYOUT", "Layout blocks require text")
                total_text += len(block["text"].encode("utf-8"))
                require(total_text <= MAX_TEXT, "LAYOUT_INPUT_LIMIT", "Layout exceeds bounded text limits")
                x, y, w, h = (block.get(key) for key in ("x", "y", "width", "height"))
                require(all(_finite(v) for v in (x, y, w, h)) and x >= 0 and y >= 0 and w > 0 and h > 0
                        and x + w <= width * 1.001 and y + h <= height * 1.001,
                        "INVALID_LAYOUT", "Layout blocks must stay inside the source page")
                confidence = block.get("confidence")
                require(confidence is None or (_finite(confidence) and 0 <= confidence <= 1),
                        "INVALID_LAYOUT", "OCR confidence must be null or 0..1")
        normalized.append(copy)
    return sorted(normalized, key=lambda page: page["page"])


def _split(box: _Box) -> list[_Box]:
    """Split explicit spaces only; anchors keep the actual containing source box."""
    text = box.text.expandtabs(8)
    chunks = [(match.start(), match.group()) for match in re.finditer(r"\S(?:.*?\S)??(?=\s{2,}|\s*$)", text)]
    if len(chunks) <= 1:
        return [box]
    return [_Box(token, box.x + box.width * offset / max(len(text), 1), box.y,
                 box.width * len(token) / max(len(text), 1), box.height,
                 box.source_rect, box.line, box.confidence, box.source_text or box.text)
            for offset, token in chunks]


def _lines(page: dict) -> list[_Line]:
    boxes = []
    if page.get("blocks"):
        metadata = page.get("metadata", {})
        require(isinstance(metadata, dict), "INVALID_LAYOUT", "Page metadata must be an object")
        for raw in page["blocks"]:
            if not raw["text"].strip():
                continue
            parse_rect = raw.get("readable_box", raw)
            require(isinstance(parse_rect, dict), "INVALID_LAYOUT", "Readable box must be an object")
            x, y, w, h = (parse_rect.get(key) for key in ("x", "y", "width", "height"))
            require(all(_finite(v) for v in (x, y, w, h)) and x >= 0 and y >= 0 and w > 0 and h > 0,
                    "INVALID_LAYOUT", "Readable geometry must be positive")
            if "readable_box" in raw:
                rw, rh = metadata.get("readable_width"), metadata.get("readable_height")
                require(_finite(rw) and _finite(rh) and rw > 0 and rh > 0 and x + w <= rw * 1.001 and y + h <= rh * 1.001,
                        "INVALID_LAYOUT", "Readable boxes require bounded readable page dimensions")
            source_rect = (raw["x"], raw["y"], raw["x"] + raw["width"], raw["y"] + raw["height"])
            # Multiline cell boxes preserve their real box; line placement is only
            # a grouping aid and is never promoted to more precise provenance.
            parts = raw["text"].splitlines() or [raw["text"]]
            for offset, part in enumerate(parts):
                if part.strip():
                    box = _Box(part, x, y + h * offset / len(parts), w, h / len(parts), source_rect,
                               None, raw.get("confidence"), raw["text"])
                    boxes.extend(_split(box))
    else:
        for line_number, original in enumerate(page["text"].splitlines(), 1):
            line = original.expandtabs(8)
            source_offsets = []
            column = 0
            for offset, character in enumerate(original):
                length = 8 - column % 8 if character == "\t" else 1
                source_offsets.extend([offset] * length)
                column += length
            for match in re.finditer(r"\S(?:.*?\S)??(?=\s{2,}|\s*$)", line):
                span = (source_offsets[match.start()], source_offsets[match.end() - 1] + 1)
                boxes.append(_Box(match.group(), float(match.start()), float(line_number), float(len(match.group())),
                                  1.0, None, line_number, source_text=original[span[0]:span[1]], source_span=span))
    result: list[_Line] = []
    for box in sorted(boxes, key=lambda b: (b.y + b.height / 2, b.x)):
        center = box.y + box.height / 2
        match = next((line for line in reversed(result[-3:]) if abs((line.y + line.height / 2) - center) <= min(line.height, box.height) * .55), None)
        if match is None:
            result.append(_Line([box], box.y, box.height))
        else:
            match.boxes.append(box)
            match.y = min(match.y, box.y)
            match.height = max(match.height, box.height)
    for line in result:
        line.boxes.sort(key=lambda box: box.x)
    return sorted(result, key=lambda line: line.y)


def _segments(line: _Line) -> list[list[_Box]]:
    groups: list[list[_Box]] = []
    for box in line.boxes:
        previous_role = _role(" ".join(item.text for item in groups[-1])) if groups else None
        next_role = _role(box.text)
        distinct_fields = bool(previous_role and next_role and previous_role != next_role)
        # PDF character geometry uses height=1; OCR words use glyph-height.
        if groups and not distinct_fields and box.x - (groups[-1][-1].x + groups[-1][-1].width) < line.height * 1.5:
            groups[-1].append(box)
        else:
            groups.append([box])
    return groups


def _header(lines: list[_Line], index: int) -> tuple[list[_Column], int] | None:
    columns = []
    for group in _segments(lines[index]):
        label = " ".join(box.text for box in group)
        role = _role(label)
        columns.append(_Column(label, role or "unknown_column", min(b.x for b in group), max(b.x + b.width for b in group), group))
    roles = [column.role for column in columns]
    if "analyte_raw" not in roles or "result" not in roles:
        return None
    # Consume explicit second-line header fragments, never the first data row.
    end = index
    for extra in range(index + 1, min(index + 3, len(lines))):
        line = lines[extra]
        tokens = [_fold(box.text) for box in line.boxes]
        if line.y - (lines[end].y + lines[end].height) > lines[index].height * 1.8:
            break
        if not tokens or not all(token in {"измерения", "значения", "интервал", "values", "range", "units", "date", "время"} for token in tokens):
            break
        for box in line.boxes:
            nearest = min(columns, key=lambda column: abs(column.x - box.x))
            nearest.label += " " + box.text
            nearest.end = max(nearest.end, box.x + box.width)
            nearest.boxes.append(box)
        end = extra
    return sorted(columns, key=lambda column: column.x), end


def _classic_headers(lines: list[_Line], index: int) -> list[_Table]:
    header = _header(lines, index)
    if header is None:
        return []
    columns, header_end = header
    starts = [i for i, column in enumerate(columns) if column.role == "analyte_raw"]
    if len(starts) < 2 or starts[0] != 0:
        return [_Table(columns, header_end)]
    groups = [columns[start:starts[i + 1] if i + 1 < len(starts) else len(columns)]
              for i, start in enumerate(starts)]
    # A repeated complete field sequence establishes independent tables.
    # Duplicate result columns within one sequence remain ambiguous.
    if any("result" not in [column.role for column in group]
           or any(sum(column.role == role for column in group) > 1
                  for role in {column.role for column in group} - {"prior_result"})
           for group in groups):
        return [_Table(columns, header_end)]
    cuts = [(left[-1].end + right[0].x) / 2 for left, right in zip(groups, groups[1:])]
    if any(left[-1].end >= right[0].x for left, right in zip(groups, groups[1:])):
        return [_Table(columns, header_end)]
    return [_Table(group, header_end, cuts[i - 1] if i else 0.0,
                   cuts[i] if i < len(cuts) else None) for i, group in enumerate(groups)]


def _anchors(boxes: list[_Box], field_name: str, page: dict, version: dict, locator_kind: str,
             *, inherited: bool = False) -> dict | list[dict] | None:
    if not boxes:
        return None
    # A line locator or actual source-box envelope is sufficient; no precision
    # is fabricated from estimated character widths or an OCR subdivision.
    by_line: dict[int, list[_Box]] = {}
    visual = []
    for box in boxes:
        if box.source_rect is None:
            require(type(box.line) is int and box.line >= 1, "INVALID_LAYOUT", "Text spans need their actual source line")
            by_line.setdefault(box.line, []).append(box)
        else:
            visual.append(box)
    anchors = []
    line_groups = [(line, line, group) for line, group in sorted(by_line.items())]
    if len(line_groups) > 20:
        # Coarsen actual contiguous lines without pretending to locate one cell.
        # Blank-line gaps may be included only by taking their real source span.
        ranges = []
        for start, end, group in line_groups:
            if ranges and start == ranges[-1][1] + 1:
                ranges[-1] = (ranges[-1][0], end, [*ranges[-1][2], *group])
            else:
                ranges.append((start, end, group))
        if len(ranges) > 20:
            ranges = [(line_groups[0][0], line_groups[-1][1], [box for _, _, group in line_groups for box in group])]
        line_groups = ranges
    for start, end, group in line_groups:
        exact_cell = start == end and any(box.cell_locator for box in group)
        if exact_cell:
            require(all(box.source_span is not None for box in group), "INVALID_LAYOUT", "Exact text cells require literal source offsets")
            cell_start = min(box.source_span[0] for box in group)
            cell_end = max(box.source_span[1] for box in group)
            excerpt = page["text"].splitlines()[start - 1][cell_start:cell_end]
            # This is a literal extracted-text character locator, not estimated
            # PDF geometry. The API's bounded line string retains the page.
            line_locator = f"{start};chars={cell_start}:{cell_end}"
        elif start == end:
            excerpt = " ".join(box.text for box in group)
            line_locator = start
        else:
            # A coarse range quotes the real complete native span, including
            # intervening blank lines/columns, rather than inventing adjacency
            # between separated cell excerpts.
            excerpt = "".join(page["text"].splitlines(keepends=True)[start - 1:end])
            line_locator = f"{start}-{end}"
        require(0 < len(excerpt) <= MAX_ISSUE_TEXT, "LAYOUT_SOURCE_SPAN_LIMIT", "A source span needs bounded linked fragments")
        anchors.append({"version_id": version["version_id"], "source_sha256": version["source_sha256"],
                        "field": field_name, "locator": {"kind": locator_kind, "page": page["page"], "line": line_locator},
                        "excerpt": excerpt, "inherited": inherited})
    if visual:
        x0 = min(box.source_rect[0] for box in visual)
        y0 = min(box.source_rect[1] for box in visual)
        x1 = max(box.source_rect[2] for box in visual)
        y1 = max(box.source_rect[3] for box in visual)
        excerpts = list(dict.fromkeys(box.source_text or box.text for box in visual))
        excerpt = "\n".join(excerpts)
        require(0 < len(excerpt) <= MAX_ISSUE_TEXT, "LAYOUT_SOURCE_SPAN_LIMIT", "A source span needs bounded linked fragments")
        anchors.append({"version_id": version["version_id"], "source_sha256": version["source_sha256"],
                        "field": field_name, "locator": {"kind": locator_kind, "page": page["page"],
                        "region": [max(0.0, x0 / page["width"]), max(0.0, y0 / page["height"]),
                                   min(1.0, x1 / page["width"]), min(1.0, y1 / page["height"])]},
                        "excerpt": excerpt, "inherited": inherited})
    if len(anchors) > 20:
        # Mixed representations need one bounded source fragment per span;
        # ordinary native pages and visual pages have already been coarsened.
        raise V2Error("LAYOUT_SOURCE_SPAN_LIMIT", "Mixed source spans need bounded linked fragments")
    return anchors[0] if len(anchors) == 1 else anchors


def _clinical(raw: str | None, role: str) -> dict:
    result = {"raw": raw or None, "role": role, "precision": "unknown", "value": None}
    if not raw:
        return result
    token = raw.strip()
    try:
        if re.fullmatch(r"\d{2}\.\d{2}\.\d{4}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?", token):
            date_text, *time_text = re.split(r"[ T]", token, maxsplit=1)
            day, month, year = date_text.split(".")
            parsed = f"{year}-{month}-{day}" + ("T" + time_text[0] if time_text else "")
            datetime.fromisoformat(parsed) if time_text else date.fromisoformat(parsed)
            result.update(precision="datetime" if time_text else "date", value=parsed)
        elif re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})?)?", token):
            parsed = token.replace(" ", "T")
            datetime.fromisoformat(parsed.replace("Z", "+00:00")) if "T" in parsed else date.fromisoformat(parsed)
            result.update(precision="datetime" if "T" in parsed else "date", value=parsed)
        elif re.fullmatch(r"\d{4}-\d{2}", token):
            date.fromisoformat(token + "-01")
            result.update(precision="month", value=token)
        elif re.fullmatch(r"\d{4}", token):
            date.fromisoformat(token + "-01-01")
            result.update(precision="year", value=token)
    except ValueError:
        pass
    return result


def _time_role(label: str) -> str:
    return next((role for role, pattern in TIME_LABELS if re.fullmatch(pattern, label.strip(), re.I)), "unknown")


def _metadata(lines: list[_Line], end: int) -> dict:
    times = []
    fields = {}
    for line in lines[:end]:
        text = line.text
        matches = list(META_LABEL.finditer(text))
        for index, match in enumerate(matches):
            stop = matches[index + 1].start() if index + 1 < len(matches) else len(text)
            raw = text[match.end():stop].strip(" :：;,")
            if not raw:
                continue
            role = _time_role(match.group())
            if role == "unknown" and re.match(r"(?:рождени\w*|of\s+birth|birth)\b", raw, re.I):
                continue  # A birth date is never a clinical sample timestamp.
            if _fold(match.group()) in {"биоматериал", "материал", "specimen"}:
                fields["specimen"] = (raw, line.boxes)
            elif _fold(match.group()) in {"метод", "method"}:
                fields["method"] = (raw, line.boxes)
            else:
                times.append((_clinical(raw, role), line.boxes))
    # A report/print date cannot displace an explicitly collected date. Date
    # roles are retained if only a reported/performed date exists on this page.
    selected = next(([item for item in times if item[0]["role"] == role] for role in ("collected", "performed", "reported", "unknown")
                     if any(item[0]["role"] == role for item in times)), [])
    if selected:
        distinct = {(item[0]["raw"], item[0]["value"]) for item in selected}
        if len(distinct) == 1:
            fields["clinical_time"] = selected[0]
        else:
            fields["clinical_time"] = ({"raw": " | ".join(item[0]["raw"] for item in selected),
                                        "role": selected[0][0]["role"], "precision": "unknown", "value": None},
                                       [box for _, boxes in selected for box in boxes])
    return fields


def _metadata_line(line: _Line) -> bool:
    """An explicit standalone metadata label, not a table field header."""
    token = line.text.strip()
    match = META_LABEL.match(token)
    if match is None or match.end() == len(token) or token[match.end()] not in " :：\t":
        return False
    raw = token[match.end():].strip(" :：;,\t")
    return bool(raw and not (_time_role(match.group()) == "unknown"
                             and re.match(r"(?:рождени\w*|of\s+birth|birth)\b", raw, re.I)))


def _section_metadata(lines: list[_Line], header_index: int, first_header: int,
                      previous_header_end: int, document_metadata: dict,
                      later_explicit_metadata: bool) -> dict:
    if header_index == first_header:
        return document_metadata
    start = header_index
    # Only the trailing inter-table span belongs to the incoming section.
    # Unknown intervening prose is not silently crossed to borrow a timestamp.
    while start > previous_header_end + 1:
        line = lines[start - 1]
        if not (_metadata_line(line) or COMMENT.match(line.text.strip()) or FOOTER.match(line.text.strip())):
            break
        start -= 1
    local_lines = [line for line in lines[start:header_index] if _metadata_line(line)]
    local = _metadata(local_lines, len(local_lines))
    if local:
        return local
    # A pre-table document timestamp may cover repeated tables only in the
    # absence of any explicit later section metadata. Method/specimen never
    # migrate from the first panel into an independent later panel.
    if not later_explicit_metadata and "clinical_time" in document_metadata:
        return {"clinical_time": document_metadata["clinical_time"]}
    return {}


def _parallel_metadata(lines: list[_Line], header_index: int, table: _Table,
                       peers: list[_Table], first_header: int, previous_header_end: int,
                       document_metadata: dict, later_explicit_metadata: bool) -> dict:
    scoped = [_matrix_region(line, table.start, table.end) for line in lines]
    if header_index != first_header:
        return _section_metadata(scoped, header_index, first_header, previous_header_end,
                                 document_metadata, later_explicit_metadata)
    scope_start = header_index
    for index, line in enumerate(lines[:header_index]):
        occupied = set()
        groups = _segments(line)
        for group in groups:
            x0 = min(box.x for box in group)
            x1 = max(box.x + box.width for box in group)
            region = next((i for i, peer in enumerate(peers)
                           if x0 >= peer.start and (peer.end is None or x1 < peer.end)), None)
            if region is None:
                break  # A page-wide prose line cannot establish panel scopes.
            occupied.add(region)
        else:
            if len(occupied) > 1:
                scope_start = index
                break
    local = _metadata(scoped[scope_start:header_index], header_index - scope_start)
    shared = _metadata(lines, scope_start)
    # The explicit document date above parallel panel context may cover both
    # panels. Panel-local method/specimen/date anchors stay in their region.
    if "clinical_time" not in local and "clinical_time" in shared:
        local["clinical_time"] = shared["clinical_time"]
    return local


def _result(raw: str) -> dict | None:
    stripped = raw.strip()
    match = SCALAR.fullmatch(stripped)
    if match:
        operator, number = match.groups()
        result = {"kind": "numeric_censored" if operator else "numeric_exact", "raw": stripped,
                  "decimal": number.replace(",", ".")}
        if operator:
            result["operator"] = operator
        return result
    token = _fold(stripped)
    if re.fullmatch(r"\+{1,4}|\d+:\d+", stripped):
        return {"kind": "semiquantitative", "raw": stripped, "value": stripped}
    if token in {"материал непригоден", "invalid specimen", "отменен", "отменён", "cancelled", "не выполнено", "not performed"}:
        reason = "invalid_specimen" if token in {"материал непригоден", "invalid specimen"} else "not_performed" if token in {"не выполнено", "not performed"} else "cancelled"
        return {"kind": "no_result", "raw": stripped, "reason": reason}
    if re.fullmatch(r"(?:не )?(?:обнаружен[оаы]?|выявлен[оаы]?)|положительн(?:ый|ая|ое|о)|отрицательн(?:ый|ая|ое|о)|positive|negative|detected|not detected|present|absent|trace|следы", token):
        return {"kind": "qualitative", "raw": stripped, "value": stripped}
    return None


def _is_unit(raw: str) -> bool:
    token = raw.strip()
    if inspect_unit(token)["status"] == "known":
        return True
    if not UNIT.fullmatch(token):
        return False
    # Any arbitrary word following a number is not automatically a unit.
    return "/" in token or token.casefold() in {
        "%", "‰", "u", "iu", "miu", "g", "mg", "µg", "μg", "ng", "pg", "kg", "fl", "pl",
        "mm", "cm", "ml", "l", "mmhg", "мм", "см", "мл", "л", "г", "мг", "мкг", "нг", "пг", "ед", "ме",
    }


def _reference(raw: str, unit: str | None) -> dict:
    result = {"kind": "laboratory_reference", "raw": raw, "unit_raw": unit}
    match = RANGE.fullmatch(raw.strip())
    if match and Decimal(match[1].replace(",", ".")) <= Decimal(match[2].replace(",", ".")):
        result.update(low=match[1].replace(",", "."), high=match[2].replace(",", "."), low_inclusive=True, high_inclusive=True)
    else:
        match = SCALAR.fullmatch(raw.strip())
        if match and match[1]:
            operator, number = match.groups()
            key = "high" if operator in {"<", "<=", "≤"} else "low"
            result.update({key: number.replace(",", "."), key + "_inclusive": operator in {"<=", ">=", "≤", "≥"}})
        else:
            result["text"] = raw
    return result


def _cells(line: _Line, columns: list[_Column]) -> dict[int, list[_Box]]:
    cells: dict[int, list[_Box]] = {}
    boundaries = [column.x - line.height * .75 for column in columns[1:]]
    for box in line.boxes:
        index = box.matrix_column if box.matrix_column is not None else sum(box.x >= boundary for boundary in boundaries)
        require(0 <= index < len(columns), "INVALID_LAYOUT", "Joined source cell needs its original matrix column")
        cells.setdefault(index, []).append(box)
    return cells


def _text(boxes: list[_Box]) -> str:
    return " ".join(box.text.strip() for box in boxes if box.text.strip())


def _matrix_region(line: _Line, start: float, end: float | None) -> _Line:
    return _Line([box for box in line.boxes if box.x >= start and (end is None or box.x < end)], line.y, line.height)


def _date_shaped(raw: str) -> bool:
    """A source date shape is evidence of a row, never evidence of its year."""
    token = raw.strip()
    return bool(_clinical(token, "unknown")["value"] is not None or re.fullmatch(
        r"\d{1,2}[./-]\d{1,2}(?:[./-]\d{2,4})?(?:[ T]\d{1,2}:\d{2}(?::\d{2})?)?", token))


def _matrix_result_shaped(raw: str) -> bool:
    if not raw:
        return False
    if _result(raw) is not None:
        return True
    match = INLINE_SCALAR.fullmatch(raw)
    return bool(match and (match[4] is None or _matrix_value_unit(match[4])))


def _matrix_reference_shaped(raw: str) -> bool:
    match = RANGE.fullmatch(raw.strip())
    if match:
        return Decimal(match[1].replace(",", ".")) <= Decimal(match[2].replace(",", "."))
    scalar = SCALAR.fullmatch(raw.strip())
    return bool((scalar and scalar[1]) or _fold(raw) in {
        "negative", "not detected", "absent", "trace", "отрицательный", "отрицательно", "не обнаружено", "не выявлено", "следы"})


def _matrix_unit(raw: str) -> str | None:
    token = raw.strip()
    wrapped = re.fullmatch(r"\(([^()]*)\)", token)
    if wrapped:
        token = wrapped[1].strip()
    return token if _is_unit(token) else None


def _matrix_value_unit(raw: str) -> str | None:
    """An explicit unit subcell can have unreadable/unknown source glyphs."""
    if unit := _matrix_unit(raw):
        return unit
    wrapped = re.fullmatch(r"\(([^()]*)\)", raw.strip())
    if not wrapped:
        return None
    token = wrapped[1].strip()
    if not token or len(token) > 80 or _result(token) is not None:
        return None
    # Only short unit-like characters in parentheses immediately following a
    # value qualify. Arbitrary prose never supplies a medical unit or reference.
    unit_like = bool(re.fullmatch(r"[a-zа-яёµμ0-9|?*^°./·×⁰¹²³⁴⁵⁶⁷⁸⁹⁻−+\- ]+", token, re.I))
    return token if unit_like and ("/" in token or "^" in token or (" " not in token and len(token) <= 12)) else None


def _matrix_unit_boxes(boxes: list[_Box], unit: str) -> list[_Box]:
    return [replace(box, text=unit if i == 0 else "", source_text=box.source_text or box.text, cell_locator=True)
            for i, box in enumerate(boxes)]


def _matrix_header_unit(boxes: list[_Box]) -> tuple[list[_Box], list[tuple[str, list[_Box]]]]:
    """Separate only a visible, syntactically explicit trailing unit."""
    label = _text(boxes)
    # Parentheses also occur in analyte names. Only a recognized unit syntax
    # inside the final parentheses may be separated from the actual name.
    match = re.fullmatch(r"(.+?)\s*\(([^()]*)\)\s*", label)
    if not match:
        match = re.fullmatch(r"(.+?)\s*([%‰])\s*", label)
    if not match or not _is_unit(match[2]):
        return boxes, []
    name, unit = match[1].rstrip(), match[2].strip()
    if len(boxes) == 1:
        original = boxes[0]
        return [replace(original, text=name, source_text=original.source_text or original.text)], [
            (unit, [replace(original, text=unit, source_text=original.source_text or original.text)])]
    # Keep the full header anchor when a unit crosses word boxes; the parsed
    # name is a literal source substring and the locator remains its envelope.
    rest = [replace(box, text="", source_text=box.source_text or box.text) for box in boxes[1:]]
    return [replace(boxes[0], text=name, source_text=boxes[0].source_text or boxes[0].text), *rest], [
        (unit, [replace(boxes[0], text=unit, source_text=boxes[0].source_text or boxes[0].text), *rest])]


def _matrix_headers(lines: list[_Line], index: int) -> list[_Matrix]:
    groups = _segments(lines[index])
    starts = [i for i, group in enumerate(groups) if _role(_text(group)) == "clinical_time"]
    implicit_x = None
    if not starts and groups and all(_text(group) and _role(_text(group)) is None
                                    and not _matrix_result_shaped(_text(group)) and not _date_shaped(_text(group))
                                    and not _matrix_unit(_text(group)) for group in groups):
        # A blank top-left corner is common in visibly transposed grids. The
        # actual left date cell establishes its x coordinate. It supplies no
        # date role and cannot lend a date/year/unit to another source row.
        for extra in range(index + 1, min(index + 7, len(lines))):
            lower = lines[extra]
            if lower.y - (lines[index].y + lines[index].height) > lines[index].height * 8:
                break
            if not lower.boxes:
                continue
            first_box = lower.boxes[0]
            if (re.fullmatch(r"(?:\d{1,2}[./-]\d{1,2}(?:[./-]\d{2,4})?|\d{4}-\d{2}-\d{2})(?:[ T]\d{1,2}:\d{2}(?::\d{2})?)?", first_box.text.strip())
                    and first_box.x + first_box.width <= min(box.x for box in groups[0]) + lower.height * .75
                    and any(_matrix_result_shaped(_text(group)) for group in _segments(lower)[1:])):
                implicit_x = first_box.x
                groups = [[], *groups]
                starts = [0]
                break
    matrices = []
    for offset, first in enumerate(starts):
        last = starts[offset + 1] if offset + 1 < len(starts) else len(groups)
        selected = groups[first:last]
        if len(selected) < 2:
            continue
        labels = [_text(group) if group else "Unlabelled date" for group in selected]
        # Recognized classic field headers are not analytes, and numeric/date
        # cells cannot become analyte headers. One explicit Date/test pair is
        # enough; an implicit date column is handled separately below.
        if any(_role(label) is not None or _matrix_result_shaped(label) or _date_shaped(label)
               for label in labels[1:]):
            continue
        start = min(box.x for box in selected[0]) if selected[0] else implicit_x
        end = min(box.x for box in groups[last]) if last < len(groups) else None
        columns = [_Column(label, "clinical_time" if i == 0 else "transposed_analyte",
                           min(box.x for box in group) if group else start,
                           max(box.x + box.width for box in group) if group else start, list(group))
                   for i, (label, group) in enumerate(zip(labels, selected))]
        matrix = _Matrix(columns, index, start, end, context=[_matrix_region(lines[index], start, end)])
        for i in range(1, len(columns)):
            columns[i].boxes, units = _matrix_header_unit(columns[i].boxes)
            columns[i].label = _text(columns[i].boxes)
            if units:
                matrix.units[i] = units
        # Wrapped headers are consumed only before the first date/result row,
        # with a blank date cell and close, column-aligned source fragments.
        for extra in range(index + 1, min(index + 5, len(lines))):
            line = _matrix_region(lines[extra], start, end)
            if not line.boxes or line.y - (lines[matrix.header_end].y + lines[matrix.header_end].height) > lines[index].height * 1.8:
                break
            cells = _cells(line, columns)
            left = _text(cells.get(0, []))
            if left or any(_matrix_result_shaped(_text(boxes)) for i, boxes in cells.items() if i):
                break
            if any(_role(_text(boxes)) is not None or _date_shaped(_text(boxes)) for boxes in cells.values()):
                break
            if not cells or any(i == 0 or i >= len(columns) for i in cells):
                break
            for i, boxes in cells.items():
                token = _text(boxes)
                if unit := _matrix_unit(token):
                    matrix.units.setdefault(i, []).append((unit, _matrix_unit_boxes(boxes, unit)))
                else:
                    name_boxes, units = _matrix_header_unit(boxes)
                    columns[i].boxes.extend(name_boxes)
                    columns[i].label = _text(columns[i].boxes)
                    matrix.units.setdefault(i, []).extend(units)
            matrix.context.append(line)
            matrix.header_end = extra
        # A labelled header alone does not prove a laboratory matrix. Require
        # an actual nearby date or an undated row of recognizable results.
        evidence = False
        for extra in range(matrix.header_end + 1, min(matrix.header_end + 7, len(lines))):
            line = _matrix_region(lines[extra], start, end)
            cells = _cells(line, columns)
            left = _text(cells.get(0, []))
            results = [_text(cells.get(i, [])) for i in range(1, len(columns))]
            if (_date_shaped(left) or not left) and any(_matrix_result_shaped(raw) for raw in results):
                evidence = True
                break
            if _role(left) not in {"unit_raw", "reference_intervals"}:
                break
        if evidence:
            matrices.append(matrix)
    return matrices


def _near_date_band(date_boxes: list[_Box], result_line: _Line) -> bool:
    """One text-height window, not a tall-cell bridge across dated rows."""
    result_height = median(box.height for box in result_line.boxes)
    date_top = min(box.y for box in date_boxes)
    date_bottom = max(box.y + box.height for box in date_boxes)
    # Never use a multi-row/tall date region to enlarge the association window.
    return (date_bottom - date_top <= result_height * 2.5
            and date_top <= result_line.y + result_line.height + result_height * 1.5
            and date_bottom >= result_line.y - result_height * .5)


def _value_unit_subcell(box: _Box, lines: list[_Line], line_index: int) -> bool:
    """Source geometry, not clinical unit identity, establishes this subcell."""
    if _matrix_value_unit(box.text) is None:
        return False
    for line in lines[max(0, line_index - 4):line_index + 1]:
        for value in line.boxes:
            if value is box or not _matrix_result_shaped(value.text):
                continue
            height = max(value.height, box.height)
            if (abs(box.x - value.x) <= height * .85 and box.y >= value.y + value.height * .5
                    and box.y <= value.y + value.height + height * 2.5):
                return True
    return False


def _geometry_matrix_headers(lines: list[_Line]) -> list[tuple[int, _Matrix]]:
    """Recover dense columns from explicit independent source result boxes.

    Word proximity is unsuitable when nearly touching header cells contain
    long names. Distinct result-box starts supply columns only if each one has
    a visibly aligned analyte header and one nearby actual source date cell.
    This does not invent missing headers, dates, or medical units.
    """
    matrices = []
    for data_index, data_line in enumerate(lines):
        values = [box for box in data_line.boxes if box.source_rect is not None and _matrix_result_shaped(box.text)]
        if len(values) < 2 or len({box.x for box in values}) != len(values):
            continue
        values.sort(key=lambda box: box.x)
        height = median(box.height for box in values)
        # Numeric words in the same original containing OCR box are not
        # independent cell geometry and cannot establish a dense grid.
        if len({box.source_rect for box in values}) != len(values):
            continue
        date_options = []
        for date_line in lines[max(0, data_index - 4):data_index + 5]:
            left = [box for box in date_line.boxes if box.x + box.width <= values[0].x + height * .75]
            if left and _date_shaped(_text(left)) and _near_date_band(left, data_line):
                date_options.append(left)
        if len(date_options) != 1:
            continue
        date_boxes = date_options[0]
        start = min(box.x for box in date_boxes)
        columns = [_Column("Unlabelled date", "clinical_time", start, max(box.x + box.width for box in date_boxes), [])]
        columns.extend(_Column("", "transposed_analyte", box.x, box.x + box.width, []) for box in values)
        nearby = [(index, line) for index, line in enumerate(lines[max(0, data_index - 8):data_index], max(0, data_index - 8))
                  if data_line.y - height * 7 <= line.y < data_line.y]
        nearest: dict[int, float] = {}
        for source_index, line in nearby:
            for column, boxes in _cells(line, columns).items():
                if column == 0:
                    continue
                for box in boxes:
                    if (_role(box.text) is None and not _matrix_result_shaped(box.text) and not _date_shaped(box.text)
                            and not _matrix_unit(box.text) and not _value_unit_subcell(box, lines, source_index)
                            and abs(box.x - columns[column].x) <= max(height, box.height) * .85):
                        nearest[column] = max(nearest.get(column, -math.inf), box.y)
        if set(nearest) != set(range(1, len(columns))):
            continue
        header_top = min(nearest.values())
        context = []
        units: dict[int, list[tuple[str, list[_Box]]]] = {}
        header_indices = []
        for index, line in nearby:
            selected: dict[int, list[_Box]] = {}
            for column, boxes in _cells(line, columns).items():
                if column == 0:
                    continue
                for box in boxes:
                    if box.y + box.height < header_top or box.y < header_top - height * .3:
                        continue
                    if _role(box.text) is not None or _matrix_result_shaped(box.text) or _date_shaped(box.text):
                        continue
                    if _value_unit_subcell(box, lines, index):
                        continue
                    selected.setdefault(column, []).append(box)
            if not selected:
                continue
            selected_boxes = [box for boxes in selected.values() for box in boxes]
            context.append(_Line(selected_boxes, line.y, line.height))
            header_indices.append(index)
            for column, boxes in selected.items():
                token = _text(boxes)
                if unit := _matrix_unit(token):
                    units.setdefault(column, []).append((unit, _matrix_unit_boxes(boxes, unit)))
                else:
                    name_boxes, header_units = _matrix_header_unit(boxes)
                    columns[column].boxes.extend(name_boxes)
                    units.setdefault(column, []).extend(header_units)
        if not header_indices or any(not _text(column.boxes) for column in columns[1:]):
            continue
        for column in columns[1:]:
            column.label = _text(column.boxes)
        matrix = _Matrix(columns, max(header_indices), start, None, units=units, context=context)
        header_index = min(header_indices)
        if not any(existing_index == header_index for existing_index, _ in matrices):
            matrices.append((header_index, matrix))
    return matrices


def _matrix_date_bands(matrix: _Matrix, body: list[_Line]) -> list[_Line]:
    """Join a date between value/unit bands without crossing another date."""
    if not any(box.source_rect is not None for line in body for box in line.boxes):
        return body
    cells = [_cells(_matrix_region(line, matrix.start, matrix.end), matrix.columns) for line in body]
    date_rows = [index for index, row in enumerate(cells) if _date_shaped(_text(row.get(0, [])))]
    require(len(date_rows) <= MAX_ROWS, "ROW_LIMIT", "Layout exceeds 1000 whole source-row candidates")
    merges: dict[int, list[int]] = {}
    used_results = set()
    for date_index in date_rows:
        date_row = cells[date_index]
        if any(_matrix_result_shaped(_text(boxes)) for column, boxes in date_row.items() if column):
            continue
        candidates = []
        for result_index in range(max(0, date_index - 4), min(len(cells), date_index + 5)):
            row = cells[result_index]
            if result_index in date_rows or _text(row.get(0, [])) or result_index in used_results:
                continue
            if not any(_matrix_result_shaped(_text(boxes)) for column, boxes in row.items() if column):
                continue
            if not _near_date_band(date_row[0], body[result_index]):
                continue
            competing = [other for other in date_rows if abs(other - result_index) <= 4
                         and _near_date_band(cells[other][0], body[result_index])]
            if competing != [date_index]:
                continue
            candidates.append(result_index)
        occupied = []
        for index in candidates:
            occupied.extend(column for column, boxes in cells[index].items() if column and _text(boxes))
        if not candidates or len(set(occupied)) != len(occupied):
            continue
        merges[date_index] = candidates
        used_results.update(candidates)
    output = []
    for index, line in enumerate(body):
        if index in used_results:
            continue
        if index not in merges:
            output.append(line)
            continue
        date_row = cells[index]
        combined = [replace(box, matrix_column=0) for box in date_row[0]]
        for other in merges[index]:
            for column, boxes in cells[other].items():
                combined.extend(replace(box, matrix_column=column) for box in boxes)
        # Unit words that share the date's text band remain a separate, actual
        # source unit continuation. They never become numeric result anchors.
        unit_boxes, remaining = [], []
        for column, boxes in date_row.items():
            if not column:
                continue
            (unit_boxes if _matrix_value_unit(_text(boxes)) else remaining).extend(
                replace(box, matrix_column=column) for box in boxes)
        combined.extend(remaining)
        top = min(box.y for box in combined)
        # Each box keeps the membership computed in its original glyph band.
        # The merged height is only a vertical continuation aid; it cannot
        # shift a sparse/right-aligned value across a horizontal boundary.
        text_height = max(body[other].height for other in merges[index])
        output.append(_Line(sorted(combined, key=lambda box: box.x), top, text_height))
        if unit_boxes:
            top = min(box.y for box in unit_boxes)
            output.append(_Line(sorted(unit_boxes, key=lambda box: box.x), top, max(box.height for box in unit_boxes)))
    return sorted(output, key=lambda line: line.y)


def _matrix_candidates(matrix: _Matrix, body: list[_Line]) -> list[tuple[_Candidate, list[_Column]]]:
    candidates = []
    started = False
    suspended = False
    previous_rows: dict[int, _Candidate] = {}
    previous_line = None
    for full_line in _matrix_date_bands(matrix, body):
        line = _matrix_region(full_line, matrix.start, matrix.end)
        if not line.boxes:
            continue
        cells = _cells(line, matrix.columns)
        left = _text(cells.get(0, []))
        role = _role(left)
        right_tokens = [_text(boxes) for i, boxes in cells.items() if i and _text(boxes)]
        new_header_shape = (started and not left and right_tokens
                            and all(not _matrix_result_shaped(token) and not _matrix_value_unit(token)
                                    and not _date_shaped(token) for token in right_tokens))
        if suspended or new_header_shape:
            suspended = True
            candidates.append((_Candidate(cells=cells, lines=[line], reasons=["MATRIX_SECTION_BOUNDARY_UNCERTAIN"]), matrix.columns))
            previous_rows = {}
            previous_line = None
            continue
        if not started and role in {"unit_raw", "reference_intervals"}:
            matrix.context.append(line)
            for i in range(1, len(matrix.columns)):
                boxes = cells.get(i, [])
                if not _text(boxes):
                    continue
                if role == "unit_raw":
                    raw_unit = _text(boxes)
                    unit = _matrix_unit(raw_unit)
                    matrix.units.setdefault(i, []).append((unit or raw_unit, _matrix_unit_boxes(boxes, unit) if unit else boxes))
                else:
                    matrix.references.setdefault(i, []).extend(boxes)
            continue
        unit_cells = {i: _matrix_value_unit(_text(boxes)) for i, boxes in cells.items() if i}
        if (started and not left and unit_cells and all(unit_cells.values()) and previous_line is not None
                and line.y - (previous_line.y + previous_line.height) <= previous_line.height * 1.8):
            for i, unit in unit_cells.items():
                previous = previous_rows.get(i)
                if previous is None:
                    continue
                previous.lines.append(line)
                boxes = _matrix_unit_boxes(cells[i], unit)
                prior_unit = _text(previous.cells.get(2, []))
                if prior_unit and prior_unit != unit:
                    previous.reasons.append("CONFLICTING_MATRIX_UNITS")
                    if not previous.unit_hypotheses:
                        previous.unit_hypotheses.append((prior_unit, list(previous.cells.get(2, []))))
                    previous.unit_hypotheses.append((unit, boxes))
                    previous.cells.setdefault(2, []).extend(boxes)
                else:
                    previous.cells[2] = boxes
                previous.inherited_roles.discard("unit_raw")
            previous_line = line
            continue
        result_row = (_date_shaped(left) or not left) and any(i in cells for i in range(1, len(matrix.columns)))
        if not result_row:
            preserved = _Candidate(cells=cells, lines=[line], reasons=["NON_DATA_MATRIX_ROW_PRESERVED"])
            candidates.append((preserved, matrix.columns))
            previous_rows = {}
            previous_line = None
            continue
        started = True
        previous_rows = {}
        previous_line = line
        for i, analyte in enumerate(matrix.columns[1:], 1):
            columns = [_Column(analyte.label, "analyte_raw", analyte.x, analyte.end, analyte.boxes),
                       _Column(analyte.label, "result", analyte.x, analyte.end, []),
                       _Column("Units", "unit_raw", analyte.x, analyte.end, []),
                       _Column(matrix.columns[0].label, "clinical_time", matrix.columns[0].x, matrix.columns[0].end, []),
                       _Column("Reference range", "reference_intervals", analyte.x, analyte.end, [])]
            result_boxes = [replace(box, cell_locator=True) for box in cells.get(i, [])]
            time_boxes = [replace(box, cell_locator=True) for box in cells.get(0, [])]
            candidate = _Candidate(cells={0: analyte.boxes, 1: result_boxes, 3: time_boxes},
                                   lines=[*matrix.context, line], inherited_roles={"analyte_raw", "unit_raw", "reference_intervals"})
            original_result_regions = {box.source_rect for box in result_boxes if box.source_rect is not None}
            if original_result_regions and any(box.source_rect in original_result_regions
                                              for other, boxes in cells.items() if other not in {0, i} for box in boxes):
                candidate.reasons.append("MATRIX_RESULT_CELL_NOT_SEPARATED")
            # Preserve other actual cells as distinct source context. They are
            # not attached to the current result field or used as prior values.
            for other, boxes in sorted(cells.items()):
                if other in {0, i}:
                    continue
                candidate.cells[len(columns)] = boxes
                columns.append(_Column(matrix.columns[other].label, "other_matrix_result", matrix.columns[other].x,
                                       matrix.columns[other].end, boxes))
            units = matrix.units.get(i, [])
            distinct_units = list(dict.fromkeys(unit for unit, _ in units))
            if len(distinct_units) > 1:
                candidate.reasons.append("CONFLICTING_MATRIX_UNITS")
                candidate.unit_hypotheses = units
                candidate.cells[2] = [box for _, boxes in units for box in boxes]
            elif units:
                candidate.cells[2] = units[0][1]
            if matrix.references.get(i):
                reference_boxes = matrix.references[i]
                if _matrix_reference_shaped(_text(reference_boxes)):
                    candidate.cells[4] = reference_boxes
                else:
                    candidate.cells[len(columns)] = reference_boxes
                    columns.append(_Column("Reference range", "unsupported_matrix_reference", analyte.x, analyte.end, reference_boxes))
                    candidate.reasons.append("REFERENCE_MATRIX_TEXT_PRESERVED")
            if not left:
                candidate.reasons.append("MISSING_MATRIX_DATE")
            if _time_role(matrix.columns[0].label) == "unknown":
                candidate.reasons.append("UNKNOWN_CLINICAL_TIME_ROLE")
            candidates.append((candidate, columns))
            previous_rows[i] = candidate
    return candidates


def _name_continuation(previous: str, following: str) -> bool:
    """Accept visible linguistic wrapping cues; a new capitalized name is not one."""
    if not previous or not following:
        return False
    return (following[0].islower() or following.startswith(("(", ")", ",", "-", "–", "/"))
            or (previous.rstrip().endswith(",") and following in {"%", "‰"})
            or previous.count("(") > previous.count(")") or previous.rstrip().endswith(("-", "/"))
            or bool(re.search(r"(?:\bк|\bна|\bof|\bto|\band)\s*$", previous, re.I)))


def _candidate_boxes(candidate: _Candidate) -> list[_Box]:
    return [box for line in candidate.lines for box in line.boxes] + [box for boxes in candidate.cells.values() for box in boxes] + candidate.comments


def _source_text(candidate: _Candidate, page: dict) -> tuple[str, int | None]:
    boxes = _candidate_boxes(candidate)
    if not boxes:
        return page["text"], 1 if page["text"] else None
    lines = sorted({box.line for box in boxes if box.line is not None})
    if lines and not any(box.source_rect is not None for box in boxes):
        original = page["text"].splitlines(keepends=True)
        return "".join(original[lines[0] - 1:lines[-1]]), lines[0]
    source = []
    seen = set()
    for box in sorted(boxes, key=lambda box: (box.y, box.x)):
        original = box.source_text or box.text
        identity = (box.source_rect, original) if box.source_rect is not None else (box.line, box.x, original)
        if identity not in seen:
            source.append(original)
            seen.add(identity)
    return "\n".join(source), None


def _issue_single(candidate: _Candidate, columns: list[_Column], reasons: list[str], page: dict, version: dict,
           locator_kind: str, proposed_row: dict | None = None, alternatives: list[dict] | None = None) -> dict:
    raw_cells = []
    for index, boxes in sorted(candidate.cells.items()):
        anchors = _anchors(boxes, columns[index].role, page, version, locator_kind)
        raw_cells.append({"column": index, "role": columns[index].role, "column_label": columns[index].label,
                          "text": _text(boxes), "anchors": anchors if isinstance(anchors, list) else [anchors] if anchors else []})
    if candidate.comments:
        anchors = _anchors(candidate.comments, "comment", page, version, locator_kind)
        raw_cells.append({"column": None, "role": "comment", "column_label": "comment", "text": _text(candidate.comments),
                          "anchors": anchors if isinstance(anchors, list) else [anchors] if anchors else []})
    return {"page": page["page"], "source": page["source"], "raw_text": _source_text(candidate, page)[0],
            "raw_cells": raw_cells, "reason_codes": list(dict.fromkeys(reasons)),
            "alternatives": alternatives or [], "proposed_row": proposed_row}


def _issues(candidate: _Candidate, columns: list[_Column], reasons: list[str], page: dict, version: dict,
            locator_kind: str, proposed_row: dict | None = None, alternatives: list[dict] | None = None) -> list[dict]:
    """Keep complete oversized evidence as linked spans, never a truncated row."""
    raw_text, first_line = _source_text(candidate, page)
    issue = None
    bounded = (len(raw_text) <= MAX_ISSUE_TEXT and len(candidate.cells) + bool(candidate.comments) <= 32
               and len(alternatives or []) <= 16
               and all(index <= 32 and len(columns[index].label) <= 200 and len(_text(boxes)) <= MAX_ISSUE_TEXT
                       for index, boxes in candidate.cells.items())
               and len(_text(candidate.comments)) <= MAX_ISSUE_TEXT)
    if bounded:
        try:
            issue = _issue_single(candidate, columns, reasons, page, version, locator_kind, proposed_row, alternatives)
        except V2Error as exc:
            if exc.code != "LAYOUT_SOURCE_SPAN_LIMIT":
                raise
        if issue is not None and len(canonical(issue)) <= MAX_ISSUE_BYTES:
            return [issue]
    # The source is retained verbatim for native text and as original OCR block
    # strings for geometry. A fragment's broad line range/box is truthful; char
    # offsets describe this preserved stream, not invented PDF cell geometry.
    group_id = "layout_span_" + digest({"version_id": version["version_id"], "source_sha256": version["source_sha256"],
                                        "page": page["page"], "source": page["source"], "raw_text": raw_text})
    parts = [(start, raw_text[start:start + FRAGMENT_CHARS]) for start in range(0, len(raw_text), FRAGMENT_CHARS)] or [(0, "")]
    require(len(parts) <= MAX_ISSUES, "ISSUE_LIMIT", "A source span exceeds the document issue limit")
    boxes = [box for box in _candidate_boxes(candidate) if box.source_rect is not None]
    related = []
    if proposed_row:
        row_anchors = proposed_row["field_anchors"].get("result")
        row_anchors = row_anchors if isinstance(row_anchors, list) else [row_anchors] if row_anchors else []
        related = [anchor["locator"] for anchor in row_anchors]
    fragments = []
    for index, (start, content) in enumerate(parts, 1):
        stop = start + len(content)
        locator = {"kind": locator_kind, "page": page["page"]}
        if first_line is not None:
            line_start = first_line + raw_text[:start].count("\n")
            line_end = first_line + raw_text[:max(start, stop - 1)].count("\n")
            locator["line"] = line_start if line_start == line_end else f"{line_start}-{line_end}"
        elif boxes:
            locator["region"] = [max(0.0, min(box.source_rect[0] for box in boxes) / page["width"]),
                                 max(0.0, min(box.source_rect[1] for box in boxes) / page["height"]),
                                 min(1.0, max(box.source_rect[2] for box in boxes) / page["width"]),
                                 min(1.0, max(box.source_rect[3] for box in boxes) / page["height"])]
        else:
            # Empty unreadable source has no fabricated line, region or excerpt.
            locator = None
        anchors = [{"version_id": version["version_id"], "source_sha256": version["source_sha256"],
                    "field": "unresolved_source_span", "locator": locator, "excerpt": content, "inherited": False}] if content and locator else []
        link = {"kind": "ordered_source_fragment", "group_id": group_id, "index": index, "count": len(parts),
                "start_character": start, "end_character": stop, "previous_index": index - 1 if index > 1 else None,
                "next_index": index + 1 if index < len(parts) else None, "related_result_locators": related}
        fragment = {"page": page["page"], "source": page["source"], "raw_text": content,
                    "raw_cells": [{"column": None, "column_label": None, "role": "unresolved_source_span", "text": content, "anchors": anchors}],
                    "reason_codes": list(dict.fromkeys([*reasons, "SOURCE_SPAN_FRAGMENT"])),
                    "alternatives": [link], "proposed_row": None}
        require(len(canonical(fragment)) <= MAX_ISSUE_BYTES, "ISSUE_LIMIT", "A linked source fragment exceeds the bounded issue size")
        fragments.append(fragment)
    return fragments


def _propose_row(candidate: _Candidate, columns: list[_Column], metadata: dict, page: dict,
                 version: dict, locator_kind: str) -> tuple[dict | None, list[dict]]:
    roles: dict[str, list[_Box]] = {}
    for index, boxes in candidate.cells.items():
        roles.setdefault(columns[index].role, []).extend(boxes)
    raw = {role: _text(boxes) for role, boxes in roles.items()}
    reasons = list(candidate.reasons)
    alternatives = [{"kind": "source_unit_candidate", "unit_raw": unit,
                     "anchors": _anchors(boxes, "unit_raw", page, version, locator_kind)}
                    for unit, boxes in candidate.unit_hypotheses]
    analyte, raw_result = raw.get("analyte_raw", ""), raw.get("result", "")
    duplicate_roles = [role for role in set(column.role for column in columns)
                       if role not in {"prior_result", "other_matrix_result"}
                       and sum(column.role == role for column in columns) > 1]
    if duplicate_roles:
        reasons.append("AMBIGUOUS_COLUMNS")
    if not analyte:
        reasons.append("MISSING_ANALYTE")
    if not raw_result:
        reasons.append("MISSING_RESULT")
    unit = raw.get("unit_raw") or None
    # Native text can collapse adjacent unit/reference columns. Preserve the
    # candidate raw cell, but never allow a merged range or prose to pass as a
    # certain unit merely because its header was recognized.
    unit_ambiguous = bool(unit and not _is_unit(unit))
    if unit_ambiguous:
        reasons.append("UNIT_CELL_AMBIGUOUS")
    flag = raw.get("lab_flag_raw") or None
    result = _result(raw_result)
    result_boxes = roles.get("result", [])
    unit_boxes = roles.get("unit_raw", [])
    flag_boxes = roles.get("lab_flag_raw", [])
    # A uniquely separated suffix is retained as unit/flag. Multiple numeric
    # cells or an unrecognized suffix stay in an issue, never become no_result.
    if result is None and raw_result:
        qualitative_flag = re.fullmatch(r"(.+?)\s+([*↑↓]+|[HL])", raw_result)
        if qualitative_flag and _result(qualitative_flag[1]) is not None:
            result = _result(qualitative_flag[1])
            flag = " ".join(filter(None, (flag, qualitative_flag[2])))
            flag_boxes = [*flag_boxes, *result_boxes]
    if result is None and raw_result:
        match = INLINE_SCALAR.fullmatch(raw_result)
        if match:
            operator, number, suffix_flag, suffix_unit = match.groups()
            parsed_suffix_unit = _matrix_value_unit(suffix_unit) if suffix_unit else None
            if suffix_unit is None or parsed_suffix_unit:
                if suffix_unit and unit and parsed_suffix_unit != unit:
                    reasons.append("CONFLICTING_UNIT_CELLS")
                    alternatives.extend([
                        {"kind": "source_unit_candidate", "unit_raw": unit,
                         "anchors": _anchors(unit_boxes, "unit_raw", page, version, locator_kind)},
                        {"kind": "source_unit_candidate", "unit_raw": parsed_suffix_unit,
                         "anchors": _anchors(result_boxes, "unit_raw", page, version, locator_kind)},
                    ])
                else:
                    result = _result(raw_result[:match.end(2)].strip())
                    if suffix_unit and not unit:
                        unit = parsed_suffix_unit
                        unit_boxes = result_boxes
                    if suffix_flag:
                        flag = " ".join(filter(None, (flag, suffix_flag)))
                        flag_boxes = [*flag_boxes, *result_boxes]
            else:
                reasons.append("AMBIGUOUS_RESULT_SUFFIX")
    if result is None and raw_result:
        reasons.append("UNSUPPORTED_RESULT_TEXT")
    if unit and not _is_unit(unit):
        unit_ambiguous = True
        reasons.append("UNIT_CELL_AMBIGUOUS")
    for index, boxes in candidate.cells.items():
        if columns[index].role == "prior_result" and _text(boxes):
            prior_raw = _text(boxes)
            alternatives.append({"kind": "separate_prior_result", "column_label": columns[index].label,
                                 "result": _result(prior_raw) or {"kind": "text_unparsed", "raw": prior_raw},
                                 "clinical_time": _clinical(columns[index].label, "unknown"),
                                 "anchors": _anchors(boxes, "result", page, version, locator_kind)})
            reasons.append("PRIOR_RESULT_COLUMN_SEPARATED")
    if candidate.comments:
        reasons.append("ROW_COMMENT_CONTINUATION")
    if raw.get("unknown_column"):
        reasons.append("UNSUPPORTED_COLUMN_PRESERVED")
    confidence = [box.confidence for boxes in candidate.cells.values() for box in boxes if box.confidence is not None]
    if confidence and min(confidence) < .7:
        reasons.append("LOW_OCR_CONFIDENCE")
    fatal = {"AMBIGUOUS_COLUMNS", "MISSING_ANALYTE", "MISSING_RESULT", "UNSUPPORTED_RESULT_TEXT", "AMBIGUOUS_RESULT_SUFFIX", "CONFLICTING_UNIT_CELLS", "AMBIGUOUS_ROW_CONTINUATION", "CONFLICTING_MATRIX_UNITS", "MATRIX_RESULT_CELL_NOT_SEPARATED"}
    if fatal.intersection(reasons):
        return None, _issues(candidate, columns, reasons, page, version, locator_kind, alternatives=alternatives)
    limits = {"analyte_raw": 1000, "result": 4000, "clinical_time": 1000}
    if any(len(value) > limits.get(role, 4000) for role, value in raw.items() if role not in {"prior_result", "unknown_column"}):
        return None, _issues(candidate, columns, [*reasons, "SOURCE_FIELD_LIMIT"], page, version, locator_kind)
    row = {"analyte_raw": analyte, "mapping_status": "unmapped", "result": result, "unit_raw": unit,
           "clinical_time": {"raw": None, "role": "unknown", "precision": "unknown", "value": None},
           "reference_intervals": [], "specimen": None, "method": None, "lab_flag_raw": flag,
           "field_anchors": {}, "missing_reasons": {}, "field_status": {},
           "extraction_method": "local_ocr" if page["source"] == "vision_ocr" else "native_layout"}
    anchors = row["field_anchors"]
    anchors["analyte_raw"] = _anchors(roles["analyte_raw"], "analyte_raw", page, version, locator_kind,
                                       inherited="analyte_raw" in candidate.inherited_roles)
    anchors["result"] = _anchors(result_boxes, "result", page, version, locator_kind)
    if unit:
        anchors["unit_raw"] = _anchors(unit_boxes, "unit_raw", page, version, locator_kind,
                                       inherited="unit_raw" in candidate.inherited_roles and unit_boxes != result_boxes)
    if flag:
        anchors["lab_flag_raw"] = _anchors(flag_boxes, "lab_flag_raw", page, version, locator_kind)
    for field_name in ("specimen", "method", "clinical_time"):
        if raw.get(field_name):
            label = next(column.label for column in columns if column.role == field_name)
            row[field_name] = _clinical(raw[field_name], _time_role(label)) if field_name == "clinical_time" else raw[field_name]
            anchors[field_name] = _anchors(roles[field_name], field_name, page, version, locator_kind)
        elif field_name in metadata:
            row[field_name], source_boxes = metadata[field_name]
            anchors[field_name] = _anchors(source_boxes, field_name, page, version, locator_kind, inherited=True)
    reference = raw.get("reference_intervals")
    reference_scalar = SCALAR.fullmatch(reference.strip()) if reference else None
    simple_reference = bool(reference and (RANGE.fullmatch(reference.strip()) or
        (reference_scalar and reference_scalar[1]) or _fold(reference) in {
            "negative", "not detected", "absent", "trace", "отрицательный", "отрицательно", "не обнаружено", "не выявлено", "следы"}))
    reference_ambiguous = bool(reference and not simple_reference)
    if reference_ambiguous:
        reasons.append("REFERENCE_CELL_AMBIGUOUS")
    if reference:
        row["reference_intervals"] = [_reference(reference, unit)]
        anchors["reference_intervals"] = _anchors(roles["reference_intervals"], "reference_intervals", page, version, locator_kind,
                                                  inherited="reference_intervals" in candidate.inherited_roles)
    for field_name in ("unit_raw", "specimen", "method", "reference_intervals"):
        if not row[field_name]:
            row["missing_reasons"][field_name] = "not_reported"
    if unit_ambiguous and not reference:
        row["missing_reasons"]["reference_intervals"] = "ambiguous"
    clinical = row["clinical_time"]
    if clinical["precision"] == "unknown":
        row["missing_reasons"]["clinical_time"] = "ambiguous" if clinical["raw"] else "not_reported"
        if clinical["raw"]:
            reasons.append("UNKNOWN_CLINICAL_TIME")
    row["field_status"] = {field_name: "proposed" for field_name in anchors}
    if unit_ambiguous:
        row["field_status"]["unit_raw"] = "ambiguous"
        if not reference:
            row["field_status"]["reference_intervals"] = "ambiguous"
    if reference_ambiguous:
        row["field_status"]["reference_intervals"] = "ambiguous"
    if "REFERENCE_MATRIX_TEXT_PRESERVED" in reasons:
        row["field_status"]["reference_intervals"] = "ambiguous"
        row["missing_reasons"]["reference_intervals"] = "ambiguous"
    if clinical["precision"] == "unknown" and clinical["raw"]:
        row["field_status"]["clinical_time"] = "ambiguous"
    if "UNKNOWN_CLINICAL_TIME_ROLE" in reasons or "MISSING_MATRIX_DATE" in reasons:
        row["field_status"]["clinical_time"] = "ambiguous"
        if clinical["precision"] == "unknown":
            row["missing_reasons"]["clinical_time"] = "ambiguous"
    if confidence and min(confidence) < .7:
        for field_name in anchors:
            row["field_status"][field_name] = "ambiguous"
    row = lab_observation(row, version["version_id"], version["source_sha256"])
    issues = _issues(candidate, columns, reasons, page, version, locator_kind, row, alternatives) if reasons else []
    return row, issues


def _propose(candidate: _Candidate, columns: list[_Column], metadata: dict, page: dict,
             version: dict, locator_kind: str) -> tuple[dict | None, list[dict]]:
    try:
        return _propose_row(candidate, columns, metadata, page, version, locator_kind)
    except V2Error as exc:
        bounded_field = exc.code == "invalid_field" and "bounded non-empty string" in exc.message
        bounded_decimal = exc.code == "invalid_decimal" and "plain Decimal string" in exc.message
        if exc.code != "LAYOUT_SOURCE_SPAN_LIMIT" and not bounded_field and not bounded_decimal:
            raise
        # An oversized field is quarantined as evidence, not replaced by a
        # shortened value or a falsely typed observation. Document hard caps
        # retain their separate errors and are never caught here.
        context = [box for _, boxes in metadata.values() for box in boxes]
        preserved = _Candidate(cells=candidate.cells, lines=candidate.lines,
                               comments=[*candidate.comments, *context], reasons=candidate.reasons,
                               inherited_roles=candidate.inherited_roles, unit_hypotheses=candidate.unit_hypotheses)
        return None, _issues(preserved, columns, [*candidate.reasons, "SOURCE_FIELD_LIMIT"], page, version, locator_kind)


def propose_lab_rows(pages: list[dict], version: dict, *, locator_kind: str = "pdf") -> dict:
    """Propose whole lab rows or retain their raw source as unresolved issues.

    ``rows`` carry field_status=proposed regardless of extraction source. Issues
    can accompany a row (unknown time, low confidence, comment, prior values) or
    have proposed_row=null when the row cannot be safely structured. Missing
    result cells are issues; only explicit cancellation/nonperformance tokens
    may produce no_result. Count and page limits raise before a result returns.
    """
    require(isinstance(version, dict), "INVALID_LAYOUT", "Layout needs a registered document version")
    identifier(version.get("version_id"), "version_id")
    require(isinstance(version.get("source_sha256"), str) and SHA256_RE.fullmatch(version["source_sha256"]),
            "INVALID_LAYOUT", "Layout needs the original source SHA-256")
    require(locator_kind in {"pdf", "image"}, "INVALID_LAYOUT", "Layout locators must identify PDF or image")
    pages = _pages(pages)
    require(locator_kind != "image" or (len(pages) == 1 and pages[0]["page"] == 1), "INVALID_LAYOUT", "An image has exactly one page")
    rows, issues, processed, unprocessed = [], [], [], []
    source_candidates = 0
    for page in pages:
        lines = _lines(page)
        headers = [(index, table) for index in range(len(lines)) for table in _classic_headers(lines, index)]
        matrices = []
        for index in range(len(lines)):
            for matrix in _matrix_headers(lines, index):
                if any(index <= earlier.header_end and (earlier.end is None or matrix.start < earlier.end)
                       and (matrix.end is None or earlier.start < matrix.end) for _, earlier in matrices):
                    continue
                matrices.append((index, matrix))
        for index, matrix in _geometry_matrix_headers(lines):
            if any(start <= index <= existing.header_end and (existing.end is None or matrix.start < existing.end)
                   and (matrix.end is None or existing.start < matrix.end) for start, existing in matrices):
                continue
            matrices.append((index, matrix))
        matrices.sort(key=lambda item: item[0])
        boundaries = sorted({index for index, _ in [*headers, *matrices]})
        if not headers and not matrices:
            candidate = _Candidate(lines=lines)
            candidate.comments = [box for line in lines for box in line.boxes]
            issues.extend(_issues(candidate, [], ["TABLE_HEADER_UNRECOGNIZED" if lines else "NO_READABLE_LAYOUT"], page, version, locator_kind))
            unprocessed.append(page["page"])
            continue
        page_fatal = False
        page_rows = 0
        header_ends = {index: table.header_end for index, table in headers}
        for index, matrix in matrices:
            header_ends[index] = max(header_ends.get(index, index), matrix.header_end)
        header_lines = {index for start, end in header_ends.items() for index in range(start, end + 1)}
        first_header = boundaries[0]
        document_metadata = _metadata(lines, first_header)
        metadata_indices = {index for index, line in enumerate(lines) if index > first_header
                            and index not in header_lines and _metadata_line(line)}
        for index in sorted(metadata_indices):
            line = lines[index]
            boxes = line.boxes
            context_columns = [_Column("Source metadata", "source_metadata", min(box.x for box in boxes),
                                       max(box.x + box.width for box in boxes), boxes)]
            issues.extend(_issues(_Candidate(cells={0: boxes}, lines=[line]), context_columns,
                                  ["SOURCE_METADATA_CONTEXT"], page, version, locator_kind))
        for header_index, matrix in matrices:
            stop = next((index for index in boundaries if index > header_index), len(lines))
            body = [line for index, line in enumerate(lines[matrix.header_end + 1:stop], matrix.header_end + 1)
                    if index not in metadata_indices]
            candidates = _matrix_candidates(matrix, body)
            for candidate, columns in candidates:
                source_candidates += 1
                require(source_candidates <= MAX_ROWS, "ROW_LIMIT", "Layout exceeds 1000 whole source-row candidates")
                row, candidate_issues = _propose(candidate, columns, {}, page, version, locator_kind)
                if row:
                    rows.append(row)
                    page_rows += 1
                if candidate_issues:
                    issues.extend(candidate_issues)
                    page_fatal = page_fatal or row is None
            if not candidates:
                preserved = _Candidate(lines=matrix.context, comments=[box for line in matrix.context for box in line.boxes])
                issues.extend(_issues(preserved, [], ["TABLE_WITHOUT_SOURCE_ROWS"], page, version, locator_kind))
                page_fatal = True
        for header_index, table in headers:
            columns, header_end = table.columns, table.header_end
            stop = next((index for index in boundaries if index > header_index), len(lines))
            previous_header = max((index for index in boundaries if index < header_index), default=None)
            previous_end = header_ends[previous_header] if previous_header is not None else -1
            peers = [peer for index, peer in headers if index == header_index]
            metadata = (_parallel_metadata(lines, header_index, table, peers, first_header, previous_end,
                                           document_metadata, bool(metadata_indices)) if len(peers) > 1 else
                        _section_metadata(lines, header_index, first_header, previous_end, document_metadata,
                                          bool(metadata_indices)))
            analyte_index = next(index for index, column in enumerate(columns) if column.role == "analyte_raw")
            result_index = next(index for index, column in enumerate(columns) if column.role == "result")
            current: _Candidate | None = None
            candidates = []
            body = [region for index, line in enumerate(lines[header_end + 1:stop], header_end + 1)
                    if index not in metadata_indices and
                    (region := _matrix_region(line, table.start, table.end)).boxes]
            typical_height = median(line.height for line in body) if body else lines[header_index].height
            for line in body:
                if FOOTER.match(line.text.strip()):
                    if current:
                        candidates.append(current)
                        current = None
                    continue
                if COMMENT.match(line.text.strip()):
                    if current:
                        current.comments.extend(line.boxes)
                        current.lines.append(line)
                    else:
                        candidates.append(_Candidate(lines=[line], comments=line.boxes, reasons=["ORPHAN_COMMENT"]))
                    continue
                cells = _cells(line, columns)
                has_analyte = bool(_text(cells.get(analyte_index, [])))
                has_result = bool(_text(cells.get(result_index, [])))
                close = current is not None and line.y - (current.lines[-1].y + current.lines[-1].height) <= typical_height * 1.7
                current_result = bool(current and _text(current.cells.get(result_index, [])))
                if current is None:
                    current = _Candidate(cells=cells, lines=[line])
                elif has_analyte and has_result and current_result:
                    candidates.append(current)
                    current = _Candidate(cells=cells, lines=[line])
                elif has_result and not has_analyte and current_result and not (
                    close and _result(_text(current.cells[result_index])) is None
                    and _result(_text(current.cells[result_index]) + " " + _text(cells[result_index])) is not None
                ):
                    # A result-only second line could be another observation or
                    # an OCR split; never append two independent scalar results.
                    candidates.append(current)
                    current = _Candidate(cells=cells, lines=[line], reasons=["AMBIGUOUS_ROW_CONTINUATION"])
                elif has_analyte and not _name_continuation(_text(current.cells.get(analyte_index, [])), _text(cells[analyte_index])):
                    # A complete capitalized name may be an additional test with
                    # a blank result. Preserve it separately instead of silently
                    # swallowing it as a wrapped analyte from the preceding row.
                    candidates.append(current)
                    current = _Candidate(cells=cells, lines=[line])
                elif close and (not has_result or not current_result or _result(
                    _text(current.cells.get(result_index, [])) + " " + _text(cells.get(result_index, []))
                ) is not None):
                    for index, boxes in cells.items():
                        current.cells.setdefault(index, []).extend(boxes)
                    current.lines.append(line)
                    if has_analyte or has_result:
                        current.reasons.append("MULTILINE_ROW_PROPOSED")
                else:
                    candidates.append(current)
                    current = _Candidate(cells=cells, lines=[line])
            if current:
                candidates.append(current)
            for candidate in candidates:
                source_candidates += 1
                require(source_candidates <= MAX_ROWS, "ROW_LIMIT", "Layout exceeds 1000 whole source-row candidates")
                row, candidate_issues = _propose(candidate, columns, metadata, page, version, locator_kind)
                if row:
                    rows.append(row)
                    page_rows += 1
                if candidate_issues:
                    issues.extend(candidate_issues)
                    page_fatal = page_fatal or row is None
            if not candidates:
                issues.extend(_issues(_Candidate(lines=lines[header_index:header_end + 1], comments=lines[header_index].boxes),
                                      columns, ["TABLE_WITHOUT_SOURCE_ROWS"], page, version, locator_kind))
                page_fatal = True
        require(len(issues) <= MAX_ISSUES, "ISSUE_LIMIT", "Layout exceeds 1000 complete source issues")
        (unprocessed if page_fatal or page_rows == 0 else processed).append(page["page"])
    codes = sorted({reason for issue in issues for reason in issue["reason_codes"]})
    require(len(issues) <= MAX_ISSUES, "ISSUE_LIMIT", "Layout exceeds 1000 complete source issues")
    coverage = {"status": "partial" if issues else "complete", "expected_count": source_candidates if not unprocessed else None,
                "expected_count_basis": "extractor_count" if not unprocessed else "unknown", "processed_pages": processed,
                "unprocessed_pages": unprocessed, "errors": codes, "method": "local_ocr" if any(page["source"] == "vision_ocr" for page in pages) else "native_layout",
                "model": None, "provider": "v2-layout", "extractor_version": "2"}
    if not rows and unprocessed:
        coverage["status"] = "visual_required" if all(page["source"] == "pdf_text" for page in pages) else "partial"
    return {"rows": rows, "issues": issues, "coverage": coverage}
