"""Deterministic, fully fictional source fixtures for a production-chain exercise.

Authoritative labels are authored from the source specification, never from
recognition outputs. Importing this helper has no side effects. Generation is
allowed only into a new caller-owned temporary directory. It does not import
production recognition, parse PDFs, use a network, or touch runtime settings.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import textwrap


DEFAULT_FONT = Path.home() / Path(
    ".cache/codex-runtimes/codex-primary-runtime/dependencies/"
    "native/poppler/poppler/fonts/DejaVuSans.ttf"
)
SUBJECT = "SYNTHETIC-SUBJECT-CHAIN-001"
TITLE = "SYNTHETIC / ИСКУССТВЕННЫЙ"


def _numeric(name, raw, decimal, unit, ref, low=None, high=None, *, operator=None):
    result = {"kind": "numeric_censored" if operator else "numeric_exact",
              "raw": raw, "decimal": decimal}
    if operator:
        result["operator"] = operator
    reference = {"kind": "laboratory_reference", "raw": ref, "unit_raw": unit}
    if low is not None:
        reference.update(low=low, low_inclusive=True)
    if high is not None:
        reference.update(high=high, high_inclusive=True)
    return {"analyte_raw": name, "result": result, "unit_raw": unit,
            "reference_intervals": [reference], "purpose": "subject_observation"}


def _text(name, raw, kind, ref, *, unit=None, reason=None, control=False):
    result = {"kind": kind, "raw": raw}
    if kind in {"qualitative", "semiquantitative"}:
        result["text"] = raw
    if reason:
        result["reason"] = reason
    return {"analyte_raw": name, "result": result, "unit_raw": unit,
            "reference_intervals": [{"kind": "laboratory_reference", "raw": ref,
                                     "unit_raw": unit}],
            "purpose": "control_exclusion" if control else "subject_observation"}


def _control(name, unit="ммоль/л"):
    row = _numeric(name, "9,99", "9.99", unit, "8,0-12,0", "8.0", "12.0")
    row["purpose"] = "control_exclusion"
    return row


def specifications():
    """Return fresh immutable-by-convention specifications, independent of output."""
    return {
        "native_a": {
            "filename": "native_a.pdf", "laboratory": "Вымышленная лаборатория Лаб-А",
            "collected_raw": "15.01.2040", "collected_value": "2040-01-15",
            "reported_raw": "16.01.2040", "reported_value": "2040-01-16",
            "sections": [
                {"title": "Секция 1. Синтетическая биохимия", "column": "left",
                 "specimen": "Синтетическая сыворотка", "method": "Фотометрия М-01",
                 "rows": [
                     _numeric("Альфин", "5,4", "5.4", "мкмоль/л", "3,0-6,0", "3.0", "6.0"),
                     _numeric("Беталин", "12,0", "12.0", "µg/L", "8,0-15,0", "8.0", "15.0"),
                     _numeric("Гаммицин", "6,2", "6.2", "10⁹/л", "4,0-8,0", "4.0", "8.0"),
                     _numeric("Дельта-маркер", "<0,05", "0.05", "мкг/л", "<0,10", high="0.10", operator="<"),
                 ]},
                {"title": "Секция 2. Синтетические тесты", "column": "right",
                 "specimen": "Синтетическая моча", "method": "Полоски П-02",
                 "rows": [
                     _text("Эпсилон-тест", "не обнаружено", "qualitative", "не обнаружено"),
                     _text("Зета-полоска", "++", "semiquantitative", "отрицательно"),
                     _text("Эта-индекс", "не выполнено", "no_result", "0,0-2,0", unit="ед/л", reason="not_performed"),
                     _control("КОНТРОЛЬ К-01"),
                 ]},
            ]},
        "native_b": {
            "filename": "native_b.pdf", "laboratory": "Вымышленная лаборатория Лаб-Б",
            "collected_raw": "15.02.2040", "collected_value": "2040-02-15",
            "reported_raw": "16.02.2040", "reported_value": "2040-02-16",
            "sections": [
                {"title": "Секция 1. Синтетическая биохимия", "column": "left",
                 "specimen": "Синтетическая сыворотка", "method": "Фотометрия М-01",
                 "rows": [
                     _numeric("Альфин", "6,1", "6.1", "мкмоль/л", "3,5-6,5", "3.5", "6.5"),
                     _numeric("Беталин", "10,8", "10.8", "µg/L", "7,0-16,0", "7.0", "16.0"),
                     _numeric("Гаммицин", "7,3", "7.3", "10^9/л", "4,5-9,0", "4.5", "9.0"),
                     _numeric("Иота-маркер", ">2,5", "2.5", "нг/мл", "<1,5", high="1.5", operator=">"),
                 ]},
                {"title": "Секция 2. Синтетические тесты", "column": "right",
                 "specimen": "Синтетическая моча", "method": "Полоски П-02",
                 "rows": [
                     _text("Каппа-тест", "обнаружено", "qualitative", "не обнаружено"),
                     _text("Лямбда-полоска", "+", "semiquantitative", "отрицательно"),
                     _text("Мю-индекс", "не выполнено", "no_result", "0,0-3,0", unit="ед/л", reason="not_performed"),
                     _control("КОНТРОЛЬ К-02"),
                 ]},
            ]},
        "raster_c": {
            "filename": "photo_c.png", "laboratory": "Вымышленная лаборатория Лаб-В",
            "collected_raw": "неизвестна", "collected_value": None,
            "reported_raw": "20.03.2040", "reported_value": "2040-03-20",
            "sections": [
                {"title": "Синтетическая таблица С", "column": "full",
                 "specimen": "Синтетическая плазма", "method": "Тест С-03",
                 "rows": [
                     _numeric("Ню-маркер", "4,7", "4.7", "µmol/L", "4,0-6,0", "4.0", "6.0"),
                     _numeric("Кси-маркер", "220", "220", "мкг/л", "200-300", "200", "300"),
                     _numeric("Омикрон-счёт", "1,3", "1.3", "10¹²/л", "1,0-2,0", "1.0", "2.0"),
                     _numeric("Пи-маркер", "<=0,20", "0.20", "ng/mL", "<=0,50", high="0.50", operator="<="),
                     _text("Ро-тест", "отрицательно", "qualitative", "отрицательно"),
                     _text("Сигма-полоска", "+", "semiquantitative", "отрицательно"),
                     _text("Тау-индекс", "не выполнено", "no_result", "0,0-1,0", unit="ед/л", reason="not_performed"),
                     _control("КОНТРОЛЬ К-03"),
                 ]},
            ]},
    }


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _wrap(text, max_width, width_fn):
    lines, current = [], ""
    for word in str(text).split():
        candidate = f"{current} {word}".strip()
        if current and width_fn(candidate) > max_width:
            lines.append(current)
            current = word
        else:
            current = candidate
    return lines + [current]


def _region(box, width, height):
    return [round(box[0] / width, 6), round(box[1] / height, 6),
            round(box[2] / width, 6), round(box[3] / height, 6)]


def _labels(source_id, spec, section, row, n, regions, metadata, column_region):
    # These are semantic source labels, not production LabObservation records.
    result = dict(row["result"])
    refs = [dict(ref) for ref in row["reference_intervals"]]
    for ref in refs:
        if ref["raw"].startswith("<") and not ref["raw"].startswith("<="):
            ref["high_inclusive"] = False
    unknown_date = spec["collected_value"] is None
    return {
        "row_id": f"{source_id}:{section['column']}:{n:02d}", "source_id": source_id,
        "page": 1, "column": section["column"], "section": section["title"],
        "table_row": n, "purpose": row["purpose"],
        "analyte_raw": row["analyte_raw"], "result": result,
        "unit_raw": row["unit_raw"], "reference_intervals": refs,
        "clinical_time": {
            "raw": spec["collected_raw"],
            "role": "unknown" if unknown_date else "collected",
            "precision": "unknown" if unknown_date else "date",
            "value": spec["collected_value"],
        },
        "reported_time": {"raw": spec["reported_raw"], "role": "reported",
                          "precision": "date", "value": spec["reported_value"]},
        "specimen": section["specimen"], "method": section["method"],
        "expected_disposition": "exclude_control" if row["purpose"] == "control_exclusion" else "candidate_or_deferred_if_unsupported",
        "column_region": column_region, "field_regions": regions,
        "metadata_regions": metadata,
        "layout_reading_order": "column then top to bottom",
        "unit_missing_reason": "not_reported" if row["unit_raw"] is None else None,
    }


def _native_pdf(path, source_id, spec, font_path):
    from reportlab.pdfgen import canvas
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.lib.pagesizes import A4
    font = "ProductionFixtureSans"
    if font not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(font, str(font_path)))
    width, height = A4
    c = canvas.Canvas(str(path), pagesize=A4, invariant=1, pageCompression=0)
    c.setTitle(f"{TITLE} {source_id}")
    c.setAuthor("Synthetic fixture generator")
    c.setSubject("Entirely invented source; no real medical data")

    def text(x, top, value, size=9, color="#253445"):
        c.setFillColor(color)
        c.setFont(font, size)
        c.drawString(x, height - top, value)

    def box(x, top, w, h, color):
        c.setFillColor(color)
        c.rect(x, height - top - h, w, h, fill=1, stroke=0)

    margin, gap = 28, 18
    table_w = (width - margin * 2 - gap) / 2
    box(0, 0, width, 68, "#e7edf4")
    text(margin, 30, TITLE, 15, "#203951")
    text(margin, 49, "Все данные вымышлены. Источник для технической проверки.", 9)
    text(margin, 88, spec["laboratory"], 11)
    text(margin, 108, f"Субъект: {SUBJECT}", 8.7)
    text(margin, 129, f"Дата взятия: {spec['collected_raw']}", 9)
    text(margin, 146, f"Дата отчёта: {spec['reported_raw']}", 9)
    labels = []
    for i, section in enumerate(spec["sections"]):
        x = margin + i * (table_w + gap)
        text(x, 183, section["title"], 8.5)
        text(x, 204, f"Материал: {section['specimen']}", 8)
        text(x, 222, f"Метод: {section['method']}", 8)
        xs = [x, x + 87, x + 145, x + 193, x + table_w]
        header_top, header_h, row_h = 240, 32, 70
        box(x, header_top, table_w, header_h, "#dce6ed")
        headers = ["Показатель", "Результат", "Единица", "Референс"]
        for j, header in enumerate(headers):
            text(xs[j] + 4, header_top + 19, header, 7.4)
        meta = {
            "clinical_time": _region([margin, 117, 260, 134], width, height),
            "reported_time": _region([margin, 134, 260, 151], width, height),
            "specimen": _region([x, 192, x + table_w, 209], width, height),
            "method": _region([x, 210, x + table_w, 227], width, height),
        }
        col_region = _region([x, 167, x + table_w, header_top + header_h + 4 * row_h], width, height)
        for n, row in enumerate(section["rows"], start=1):
            top = header_top + header_h + (n - 1) * row_h
            box(x, top, table_w, row_h, "#fff0dd" if row["purpose"] == "control_exclusion" else ("#f2f5f7" if n % 2 == 0 else "#ffffff"))
            vals = [row["analyte_raw"], row["result"]["raw"], row["unit_raw"] or "-", row["reference_intervals"][0]["raw"]]
            regions = {}
            for j, val in enumerate(vals):
                size = 7.7
                lines = _wrap(val, xs[j + 1] - xs[j] - 8, lambda v: pdfmetrics.stringWidth(v, font, size))
                if row["purpose"] == "control_exclusion" and j == 0:
                    lines.extend(["не результат", "субъекта"])
                for k, line in enumerate(lines):
                    text(xs[j] + 4, top + 20 + k * 12, line, size)
                regions[["analyte_raw", "result", "unit_raw", "reference_intervals"][j]] = _region([xs[j], top, xs[j + 1], top + row_h], width, height)
            regions["row"] = _region([x, top, x + table_w, top + row_h], width, height)
            labels.append(_labels(source_id, spec, section, row, n, regions, meta, col_region))
        c.setStrokeColor("#b5c3cf")
        c.setLineWidth(0.5)
        c.rect(x, height - header_top - header_h - 4 * row_h, table_w, header_h + 4 * row_h, fill=0, stroke=1)
        for edge in xs[1:-1]:
            c.line(edge, height - header_top, edge, height - header_top - header_h - 4 * row_h)
        for n in range(5):
            yy = height - header_top - header_h - n * row_h
            c.line(x, yy, x + table_w, yy)
    text(margin, 636, "Справочные интервалы принадлежат только указанной вымышленной лаборатории.", 8)
    text(margin, 655, "КОНТРОЛЬ не является результатом субъекта. Символ '-' означает отсутствие единицы.", 8)
    text(margin, 788, "ИСКУССТВЕННЫЙ ИСТОЧНИК / Только техническая проверка", 8, "#617184")
    text(width - 80, 788, "Стр. 1 / 1", 8, "#617184")
    c.showPage()
    c.save()
    return labels, {"width": width, "height": height, "coordinate_unit": "pt", "pages": 1}


def _raster_png(path, source_id, spec, font_path):
    from PIL import Image, ImageDraw, ImageFont
    width, height = 1500, 1950
    image = Image.new("RGB", (width, height), "#f1eee8")
    draw = ImageDraw.Draw(image)
    draw.rectangle([36, 28, width - 30, height - 28], fill="#c8c5bf")
    draw.rectangle([29, 19, width - 39, height - 38], fill="#fffefd")
    fonts = {size: ImageFont.truetype(str(font_path), size) for size in (24, 26, 28, 30, 32, 40)}
    def text(x, top, value, size=28, color="#263547"):
        draw.text((x, top), value, fill=color, font=fonts[size])
    x0, x1 = 78, 1422
    draw.rectangle([x0, 57, x1, 160], fill="#e7edf4")
    text(98, 71, TITLE, 40)
    text(98, 125, "Все данные вымышлены. Синтетическая фотография таблицы.", 24)
    text(x0, 186, spec["laboratory"], 32)
    text(x0, 236, f"Субъект: {SUBJECT}", 28)
    text(x0, 283, f"Дата взятия: {spec['collected_raw']}", 28)
    text(810, 283, f"Дата отчёта: {spec['reported_raw']}", 28)
    section = spec["sections"][0]
    text(x0, 333, f"Материал: {section['specimen']}", 28)
    text(810, 333, f"Метод: {section['method']}", 28)
    text(x0, 383, section["title"], 30)
    xs = [x0, x0 + 430, x0 + 745, x0 + 955, x1]
    header_top, header_h, row_h = 443, 68, 135
    draw.rectangle([x0, header_top, x1, header_top + header_h], fill="#dce6ed")
    for j, val in enumerate(["Показатель", "Результат", "Единица", "Референс"]):
        text(xs[j] + 14, header_top + 17, val, 26)
    meta = {
        "clinical_time": _region([x0, 278, 760, 321], width, height),
        "reported_time": _region([810, 278, x1, 321], width, height),
        "specimen": _region([x0, 328, 770, 373], width, height),
        "method": _region([810, 328, x1, 373], width, height),
    }
    col_region = _region([x0, 375, x1, header_top + header_h + 8 * row_h], width, height)
    labels = []
    for n, row in enumerate(section["rows"], start=1):
        top = header_top + header_h + (n - 1) * row_h
        draw.rectangle([x0, top, x1, top + row_h], fill="#fff0dd" if row["purpose"] == "control_exclusion" else ("#f2f5f7" if n % 2 == 0 else "#fffefd"))
        vals = [row["analyte_raw"], row["result"]["raw"], row["unit_raw"] or "-", row["reference_intervals"][0]["raw"]]
        regions = {}
        for j, val in enumerate(vals):
            lines = _wrap(val, xs[j + 1] - xs[j] - 28, lambda v: draw.textlength(v, font=fonts[28]))
            if row["purpose"] == "control_exclusion" and j == 0:
                lines.append("не результат субъекта")
            for k, line in enumerate(lines):
                text(xs[j] + 14, top + 25 + k * 40, line, 28)
            regions[["analyte_raw", "result", "unit_raw", "reference_intervals"][j]] = _region([xs[j], top, xs[j + 1], top + row_h], width, height)
        regions["row"] = _region([x0, top, x1, top + row_h], width, height)
        labels.append(_labels(source_id, spec, section, row, n, regions, meta, col_region))
    for edge in xs:
        draw.line([(edge, header_top), (edge, header_top + header_h + 8 * row_h)], fill="#aebfce", width=2)
    for n in range(9):
        yy = header_top + header_h + n * row_h
        draw.line([(x0, yy), (x1, yy)], fill="#aebfce", width=2)
    draw.line([(x0, header_top), (x1, header_top)], fill="#aebfce", width=2)
    text(x0, 1642, "Дата взятия неизвестна. Дата отчёта не заменяет дату взятия.", 26)
    text(x0, 1704, "КОНТРОЛЬ не является результатом субъекта.", 26)
    text(x0, 1840, "ИСКУССТВЕННЫЙ ИСТОЧНИК / Только техническая проверка", 24)
    text(1250, 1840, "Стр. 1 / 1", 24)
    image.save(path, format="PNG", optimize=False)
    return labels, {"width": width, "height": height, "coordinate_unit": "pixel", "pages": 1,
                    "synthetic_photo_style": "paper on neutral background, no blur or distortion"}


def _image_only_pdf(path, image_path):
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import ImageReader
    from reportlab.lib.pagesizes import A4
    width, height = A4
    c = canvas.Canvas(str(path), pagesize=A4, invariant=1, pageCompression=0)
    c.setTitle(f"{TITLE} image_only_c")
    c.setAuthor("Synthetic fixture generator")
    c.setSubject("Image-only representation of a wholly fictional raster table")
    c.drawImage(ImageReader(str(image_path)), 0, 0, width=width, height=height)
    c.showPage()
    c.save()
    return {"width": width, "height": height, "coordinate_unit": "pt", "pages": 1,
            "image_only": True, "same_pixels_as": "photo_c"}


def scoring_policy():
    return {
        "schema": "synthetic-production-chain-scoring/1.0",
        "frozen_before_recognition": True,
        "row_matching": "source_id + page + column + analyte_raw; result-region overlap resolves duplicates",
        "row_denominator": "7 subject rows per representation; 28 across 4 representations; 21 unique logical subject rows",
        "controls": "4 printed controls across representations excluded from observation denominator; any accepted subject observation from a control is a false positive",
        "fields": {
            "analyte_raw": "Exact case-sensitive Cyrillic text after whitespace collapse; no invented canonical mapping required.",
            "result.kind": "Exact typed kind; unsupported cases must be explicitly deferred/pending and cannot be relabeled numeric_exact.",
            "result.raw": "Exact source text after whitespace collapse; no decimal, sign, censor, plus-sign or case loss.",
            "result.decimal": "Exact Decimal numeric equivalence of string; applies only to exact/censored numeric kinds.",
            "result.operator": "Exact printed censor relation; <= and Unicode less-or-equal may normalize only in typed operator; raw retains source.",
            "unit_raw": "Exact source typography after whitespace collapse; µ vs мк and exponent must be preserved; '-' is absent, not a unit.",
            "reference_intervals": "Own laboratory raw reference required; low/high and inclusivity scored when parser supplies typed bounds; no reference substituted across documents.",
            "clinical_time": "Printed collection date yields collected/date/value; explicit unknown collection stays unknown with no value. Report date may be separately captured as reported, never invented as collected.",
            "specimen": "Exact section metadata after whitespace collapse; no inheritance across spatial columns.",
            "method": "Exact section metadata after whitespace collapse; no inheritance across spatial columns.",
            "source_locator": "Must bind source hash, page 1 and correct column and overlap the frozen row/result region; metadata anchors must use own section or explicitly shared printed collection header.",
        },
        "denominators": "Per-field scores use only applicable subject rows; absent units and unknown dates use explicit absence tests rather than disappearing from scoring.",
        "defer_policy": "Safe unsupported states remain pending/deferred with named reason, raw source text and locator; they count as unsupported, not correct typed extraction, and cannot be repaired from golden labels.",
        "no_result_policy": "'не выполнено' is no_result, never zero. Preserve original raw and explicit pending if unsupported.",
        "semantic_review": "Golden labels are wholly fictional source truth, not proof of model quality, clinical validity or human review.",
        "history_expectations": [
            {"analyte_raw": "Альфин", "a": "5.4", "b": "6.1", "expected_delta": "0.7", "unit_code": "umol/L"},
            {"analyte_raw": "Беталин", "a": "12.0", "b": "10.8", "expected_delta": "-1.2", "unit_code": "ug/L"},
            {"analyte_raw": "Гаммицин", "a": "6.2", "b": "7.3", "expected_delta": "1.1", "unit_code": "10*9/L"},
        ],
        "history_preconditions": "Arithmetic expectations apply only after legitimate independent field review, matching known specimen/method and canonical analyte mapping; references remain source-specific. Censored, qualitative, semiquantitative, no-result and unknown-collection rows have no imputed arithmetic.",
    }


def generate_fixtures(output_dir, *, font_path=DEFAULT_FONT):
    """Create all sources and preauthored labels into a new private tmp namespace.

    The caller owns rendering/visual inspection and must freeze this complete
    bundle before any production recognition. Existing paths are rejected.
    """
    output_dir, font_path = Path(output_dir), Path(font_path)
    if output_dir.exists():
        raise FileExistsError(f"Fixture output must be a new namespace: {output_dir}")
    if not font_path.is_file():
        raise FileNotFoundError(f"Cyrillic/symbol font missing: {font_path}")
    output_dir.mkdir(parents=True)
    specs = specifications()
    rows, sources = [], []
    for source_id in ("native_a", "native_b"):
        spec = specs[source_id]
        labels, geometry = _native_pdf(output_dir / spec["filename"], source_id, spec, font_path)
        rows.extend(labels)
        sources.append({"source_id": source_id, "filename": spec["filename"],
                        "mime_type": "application/pdf", "content": "native text, two spatial columns",
                        "laboratory": spec["laboratory"], "geometry": geometry,
                        "expected_subject_rows": 7, "expected_control_rows": 1})
    spec = specs["raster_c"]
    labels, geometry = _raster_png(output_dir / spec["filename"], "photo_c", spec, font_path)
    rows.extend(labels)
    sources.append({"source_id": "photo_c", "filename": spec["filename"], "mime_type": "image/png",
                    "content": "synthetic photographed-table raster", "laboratory": spec["laboratory"],
                    "geometry": geometry, "expected_subject_rows": 7, "expected_control_rows": 1,
                    "logical_source_id": "raster_c"})
    geometry = _image_only_pdf(output_dir / "image_only_c.pdf", output_dir / spec["filename"])
    for original in labels:
        row = json.loads(json.dumps(original))
        row["source_id"] = "image_only_c"
        row["row_id"] = row["row_id"].replace("photo_c:", "image_only_c:", 1)
        rows.append(row)
    sources.append({"source_id": "image_only_c", "filename": "image_only_c.pdf", "mime_type": "application/pdf",
                    "content": "image only; same pixels as photo_c, no hidden OCR layer", "laboratory": spec["laboratory"],
                    "geometry": geometry, "expected_subject_rows": 7, "expected_control_rows": 1,
                    "logical_source_id": "raster_c"})
    _json(output_dir / "expected_rows.json", {"schema": "synthetic-source-truth/1.0",
          "synthetic": True, "subject_id": SUBJECT,
          "authorship": "Labels defined directly in fixture specifications before recognition; no extraction output consulted.",
          "coordinate_system": "normalized top-left x0,y0,x1,y1; image-only PDF normalized regions use stretched raster coordinates",
          "rows": rows})
    _json(output_dir / "scoring_policy.json", scoring_policy())
    _json(output_dir / "source_specifications.json", specs)
    contract = textwrap.dedent("""\
        # Frozen synthetic production-chain fixtures

        Every subject, analyte, laboratory, result, reference interval and method
        is invented. These are technical fixtures, never medical evidence.

        `native_a.pdf` and `native_b.pdf` are native-text, single-page Russian
        reports. Each has left and right spatial columns with four printed rows
        each, seven subject observations and one explicitly excluded control.
        The three shared invented numeric analytes have dates 15.01.2040 and
        15.02.2040, matching synthetic serum/method, differing laboratory
        references, Cyrillic micro prefixes, Latin micro sign and exponents.

        `photo_c.png` is a wholly generated camera-style page, not a photograph
        of a real report. `image_only_c.pdf` contains only that raster, with no
        hidden text/OCR layer. Each represents the same seven logical subject
        rows and one control. Its collection date is explicitly unknown; the
        separate report date must never be promoted to collection time.

        `expected_rows.json` is preauthored source truth including every printed
        row, page, column, normalized field regions and metadata regions.
        `scoring_policy.json` fixes fields, controls, applicable denominators,
        pending/defer treatment and conditional history arithmetic. Unknown and
        unsupported values must remain unknown/pending; golden labels must not
        be used to repair outputs or generate field-review receipts.

        `fixture_manifest.json` fixes SHA-256 values for every source and label
        file, the exact generator and font. The manifest's freeze_sha256 is the
        SHA-256 of its canonical UTF-8 JSON before that field is added. Verify
        hashes before and after execution. Do not mutate labels after seeing
        extraction output; any later fixture revision is a new namespace/run.

        Render all three PDFs locally and visually inspect complete pages
        before recognition. This visual check is artifact QA, not an extraction
        quality claim. Production PDF parsing uses the repository's mandatory
        nested parser policy; this generator invokes no recognition or decoder.
        No credentials, real source documents, host settings, medical sources,
        network calls or other chats are involved in authoring this bundle.
        """)
    (output_dir / "fixture_contract.md").write_text(contract, encoding="utf-8")
    files = [{"filename": path.name, "sha256": _sha(path), "bytes": path.stat().st_size}
             for path in sorted(output_dir.iterdir()) if path.is_file()]
    manifest = {"schema": "synthetic-fixture-manifest/1.0", "synthetic": True,
                "frozen_before_recognition": True, "fixture_revision": "chain-20261014-v1",
                "subject_id": SUBJECT, "sources": sources, "files": files,
                "generator_sha256": _sha(__file__), "font_sha256": _sha(font_path),
                "generator": "tests/v2/production_chain_fixtures.py", "font_basename": font_path.name,
                "printed_rows": 32, "subject_rows_by_representation": 28,
                "unique_logical_subject_rows": 21, "control_rows_by_representation": 4}
    encoded = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest["freeze_sha256"] = hashlib.sha256(encoded).hexdigest()
    _json(output_dir / "fixture_manifest.json", manifest)
    return manifest


def verify_manifest(output_dir):
    """Check the complete frozen bundle without parsing its sources."""
    output_dir = Path(output_dir)
    manifest = json.loads((output_dir / "fixture_manifest.json").read_text(encoding="utf-8"))
    freeze = manifest.pop("freeze_sha256")
    encoded = json.dumps(manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if hashlib.sha256(encoded).hexdigest() != freeze:
        raise ValueError("Frozen manifest checksum changed")
    for record in manifest["files"]:
        path = output_dir / record["filename"]
        if path.is_symlink() or not path.is_file() or _sha(path) != record["sha256"] or path.stat().st_size != record["bytes"]:
            raise ValueError(f"Frozen fixture mismatch: {record['filename']}")
    if _sha(__file__) != manifest["generator_sha256"]:
        raise ValueError("Fixture generator changed after freeze")
    manifest["freeze_sha256"] = freeze
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--font", type=Path, default=DEFAULT_FONT)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    result = verify_manifest(args.output_dir) if args.verify else generate_fixtures(args.output_dir, font_path=args.font)
    print(json.dumps({"freeze_sha256": result["freeze_sha256"], "sources": len(result["sources"]),
                      "subject_rows": result["subject_rows_by_representation"]}, sort_keys=True))
