# Приватный whole-row preview

`health_analyzer.v2.preview` создаёт автономный локальный HTML на стандартной
библиотеке Python. Он не читает оригиналы, БД или ключи, не выполняет OCR и не
пишет review events, revisions или подтверждённые записи. Экспорт HTML — новый
файл с правами `0600`; существующий файл никогда не заменяется.

## API

```python
from health_analyzer.v2.preview import render_preview, export_preview, prepare_decisions

html = render_preview(bundles, title="Проверка строк", page_size=25)
metadata = export_preview(bundles, "/approved/private/output/new-preview.html")
proposal = prepare_decisions(bundle, decisions, visible_draft_ids=["draft_synthetic"])
```

Каждый bundle содержит:

```text
profile: {subject_id, label, group_id?: explicit local UI group}
document: {document_id, label}
snapshot: точный frozen prepare_review payload
snapshot_verification?: точный verification wrapper read-only backend reader
source_state: {
  subject_id, version_id, source_sha256,
  status: unchanged | changed | unavailable | unverified,
  observed_source_sha256: SHA | null,
  checked_at: ISO timestamp с timezone | null,
  archive_drift?: unchanged | changed | unavailable | not_checked
}
fragments: [fragment, ...]
document_fragments?: [source-bound header image, ...]
review_flags?: [{draft_id: existing ID | null, field: row field | null,
                code: identity_conflict | not_visually_supported | unresolved_reading,
                note: строка 1..2000 символов}, ...]
```

`source_state.status` относится к сохранённой версии байтов. Для `unchanged`
обязательны реально проверенный SHA, равный snapshot source SHA, и время
проверки; для `changed` наблюдаемый SHA отличается. Presenter проверяет
согласованность этих данных, но самостоятельно файл не открывает. Изменение
архива отображается отдельно: сохранная immutable копия не становится
повреждённой лишь из-за изменения другого архивного файла.

Каждый fragment явно связан со snapshot и существующим field anchor:

```text
subject_id, version_id, source_sha256, snapshot_id, snapshot_sha256,
draft_id, field, anchor_index: 0-based, locator: точно как в anchor.locator
kind: literal_anchor_excerpt
text: точная anchor.excerpt
provenance: {kind: source_anchor, receipt_id: string | null}
```

Либо изображение:

```text
те же поля scope и locator
kind: image_crop
mime: image/png | image/jpeg
data_base64: канонический base64 фактических переданных bytes
provenance: {kind: local_source_render | model_reported, receipt_id: string | null}
```

Необязательный `quality` — `{status: readable | degraded | unknown, notes?: str}`.
Числовая confidence не является вероятностью правильного чтения и не принимается.
Presenter вычисляет SHA переданных asset bytes. Объявленный `local_source_render`
или переданный receipt ID сохраняют своё происхождение; presenter не доказывает,
что crop получен именно из оригинала, и не создаёт человеческую отметку.
Выдержки явно называются «Извлечённый текст»; это не пиксели оригинала.
Fragment не принимает путь, URL, SVG, HTML или произвольные дополнительные поля.
Compressed image ограничен 5 MiB; PNG IHDR и JPEG SOF проверяются без декодера:
максимальная сторона 12000 pixels, площадь 40 миллионов pixels. PNG IHDR CRC
и dimension-bearing JPEG frame обязательны. PNG chunk lengths/CRCs проверяются,
IDAT обязателен, а APNG animation chunks отклоняются. Это ограничение ресурсов браузера,
а не доказательство pixel derivation или клинической правильности.

`document_fragments` — максимум 20 image assets на snapshot для сверки шапки.
Сохраняются те же subject/version/source SHA/snapshot ID/SHA bindings, `page`
1..500, `region` с normalized source coordinates `[x0,y0,x1,y1]`,
`purpose=identity_header|document_header` и те же image mime/base64/provenance/
quality. Здесь нет `draft_id`, `field`, `locator`, OCR text либо выдуманного row
anchor. Шапка показывается отдельно и не устанавливает факт личности или
совпадение человека с профилем; имеющийся identity conflict блокируется
явным `review_flags` и не разрешается наличием изображения.

## Привязка и неопределённость

Caller обязан получить snapshot через проверенный `SignedStore` либо другой
явно проверенный read-only export. Presenter сверяет
`digest({k: v for k, v in snapshot.items() if k != "snapshot_sha256"})` с SHA,
lineage каждого draft, профиль, version/source SHA, run, row order, anchors и
fragment scope. SHA здесь — content binding, не проверка store HMAC,
достоверности OCR, медицинского смысла или человеческого решения. При будущем
commit существующий backend повторно проверяет реальный persisted snapshot,
текущую selection, source bytes и row/revision tokens.

`snapshot_verification` копируется точно из `get_review_snapshot(...).verification`:
`{method: signed_store_hmac, checked_at, state: current|stale, reasons,
snapshot_sha256, source_bytes_checked: false, clinical_validation: not_provided}`.
SHA обязан совпадать с frozen snapshot. Current имеет пустой reasons; stale —
известные причины изменения extraction selection/run, review state или observation
revision. Отсутствующий или stale wrapper блокирует предложение принять, но
сохраняет возможность defer/reject/request_correction. Wrapper передаётся caller
как результат backend: presenter не аутентифицирует его самостоятельно и не имеет
HMAC keys. Source bytes проверяются отдельно через `source_state`; HMAC/freshness
не являются доказательством OCR или медицинской правильности. Wrapper сохранён
отдельно в PROPOSED packet и не повышает `confirmation_assurance=none`.

Необязательный `profile.group_id` — явный UI tag вызывающей стороны для двух
авторизованных людей, когда их snapshots хранятся в разных test namespaces.
Одинаковый group_id требует одинаковый label. Presenter не выводит личность из
содержимого и не объединяет namespaces: каждый bundle и proposal сохраняет точный
`subject_id`. `profile_group_id` добавляется отдельно к предложению; document key
всегда включает subject/version. Метаданные экспорта отдельно считают UI profiles
и subject_namespaces. Такой group tag не является удостоверением личности.

Поля не меняются: raw strings, tagged result и отдельные Decimal strings,
date role/precision, каждый исходный референс, population/context,
method/specimen, статусы, missing reasons и inherited anchors сохранены.
Полный frozen snapshot доступен целиком. Coverage отображается из snapshot;
ожидаемое число `null` и необработанные страницы не скрываются.

Неясное поле/mapping, неразобранный результат, пустой no-result, source integrity
`changed/unavailable/unverified`, source-review flag или degraded material
fragment блокируют предложение принять. Требуются фрагменты доступных material
anchors: analyte, result, unit, clinical time, reference intervals. Отсутствующие
method/specimen не превращаются в известные и не требуют выдуманного crop.
`review_flags` — аннотации сверки источника, не клиническое подтверждение.
Document flag с `draft_id=null` блокирует все строки своего frozen snapshot.

## Решения и приватность

По умолчанию показываются 25 целых строк, максимум 100. Существующие snapshots
по 100 строк можно проходить несколькими экранами; большие документы передаются
несколькими snapshots. Навигация разделяет профили, документ/версию, snapshot и
страницу источника. Ни один asset или source fragment не обрезается молча.

Выбор изначально пуст. «Выбрать только показанные строки» — явный выбор текущего
экрана. Подготовка группового решения действует только на выбранные видимые IDs.
Экспортируемый JSON имеет `state=PROPOSED`, `confirmation_assurance=none` и
schema `health-analyzer.preview-decisions/1.0`; это не review event и не backend
commit request. Он связывает subject/document/version/source SHA/run/selection,
snapshot ID/SHA, visible IDs, selected IDs, source_state/review_flags и действия.
Поддержаны предложения `confirm`, `reject`, `defer`, `request_correction`.
Последнее сохраняет plain-language `correction_note` без выдуманного typed patch:
caller готовит новый review после разбора исправления в приватном чате.

HTML не вызывает backend, model, сеть или сервер; нет localStorage, eval,
произвольного чтения файлов либо внешних ресурсов. CSP запрещает внешние
соединения; разрешены только inline script/style с точными SHA и переданные
PNG/JPEG data URLs. OCR, документы, labels, notes и script-closing tags всегда
экранируются, а динамический UI использует `textContent`.
Изображение включается один раз в своём inline `img` data URL с lazy decoding;
UI JSON manifest сохраняет его scope/provenance/quality/SHA, а не второй base64.
Все frozen snapshots/typed fields сохранены целиком. UI manifest — проекция для
навигации, не замена исходного source-bound bundle для повторной API validation.
Browser UI блокирует предложение принять, пока каждый material image выбранных
строк и переданная шапка документа не завершили decoding (`complete` и
`naturalWidth > 0`). При необходимости preparation запускает eager load уже
встроенных data URLs, без сети. Load/error события отменяют связанный prepared
packet; decode failure помечается и блокирует соответствующую строку/документ.
Python `prepare_decisions` выполняет только structural codec checks, не полный
image decode; оно не объявляет пиксели подтверждёнными или медицински проверенными.
Оригиналы/история immutable, подтверждено этой страницей всегда 0. Предложение
передаётся в приватный чат для отдельного решения и существующего backend path.
HTML содержит приватные данные: хранить и открывать его в согласованном локальном
private output; синтетический preview и fixtures не содержат PHI.

## Проверка

Точечный regression suite: `tests/v2/test_preview.py`. Проверяет раздельные
профили и version lineage, изменение frozen snapshot, неверные anchors,
unsafe assets/XSS/CSP, missing fragments, ambiguity/identity/source blockers,
явную subset scope, неизменность исходного bundle, лимиты 25/100, private
exclusive export и независимость archive drift от saved-copy integrity.
