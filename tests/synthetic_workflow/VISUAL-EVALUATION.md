# Visual reading exercise

Date: 2026-11-10.

This independent, manual model-vision exercise used only artificial fixtures.
From the repository root, the fixture generator created a new temporary folder:

```sh
python3 tests/synthetic_workflow/generate.py /absolute/new/temporary-folder
```

Each PDF page was rendered to PNG at 120 dpi with Poppler `pdftoppm`. The model
inspected the rendered page images and recorded a page-by-page transcription
before opening the generator's `expected.json`. Only afterward was the recorded
transcription compared with that oracle. The test used the visual images, not
PDF text extraction, to prepare the transcription.

All four generated PDFs were inspected, comprising five pages. The recorded
transcription matched **23 of 23 expected lines**. This included the printed
inequality, units, an indeterminate qualitative result, and statements that a
method or underlying examination images were unavailable.

This is a single small, informal exercise, not an automated model benchmark or
clinical validation. The documents contain large, clear English text with
invented markers and simple layouts. The words indicating an unreadable result
were themselves legible; they do not test an actually blurred or illegible
source. The exercise does not establish performance on real reports, complex
tables, Cyrillic text, photographs, low-quality scans, handwriting, or missing
pages. It does not test patient selection, archival persistence, the installed
Codex plugin, public source retrieval, medical interpretation, or clinician review.
No real patient information or medical records were used.
