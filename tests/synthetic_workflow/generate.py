"""Generate artificial PDF inputs. No actual person, facility or result is used."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


# Explicitly fictional analytes and values: these are format samples, not medical data.
DOCUMENTS = {
    "lab_panel.pdf": [
        ["SYNTHETIC TEST DOCUMENT - NOT MEDICAL DATA", "Panel Alpha", "Date: 2040-02-03",
         "Marker A: 12.4 unit-A", "Reference: 8.0 - 15.0 unit-A"],
        ["SYNTHETIC TEST DOCUMENT - PAGE 2", "Marker B: < 3.2 unit-B",
         "Comment: specimen and method not supplied"],
    ],
    "qualitative.pdf": [["SYNTHETIC TEST DOCUMENT - NOT MEDICAL DATA", "Qualitative test X",
                         "Date: 2040-03-04", "Result: indeterminate", "Method: fictional method Q"]],
    "exam_report.pdf": [["SYNTHETIC TEST DOCUMENT - NOT MEDICAL DATA", "Written examination report",
                         "Date: 2040-04-05", "Finding: fictional observation Z",
                         "Conclusion: simulated report only; no images provided"]],
    "other_sample.pdf": [["SYNTHETIC TEST DOCUMENT - NOT MEDICAL DATA", "Sample type: fictional sample Y",
                          "Date: 2040-05-06", "Result: cannot be read", "Method: not supplied"]],
}


def _escape(text: str) -> str:
    # These fixtures deliberately use ASCII: Helvetica has no embedded Unicode font.
    text.encode("ascii")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def make_pdf(pages: list[list[str]]) -> bytes:
    """Make a genuine, self-contained PDF 1.4 with a valid xref and text layer."""
    if not pages:
        raise ValueError("At least one page is required")
    objects: list[bytes] = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{4 + 2 * i} 0 R" for i in range(len(pages)))
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode())
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for i, lines in enumerate(pages):
        content_ref = 5 + 2 * i
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                       f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_ref} 0 R >>".encode())
        stream = ("BT /F1 14 Tf 48 740 Td 19 TL\n" +
                  "\n".join(f"({_escape(line)}) Tj T*" for line in lines) + "\nET\n").encode("ascii")
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"endstream")
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, item in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{i} 0 obj\n".encode() + item + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(output)


def generate(destination: Path) -> None:
    # Refuse to overwrite real files; the caller must provide a new directory.
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, pages in DOCUMENTS.items():
        with (destination / name).open("xb") as output:
            output.write(make_pdf(pages))
    manifest = {"origin": "artificial test fixtures; no real persons or results",
                "documents": {name: {"pages": pages} for name, pages in DOCUMENTS.items()}}
    with (destination / "expected.json").open("x", encoding="utf-8") as output:
        json.dump(manifest, output, ensure_ascii=False, indent=2)
        output.write("\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="Path to a new directory")
    generate(parser.parse_args().destination)
