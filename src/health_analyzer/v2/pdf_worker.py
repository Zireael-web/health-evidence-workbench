"""Relocatable isolated entrypoint for the existing bounded PDF parser."""
from pathlib import Path
import sys

# Only this checkout/package root is added, never cwd or a caller-provided path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from health_analyzer.ingest.pypdf_worker import main

if __name__ == "__main__":
    raise SystemExit(main())
