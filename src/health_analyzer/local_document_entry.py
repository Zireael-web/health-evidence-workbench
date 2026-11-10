"""Fixed source/installed-package entry for bounded local document workers."""
from pathlib import Path
import runpy
import sys

# Isolated Python deliberately ignores PYTHONPATH. Add only this trusted
# package location; no source-file path or caller-selected code is executed.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
runpy.run_module("health_analyzer.local_documents", run_name="__main__")
