"""Isolated entrypoint in source checkouts and noneditable installations."""
from pathlib import Path
import sys

# The package's trusted library root, not cwd, env or a caller-specified path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from health_analyzer.v2.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
