"""Public-only plugin launcher. No automatic installation or live defaults."""
from pathlib import Path
import os
import sys

# A deployment-rendered MCP entry should pin its interpreter. This optional
# explicit override makes the portable template work when python3 lacks MCP.
# It is a runtime path, never a credential or a legacy namespace default.
selected_python = os.environ.get("HEALTH_ANALYZER_V2_PYTHON")
if selected_python:
    candidate = Path(selected_python)
    if not candidate.is_absolute() or not candidate.is_file() or selected_python.startswith("${"):
        print('{"error":{"code":"runtime_unavailable","message":"HEALTH_ANALYZER_V2_PYTHON must be an explicit interpreter path"}}', file=sys.stderr)
        raise SystemExit(2)
    if candidate.resolve() != Path(sys.executable).resolve():
        os.execv(str(candidate), [str(candidate), "-I", "-B", str(Path(__file__).resolve())])

source_root = os.environ.get("HEALTH_ANALYZER_V2_CODE_ROOT")
config = os.environ.get("HEALTH_ANALYZER_V2_CONFIG")
if not source_root or not config or source_root.startswith("${") or config.startswith("${"):
    print('{"error":{"code":"configuration_required","message":"Configure explicit HEALTH_ANALYZER_V2_CODE_ROOT and HEALTH_ANALYZER_V2_CONFIG"}}', file=sys.stderr)
    raise SystemExit(2)
root = Path(source_root).resolve()
if not (root / "src/health_analyzer/v2/cli.py").is_file():
    print('{"error":{"code":"runtime_unavailable","message":"Configured source root does not contain the v2 runtime"}}', file=sys.stderr)
    raise SystemExit(2)
sys.path.insert(0, str(root / "src"))
from health_analyzer.v2.cli import main

raise SystemExit(main(["--config", config, "serve", "--zone", "public-research", "--transport", "stdio"]))
