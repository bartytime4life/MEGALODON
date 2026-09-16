"""Keep the hosted companion controls byte-identical to the packaged local HUD."""
from pathlib import Path
import runpy

root = Path(__file__).resolve().parents[1]
assets = runpy.run_path(str(root / "megalodon/dashboard_tool_assets.py"))
for key, filename in {
    "LIFECYCLE_JS": "lifecycle.js", "READINESS_JS": "readiness.js",
    "CONTROLS_JS": "controls.js", "CONTROLS_CSS": "controls.css",
}.items():
    (root / "site/dist" / filename).write_text(assets[key])
