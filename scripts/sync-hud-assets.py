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

snapshot = runpy.run_path(str(root / "megalodon/dashboard_snapshot.py"))
(root / "site/dist/snapshot.js").write_text(snapshot["SNAPSHOT_VALIDATOR_JS"] + snapshot["SNAPSHOT_HOSTED_JS"])

coverage = runpy.run_path(str(root / "megalodon/telemetry_catalog.py"))
index = root / "site/dist/index.html"
text = index.read_text()
start, end = '<!-- TELEMETRY_COVERAGE_START -->', '<!-- TELEMETRY_COVERAGE_END -->'
if start in text and end in text:
    a, b = text.index(start) + len(start), text.index(end)
    index.write_text(text[:a] + '\n' + coverage['coverage_html'](hosted=True) + '\n' + text[b:])
(root / "site/dist/telemetry.css").write_text(coverage['COVERAGE_CSS'])
