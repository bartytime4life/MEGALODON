"""Render a finite documentation schematic; never read host or runtime data.

Requires Pillow and local DejaVu fonts. Motion illustrates record direction,
not measured throughput, network routes, a live UI session or acceptance.
"""
from pathlib import Path
import hashlib
import json

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets/docs"
SIZE = (1200, 700)
BG, PANEL, LINE = "#071923", "#102c39", "#365363"
INK, MUTED, CYAN, GOLD = "#e9f5fa", "#abc0cc", "#75e4dc", "#efc57a"
FONTS = Path("/usr/share/fonts/truetype/dejavu")


def font(size, bold=False):
    return ImageFont.truetype(str(FONTS / ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf")), size)


def render():
    im = Image.new("RGB", SIZE, BG)
    d = ImageDraw.Draw(im)
    for x in range(32, 1200, 40):
        for y in range(32, 700, 40):
            d.ellipse((x, y, x+1, y+1), fill="#17313e")
    d.rectangle((44, 40, 50, 149), fill=CYAN)
    d.text((72, 40), "MEGALODON / THE SIGNAL PATH", font=font(18, True), fill=CYAN)
    d.text((72, 77), "From an observation to a question you can answer.", font=font(34, True), fill=INK)
    d.text((72, 130), "A source-linked schematic of the metadata core. Every step keeps its limits.", font=font(21), fill=MUTED)
    stages = [
        ("01 / ADMIT", "Validate", ["Typed metadata", "Reviewed fields", "Bounded inputs"]),
        ("02 / ANALYZE", "Recognize a pattern", ["Three fixed heuristics", "Per-source windows", "Reviewable findings"]),
        ("03 / RETAIN", "Keep the evidence", ["Private SQLite", "Event + finding links", "Ingestion receipts"]),
        ("04 / REVIEW", "Inspect and explain", ["Finding inspector", "History and reports", "Source and time scope"]),
    ]
    for i, (label, title, lines) in enumerate(stages):
        x = 44+i*284
        d.rounded_rectangle((x, 216, x+260, 430), radius=18, fill=PANEL, outline=LINE, width=2)
        d.text((x+17, 237), label, font=font(16, True), fill=CYAN)
        d.text((x+17, 278), title, font=font(21, True), fill=INK)
        for row, line in enumerate(lines):
            d.text((x+17, 326+row*28), line, font=font(18), fill=MUTED)
    paths = []
    for i in range(3):
        x1, x2, y = 304+i*284, 328+i*284, 312
        d.line((x1, y, x2, y), fill=CYAN, width=2)
        d.polygon(((x2, y), (x2-7, y-4), (x2-7, y+4)), fill=CYAN)
        paths.append((x1, y, x2, y))
    d.line((174, 430, 174, 467), fill=GOLD, width=2)
    d.text((44, 480), "Invalid input is refused; a valid record does not authenticate its source.", font=font(22), fill=GOLD)
    d.rounded_rectangle((44, 533, 1156, 601), radius=14, fill=PANEL, outline=LINE)
    for x, title, detail in [(62, "SYN_FLOOD", "100 / 10 s"), (427, "PORT_SCAN", "20 ports / 5 s"), (792, "DNS_TUNNELING", "length >= 50")]:
        d.text((x, 544), title, font=font(17, True), fill=INK)
        d.text((x, 573), detail, font=font(16), fill=MUTED)
    d.text((44, 630), "DEFAULT RULES / SYNTHETIC MOTION / NO MALWARE VERDICT / NO LIVE TELEMETRY", font=font(17, True), fill=MUTED)
    d.text((44, 662), "Observation time, detection time and projection time remain separate.", font=font(18), fill=MUTED)
    return im, paths


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    still, paths = render()
    still.save(OUT / "signal-path.png", optimize=True)
    # Fixed labels and connected trajectories avoid flashing or implied UI actions.
    frames = []
    for index in range(60):
        frame = still.copy()
        d = ImageDraw.Draw(frame)
        for lane, (x1, y1, x2, y2) in enumerate(paths):
            progress = ((index/20)-lane/3) % 1
            x, y = x1+(x2-x1)*progress, y1+(y2-y1)*progress
            d.ellipse((x-3, y-3, x+3, y+3), fill=INK)
        # The moving trace is below the card labels, never over the evidence text.
        for lane in range(4):
            x = 61+lane*284
            head = int(((index/60+lane/4) % 1)*220)
            d.line((x, 409, x+head, 409), fill=CYAN, width=3)
        frames.append(frame)
    frames.append(still)
    frames[0].save(OUT / "signal-path.gif", save_all=True, append_images=frames[1:],
                   duration=[60]*60+[1200], optimize=True, disposal=1)
    manifest = {
        "schema": 1,
        "kind": "explanatory-metadata-schematic",
        "source_basis": "7c912322b12fe40fbe92de79b32fdc678054a3da",
        "motion": "One 4.8-second play; no loop extension; final still retained.",
        "limits": ["Not an application recording", "Not network routes or measured throughput",
                   "No host, model, sensor or private data read"],
        "assets": {p.name: {"bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                   for p in (OUT / "signal-path.gif", OUT / "signal-path.png")},
    }
    (OUT / "signal-path-provenance.json").write_text(json.dumps(manifest, indent=2)+"\n")


if __name__ == "__main__":
    main()
