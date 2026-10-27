"""Compose original synthetic screenshots with finite editorial motion.

This is a presentation of two historical stills, never a simulated interaction
or a recording of a currently running application. Requires Pillow/DejaVu.
"""
from pathlib import Path
import hashlib
import json

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets/docs"
BG, INK, MUTED, CYAN = "#071923", "#e9f5fa", "#abc0cc", "#75e4dc"
FONT = Path("/usr/share/fonts/truetype/dejavu")


def font(size, bold=False):
    return ImageFont.truetype(str(FONT / ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf")), size)


def main():
    im = Image.new("RGB", (1200, 900), BG)
    d = ImageDraw.Draw(im)
    d.text((44, 30), "MEGALODON / INVESTIGATION WORKSPACE", font=font(18, True), fill=CYAN)
    d.text((44, 70), "See the finding. Follow the evidence.", font=font(42, True), fill=INK)
    d.text((44, 130), "Two original synthetic browser views. One inspectable chain.", font=font(23), fill=MUTED)
    for name, width, x, y in [("finding-inspector-desktop.png", 840, 44, 191),
                              ("finding-inspector-mobile.png", 180, 976, 234)]:
        capture = Image.open(OUT / name).convert("RGB")
        height = round(width*capture.height/capture.width)
        d.rounded_rectangle((x-4, y-4, x+width+4, y+height+4), radius=6, fill="#365363")
        im.paste(capture.resize((width, height), Image.Resampling.LANCZOS), (x, y))
    d.text((44, 782), "RECORDED FINDING", font=font(16, True), fill=CYAN)
    d.text((345, 782), "LINKED EVENT", font=font(16, True), fill=CYAN)
    d.text((639, 782), "INGESTION RECEIPT", font=font(16, True), fill=CYAN)
    d.text((953, 782), "DISTINCT CLOCKS", font=font(16, True), fill=CYAN)
    d.line((44, 825, 1156, 825), fill="#365363", width=2)
    d.text((44, 856), "HISTORICAL STILLS / PR #654 / EDITORIAL MOTION ONLY / NO LIVE TELEMETRY", font=font(18, True), fill=MUTED)
    im.save(OUT / "workspace-reel.png", optimize=True)
    frames=[]
    for i in range(60):
        frame=im.copy(); draw=ImageDraw.Draw(frame)
        head=44+int(i/59*1112)
        draw.line((max(44,head-100),825,head,825),fill=CYAN,width=4)
        draw.ellipse((head-3,822,head+3,828),fill=INK)
        frames.append(frame)
    frames.append(im)
    frames[0].save(OUT / "workspace-reel.gif",save_all=True,append_images=frames[1:],
                   duration=[60]*60+[1200],optimize=True,disposal=1)
    sources={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in
             (OUT/"finding-inspector-desktop.png",OUT/"finding-inspector-mobile.png")}
    manifest={"schema":1,"kind":"historical-synthetic-screenshot-composition",
              "capture_candidate":"424d957472ad121becec635171bc281bec2de995",
              "capture_run":39180659477,"source_sha256":sources,
              "motion":"One 4.8-second play; no loop extension; final still retained.",
              "limits":["Editorial motion around stills, not a live interaction",
                        "Original captures resized proportionally without cropping",
                        "No current-head UI or installed-host acceptance"],
              "assets":{p.name:{"bytes":p.stat().st_size,"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
                        for p in (OUT/"workspace-reel.gif",OUT/"workspace-reel.png")}}
    (OUT/"workspace-reel-provenance.json").write_text(json.dumps(manifest,indent=2)+"\n")


if __name__ == "__main__":
    main()
