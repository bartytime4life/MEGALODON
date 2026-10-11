"""Render original Wiki diagrams (requires Pillow; no telemetry or network I/O)."""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "wiki"
INK, MUTED, CYAN, GOLD = "#e9f5fa", "#abc0cc", "#75e4dc", "#efc57a"
FONT = Path("/usr/share/fonts/truetype/dejavu")


def font(size, bold=False):
    return ImageFont.truetype(str(FONT / ("DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf")), size)


def canvas(kicker, title, subtitle):
    image = Image.new("RGB", (1600, 1000), "#081923")
    draw = ImageDraw.Draw(image)
    for x in range(0, 1600, 80):
        draw.line((x, 0, x, 1000), fill="#102733")
    for y in range(0, 1000, 80):
        draw.line((0, y, 1600, y), fill="#102733")
    draw.rectangle((70, 68, 78, 200), fill=CYAN)
    draw.text((105, 64), kicker, font=font(20, True), fill=CYAN)
    draw.text((105, 108), title, font=font(52, True), fill=INK)
    draw.text((105, 183), subtitle, font=font(24), fill=MUTED)
    return image, draw


def card(draw, box, number, title, lines, accent=CYAN):
    x, y, right, bottom = box
    draw.rounded_rectangle(box, radius=18, fill="#102c39", outline="#365363", width=2)
    draw.text((x+26, y+22), number, font=font(20, True), fill=accent)
    draw.text((x+26, y+62), title, font=font(29, True), fill=INK)
    for i, line in enumerate(lines):
        draw.text((x+26, y+115+i*36), line, font=font(23), fill=MUTED)


def arrow(draw, x1, y1, x2, y2, color=CYAN):
    draw.line((x1, y1, x2, y2), fill=color, width=4)
    draw.polygon(((x2, y2), (x2-12, y2-8), (x2-12, y2+8)), fill=color)


def architecture():
    image, draw = canvas("MEGALODON / SYSTEM DESIGN", "Evidence before action.",
                         "Local metadata becomes inspectable evidence; authority stays explicit.")
    card(draw, (70, 280, 510, 548), "01 / OBSERVE", "Bounded inputs",
         ["Packet metadata + offline logs", "Fixed collectors and source IDs", "Payloads stay outside core"])
    card(draw, (580, 280, 1020, 548), "02 / QUALIFY", "Deterministic core",
         ["Typed admission + fixed rules", "Private segmented SQLite", "Capacity + provenance limits"])
    card(draw, (1090, 280, 1530, 548), "03 / EXPLAIN", "Local visual HUD",
         ["Atlas, history and findings", "Source-separated visual reports", "Missing evidence stays visible"])
    arrow(draw, 516, 407, 570, 407)
    arrow(draw, 1026, 407, 1080, 407)
    card(draw, (70, 642, 765, 888), "SEPARATE / ADVICE", "Pinned local model",
         ["Bounded explanations and closed proposals", "No model-generated commands or execution"], GOLD)
    card(draw, (835, 642, 1530, 888), "SEPARATE / AUTHORITY", "Operator-reviewed workflows",
         ["Fixed actions + protected scopes + receipts", "Containment: preview, OS approval, expiry"], GOLD)
    draw.line((800, 576, 800, 610), fill=GOLD, width=3)
    draw.line((417, 610, 1182, 610), fill=GOLD, width=3)
    draw.line((417, 610, 417, 632), fill=GOLD, width=3)
    draw.line((1182, 610, 1182, 632), fill=GOLD, width=3)
    draw.text((70, 935), "Architecture illustration / no live telemetry / full boundaries in the Wiki", font=font(21), fill=MUTED)
    return image


def benchmark():
    import json
    data = json.loads((ROOT / "docs/benchmarks/efficient-recording-comparison.json").read_text())["cases"]
    before, after = data["before_packets"], data["after_packets"]
    reduction = 100*(1-after["os_write_bytes"]/before["os_write_bytes"])
    image, draw = canvas("MEGALODON / RECORDED ENGINEERING RESULT", "Write less. Keep the evidence.",
                         "October 1, 2026 / 10,000 synthetic packet records / one workstation")
    draw.text((90, 290), f"{reduction:.1f}%", font=font(110, True), fill=CYAN)
    draw.text((94, 418), "fewer OS-written bytes", font=font(30), fill=INK)
    draw.text((94, 463), "10,000 / 10,000 retained in each run", font=font(25), fill=MUTED)
    left, full = 690, 740
    for y, label, case, color in [(300, "Before", before, GOLD), (462, "Balanced", after, CYAN)]:
        draw.text((left, y), label, font=font(25, True), fill=INK)
        draw.rectangle((left, y+47, left+full, y+93), fill="#1b3543")
        length = max(14, round(full*case["os_write_bytes"]/before["os_write_bytes"]))
        draw.rectangle((left, y+47, left+length, y+93), fill=color)
        draw.text((left, y+104), f'{case["os_write_bytes"]:,} bytes', font=font(23), fill=MUTED)
    card(draw, (70, 685, 770, 890), "TRADEOFF / DISCLOSED", "History-query p95 increased",
         [f'{before["query_p95_ms"]:.2f} ms before / {after["query_p95_ms"]:.2f} ms Balanced'], GOLD)
    card(draw, (835, 685, 1530, 890), "SCOPE / FINITE", "A measured workload",
         ["No production accuracy or SSD lifetime claim"], CYAN)
    draw.text((70, 935), "Source: docs/benchmarks/efficient-recording-comparison.json / bars share one scale", font=font(21), fill=MUTED)
    return image


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for name, image in [("evidence-architecture.png", architecture()), ("recording-result.png", benchmark())]:
        image.save(OUT / name, optimize=True)
