"""Render finite technical explainers from public constants and a synthetic capture.

Documentation tooling only; requires Pillow and local DejaVu fonts. No runtime
imports, telemetry, network, executable examples or third-party image fetches.
Each GIF plays twice for 4.8 seconds total, then retains the final still. Every
frame keeps the same labels; only the focus outline moves. PNGs offer no-motion
alternatives. Colors and type follow the existing MEGALODON field guide.
"""
from pathlib import Path
import hashlib
import json

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'assets/docs'
FONT = Path('/usr/share/fonts/truetype/dejavu')
BG, PANEL, LINE = '#071923', '#102c39', '#365363'
INK, MUTED, CYAN, GOLD = '#e9f5fa', '#abc0cc', '#75e4dc', '#efc57a'
SIZE = (1200, 620)


def font(size, bold=False):
    return ImageFont.truetype(str(FONT / ('DejaVuSans-Bold.ttf' if bold else 'DejaVuSans.ttf')), size)


def canvas(kicker, title, subtitle):
    im = Image.new('RGB', SIZE, BG)
    d = ImageDraw.Draw(im)
    d.rectangle((44, 38, 50, 148), fill=CYAN)
    d.text((72, 37), kicker, font=font(18, True), fill=CYAN)
    d.text((72, 74), title, font=font(42, True), fill=INK)
    d.text((72, 132), subtitle, font=font(21), fill=MUTED)
    d.line((44, 554, 1156, 554), fill=LINE, width=2)
    d.text((44, 575), 'EXPLANATORY DIAGRAM  /  NO LIVE TELEMETRY  /  NO ACTION PERFORMED',
           font=font(17, True), fill=MUTED)
    return im, d


def card(d, box, label, title, lines, accent=CYAN):
    x, y, _, _ = box
    d.rounded_rectangle(box, radius=16, fill=PANEL, outline=LINE, width=2)
    d.text((x+18, y+18), label, font=font(15, True), fill=accent)
    d.text((x+18, y+51), title, font=font(23, True), fill=INK)
    for row, line in enumerate(lines):
        d.text((x+18, y+95+row*30), line, font=font(18), fill=MUTED)


def arrow(d, a, b):
    d.line((*a, *b), fill=LINE, width=3)
    x, y = b
    d.polygon(((x, y), (x-10, y-7), (x-10, y+7)), fill=CYAN)


def evidence():
    im, d = canvas('MEGALODON / EVIDENCE PATH', 'Follow the finding back.',
                   'Recorded observations, source qualification and review stay connected.')
    boxes = [(44+i*283, 219, 307+i*283, 439) for i in range(4)]
    labels = [
        ('01 / INPUT', 'Metadata', ['Typed fields', 'Bounded admission', 'No packet payload']),
        ('02 / ANALYSIS', 'Fixed rules', ['Three heuristics', 'Source + time scope', 'Review, not verdict']),
        ('03 / RETAIN', 'SQLite evidence', ['Event + finding', 'Ingestion receipt', 'Private local history']),
        ('04 / INSPECT', 'Local workspace', ['Linked inspector', 'History + reports', 'Gaps stay visible']),
    ]
    for box, data in zip(boxes, labels):
        card(d, box, *data)
    for i in range(3):
        arrow(d, (boxes[i][2]+3, 327), (boxes[i+1][0]-3, 327))
    d.text((44, 486), 'Observation time, detection time and projection time answer different questions.',
           font=font(22), fill=INK)
    return im, boxes


def model():
    im, d = canvas('MEGALODON / MODEL AUTHORITY', 'Advice has a boundary.',
                   'Runtime model selection and canonical Airlock acceptance are separate.')
    boxes = [(44, 207, 395, 418), (423, 207, 774, 418), (802, 207, 1156, 418)]
    card(d, boxes[0], 'ADMIT / BEFORE INVENTORY', 'Local provider checks',
         ['Literal loopback provider', 'Listener posture first', 'Selected model digest'])
    card(d, boxes[1], 'EXPLAIN / UNTRUSTED TEXT', 'Bounded model advice',
         ['Evidence context + limits', 'Closed proposal vocabulary', 'No generated command route'])
    card(d, boxes[2], 'DECIDE / SEPARATE WORKFLOW', 'Explicit operator action',
         ['Fixed workflow and scope', 'Independent authorization', 'Outcome and readback'], GOLD)
    arrow(d, (399, 310), (419, 310))
    # A separator, rather than an execution arrow, marks the authority boundary.
    d.line((788, 205, 788, 422), fill=GOLD, width=3)
    d.text((44, 462), 'Canonical Qwen record: UNBOUND / operator decision NOT_RECORDED',
           font=font(23, True), fill=GOLD)
    d.text((44, 506), 'A response is not evidence, provider containment, permission or successful execution.',
           font=font(21), fill=MUTED)
    return im, boxes


def recovery():
    im, d = canvas('MEGALODON / RECOVERY EVIDENCE', 'Changes are not recoverability.',
                   'AIDE observations and external backup receipts answer different questions.')
    boxes = [(44, 206, 395, 421), (423, 206, 774, 421), (802, 206, 1156, 421)]
    card(d, boxes[0], 'LOCAL / INTEGRITY', 'AIDE observation',
         ['Baseline + comparison', 'Change-category flags', 'No malicious attribution'])
    card(d, boxes[1], 'EXTERNAL / PINNED RECORDS', 'Receipt admission',
         ['Backup + isolated test', 'Separate operator trust', 'Digests, dates and expiry'])
    card(d, boxes[2], 'CURRENT / HOST RECOVERY', 'Restore stays held',
         ['restore_eligible = false', 'Conflicts not assessed', 'No host restore route'], GOLD)
    d.text((44, 465), 'Valid external records do not open a backup or establish a safe current-host restore.',
           font=font(22), fill=INK)
    d.text((44, 507), 'Audit-database restore and reference-library rollback are separate capabilities.',
           font=font(21), fill=MUTED)
    return im, boxes


def inspector():
    # Preserve the entire original capture; a separate caption strip prevents
    # annotations from replacing screenshot content or implying an interaction.
    capture = Image.open(OUT / 'finding-inspector-desktop.png').convert('RGB')
    im = Image.new('RGB', (1200, 960), BG)
    im.paste(capture.resize((1200, 833), Image.Resampling.LANCZOS), (0, 0))
    d = ImageDraw.Draw(im)
    d.text((28, 851), 'ANNOTATED STILL / historical synthetic browser capture / PR #654',
           font=font(20, True), fill=CYAN)
    d.text((28, 888), '1 Finding     2 Linked event     3 Ingestion receipt     4 Separate clocks',
           font=font(23), fill=INK)
    d.text((28, 928), 'Moving emphasis only. No live session or current-head UI acceptance.',
           font=font(17), fill=MUTED)
    boxes = [(40, 464, 402, 553), (412, 464, 775, 553), (785, 464, 1146, 553),
             (40, 566, 1147, 641)]
    return im, boxes


def save(name, render):
    base, boxes = render()
    frames = []
    for index in range(24):
        frame = base.copy()
        d = ImageDraw.Draw(frame)
        chosen = min(len(boxes)-1, index*len(boxes)//24)
        d.rounded_rectangle(boxes[chosen], radius=14, outline=CYAN, width=4)
        frames.append(frame)
    # All outlines in the static image disclose the complete diagram at once.
    still = base.copy()
    for box in boxes:
        ImageDraw.Draw(still).rounded_rectangle(box, radius=14, outline=CYAN, width=3)
    still.save(OUT / f'{name}.png', optimize=True)
    frames[0].save(OUT / f'{name}.gif', save_all=True, append_images=frames[1:],
                   duration=100, loop=1, optimize=True, disposal=1)


def main():
    for name, render in [('evidence-flow', evidence), ('model-authority', model),
                         ('recovery-evidence', recovery), ('finding-walkthrough', inspector)]:
        save(name, render)
    paths = sorted(p for p in OUT.iterdir() if p.stem in {
        'evidence-flow', 'model-authority', 'recovery-evidence', 'finding-walkthrough'})
    manifest = {'kind': 'public-documentation-explainers', 'schema': 1,
                'source_basis': '2cb706039724d9ea0bda09cbd3c17698b15ba55c',
                'capture_provenance': 'assets/docs/capture-provenance.json',
                'motion': 'Two 2.4-second plays, no flashes; labels stay visible.',
                'assets': {p.name: {'bytes': p.stat().st_size,
                                  'sha256': hashlib.sha256(p.read_bytes()).hexdigest()}
                           for p in paths}}
    (OUT / 'motion-provenance.json').write_text(json.dumps(manifest, indent=2)+'\n')


if __name__ == '__main__':
    main()
