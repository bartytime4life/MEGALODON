"""A manifest too large for one request, such as a memory capture's, leaves the machine in pieces and is checked whole."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from megalodon import evidence, fleet
from megalodon import evidence_shipping as shipping
from test_evidence_shipping import Machine, unseal
from test_fleet import collector, machine  # noqa: F401

NOW = "2026-11-20T22:00:00Z"


def capture(web, name, *, regions=6000):
    """A sealed bundle whose manifest describes thousands of memory regions, as a capture's does."""
    base = web.bundles / name
    base.mkdir(parents=True)
    content = os.urandom(5000)
    (base / "regions.bin").write_bytes(content)
    manifest = dict(schema=evidence.SCHEMA, kind="memory", collected_at="2026-11-20T12:00:00Z",
                    files=[dict(file="regions.bin", size=len(content), sha256=hashlib.sha256(content).hexdigest())],
                    regions=[dict(start=f"{0x7f0000000000 + i * 4096:x}", end=f"{0x7f0000001000 + i * 4096:x}",
                                  perms="r-xp", path=f"/usr/lib/x86_64-linux-gnu/libexample-{i}.so.1.2.3")
                             for i in range(regions)])
    (base / "manifest.json").write_text(json.dumps(manifest))
    evidence._seal(base)
    return base, content


def test_a_manifest_too_large_for_one_request_arrives_whole_and_its_files_follow(collector, tmp_path):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    base, content = capture(web, "20261120T120000Z")
    raw = (base / "manifest.json").read_bytes()
    assert len(base64.b64encode(raw)) > shipping.MAX_BATCH_BYTES and len(raw) > shipping.CHUNK, \
        "larger than one request, and more than one piece"
    result = web.push()
    assert (result["manifests"], result["large_manifests"], result["too_large"]) == (1, 1, 0)
    assert (result["files_completed"], result["bundles_incomplete"]) == (1, 0), "its file followed in the same push"
    held = shipping.held(data, "web-1")
    copy = Path(held["bundles"][0]["path"])
    assert (copy / "manifest.json").read_bytes() == raw and (copy / "regions.bin").read_bytes() == content
    # Gone from the machine, still provable on the collector.
    unseal(base)
    for path in sorted(base.rglob("*"), reverse=True):
        path.unlink()
    assert shipping.verify(data, "web-1")["bundles"] == [dict(bundle="20261120T120000Z", intact=True, problems=[])]
    assert web.push()["requests"] == 0, "nothing is sent twice"
    usage = json.loads((shipping._store(data, "web-1") / "usage.json").read_text())["bytes"]
    assert usage == len(raw) + len(content), "each byte counted once, though the manifest came in pieces"


def test_an_interrupted_manifest_resumes_from_where_the_collector_stands(collector, tmp_path, monkeypatch):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    base, _ = capture(web, "b1")
    monkeypatch.setattr(shipping, "MAX_REQUESTS", 1)
    first = web.push()
    assert (first["requests"], first["manifests"], first["bundles_incomplete"]) == (1, 0, 1), "one piece only"
    (web.dir / "cursor.json").unlink()                   # lost: the collector says where the manifest stands
    monkeypatch.setattr(shipping, "MAX_REQUESTS", 400)
    second = web.push()
    assert (second["manifests"], second["bundles_incomplete"]) == (1, 0)
    assert shipping.held(data, "web-1")["findings"] == [] and shipping.verify(data, "web-1")["bundles"][0]["intact"]


def parts(raw, digest=None, size=None):
    digest = digest or hashlib.sha256(raw).hexdigest()
    return [dict(kind="manifest_part", bundle="b1", sha256=digest, size=size or len(raw), offset=offset,
                 data=base64.b64encode(raw[offset:offset + shipping.CHUNK]).decode())
            for offset in range(0, len(raw), shipping.CHUNK)]


def store(tmp_path):
    folder = tmp_path / "store"
    folder.mkdir()
    return folder, shipping._Usage(folder)


def big_manifest(extra=""):
    return json.dumps(dict(schema=evidence.SCHEMA, collected_at=NOW, files=[], note=extra,
                           regions=["x" * 200] * 3000)).encode()


def test_pieces_that_do_not_make_the_manifest_they_claim_are_refused(tmp_path):
    folder, usage = store(tmp_path)
    raw = big_manifest()
    forged = parts(raw, digest="0" * 64)
    answers = [shipping._take_manifest_part(folder, item, NOW, usage) for item in forged]
    assert answers[-1] == dict(ok=False, have=0, error="the pieces do not make the manifest they were sent as: "
                                                       "send it again")
    assert not (folder / "evidence/b1/manifest.json").exists() and not (folder / "evidence-partial/b1/manifest.json").exists(), \
        "nothing is held: neither a manifest nor its pieces"
    assert [a["ok"] for a in (shipping._take_manifest_part(folder, i, NOW, usage) for i in parts(raw))][-1], \
        "sent again honestly, it is taken"
    assert (folder / "evidence/b1/manifest.json").read_bytes() == raw


def test_pieces_arrive_in_order_and_a_new_manifest_starts_over(tmp_path):
    folder, usage = store(tmp_path)
    first, second = big_manifest("one"), big_manifest("two")
    a = parts(first)
    assert shipping._take_manifest_part(folder, a[1], NOW, usage) == dict(ok=False, have=0,
                                                                          error="pieces arrive in order")
    assert shipping._take_manifest_part(folder, a[0], NOW, usage)["have"] == shipping.CHUNK
    assert shipping._take_manifest_part(folder, a[0], NOW, usage) == dict(ok=True, have=shipping.CHUNK), \
        "a piece sent again is acknowledged, not appended"
    b = parts(second)
    assert shipping._take_manifest_part(folder, b[0], NOW, usage)["have"] == shipping.CHUNK, "begun again from nothing"
    for item in b[1:]:
        answer = shipping._take_manifest_part(folder, item, NOW, usage)
    assert answer == dict(ok=True, have=len(second))
    assert (folder / "evidence/b1/manifest.json").read_bytes() == second


def test_a_whole_manifest_sent_again_or_changed(tmp_path):
    folder, usage = store(tmp_path)
    raw = big_manifest()
    for item in parts(raw):
        shipping._take_manifest_part(folder, item, NOW, usage)
    assert shipping._take_manifest_part(folder, parts(raw)[0], NOW, usage) == dict(ok=True, have=len(raw)), \
        "already whole: the push learns it is done"
    changed = big_manifest("changed on the machine")
    for item in parts(changed):
        answer = shipping._take_manifest_part(folder, item, NOW, usage)
    assert answer["ok"] is False and answer["have"] == 0
    conflicts = (folder / "conflicts.jsonl").read_text()
    assert "SHIPPED_EVIDENCE_CHANGED" in conflicts and "sent again with another manifest" in conflicts
    assert (folder / "evidence/b1/manifest.json").read_bytes() == raw, "the first is kept"


def test_bounds(tmp_path):
    folder, usage = store(tmp_path)
    raw = big_manifest()
    good = parts(raw)[0]
    for change in (dict(size=shipping.MAX_MANIFEST + 1), dict(size=0), dict(offset=-1), dict(bundle="../x"),
                   dict(sha256="xyz"), dict(offset=len(raw)), dict(data="not base64!")):
        answer = shipping._take_manifest_part(folder, dict(good, **change), NOW, usage)
        assert answer["ok"] is False, change
    assert not (folder / "evidence-partial").exists()


def test_a_resumed_manifest_sends_only_the_pieces_still_missing(collector, tmp_path, monkeypatch):
    data, url, _view = collector
    web = Machine(tmp_path, url, data)
    base, _ = capture(web, "b1")
    pieces = -(-len((base / "manifest.json").read_bytes()) // shipping.CHUNK)
    assert pieces >= 2
    monkeypatch.setattr(shipping, "MAX_REQUESTS", 1)
    web.push()
    monkeypatch.setattr(shipping, "MAX_REQUESTS", 400)
    second = web.push()
    assert second["requests"] == (pieces - 1) + 1, "the pieces still missing, then the one file: none sent twice"
