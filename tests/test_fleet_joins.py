"""Fleet incidents joined across machines by more than an address: a dropped tool's path, and a domain name that is
itself the finding. Paths and names every machine has never join."""
from __future__ import annotations

from datetime import timedelta

from megalodon import fleet
from megalodon import response_engine as re_
from test_fleet import collector  # noqa: F401
from test_fleet_timeline import T0, Machine


def joined(data, hours=3):
    return [r for r in fleet.fleet_timeline(data=data, now=T0 + timedelta(hours=hours))["incidents"]
            if len(r["machines"]) > 1]


def egress(machine, rule, name, address, minutes, program="/usr/bin/python3"):
    """An egress finding as the watch reports it, through the response engine's own signal mapping."""
    finding = dict(rule_id=rule, severity="CRITICAL" if rule.endswith("WATCHLISTED_NAME") else "MEDIUM",
                   program=program, detail=f"{program} connects to {name}", address=address, port=443,
                   protocol="tcp", names=[name], name=name if rule in re_.NAME_RULES else None,
                   evidence=dict(processes=[dict(program=program, pid=4000 + minutes, start=100)]))
    report = dict(checked_at=(T0 + timedelta(minutes=minutes)).strftime('%Y-%m-%dT%H:%M:%SZ'), findings=[finding])
    re_.run(policy_path=machine.policy, ledger=machine.ledger, state_path=machine.state,
            signals=re_.egress_signals(report), protected=set(), now=T0 + timedelta(minutes=minutes))


def test_the_same_dropped_tool_on_two_machines_is_one_incident(collector, tmp_path):  # noqa: F811
    data, url, _view = collector
    web, db = Machine(tmp_path, url, data, "web-1"), Machine(tmp_path, url, data, "db-1")
    web.finds("w", "egress", "OUTBOUND_FROM_TEMPORARY", "/tmp/.cache/kworker connects out", 0,
              process=["/tmp/.cache/kworker"], address=["198.51.100.7"])
    db.finds("d", "persistence", "PERSISTENCE_ADDED", "a unit runs /tmp/.cache/kworker", 90,
             file=["/tmp/.cache/kworker (deleted)"], persistence=["systemd:kworker.service"])
    for one in (web, db):
        one.push()
    (incident,) = joined(data)
    assert incident["machines"] == ["db-1", "web-1"] and incident["linked_by"] == ["file:/tmp/.cache/kworker"], \
        "a program on one and a file on the other, the same place"


def test_paths_names_and_accounts_every_machine_has_do_not_join(collector, tmp_path):  # noqa: F811
    data, url, _view = collector
    web, db = Machine(tmp_path, url, data, "web-1"), Machine(tmp_path, url, data, "db-1")
    web.finds("w", "egress", "NEW_OUTBOUND_PROGRAM", "curl connects out", 0,
              process=["/usr/bin/curl"], account=["root"], port=["tcp/443"], file=["/tmp/"])
    db.finds("d", "egress", "NEW_OUTBOUND_PROGRAM", "curl connects out", 10,
             process=["/usr/bin/curl"], account=["root"], port=["tcp/443"], file=["/tmp/"])
    for one in (web, db):
        one.push()
    assert joined(data) == []


def test_a_watchlisted_name_on_two_machines_is_one_incident(collector, tmp_path):  # noqa: F811
    data, url, _view = collector
    web, db = Machine(tmp_path, url, data, "web-1"), Machine(tmp_path, url, data, "db-1")
    # Each reaches the name at a different address: a fronted or fast-changing server.
    egress(web, "OUTBOUND_TO_WATCHLISTED_NAME", "C2.Bad-Actor.Example.", "198.51.100.20", 0)
    egress(db, "OUTBOUND_TO_WATCHLISTED_NAME", "c2.bad-actor.example", "198.51.100.21", 30)
    for one in (web, db):
        one.push()
    (incident,) = joined(data)
    assert incident["linked_by"] == ["name:c2.bad-actor.example"], "names are compared as DNS does: case and dot"


def test_an_ordinary_name_is_not_a_link(collector, tmp_path):  # noqa: F811
    data, url, _view = collector
    web, db = Machine(tmp_path, url, data, "web-1"), Machine(tmp_path, url, data, "db-1")
    egress(web, "NEW_OUTBOUND_PROGRAM", "deb.debian.example", "198.51.100.30", 0, program="/opt/a/agent")
    egress(db, "NEW_OUTBOUND_PROGRAM", "deb.debian.example", "198.51.100.31", 30, program="/opt/b/agent")
    for one in (web, db):
        one.push()
    assert joined(data) == [], "a new program reaching a mirror names it too, and every machine has one"


def test_far_apart_sightings_of_a_dropped_tool_are_not_joined(collector, tmp_path):  # noqa: F811
    data, url, _view = collector
    web, db = Machine(tmp_path, url, data, "web-1"), Machine(tmp_path, url, data, "db-1")
    web.finds("w", "egress", "OUTBOUND_FROM_TEMPORARY", "/dev/shm/x", 0, process=["/dev/shm/x"])
    db.finds("d", "egress", "OUTBOUND_FROM_TEMPORARY", "/dev/shm/x", 60 * 30, process=["/dev/shm/x"])
    for one in (web, db):
        one.push()
    assert joined(data, hours=40) == []


def test_which_entities_link_machines():
    assert fleet._link_key("address:203.0.113.9") == "address:203.0.113.9"
    assert fleet._link_key("name:c2.example") == "name:c2.example"
    assert fleet._link_key("process:/memfd:loader (deleted)") == "file:/memfd:loader"
    for ordinary in ("process:/usr/bin/curl", "file:/etc/passwd", "account:root", "port:tcp/443", "file:/tmp/",
                     "file:/tmpfile", "process:/memfd:", "persistence:systemd:x", "device:1-1#4@usb:1:2:-", "name:"):
        assert fleet._link_key(ordinary) is None, ordinary


def test_a_name_finding_keeps_its_name_and_others_do_not():
    report = dict(checked_at="2026-11-19T12:00:00Z", findings=[
        dict(rule_id="OUTBOUND_TO_GENERATED_NAME", severity="MEDIUM", program="/usr/bin/x", detail="",
             address="198.51.100.9", port=443, protocol="tcp", name="Q8X7K2.Example."),
        dict(rule_id="NEW_OUTBOUND_PROGRAM", severity="HIGH", program="/usr/bin/y", detail="",
             address="198.51.100.9", port=443, protocol="tcp", names=["mirror.example"])])
    named, ordinary = re_.egress_signals(report)
    assert named.entities["name"] == {"q8x7k2.example"} and ordinary.entities["name"] == set()
