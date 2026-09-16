const integrations = [
  {
    id: "core", name: "Python + SQLite", monogram: "PY", category: "core", status: "implemented", statusLabel: "Implemented",
    summary: "Validates bounded metadata and records events, detections, action decisions, and terminal receipts.",
    dataKind: "audit metadata", contract: "PacketEvent → local SQLite audit", owner: "megalodon.service",
    boundary: "No payload model, public listener, automatic action, or cloud dependency.",
    nextGate: "Representative replay and operator-owned retention policy.", ui: ["Event feed", "Detection linkage", "Run receipts"],
    metricA: "12.4k", metricALabel: "preview events", metricB: "0", metricBLabel: "public write APIs"
  },
  {
    id: "tshark", name: "Wireshark / TShark", monogram: "TS", category: "network", status: "implemented", statusLabel: "Implemented",
    summary: "Transforms an authorized saved PCAP or PCAPNG into bounded packet metadata and private reports.",
    dataKind: "packet metadata", contract: "Private PCAP/PCAPNG → offline-run-v1", owner: "megalodon.offline.tshark",
    boundary: "Linux-only, fixed /usr/bin/tshark, non-root, no live capture, payload, protocol tree, or name lookup.",
    nextGate: "Revalidate installed-tool compatibility and external-process containment.", ui: ["Traffic chart", "Protocol mix", "Packet rows"],
    metricA: "5.4k", metricALabel: "preview packets", metricB: "0", metricBLabel: "live captures"
  },
  {
    id: "zeek", name: "Zeek", monogram: "ZK", category: "network", status: "implemented", statusLabel: "Implemented",
    summary: "Imports separately produced conn.log JSON or TSV as source-qualified flow metadata.",
    dataKind: "flow metadata", contract: "Declared conn.log profile → offline-run-v1", owner: "megalodon.offline.zeek",
    boundary: "MEGALODON never starts Zeek; flow counts never become packet counts; no response or egress.",
    nextGate: "Producer-profile compatibility and representative flow fixtures.", ui: ["Flow counter", "Conversation rows", "Protocol context"],
    metricA: "318", metricALabel: "preview flows", metricB: "27", metricBLabel: "active pairs"
  },
  {
    id: "suricata", name: "Suricata", monogram: "SU", category: "network", status: "implemented", statusLabel: "Local read view",
    summary: "Capacity-gates atomic publication, reconciles unknown commits, and optionally shows bounded Suricata evidence in a read-only local dashboard startup snapshot.",
    dataKind: "alert metadata", contract: "suricata-eve-alert-input-v1", owner: "megalodon.offline.suricata",
    boundary: "Linux, non-root, and capability-free; existing owner-private store only. Reconciliation and the separate dashboard projection use locked read-only snapshots. No repair, retry, migration, retention deletion, sensor start, blocking, attribution, or response. This hosted Site stays synthetic and disconnected.",
    nextGate: "Installed-producer and operator acceptance; verify snapshot age and source provenance before interpreting local results.", ui: ["Alert lane", "Severity", "Terminal receipt"],
    evidence: { label: "PR #239 · optional local read-only projection", url: "https://github.com/bartytime4life/MEGALODON/pull/239" },
    metricA: "512 MiB", metricALabel: "logical consumer ceiling", metricB: "30 s", metricBLabel: "cooperative deadline"
  },
  {
    id: "scapy", name: "Scapy", monogram: "SC", category: "network", status: "bounded", statusLabel: "Optional",
    summary: "Provides explicitly enabled, interface-specific live packet metadata through the capture extra.",
    dataKind: "packet metadata", contract: "Selected interface → PacketEvent", owner: "megalodon.capture",
    boundary: "Capture authority and privilege remain external; no packet crafting or replay injection exists.",
    nextGate: "Least-privilege live-capture and backpressure validation.", ui: ["Interface rate", "Queue state", "Metadata rows"],
    metricA: "742", metricALabel: "preview events", metricB: "0", metricBLabel: "authorized interfaces"
  },
  {
    id: "nftables", name: "nftables", monogram: "NF", category: "response", status: "plan", statusLabel: "Plan only",
    summary: "Renders inert, time-limited response proposals for review against validated global targets.",
    dataKind: "action plan", contract: "Validated target → planned ActionRecord", owner: "megalodon.firewall",
    boundary: "Live application is unsupported and refused before configuration, privilege, or subprocess work.",
    nextGate: "Durable intent, terminal outcome, reconciliation, recovery, and disposable-namespace tests.", ui: ["Planned actions", "Expiry", "Refusal receipts"],
    metricA: "2", metricALabel: "preview plans", metricB: "0", metricBLabel: "actions applied"
  },
  {
    id: "clamav", name: "ClamAV", monogram: "CA", category: "endpoint", status: "manual", statusLabel: "Manual",
    summary: "Remains a separately operated file scanner with a reserved result surface in the control room.",
    dataKind: "file scan result", contract: "No MEGALODON intake contract", owner: "external operator",
    boundary: "No file-content intake, hash intake, signature update, daemon, quarantine, deletion, or result importer.",
    nextGate: "Versioned result contract, retention decision, and false-positive review.", ui: ["Reserved scan result", "Verdict", "Provenance"],
    metricA: "0", metricALabel: "imported results", metricB: "0", metricBLabel: "quarantine actions"
  },
  {
    id: "osquery", name: "osquery", monogram: "OQ", category: "endpoint", status: "proposed", statusLabel: "Proposed",
    summary: "Reserves a future endpoint-inventory view built from a closed, privacy-reviewed query profile.",
    dataKind: "endpoint metadata", contract: "Not implemented", owner: "not implemented",
    boundary: "No arbitrary SQL, process environment, command-line dump, daemon, scheduler, or remote enrollment.",
    nextGate: "Closed table and field allowlist, query-pack contract, and local privacy review.", ui: ["Host posture", "Package inventory", "Query receipt"],
    metricA: "0", metricALabel: "endpoint rows", metricB: "0", metricBLabel: "scheduled queries"
  },
  {
    id: "qwen", name: "Qwen + Ollama", monogram: "QW", category: "advisory", status: "manual", statusLabel: "Manual",
    summary: "Can explain one bounded completed metadata dossier through an explicit literal-loopback request.",
    dataKind: "advisory receipt", contract: "local-model-advisory-v1", owner: "megalodon.qwen_advisory",
    boundary: "No raw traffic, background feed, Internet access, tools, retry, detection authority, or response authority.",
    nextGate: "Independent review before invocation-to-dashboard orchestration.", ui: ["Advisory receipt", "Model provenance", "Fixed limitations"],
    metricA: "0", metricALabel: "live requests", metricB: "1", metricBLabel: "reserved receipt slot"
  },
  {
    id: "nmap", name: "Nmap", monogram: "NM", category: "network", status: "proposed", statusLabel: "Proposed",
    summary: "Reserves an import-only interface for a completed, operator-supplied bounded inventory report.",
    dataKind: "network inventory", contract: "Future completed Nmap XML import", owner: "not implemented",
    boundary: "No scan launch, target selection, script engine, service-banner intake, or network activity.",
    nextGate: "Versioned XML contract, adversarial parser fixtures, privacy review, and size limits.", ui: ["Host inventory", "Port summary", "Import receipt"],
    metricA: "0", metricALabel: "inventory hosts", metricB: "0", metricBLabel: "scans launched"
  },
  {
    id: "ossec", name: "OSSEC", monogram: "OS", category: "endpoint", status: "proposed", statusLabel: "Proposed",
    summary: "Reserves a source-qualified host-integrity alert lane from completed operator-supplied records.",
    dataKind: "host integrity alerts", contract: "Future bounded OSSEC JSON import", owner: "not implemented",
    boundary: "No agent enrollment, daemon control, unrestricted logs, configuration change, or active response.",
    nextGate: "Versioned alert contract, representative fixtures, redaction review, and limits.", ui: ["Integrity findings", "Host lane", "Import receipt"],
    metricA: "0", metricALabel: "integrity alerts", metricB: "0", metricBLabel: "active responses"
  },
  {
    id: "greenbone", name: "Greenbone CE", monogram: "GB", category: "endpoint", status: "proposed", statusLabel: "Proposed",
    summary: "Reserves a bounded review surface for a completed vulnerability report supplied by an operator.",
    dataKind: "vulnerability report", contract: "Future completed GMP XML import", owner: "not implemented",
    boundary: "No scanner launch, feed update, credential intake, target creation, scheduling, or remediation.",
    nextGate: "Versioned report contract, entity-expansion defenses, privacy review, and limits.", ui: ["Finding severity", "Affected asset", "Report receipt"],
    metricA: "0", metricALabel: "report findings", metricB: "0", metricBLabel: "scanner controls"
  },
  {
    id: "zabbix", name: "Zabbix", monogram: "ZA", category: "availability", status: "proposed", statusLabel: "Proposed",
    summary: "Reserves a future read-only availability summary with explicit endpoint and credential policy.",
    dataKind: "availability summary", contract: "Not implemented", owner: "not implemented",
    boundary: "No endpoint, credential, event history, background poller, acknowledgement, script, or remote command.",
    nextGate: "Read-only API allowlist, credential handling, request budgets, fixtures, and failure review.", ui: ["Service health", "Availability", "Read receipt"],
    metricA: "0", metricALabel: "service rows", metricB: "0", metricBLabel: "background polls"
  },
  {
    id: "nagios", name: "Nagios Core", monogram: "NG", category: "availability", status: "proposed", statusLabel: "Proposed",
    summary: "Reserves a future read-only availability surface without access to a command pipe or remote control.",
    dataKind: "availability summary", contract: "Not implemented", owner: "not implemented",
    boundary: "No CGI endpoint, credential, status archive, poller, acknowledgement, configuration, or command pipe.",
    nextGate: "Read-only field allowlist, credential handling, request budgets, fixtures, and failure review.", ui: ["Host status", "Service status", "Read receipt"],
    metricA: "0", metricALabel: "status rows", metricB: "0", metricBLabel: "commands sent"
  }
];

const toolAcquisition = {
  core: {
    source: "MEGALODON repository",
    url: "https://github.com/bartytime4life/MEGALODON#ubuntu-2404-local-evaluation-setup",
    linkLabel: "Open bounded Ubuntu setup",
    platforms: ["Ubuntu 24.04 reference", "Windows evaluation"],
    commandLabel: null,
    command: null,
    verificationLabel: "Linux verification",
    verificationCommand: "command -v python3 >/dev/null && python3 -c 'import sqlite3' && command -v sqlite3 >/dev/null && echo 'Python + SQLite installed'",
    note: "The repository recipe uses a temporary service-start guard and preserves the Linux-first evaluation boundary."
  },
  tshark: {
    source: "MEGALODON repository",
    url: "https://github.com/bartytime4life/MEGALODON#ubuntu-2404-local-evaluation-setup",
    linkLabel: "Open guarded TShark setup",
    platforms: ["Linux adapter", "Windows desktop separate"],
    commandLabel: null,
    command: null,
    verificationLabel: "MEGALODON Linux path check",
    verificationCommand: "test -x /usr/bin/tshark && /usr/bin/tshark --version",
    note: "Keep Wireshark capture permission disabled. The adapter expects /usr/bin/tshark and analyzes saved captures only."
  },
  zeek: {
    source: "MEGALODON repository + Zeek Project",
    url: "https://github.com/bartytime4life/MEGALODON#3-build-zeek-as-a-private-non-service-producer",
    linkLabel: "Open private Zeek build guide",
    platforms: ["Linux", "Containers", "macOS", "BSD"],
    commandLabel: null,
    command: null,
    verificationLabel: "Native Linux verification",
    verificationCommand: "if command -v zeek >/dev/null; then zeek --version; elif test -x /opt/zeek/bin/zeek; then /opt/zeek/bin/zeek --version; else exit 1; fi",
    note: "The reviewed path requires a pinned release digest and a private non-service prefix. MEGALODON never starts Zeek."
  },
  suricata: {
    source: "Open Information Security Foundation",
    url: "https://suricata.io/download/",
    linkLabel: "Open Suricata downloads",
    platforms: ["Linux", "Windows", "macOS / source", "BSD"],
    commandLabel: null,
    command: null,
    verificationLabel: "Linux verification",
    verificationCommand: "command -v suricata >/dev/null && suricata --build-info",
    note: "Suricata is operator-managed. Review repository, signing key, package, service state, and rollback before installation."
  },
  scapy: {
    source: "Scapy Project",
    url: "https://scapy.readthedocs.io/en/latest/installation.html",
    linkLabel: "Open Scapy install guide",
    platforms: ["Windows", "macOS", "Linux"],
    commandLabel: null,
    command: null,
    verificationLabel: "Active Python verification",
    verificationCommand: "python3 -c 'import scapy; print(scapy.__version__)'",
    note: "Use the repository's optional capture extra. Live capture still requires separately approved interface privileges."
  },
  nftables: {
    source: "MEGALODON repository",
    url: "https://github.com/bartytime4life/MEGALODON#ubuntu-2404-local-evaluation-setup",
    linkLabel: "Open guarded Ubuntu setup",
    platforms: ["Linux only"],
    commandLabel: null,
    command: null,
    verificationLabel: "Linux verification",
    verificationCommand: "if command -v nft >/dev/null; then nft --version; elif test -x /usr/sbin/nft; then /usr/sbin/nft --version; else exit 1; fi",
    note: "The repository setup suppresses service starts. MEGALODON renders inert plans and refuses live rule application."
  },
  clamav: {
    source: "Cisco Talos / ClamAV",
    url: "https://www.clamav.net/downloads",
    linkLabel: "Open official ClamAV downloads",
    platforms: ["Windows", "macOS", "Linux"],
    commandLabel: null,
    command: null,
    verificationLabel: "Linux verification",
    verificationCommand: "command -v clamscan >/dev/null && clamscan --version",
    note: "Manual companion only. Do not add it to the base recipe: packaging can create a signature-update service and egress."
  },
  osquery: {
    source: "osquery Project",
    url: "https://github.com/osquery/osquery/releases/latest",
    linkLabel: "Open official releases",
    platforms: ["Windows", "macOS", "Linux"],
    commandLabel: null,
    command: null,
    verificationLabel: "Linux verification",
    verificationCommand: "command -v osqueryi >/dev/null && osqueryi --version",
    note: "Choose the signed package for the target OS. MEGALODON has no query pack, scheduler, enrollment, or result importer yet."
  },
  qwen: {
    source: "Ollama",
    url: "https://ollama.com/download",
    linkLabel: "Download Ollama",
    platforms: ["Windows", "macOS", "Linux"],
    commandLabel: null,
    command: null,
    verificationLabel: "Local provider + model check",
    verificationCommand: "command -v ollama >/dev/null && ollama list | grep -Eiq '^qwen[^[:space:]]*[[:space:]]' && echo 'Ollama + Qwen installed'",
    note: "A mutable model pull is not authorization. The advisory path requires an operator-supplied local registry and validated artifact digest."
  },
  nmap: {
    source: "Nmap Project",
    url: "https://nmap.org/download",
    linkLabel: "Open official Nmap downloads",
    platforms: ["Windows", "macOS", "Linux", "BSD"],
    commandLabel: null,
    command: null,
    verificationLabel: "Linux verification",
    verificationCommand: "command -v nmap >/dev/null && nmap --version",
    note: "MEGALODON does not launch scans. The reserved boundary is a future completed XML report import only."
  },
  ossec: {
    source: "OSSEC Project",
    url: "https://www.ossec.net/ossec-downloads/",
    linkLabel: "Open OSSEC downloads",
    platforms: ["Windows agents", "macOS", "Linux", "Unix"],
    commandLabel: null,
    command: null,
    verificationLabel: "Default-path verification",
    verificationCommand: "if test -x /var/ossec/bin/ossec-control || test -x /var/ossec/bin/ossec-agentd; then echo 'OSSEC installed'; else exit 1; fi",
    note: "Use the vendor's package and role-specific instructions. Agent enrollment and active response stay outside MEGALODON."
  },
  greenbone: {
    source: "Greenbone Community",
    url: "https://greenbone.github.io/docs/latest/22.4/container/",
    linkLabel: "Open container install guide",
    platforms: ["Linux containers"],
    commandLabel: null,
    command: null,
    verificationLabel: "Container image verification",
    verificationCommand: "docker image ls --format '{{.Repository}}' | grep -Eq 'greenbone|openvas' && echo 'Greenbone images present'",
    note: "Greenbone is a multi-service deployment with substantial resource and privilege requirements; follow the complete official guide."
  },
  zabbix: {
    source: "Zabbix LLC",
    url: "https://www.zabbix.com/download",
    linkLabel: "Open Zabbix install selector",
    platforms: ["Linux server", "Windows agents", "Containers", "Cloud"],
    commandLabel: null,
    command: null,
    verificationLabel: "Server or agent verification",
    verificationCommand: "if command -v zabbix_server >/dev/null || command -v zabbix_agent2 >/dev/null || command -v zabbix_agentd >/dev/null || test -x /usr/sbin/zabbix_server || test -x /usr/sbin/zabbix_agent2 || test -x /usr/sbin/zabbix_agentd; then echo 'Zabbix installed'; else exit 1; fi",
    note: "Select the OS, release, database, and web server on the official page. No MEGALODON endpoint or credential contract exists yet."
  },
  nagios: {
    source: "Nagios Enterprises",
    url: "https://www.nagios.org/projects/nagios-core/",
    linkLabel: "Open Nagios Core downloads",
    platforms: ["Linux server"],
    commandLabel: null,
    command: null,
    verificationLabel: "Linux verification",
    verificationCommand: "if command -v nagios >/dev/null; then nagios --version; elif test -x /usr/local/nagios/bin/nagios; then /usr/local/nagios/bin/nagios --version; else exit 1; fi",
    note: "Nagios Core needs a host-specific installation and plugin plan. MEGALODON has no CGI, credential, or command-pipe access."
  }
};

const workflows = {
  synthetic: {
    status: "Implemented", statusClass: "implemented", platform: "Linux reference · Windows evaluation", title: "Synthetic core demonstration",
    summary: "Exercise the metadata pipeline with deterministic sample traffic. No capture tool, elevated privilege, external service, GPU, or cloud account is required.",
    command: "python -m megalodon run --source sample --max-events 256",
    produces: ["Validated metadata events", "Fixed heuristic decisions", "SQLite audit records"],
    refuses: ["Packet payload collection", "Automatic blocking", "Remote dashboard exposure"],
    boundary: "Local metadata only; the command does not start the dashboard."
  },
  replay: {
    status: "Implemented", statusClass: "implemented", platform: "Linux reference", title: "Bounded JSONL replay",
    summary: "Replay authorized metadata through finite line, byte, event, skipped-line, and optional elapsed-time limits while preserving terminal error evidence.",
    command: "python -m megalodon run --source jsonl --input ./events.jsonl --max-events 10000",
    produces: ["Accepted event ledger", "Detection and decision links", "Terminal run counters"],
    refuses: ["Unbounded aggregate reads", "Arbitrary event extensions", "Shell interpolation"],
    boundary: "The fixed aggregate UTF-8 input ceiling is 256 MiB; excess input fails closed."
  },
  offline: {
    status: "Bounded adapter", statusClass: "bounded", platform: "Linux only", title: "Isolated saved-capture analysis",
    summary: "Run a fixed-system TShark adapter against an explicitly selected PCAP or PCAPNG in a non-root analyst environment. Reports are private and redacted.",
    command: "python -m megalodon.offline --source tshark --input-root ./input --input capture.pcapng --output ./report --case case001 --max-records 10000 --timeout 30",
    produces: ["Typed metadata summary", "Redacted JSONL and CSV reports", "Run manifest and receipt"],
    refuses: ["Live capture", "Payload publication", "Root execution"],
    boundary: "Fixed /usr/bin/tshark, bounded output and time; Windows desktop Wireshark is separate."
  },
  suricata: {
    status: "Implemented · optional local view", statusClass: "implemented", platform: "Linux · non-root · capability-free", title: "Review a bounded Suricata startup snapshot",
    summary: "Point the local dashboard at an existing private Suricata store. It validates a bounded read-only snapshot at startup and serves immutable review data; the hosted Site remains synthetic and is not connected.",
    command: "python -m megalodon dashboard --suricata-db /absolute/private/suricata.sqlite",
    produces: ["Up to five validated recent publications", "At most 50 external alert metadata rows", "Explicit unconfigured, unavailable, and snapshot provenance states"],
    refuses: ["Database, schema, permission, or evidence writes", "Per-request database queries or live sensor access", "Retry, repair, retention, producer, or response authority"],
    boundary: "The optional projection validates a locked read-only startup snapshot within a cooperative five-second deadline and 64 KiB output bound. Snapshot freshness is explicit; external alert evidence does not become MEGALODON detection or action authority."
  },
  plans: {
    status: "Implemented / non-executing", statusClass: "implemented", platform: "Static catalog", title: "Capability and integration plans",
    summary: "Inspect a closed vocabulary of platform capabilities and integration steps without probing the host, locating executables, installing packages, or starting services.",
    command: "python -m megalodon hub-plan --platform linux",
    produces: ["Machine-readable workflow plan", "Explicit availability state", "Documented prerequisites"],
    refuses: ["Host probing", "Package installation", "Firewall or service changes"],
    boundary: "A plan is not an applied action, compatibility result, or production approval."
  }
};

const eventTemplates = [
  { source: "tshark", sourceLabel: "TShark", type: "packet metadata", subject: "10.0.0.42:51824 → 198.51.100.14:443", disposition: "accepted", dispositionClass: "accepted" },
  { source: "zeek", sourceLabel: "Zeek", type: "flow metadata", subject: "10.0.0.18 → resolver.example:53", disposition: "context", dispositionClass: "context" },
  { source: "suricata", sourceLabel: "Suricata", type: "alert metadata", subject: "ET POLICY synthetic fixture", disposition: "review", dispositionClass: "review" },
  { source: "core", sourceLabel: "MEGALODON", type: "detection link", subject: "PORT_SCAN · source 10.0.0.77", disposition: "review", dispositionClass: "review" },
  { source: "scapy", sourceLabel: "Scapy", type: "interface metadata", subject: "eth0 · TCP flags / length only", disposition: "accepted", dispositionClass: "accepted" },
  { source: "zeek", sourceLabel: "Zeek", type: "connection state", subject: "10.0.0.24 → 203.0.113.8:22", disposition: "context", dispositionClass: "context" },
  { source: "core", sourceLabel: "MEGALODON", type: "audit receipt", subject: "run synthetic-0042 · complete", disposition: "accepted", dispositionClass: "accepted" },
  { source: "tshark", sourceLabel: "TShark", type: "DNS metadata", subject: "telemetry.example · A query", disposition: "accepted", dispositionClass: "accepted" }
];

const detectionLanes = [
  { name: "PORT_SCAN", count: 3, source: "TShark + core", level: 72, severity: "high", detail: "Distinct destination-port threshold crossed in a bounded source window." },
  { name: "SYN_FLOOD", count: 2, source: "Suricata + core", level: 49, severity: "medium", detail: "Synthetic SYN-rate candidate retained for analyst review." },
  { name: "DNS_TUNNELING", count: 2, source: "Zeek + core", level: 34, severity: "low", detail: "Metadata-only heuristic; no DNS payload or attribution claim." }
];

const sourceContributions = [
  { name: "TShark", share: 43, detail: "packet metadata" },
  { name: "Zeek", share: 26, detail: "flow metadata" },
  { name: "Suricata", share: 16, detail: "alert metadata" },
  { name: "MEGALODON", share: 9, detail: "audit + detections" },
  { name: "Scapy", share: 6, detail: "capture metadata" }
];

const categories = [
  ["all", "All tools"], ["network", "Network"], ["endpoint", "Endpoint / file"], ["availability", "Availability"], ["advisory", "Advisory"], ["response", "Response"], ["core", "Core"]
];

const sourceOptions = [["all", "All"], ["core", "Core"], ["tshark", "TShark"], ["zeek", "Zeek"], ["suricata", "Suricata"], ["scapy", "Scapy"]];
const sourceToolIds = new Set(["core", "tshark", "zeek", "suricata", "scapy"]);
const toolPresenceKey = "megalodon-tool-presence-v2";
const toolPresenceValues = new Set(["unchecked", "installed", "missing"]);
const toolPresenceLabels = { unchecked: "Not checked", installed: "Reported present", missing: "Reported missing", stale: "Recheck note" };
const presenceMaxAge = 7 * 24 * 60 * 60 * 1000;
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
const runExamples = [
  { id: "demo-tshark-042", tool: "tshark", name: "Saved-capture replay", state: "complete", records: "5,400 packet metadata records", completeness: "Complete within the illustrated replay budget", limitation: "A saved capture covers only its collection window and vantage. It cannot establish current network health.", next: "Review installed-TShark compatibility evidence before using a real capture.", fields: ["source: tshark", "kind: packet metadata", "capture: synthetic fixture", "payload: absent"] },
  { id: "demo-zeek-018", tool: "zeek", name: "Connection-log import", state: "complete", records: "318 flow records", completeness: "Complete within the illustrated import budget", limitation: "Flow records are context; they are not packet counts or proof of malicious activity.", next: "Confirm the declared conn.log producer profile and input limits.", fields: ["source: zeek", "kind: flow metadata", "profile: illustrative conn.log", "payload: absent"] },
  { id: "demo-core-042", tool: "core", name: "Fixed detection review", state: "complete", records: "7 candidate detections", completeness: "Completed synthetic detection window", limitation: "A threshold match is a candidate finding, not attribution or action authority.", next: "Review the source observations and rule threshold before any operator decision.", fields: ["source: core", "kind: detection metadata", "actions_applied: 0", "model_authority: none"] },
  { id: "demo-scapy-009", tool: "scapy", name: "Interrupted capture example", state: "incomplete", records: "742 metadata records retained", completeness: "Incomplete — later input was not observed", limitation: "Retained records remain scoped evidence. An incomplete window cannot be reported as a clean success or zero threats.", next: "Inspect the terminal error and capture loss evidence; do not infer missing traffic.", fields: ["source: scapy", "kind: interface metadata", "completeness: incomplete", "live_connection: false"] },
  { id: "demo-suricata-007", tool: "suricata", name: "Commit outcome unknown", state: "unknown", records: "7 alert candidates; commit unproved", completeness: "Unknown — no database was queried by this Site", limitation: "An unknown commit is neither committed nor absent. Retrying could duplicate an already committed publication.", next: "Use separately reviewed read-only reconciliation for the exact publication and attempt. An indeterminate result remains on hold.", fields: ["source: suricata", "kind: alert metadata", "consumer_attempt: synthetic-007", "commit_outcome: unknown"] }
];
const runForSource = Object.fromEntries(runExamples.map((run) => [run.tool, run.id]));

function loadToolPresence() {
  try {
    const saved = JSON.parse(localStorage.getItem(toolPresenceKey) || "{}");
    if (!saved || typeof saved !== "object" || Array.isArray(saved)) return {};
    return Object.fromEntries(Object.entries(saved).filter(([id, value]) => integrations.some((item) => item.id === id) && value && typeof value === "object" && ["installed", "missing"].includes(value.status) && Number.isFinite(value.checkedAt) && value.checkedAt > 0 && value.checkedAt <= Date.now()));
  } catch {
    return {};
  }
}

const state = {
  running: !reducedMotion.matches,
  tick: 0,
  windowSeconds: 60,
  eventSearch: "",
  dispositionFilter: "all",
  selectedEvent: null,
  selectedRun: "demo-tshark-042",
  activeView: "hud",
  readiness: null,
  sourceFilter: "all",
  categoryFilter: "all",
  selectedTool: "core",
  toolPresence: loadToolPresence(),
  events: eventTemplates.map((item, index) => ({ ...item, id: `demo-event-${index + 1}`, run: runForSource[item.source], offset: [2, 18, 34, 50, 95, 140, 380, 650][index] }))
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const svgNS = "http://www.w3.org/2000/svg";

function presenceFor(id) {
  const note = state.toolPresence[id];
  if (!note) return "unchecked";
  if (Date.now() - note.checkedAt > presenceMaxAge) return "stale";
  return note.status;
}

function setToolPresence(id, value) {
  if (!integrations.some((item) => item.id === id) || !toolPresenceValues.has(value)) return;
  if (value === "unchecked") delete state.toolPresence[id];
  else state.toolPresence[id] = { status: value, checkedAt: Date.now() };
  try {
    localStorage.setItem(toolPresenceKey, JSON.stringify(state.toolPresence));
  } catch {
    // Status remains available for this page even if device-local storage is blocked.
  }
  renderIntegrationGrid();
  renderToolInspector();
}

function renderVerificationSummary() {
  const installed = integrations.filter((item) => presenceFor(item.id) === "installed").length;
  const missing = integrations.filter((item) => presenceFor(item.id) === "missing").length;
  const unchecked = integrations.length - installed - missing;
  const summary = $("#verification-summary");
  const stale = integrations.filter((item) => presenceFor(item.id) === "stale").length;
  if (summary) summary.textContent = `Manual notes: ${installed} reported present · ${missing} reported missing · ${stale} need recheck · ${unchecked - stale} not checked`;
}

function readinessLabel(id) {
  if (!state.readiness) return "Report: not loaded";
  const mapped = { core: "python-sqlite", tshark: "wireshark-tshark", qwen: "qwen-ollama", nagios: "nagios-core" }[id] || id;
  const report = state.readiness.tools.find((tool) => tool.id === mapped);
  const labels = { executable_found: "Executable found", not_found: "Not found on checked PATH", not_checked: "Not checked" };
  const stale = Date.now() - Date.parse(state.readiness.checked_at) > 24 * 60 * 60 * 1000;
  return `${stale ? "Stale report · " : "Report · "}${labels[report.status]}`;
}

let readinessImportSequence = 0;
async function importReadinessFile(file) {
  const sequence = ++readinessImportSequence;
  state.readiness = null;
  $("#clear-readiness").disabled = true;
  $("#readiness-feedback").textContent = file ? "Reading a bounded report… Previous report cleared." : "No readiness report loaded.";
  renderIntegrationGrid(); renderToolInspector();
  if (!file) return;
  try {
    if (!Number.isFinite(file.size) || file.size > 8192 || file.size < 2) throw new Error("Choose a JSON report no larger than 8 KiB.");
    const bytes = await file.arrayBuffer();
    if (sequence !== readinessImportSequence) return;
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const report = validateReadinessReport(text);
    state.readiness = report;
    const age = Date.now() - Date.parse(report.checked_at);
    $("#readiness-feedback").textContent = `${age > 86400000 ? "STALE — more than 24 hours old. " : ""}14 tool results loaded · claimed check ${report.checked_at} · ${report.platform}. Schema accepted; report authenticity is not verified. Memory only.`;
    $("#clear-readiness").disabled = false;
  } catch (error) {
    if (sequence !== readinessImportSequence) return;
    $("#readiness-feedback").textContent = `Report rejected. ${error instanceof TypeError ? "The file must be valid UTF-8 JSON." : error.message} No results retained.`;
  }
  renderIntegrationGrid(); renderToolInspector();
}

function switchView(name) {
  if (!$( `[data-view-panel="${name}"]`)) return;
  state.activeView = name;
  $$("[data-view-panel]").forEach((panel) => {
    const active = panel.dataset.viewPanel === name;
    panel.hidden = !active;
    panel.classList.toggle("active", active);
  });
  $$("[data-view]").forEach((button) => {
    const active = button.dataset.view === name;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  window.scrollTo({ top: 0, behavior: reducedMotion.matches ? "instant" : "smooth" });
}

function chartSeries(tick) {
  const length = 46;
  const ingress = [];
  const egress = [];
  for (let i = 0; i < length; i += 1) {
    const phase = i * state.windowSeconds / 60 + tick;
    const pulse = phase % 17 === 0 ? 175 : phase % 23 === 0 ? 105 : 0;
    ingress.push(Math.max(110, 505 + Math.sin(phase * 0.52) * 105 + Math.cos(phase * 0.21) * 62 + pulse));
    egress.push(Math.max(60, 255 + Math.sin(phase * 0.41 + 1.8) * 72 + Math.cos(phase * 0.15) * 38 + pulse * 0.28));
  }
  return { ingress, egress };
}

function linePath(values) {
  return values.map((value, index) => {
    const x = index * (900 / (values.length - 1));
    const y = 226 - Math.min(900, value) / 900 * 200;
    return `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
}

function renderChart() {
  const { ingress, egress } = chartSeries(state.tick);
  const ingressPath = linePath(ingress);
  $("#traffic-ingress").setAttribute("d", ingressPath);
  $("#traffic-egress").setAttribute("d", linePath(egress));
  $("#traffic-area").setAttribute("d", `${ingressPath} L900,226 L0,226 Z`);

  const markerGroup = $("#detection-markers");
  markerGroup.replaceChildren();
  [11, 28, 39].forEach((index) => {
    const x = index * (900 / (ingress.length - 1));
    const y = 226 - Math.min(900, ingress[index]) / 900 * 200;
    const stem = document.createElementNS(svgNS, "line");
    stem.setAttribute("x1", x); stem.setAttribute("x2", x); stem.setAttribute("y1", y + 8); stem.setAttribute("y2", 226); stem.setAttribute("class", "detection-stem");
    const mark = document.createElementNS(svgNS, "rect");
    mark.setAttribute("x", x - 4); mark.setAttribute("y", y - 4); mark.setAttribute("width", 8); mark.setAttribute("height", 8); mark.setAttribute("transform", `rotate(45 ${x} ${y})`); mark.setAttribute("class", "detection-marker");
    markerGroup.append(stem, mark);
  });
}

function clockString(offsetSeconds) {
  const base = new Date(Date.UTC(2026, 8, 16, 14, 24, 42 + state.tick * 2 - offsetSeconds));
  return base.toISOString().slice(11, 19);
}

function renderSourceFilters() {
  const container = $("#source-filter");
  container.replaceChildren(...sourceOptions.map(([id, label]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.className = state.sourceFilter === id ? "active" : "";
    button.setAttribute("aria-pressed", String(state.sourceFilter === id));
    button.addEventListener("click", () => {
      state.sourceFilter = id;
      renderSourceFilters();
      renderEventFeed();
    });
    return button;
  }));
}

function renderEventFeed() {
  const matched = state.events.filter((item) => item.offset <= state.windowSeconds && (state.sourceFilter === "all" || item.source === state.sourceFilter) && (state.dispositionFilter === "all" || item.disposition === state.dispositionFilter) && `${item.sourceLabel} ${item.type} ${item.subject}`.toLowerCase().includes(state.eventSearch));
  const visible = matched.slice(0, 12);
  const rows = visible.map((event) => {
    const tr = document.createElement("tr");
    const cells = [clockString(event.offset), event.sourceLabel, event.type, event.subject];
    cells.forEach((value) => {
      const td = document.createElement("td");
      td.textContent = value;
      tr.append(td);
    });
    const disposition = document.createElement("td");
    const badge = document.createElement("span");
    badge.className = `disposition ${event.dispositionClass}`;
    badge.textContent = event.disposition;
    disposition.append(badge);
    tr.append(disposition);
    const detail = document.createElement("td");
    const inspect = document.createElement("button");
    inspect.type = "button";
    inspect.className = "text-button";
    inspect.textContent = "Inspect";
    inspect.setAttribute("aria-label", `Inspect ${event.sourceLabel} ${event.type} ${event.id}`);
    inspect.addEventListener("click", () => { state.selectedEvent = { ...event, time: clockString(event.offset) }; renderEventInspector(); });
    detail.append(inspect);
    tr.append(detail);
    return tr;
  });
  if (!rows.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 6;
    cell.className = "empty-feed";
    cell.textContent = "No synthetic records match this window and these filters. This is not a statement about network safety.";
    row.append(cell); rows.push(row);
  }
  $("#event-feed").replaceChildren(...rows);
  $("#feed-count").textContent = `${visible.length} of ${matched.length} matching demo records · ${state.windowSeconds}s window · source and disposition filters apply to this table only`;
}

function renderEventInspector() {
  const event = state.selectedEvent;
  const panel = $("#event-inspector");
  panel.hidden = !event;
  if (!event) return;
  const run = runExamples.find((item) => item.id === event.run);
  panel.innerHTML = `<div class="panel-heading"><div><p class="panel-kicker">SYNTHETIC RECORD · SNAPSHOT</p><h3 id="event-inspector-title" tabindex="-1"></h3></div><button class="text-button" type="button" id="close-event">Close</button></div><dl class="evidence-fields"></dl><p class="evidence-limit"></p><button class="control-button" id="open-event-run" type="button">Follow run evidence →</button>`;
  $("#event-inspector-title").textContent = event.subject;
  const fields = [["Record", event.id], ["Source", event.sourceLabel], ["Demo time", `${event.time} UTC`], ["Type", event.type], ["Disposition", event.disposition], ["Run", event.run]];
  fields.forEach(([label, value]) => { const dt = document.createElement("dt"); dt.textContent = label; const dd = document.createElement("dd"); dd.textContent = value; panel.querySelector("dl").append(dt, dd); });
  panel.querySelector(".evidence-limit").textContent = run.limitation;
  $("#close-event").addEventListener("click", () => { state.selectedEvent = null; panel.hidden = true; $("#event-search").focus(); });
  $("#open-event-run").addEventListener("click", () => { state.selectedRun = run.id; renderRunEvidence(); switchView("evidence"); $("#evidence-title").focus({ preventScroll: true }); });
  $("#event-inspector-title").focus({ preventScroll: true });
}

function renderRunEvidence() {
  $("#run-list").replaceChildren(...runExamples.map((run) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `run-item${state.selectedRun === run.id ? " active" : ""}`;
    button.setAttribute("aria-pressed", String(state.selectedRun === run.id));
    button.innerHTML = `<span class="run-state ${run.state}">${run.state === "unknown" ? "Commit unknown" : run.state}</span><strong>${run.name}</strong><small>${run.id} · ${run.records}</small>`;
    button.addEventListener("click", () => { state.selectedRun = run.id; renderRunEvidence(); });
    return button;
  }));
  const run = runExamples.find((item) => item.id === state.selectedRun);
  const item = integrations.find((tool) => tool.id === run.tool);
  $("#run-inspector").innerHTML = `<p class="panel-kicker">ILLUSTRATIVE REVIEW RECORD</p><h2>${run.name}</h2><span class="run-state ${run.state}">${run.completeness}</span><dl class="evidence-fields"><dt>Example identity</dt><dd>${run.id}</dd><dt>Source</dt><dd>${item.name}</dd><dt>Record unit</dt><dd>${run.records}</dd><dt>Provenance</dt><dd>Bundled deterministic browser fixture</dd><dt>Observed host</dt><dd>None — no host or network access</dd></dl><h3>What this can establish</h3><p>${run.limitation}</p><h3>Next evidence gate</h3><p>${run.next}</p><h3>Bounded display fields</h3><pre class="evidence-code"></pre><button class="control-button" id="inspect-run-tool" type="button">Inspect ${item.name} contract →</button><p class="panel-footnote">Display illustration only; not a signed receipt, a schema-validation result, or independent acceptance.</p>`;
  $("#run-inspector pre").textContent = run.fields.join("\n");
  $("#inspect-run-tool").addEventListener("click", () => { state.categoryFilter = "all"; state.selectedTool = run.tool; renderCategoryFilters(); renderIntegrationGrid(); renderToolInspector(); switchView("integrations"); });
}

function renderDetectionLanes() {
  $("#detection-lanes").replaceChildren(...detectionLanes.map((item) => {
    const row = document.createElement("article");
    row.className = `detection-row ${item.severity}`;
    row.innerHTML = `<div><strong>${item.name}</strong><small>${item.count} · ${item.source}</small></div><p>${item.detail}</p><div class="lane-bar"><span style="--level:${item.level}%"></span></div>`;
    return row;
  }));
}

function renderSourceBars() {
  $("#source-bars").replaceChildren(...sourceContributions.map((item) => {
    const row = document.createElement("div");
    row.className = "source-bar";
    row.innerHTML = `<div><strong>${item.name}</strong><small>${item.share}% · ${item.detail}</small></div><div class="bar-track"><span style="--width:${item.share}%"></span></div>`;
    return row;
  }));
}

function renderCategoryFilters() {
  $("#category-filter").replaceChildren(...categories.map(([id, label]) => {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.className = state.categoryFilter === id ? "active" : "";
    button.setAttribute("aria-pressed", String(state.categoryFilter === id));
    button.addEventListener("click", () => {
      state.categoryFilter = id;
      const visible = integrations.filter((item) => id === "all" || item.category === id);
      if (!visible.some((item) => item.id === state.selectedTool)) state.selectedTool = visible[0]?.id ?? "core";
      renderCategoryFilters();
      renderIntegrationGrid();
      renderToolInspector();
    });
    return button;
  }));
}

function renderIntegrationGrid() {
  const visible = integrations.filter((item) => state.categoryFilter === "all" || item.category === state.categoryFilter);
  $("#integration-grid").replaceChildren(...visible.map((item) => {
    const presence = presenceFor(item.id);
    const button = document.createElement("button");
    button.type = "button";
    button.className = `tool-card${state.selectedTool === item.id ? " active" : ""}`;
    button.setAttribute("aria-pressed", String(state.selectedTool === item.id));
    button.innerHTML = `<div class="tool-card-top"><span class="tool-monogram">${item.monogram}</span><div class="tool-state-stack"><span class="status-pill ${item.status}">${item.statusLabel}</span><span class="presence-pill ${presence}" aria-label="Manual note: ${toolPresenceLabels[presence]}"><i aria-hidden="true"></i>${toolPresenceLabels[presence]}</span></div></div><h2>${item.name}</h2><p>${item.summary}</p><span class="readiness-card-status">${readinessLabel(item.id)}</span><footer><span>${item.dataKind}</span><span>Inspect + get →</span></footer>`;
    button.addEventListener("click", () => {
      state.selectedTool = item.id;
      renderIntegrationGrid();
      renderToolInspector();
    });
    return button;
  }));
  renderVerificationSummary();
}

function renderToolInspector() {
  const item = integrations.find((candidate) => candidate.id === state.selectedTool) ?? integrations[0];
  const acquire = toolAcquisition[item.id];
  const presence = presenceFor(item.id);
  const hasHudLane = sourceToolIds.has(item.id);
  $("#tool-inspector").innerHTML = `
    <div class="inspector-head">
      <div><span class="tool-monogram">${item.monogram}</span><div><h2>${item.name}</h2><small>${item.dataKind}</small></div></div>
      <div class="inspector-statuses"><span class="status-pill ${item.status}">${item.statusLabel}</span><span class="presence-pill ${presence}"><i aria-hidden="true"></i>${toolPresenceLabels[presence]}</span></div>
    </div>
    <div class="inspector-section inspector-metrics">
      <div><strong>${item.metricA}</strong><small>${item.metricALabel}</small></div>
      <div><strong>${item.metricB}</strong><small>${item.metricBLabel}</small></div>
    </div>
    <div class="inspector-section"><span>MEGALODON contract</span><p>${item.contract}</p></div>
    <div class="inspector-section"><span>Imported presence report · self-reported</span><p>${readinessLabel(item.id)}</p><small class="panel-footnote">${state.readiness ? `Claimed check: ${state.readiness.checked_at} · ${state.readiness.platform} · path_presence_only` : "No report loaded. The browser has not inspected this device."}</small>${item.id === "qwen" ? "<p class=\"panel-footnote\">The report checks the Ollama executable only. It does not check a Qwen model or its digest.</p>" : ""}</div>
    <div class="inspector-section"><span>Integration owner</span><p>${item.owner}</p></div>
    <div class="inspector-section"><span>HUD surfaces</span><div class="hud-slots">${item.ui.map((slot) => `<span>${slot}</span>`).join("")}</div></div>
    ${item.evidence ? `<div class="inspector-section"><span>Acceptance evidence</span><p><a class="evidence-link" href="${item.evidence.url}" target="_blank" rel="noopener noreferrer">${item.evidence.label} <span aria-hidden="true">↗</span></a></p></div>` : ""}
    <div class="inspector-section acquire-section">
      <div class="acquire-heading"><span>Setup source</span><em>Operator managed</em></div>
      <p class="acquire-source">Official source · <strong>${acquire.source}</strong></p>
      <div class="platform-tags" aria-label="Supported installation platforms">${acquire.platforms.map((platform) => `<span>${platform}</span>`).join("")}</div>
      ${acquire.command ? `<div class="install-command"><span>${acquire.commandLabel}</span><code>${acquire.command}</code><button type="button" data-copy-install>Copy command</button></div>` : `<div class="guided-install"><strong>Reviewed guidance</strong><span>Use the linked project or vendor instructions and keep installation under operator control.</span></div>`}
      <div class="acquire-actions"><a href="${acquire.url}" target="_blank" rel="noopener noreferrer">${acquire.linkLabel} <span aria-hidden="true">↗</span></a></div>
      <p class="acquire-note">${acquire.note}</p>
      <div class="verification-panel">
        <div class="verification-heading"><strong>Manual presence note</strong><span>${acquire.verificationLabel}</span></div>
        <p>Review and run this read-only command yourself. A successful result only supports this specific check; it does not verify compatibility or service health.</p>
        <div class="verify-command"><code>${acquire.verificationCommand}</code><button type="button" data-copy-verify>Copy verify</button></div>
        <div class="presence-controls" role="group" aria-label="Record ${item.name} manual presence note">
          <button type="button" class="installed${presence === "installed" ? " active" : ""}" data-set-presence="installed" aria-pressed="${presence === "installed"}">I found it</button>
          <button type="button" class="missing${presence === "missing" ? " active" : ""}" data-set-presence="missing" aria-pressed="${presence === "missing"}">Not found by me</button>
          <button type="button" class="unchecked${presence === "unchecked" ? " active" : ""}" data-set-presence="unchecked" aria-pressed="${presence === "unchecked"}">Clear</button>
        </div>
        <small>${state.toolPresence[item.id] ? `Self-reported ${new Date(state.toolPresence[item.id].checkedAt).toISOString()}. ` : ""}Saved only in this browser; recheck after 7 days. Manual notes are not verified installation evidence.</small>
      </div>
      <p class="acquire-boundary"><strong>Operator action:</strong> this HUD opens setup guidance and copies verification text. It never probes the host or executes an installer.</p>
    </div>
    <div class="inspector-section"><span>Authority boundary</span><p>${item.boundary}</p></div>
    <div class="inspector-section"><span>Next evidence gate</span><p>${item.nextGate}</p></div>
    <div class="inspector-warning">${hasHudLane ? "This tool has a synthetic lane in the HUD. No live tool connection is active." : "This interface is reserved only. MEGALODON does not currently ingest this tool's output."}</div>
    ${hasHudLane ? `<button class="control-button inspector-jump" type="button" data-source-jump="${item.id}">View synthetic lane</button>` : ""}
  `;
  const copyInstall = $("[data-copy-install]");
  if (copyInstall) copyInstall.addEventListener("click", async () => {
    await copyText(acquire.command, copyInstall, "Copied");
  });
  const copyVerify = $("[data-copy-verify]");
  if (copyVerify) copyVerify.addEventListener("click", async () => {
    await copyText(acquire.verificationCommand, copyVerify, "Copied");
  });
  $$('[data-set-presence]').forEach((button) => button.addEventListener('click', () => {
    setToolPresence(item.id, button.dataset.setPresence);
  }));
  const jump = $("[data-source-jump]");
  if (jump) jump.addEventListener("click", () => {
    state.sourceFilter = jump.dataset.sourceJump;
    renderSourceFilters();
    renderEventFeed();
    switchView("hud");
  });
}

async function copyText(value, button, successLabel = "Copied") {
  const original = button.textContent;
  try {
    await navigator.clipboard.writeText(value);
    button.textContent = successLabel;
  } catch {
    const temporary = document.createElement("textarea");
    temporary.value = value;
    temporary.setAttribute("readonly", "");
    temporary.className = "clipboard-fallback";
    document.body.append(temporary);
    temporary.select();
    let copied = false;
    try { copied = document.execCommand("copy"); } catch { /* Ask the operator to select the visible text. */ }
    temporary.remove();
    button.textContent = copied ? successLabel : "Copy unavailable — select text";
  }
  window.setTimeout(() => { button.textContent = original; }, 1600);
}

function renderWorkflow(key) {
  const item = workflows[key];
  if (!item) return;
  $$(".mission").forEach((button) => {
    const active = button.dataset.workflow === key;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  const badge = $("#workflow-status");
  badge.textContent = item.status;
  badge.className = `status-pill ${item.statusClass}`;
  $("#workflow-platform").textContent = item.platform;
  $("#workflow-title").textContent = item.title;
  $("#workflow-summary").textContent = item.summary;
  $("#workflow-command").textContent = item.command;
  $("#workflow-boundary").textContent = item.boundary;
  $("#workflow-produces").replaceChildren(...item.produces.map(listItem));
  $("#workflow-refuses").replaceChildren(...item.refuses.map(listItem));
}

function listItem(text) {
  const li = document.createElement("li");
  li.textContent = text;
  return li;
}

function addSyntheticEvent() {
  const template = eventTemplates[state.tick % eventTemplates.length];
  state.events = [{ ...template, id: `demo-stream-${state.tick}`, run: runForSource[template.source], offset: 0 }, ...state.events.map((event) => ({ ...event, offset: event.offset + 2 }))].filter((event) => event.offset <= 900).slice(0, 128);
}


function tick() {
  if (!state.running || document.hidden || state.activeView !== "hud") return;
  state.tick += 1;
  addSyntheticEvent();
  renderChart();
  renderEventFeed();
}

$$('[data-view]').forEach((button) => { button.setAttribute("aria-label", button.querySelector("span:last-child").textContent); button.addEventListener('click', () => switchView(button.dataset.view)); });
$$('[data-jump]').forEach((button) => button.addEventListener('click', () => switchView(button.dataset.jump)));
$$('.mission').forEach((button) => button.addEventListener('click', () => renderWorkflow(button.dataset.workflow)));

function renderFeedControl() {
  const button = $("#toggle-stream");
  button.textContent = state.running ? "Pause feed" : "Resume feed";
  button.setAttribute("aria-pressed", String(!state.running));
  $(".mode-badge .pulse-dot").classList.toggle("idle", !state.running);
}

$("#toggle-stream").addEventListener("click", () => {
  state.running = !state.running;
  renderFeedControl();
});

$("#time-window").addEventListener("change", (event) => {
  const seconds = Number(event.target.value);
  if (![60, 300, 900].includes(seconds)) return;
  state.windowSeconds = seconds;
  const labels = [1, 0.75, 0.5, 0.25, 0].map((fraction) => { const value = seconds * fraction; if (!value) return "now"; return value < 60 ? `-${value}s` : `-${Math.floor(value / 60)}m${value % 60 ? `${value % 60}s` : ""}`; });
  $$(".chart-time span").forEach((span, index) => { span.textContent = labels[index]; });
  renderChart(); renderEventFeed();
});

$("#event-search").addEventListener("input", (event) => { state.eventSearch = event.target.value.slice(0, 120).trim().toLowerCase(); renderEventFeed(); });
$("#event-disposition").addEventListener("change", (event) => { state.dispositionFilter = event.target.value; renderEventFeed(); });
$("#reset-feed").addEventListener("click", () => { state.sourceFilter = "all"; state.eventSearch = ""; state.dispositionFilter = "all"; $("#event-search").value = ""; $("#event-disposition").value = "all"; renderSourceFilters(); renderEventFeed(); });
$("#readiness-file").addEventListener("change", (event) => importReadinessFile(event.target.files[0]));
$("#clear-readiness").addEventListener("click", () => { readinessImportSequence += 1; state.readiness = null; $("#readiness-file").value = ""; $("#readiness-feedback").textContent = "Report forgotten. No readiness results retained."; $("#clear-readiness").disabled = true; renderIntegrationGrid(); renderToolInspector(); });
$("#clear-tool-notes").addEventListener("click", () => { state.toolPresence = {}; try { localStorage.removeItem(toolPresenceKey); localStorage.removeItem("megalodon-tool-presence-v1"); } catch { /* Current page still clears. */ } renderIntegrationGrid(); renderToolInspector(); });
reducedMotion.addEventListener("change", () => { if (reducedMotion.matches) { state.running = false; renderFeedControl(); } });

$("#copy-command").addEventListener("click", async () => {
  const command = $("#workflow-command").textContent;
  const button = $("#copy-command");
  await copyText(command, button);
});

renderChart();
renderFeedControl();
renderRunEvidence();
renderSourceFilters();
renderEventFeed();
renderDetectionLanes();
renderSourceBars();
renderCategoryFilters();
renderIntegrationGrid();
renderToolInspector();
renderWorkflow("synthetic");
window.setInterval(tick, 1900);
