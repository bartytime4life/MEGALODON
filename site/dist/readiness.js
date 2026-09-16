/* Closed, bounded display schema. A report is an unauthenticated self-report. */
const readinessToolIds = ["python-sqlite", "wireshark-tshark", "zeek", "suricata", "scapy", "nftables", "clamav", "osquery", "qwen-ollama", "nmap", "ossec", "greenbone", "zabbix", "nagios-core"];
const readinessBoundaries = [
  "Executable presence only; installation, version, compatibility, trust and running state are not verified.",
  "Python/SQLite and Scapy availability are not checked by this executable-only report.",
  "No programs executed; no network, model, firewall, configuration changes or database operations performed.",
  "Paths, hostnames, usernames and version strings are omitted; this self-report is not authenticated.",
  "Only Linux PATH entries are probed; invalid or excessive PATH input yields not_checked."
];

function validateReadinessReport(text, now = Date.now()) {
  if (typeof text !== "string" || new TextEncoder().encode(text).byteLength > 8192) throw new Error("Report exceeds the 8 KiB limit.");
  let data;
  try {
    // Inspect JSON tokens before parsing so duplicate keys cannot hide another claim.
    const stack = [];
    for (let index = 0; index < text.length; index += 1) {
      const token = text[index];
      if (token === "{") stack.push(new Set());
      else if (token === "[") stack.push(null);
      else if (token === "}" || token === "]") stack.pop();
      else if (token === '"') {
        const start = index;
        index += 1;
        while (index < text.length && text[index] !== '"') { if (text[index] === "\\") index += 1; index += 1; }
        let following = index + 1;
        while (/\s/.test(text[following] || "x")) following += 1;
        if (text[following] === ":") {
          const keys = stack[stack.length - 1];
          const key = JSON.parse(text.slice(start, index + 1));
          if (!(keys instanceof Set) || keys.has(key)) throw new Error("duplicate key");
          keys.add(key);
        }
      }
      if (stack.length > 4) throw new Error("excessive nesting");
    }
    data = JSON.parse(text);
  } catch { throw new Error("Choose valid JSON without duplicate keys or excessive nesting."); }
  const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
  if (!exactKeys(data, ["schema", "checked_at", "platform", "probe_mode", "tools", "boundaries"]) || data.schema !== "megalodon-tool-readiness-v1" || data.probe_mode !== "path_presence_only" || !["linux", "windows", "other"].includes(data.platform)) throw new Error("Unsupported report schema, platform, or probe mode.");
  if (typeof data.checked_at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(data.checked_at)) throw new Error("Report requires a UTC checked_at timestamp.");
  const checkedAt = Date.parse(data.checked_at);
  if (!Number.isFinite(checkedAt) || new Date(checkedAt).toISOString().replace(".000Z", "Z") !== data.checked_at || checkedAt > now + 300000) throw new Error("Invalid or future readiness timestamp.");
  if (!Array.isArray(data.tools) || data.tools.length !== readinessToolIds.length || !data.tools.every((tool, index) => exactKeys(tool, ["id", "status"]) && tool.id === readinessToolIds[index] && ["executable_found", "not_found", "not_checked"].includes(tool.status) && ((data.platform === "linux" && !["python-sqlite", "scapy"].includes(tool.id)) || tool.status === "not_checked"))) throw new Error("Expected the exact 14-tool presence-only registry.");
  if (!Array.isArray(data.boundaries) || data.boundaries.length !== readinessBoundaries.length || !data.boundaries.every((value, index) => value === readinessBoundaries[index])) throw new Error("Report boundary statements do not match this schema.");
  return data;
}

if (typeof module !== "undefined") module.exports = { validateReadinessReport, readinessToolIds, readinessBoundaries };
