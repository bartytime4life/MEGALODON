"""Shared inert companion controls, canonical for local and hosted HUDs.

Run scripts/sync-hud-assets.py after editing. Import performs no I/O.
"""

LIFECYCLE_JS = r"""/* Reference text only. Nothing in this module executes a command. */
const localPythonLifecycle = null;
const lifecycleCommands = (() => {
  const apt = (pkg, verify, note) => ({
    verify,
    uninstall: `sudo apt-get remove ${pkg}`,
    reinstall: `sudo apt-get install --reinstall ${pkg}`,
    note: `Ubuntu package installation only; confirm this exact package is your installed component. Installation may start services or access package repositories. ${note}`
  });
  return {
    core: {
      verify: "~/.local/bin/megalodon-manage status",
      uninstall: "~/.local/bin/megalodon-manage uninstall",
      reinstall: "./scripts/install-local.sh",
      note: "The user installer manages a private release and preserves settings and data on uninstall. Run reinstall from the reviewed checkout. These commands do not install or remove optional companions."
    },
    tshark: apt("tshark", "test -x /usr/bin/tshark && /usr/bin/tshark --version", "Use the repository's guarded setup; do not grant capture permissions."),
    zeek: {
      verify: "command -v zeek",
      uninstall: null, reinstall: null,
      note: "The repository guide builds a pinned release into a private prefix. A generic apt command would target a different installation. Use the recorded build/prefix and vendor instructions; PATH absence does not establish absence from a private prefix."
    },
    suricata: apt("suricata", "command -v suricata >/dev/null && suricata --build-info", "Does not select suricata-update or enable a MEGALODON sensor. Review service behavior first."),
    scapy: {
      verify: "python3 -m pip show scapy",
      uninstall: "python3 -m pip uninstall scapy",
      reinstall: "python3 -m pip install --force-reinstall 'scapy>=2.5,<3'",
      note: "Use the MEGALODON virtual environment and its approved package source. This may download packages; it grants no capture privilege. The version range is not a pinned artifact."
    },
    nftables: apt("nftables", "if command -v nft >/dev/null; then nft --version; elif test -x /usr/sbin/nft; then /usr/sbin/nft --version; else exit 1; fi", "Removing or reinstalling firewall software can affect host protection. These commands are not MEGALODON response actions."),
    clamav: apt("clamav", "command -v clamscan >/dev/null && clamscan --version", "Scanner package only. No explicit daemon/freshclam package selection; dependencies and service effects still require review."),
    osquery: apt("osquery", "command -v osqueryi >/dev/null && osqueryi --version", "Confirm the signed vendor repository and installed package; no query is issued."),
    qwen: {
      verify: "OLLAMA_HOST=127.0.0.1:11434 ollama list | awk '$1 == \"qwen2.5:7b\" { found=1 } END { exit !found }'",
      uninstall: "OLLAMA_HOST=127.0.0.1:11434 ollama rm qwen2.5:7b",
      reinstall: "OLLAMA_HOST=127.0.0.1:11434 ollama pull qwen2.5:7b",
      labels: {verify: "Check example model tag", uninstall: "Remove example model", reinstall: "Download example model"},
      note: "Example tag only: all three operations target qwen2.5:7b. This mutable tag is not the approved registry or an artifact digest. Commands contact the local provider; pull can download from the Internet. They neither install/remove Ollama nor establish model containment."
    },
    nmap: apt("nmap", "command -v nmap >/dev/null && nmap --version", "No scan is launched by the diagnostic.")
  };
})();

function resolveLifecycle(id, variant) {
  const defaults = lifecycleCommands[id];
  if (!defaults) throw new Error("Unknown integration");
  const base = localPythonLifecycle && Object.hasOwn(localPythonLifecycle, id)
    ? {...defaults, ...localPythonLifecycle[id]} : defaults;
  const selected = base.variants && Object.hasOwn(base.variants, variant) ? base.variants[variant] : null;
  return selected ? {...base, ...selected} : base;
}

if (typeof module !== "undefined") module.exports = {lifecycleCommands, resolveLifecycle};
"""

READINESS_JS = r"""/* Closed, bounded display schema. A report is an unauthenticated self-report. */
const readinessToolIds = ["python-sqlite", "wireshark-tshark", "zeek", "suricata", "scapy", "nftables", "clamav", "osquery", "qwen-ollama", "nmap"];
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
  if (data && data.schema === "megalodon-tool-readiness-v1") throw new Error("Old readiness report. Run python -m megalodon readiness again and import the new v2 report.");
  if (!exactKeys(data, ["schema", "checked_at", "platform", "probe_mode", "tools", "boundaries"]) || data.schema !== "megalodon-tool-readiness-v2" || data.probe_mode !== "path_presence_only" || !["linux", "windows", "other"].includes(data.platform)) throw new Error("Unsupported report schema, platform, or probe mode.");
  if (typeof data.checked_at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(data.checked_at)) throw new Error("Report requires a UTC checked_at timestamp.");
  const checkedAt = Date.parse(data.checked_at);
  if (!Number.isFinite(checkedAt) || new Date(checkedAt).toISOString().replace(".000Z", "Z") !== data.checked_at || checkedAt > now + 300000) throw new Error("Invalid or future readiness timestamp.");
  if (!Array.isArray(data.tools) || data.tools.length !== readinessToolIds.length || !data.tools.every((tool, index) => exactKeys(tool, ["id", "status"]) && tool.id === readinessToolIds[index] && ["executable_found", "not_found", "not_checked"].includes(tool.status) && ((data.platform === "linux" && !["python-sqlite", "scapy"].includes(tool.id)) || tool.status === "not_checked"))) throw new Error("Expected the exact 10-tool presence-only registry.");
  if (!Array.isArray(data.boundaries) || data.boundaries.length !== readinessBoundaries.length || !data.boundaries.every((value, index) => value === readinessBoundaries[index])) throw new Error("Report boundary statements do not match this schema.");
  return data;
}

if (typeof module !== "undefined") module.exports = { validateReadinessReport, readinessToolIds, readinessBoundaries };
"""

CONTROLS_JS = r"""const toolAcquisition = {
  core: {
    source: "MEGALODON repository",
    url: "https://github.com/bartytime4life/MEGALODON#ubuntu-2404-local-evaluation-setup",
    linkLabel: "Open bounded Ubuntu setup",
    platforms: ["Ubuntu 24.04 reference", "Windows evaluation"],
    commandLabel: null,
    command: null,
    verificationLabel: "Linux verification",
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
    note: "MEGALODON does not launch scans. The reserved boundary is a future completed XML report import only."
  },
};

// Publisher pages are separate from repository-specific integration recipes.
const toolPublisherDownloads = {
  tshark: {url: 'https://www.wireshark.org/download.html', label: 'Wireshark / TShark downloads'},
  zeek: {url: 'https://zeek.org/get-zeek/', label: 'Zeek downloads'},
  nftables: {url: 'https://netfilter.org/projects/nftables/index.html', label: 'nftables install guide'}
};

// Fixed copy-only setup recipes. These are not installation observations.
const companionSetupGuide = "https://github.com/bartytime4life/MEGALODON/blob/f6d25ad336623fceee9cd9726092fbe8a7a82cb6/docs/companion-setup.md";
const companionSetupGuides = {
  "scapy": {
    "note": "Optional Python package, not required to open MEGALODON. Linux is supported. The PATH-only check intentionally leaves Scapy not checked. Choose the environment before installing; a standalone environment is not the HUD environment. Commands below run only when you paste them into a terminal.",
    "steps": [
      {
        "title": "Check HUD Python package",
        "kind": "Package metadata check",
        "context": "Local HUD: any directory, using the serving interpreter. Hosted Site: activate your reviewed MEGALODON environment first.",
        "currentPython": true,
        "expected": "Package information means Scapy metadata exists only in that Python environment. A missing-package message is not proof of absence elsewhere. No capture or import test is performed."
      },
      {
        "title": "Prepare standalone Python tools",
        "kind": "Optional host change",
        "context": "Ubuntu 24.04, normal terminal, any directory. Skip when python3-venv is already installed.",
        "command": "sudo apt update && sudo apt install python3-venv",
        "expected": "Review the apt prompt. This accesses package repositories; it does not install Scapy or grant capture privileges."
      },
      {
        "title": "Create standalone environment",
        "kind": "Optional local files",
        "context": "Any directory. Uses $HOME/scapy/.venv, not the MEGALODON desktop release.",
        "command": "if test -e \"$HOME/scapy/.venv\" || test -L \"$HOME/scapy/.venv\"; then\n  printf '%s\\n' 'Environment already exists. Inspect it first; nothing was replaced.'\nelse\n  python3 -m venv \"$HOME/scapy/.venv\"\nfi",
        "expected": "A new environment is created, or an existing path is left alone. Inspect an existing environment rather than recreating it."
      },
      {
        "title": "Install standalone Scapy",
        "kind": "Optional package download",
        "context": "Any directory, only after checking that the standalone environment is the one you intend to modify.",
        "command": "\"$HOME/scapy/.venv/bin/python\" -m pip install 'scapy>=2.5,<3'",
        "expected": "Scapy is installed into the standalone environment only. The version range is not a pinned artifact. No sudo pip, live capture or packet sending."
      },
      {
        "title": "Check standalone package",
        "kind": "Package metadata check",
        "context": "Any directory. Does not check the separate HUD Python environment.",
        "command": "\"$HOME/scapy/.venv/bin/python\" -I -c \"from importlib.metadata import version; print('Scapy package:', version('scapy'))\"",
        "expected": "A version prints. Missing interpreter and PackageNotFoundError have different causes; use the guide below. A successful copy is not a successful check."
      }
    ]
  }
};

/* Shared local/hosted companion controls. Text copying and explicit navigation only. */
const MegalodonControls = (() => {
  const ids = ['core', 'tshark', 'zeek', 'suricata', 'scapy', 'nftables', 'clamav', 'osquery', 'qwen', 'nmap'];
  const localConsoleSuggestions = Object.freeze({});
  const storageKey = 'megalodon-console-links-v1';
  let memory = null;
  function consoleURL(raw) {
    if (typeof raw !== 'string' || raw.length > 2048 || /[\s\\]/.test(raw)) throw new Error('Use a complete http:// or https:// console address without spaces.');
    const url = new URL(raw);
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.search || url.hash) {
      throw new Error('Use an HTTP(S) address without a password, query, or fragment.');
    }
    return url.href;
  }
  function links() {
    if (memory !== null) return memory;
    memory = {};
    try {
      const raw = localStorage.getItem(storageKey);
      if (raw && raw.length <= 32768) {
        const data = JSON.parse(raw);
        if (data && typeof data === 'object' && !Array.isArray(data)) {
          ids.forEach(id => {
            if (Object.hasOwn(data, id)) { try { memory[id] = consoleURL(data[id]); } catch (_) {} }
          });
          if (Object.hasOwn(data, 'ossec') || Object.hasOwn(data, 'zabbix')) {
            localStorage.setItem(storageKey, JSON.stringify(memory));
          }
        }
      }
    } catch (_) { /* Session-only operation remains available. */ }
    return memory;
  }
  function save(id, raw) {
    if (!ids.includes(id)) throw new Error('Unknown companion tool.');
    const value = raw ? consoleURL(raw) : null;
    const data = links();
    if (value) data[id] = value; else delete data[id];
    try { localStorage.setItem(storageKey, JSON.stringify(data)); return true; }
    catch (_) { return false; }
  }
  const node = (tag, text, className) => {
    const element = document.createElement(tag);
    if (text) element.textContent = text;
    if (className) element.className = className;
    return element;
  };
  function mount(parent, id, name, options = {}) {
    if (!ids.includes(id)) throw new Error('Unknown companion tool.');
    const root = node('section', '', 'companion-controls');
    root.setAttribute('aria-label', `${name} controls`);
    const feedback = node('p', '', 'companion-feedback'); feedback.setAttribute('role', 'status');
    const open = node('a', 'Open companion console ↗', 'companion-button');
    open.target = '_blank'; open.rel = 'noopener noreferrer'; open.referrerPolicy = 'no-referrer';
    const suggestedURL = options.local === true ? localConsoleSuggestions[id] || null : null;
    const suggested = node('a', 'Open suggested local console ↗', 'companion-button companion-button-primary');
    suggested.target = '_blank'; suggested.rel = 'noopener noreferrer'; suggested.referrerPolicy = 'no-referrer';
    if (suggestedURL) suggested.href = suggestedURL;
    const destination = node('p', '', 'companion-destination');
    const editor = node('details', '', 'companion-editor');
    editor.append(node('summary', 'Set console link'));
    const label = node('label', `${name} console address`);
    const input = node('input'); input.type = 'url'; input.maxLength = 2048; input.placeholder = 'http://127.0.0.1:port/'; input.autocomplete = 'off';
    label.append(input);
    const saveButton = node('button', 'Save link'); saveButton.type = 'button';
    const removeButton = node('button', 'Remove link'); removeButton.type = 'button';
    let view = null;
    if (typeof options.view === 'function') {
      view = node('button', 'View in HUD', 'companion-button'); view.type = 'button';
      view.addEventListener('click', () => options.view(id, name, links()[id] || suggestedURL || null));
      root.append(view);
    }
    const repaint = () => {
      const url = links()[id]; open.hidden = !url;
      if (url) open.href = url; else open.removeAttribute('href');
      suggested.hidden = !suggestedURL || Boolean(url);
      input.value = url || '';
      destination.textContent = url ? `Saved destination: ${url}`
        : suggestedURL ? `Suggested local address: ${suggestedURL} Fixed suggestion; not checked or saved.`
        : 'Have a web console for this tool? Add its address once.';
      if (view) view.textContent = url ? 'View saved console in HUD'
        : suggestedURL ? 'View suggested console in HUD' : 'View in HUD';
      removeButton.disabled = !url;
    };
    saveButton.addEventListener('click', () => {
      try {
        const persistent = save(id, input.value.trim()); repaint();
        feedback.textContent = persistent ? 'Link saved in this browser. No connection was tested.' : 'Link kept for this page only; browser storage is unavailable.';
        editor.open = false;
        (open.hidden ? editor.querySelector('summary') : open).focus();
        if (typeof options.changed === 'function') options.changed(id);
      } catch (error) { feedback.textContent = error.message; input.focus(); }
    });
    removeButton.addEventListener('click', () => { save(id, ''); repaint(); feedback.textContent = 'Console link removed.'; input.focus(); if (typeof options.changed === 'function') options.changed(id); });
    editor.append(label, saveButton, removeButton, node('p', 'Saved only in this browser and origin. Do not paste credentials. Opens the actual companion app in a new tab; it is not a data connection.', 'companion-help'));
    root.append(open);
    if (suggestedURL) root.append(suggested);
    root.append(destination, editor);
    const acquisition = toolAcquisition[id];
    const publisher = toolPublisherDownloads[id];
    const guide = node('a', `${publisher ? publisher.label : acquisition.linkLabel} ↗`, 'companion-download');
    guide.href = publisher ? publisher.url : acquisition.url; guide.target = '_blank'; guide.rel = 'noopener noreferrer';
    root.append(guide);
    if (publisher) {
      const recipe = node('a', 'MEGALODON setup guidance ↗'); recipe.href = acquisition.url; recipe.target = '_blank'; recipe.rel = 'noopener noreferrer'; root.append(recipe);
    }
    root.append(node('p', 'Opens the publisher or project page in a new tab. In the local HUD, use Install where a one-click package exists.', 'companion-help'));
    if (typeof runLocalChecks === 'function') {
      const check = node('a', 'Check availability in Home →', 'companion-button'); check.href = '#setup-title';
      check.addEventListener('click', () => runLocalChecks(id)); root.append(check);
    }

    const unified = node('details', '', 'companion-unified-setup');
    unified.append(node('summary', 'Install, configure, verify and uninstall'));
    unified.append(node('p', 'From the reviewed checkout, this single script previews fixed install/removal recipes. Add --apply only in your terminal after review; uninstall needs typed confirmation. Configure prints tool-specific steps; verify checks executable presence only.', 'companion-help'));
    ['plan', 'install', 'configure', 'verify', 'uninstall'].forEach(action => {
      const command = `./scripts/manage-companion.sh ${id} ${action}`;
      const row = node('div', '', 'companion-command');
      const copy = node('button', `Copy ${action}`); copy.type = 'button';
      copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(command); feedback.textContent = 'Command copied. Run it in your local MEGALODON environment.'; }
        catch (_) { feedback.textContent = 'Select and copy the displayed command.'; }
      });
      row.append(node('code', command), copy); unified.append(row);
    });
    root.append(unified);

    const setup = companionSetupGuides[id];
    if (setup) {
      const easy = node('details', '', 'companion-setup');
      easy.append(node('summary', 'Easy setup and verification'));
      easy.append(node('p', setup.note, 'companion-help'));
      const walkthrough = node('a', 'Open complete setup and troubleshooting ↗', 'companion-button');
      walkthrough.href = companionSetupGuide; walkthrough.target = '_blank';
      walkthrough.rel = 'noopener noreferrer'; walkthrough.referrerPolicy = 'no-referrer';
      easy.append(walkthrough);
      setup.steps.forEach((step, index) => {
        const row = node('div', '', 'companion-command');
        row.append(node('strong', `${index + 1}. ${step.title}`));
        row.append(node('p', `${step.kind}. ${step.context}`, 'companion-help'));
        const command = step.currentPython ? resolveLifecycle('scapy').verify : step.command;
        if (command) {
          const code = node('code', command);
          const copy = node('button', `Copy step ${index + 1}: ${step.title}`);
          copy.type = 'button';
          copy.addEventListener('click', async () => {
            try {
              await navigator.clipboard.writeText(command);
              feedback.textContent = 'Step copied, not executed or verified. Review it in your terminal before running.';
            } catch (_) {
              feedback.textContent = 'Clipboard unavailable. Select and copy the displayed command. No check was run.';
            }
          });
          row.append(code, copy);
        }
        if (step.url) {
          const link = node('a', `${step.linkLabel} ↗`);
          link.href = step.url; link.target = '_blank'; link.rel = 'noopener noreferrer';
          link.referrerPolicy = 'no-referrer'; row.append(link);
        }
        row.append(node('p', `Expected result: ${step.expected}`, 'companion-help'));
        easy.append(row);
      });
      root.append(easy);
    }

    const lifecycle = node('details', '', 'companion-lifecycle');
    lifecycle.append(node('summary', 'Advanced: terminal checks and maintenance'));
    const commands = node('div');
    const renderCommands = variant => {
      commands.replaceChildren();
      const entry = resolveLifecycle(id, variant);
      commands.append(node('p', entry.note, 'companion-help'));
      [['verify', entry.labels?.verify || 'Verify'], ['reinstall', entry.labels?.reinstall || 'Reinstall'], ['uninstall', entry.labels?.uninstall || 'Remove']].forEach(([key, title]) => {
        if (!entry[key]) return;
        const row = node('div', '', 'companion-command');
        const code = node('code', entry[key]);
        const copy = node('button', `Copy ${title.toLowerCase()}`); copy.type = 'button';
        copy.addEventListener('click', async () => {
          try { await navigator.clipboard.writeText(entry[key]); feedback.textContent = `${title} command copied. Review it in your terminal before running.`; }
          catch (_) { feedback.textContent = 'Clipboard unavailable. Select and copy the command shown above.'; }
        });
        row.append(node('strong', title), code, copy); commands.append(row);
      });
      if (!entry.uninstall || !entry.reinstall) commands.append(node('p', 'Removal or reinstall depends on your installation method. Use the matching vendor instructions.', 'companion-help'));
    };
    const base = resolveLifecycle(id);
    lifecycle.append(commands); root.append(lifecycle, feedback); parent.append(root);
    repaint(); renderCommands(); return root;
  }
  return {consoleURL, save, links, mount, ids};
})();
if (typeof module !== 'undefined') module.exports = MegalodonControls;
"""

CONTROLS_CSS = r""".companion-controls { margin: 1rem 0; min-width: 0; font-size: .875rem; line-height: 1.55; }
.companion-controls [hidden] { display: none !important; }
.companion-controls a, .companion-controls button { display: inline-flex; align-items: center; min-height: 44px; padding: .6rem .85rem; border: 1px solid #38627a; border-radius: .5rem; background: #122938; color: #a8eeff; text-decoration: none; font: inherit; cursor: pointer; margin: .2rem .35rem .2rem 0; }
.companion-controls .companion-button-primary { border-color: #6acabb; background: #163c39; color: #dcfff8; font-weight: 700; }
.companion-controls button:disabled { opacity: .55; cursor: default; }
.companion-controls :focus-visible { outline: 2px solid #5be2fa; outline-offset: 3px; }
.companion-controls details { border-top: 1px solid #2a4355; margin-top: .6rem; padding-top: .35rem; }
.companion-controls summary { cursor: pointer; min-height: 44px; padding: .65rem 0; color: #c8e7f1; font-size: .875rem; }
.companion-controls label { display: grid; gap: .4rem; margin: .5rem 0; }
.companion-controls input, .companion-controls select { width: 100%; min-width: 0; min-height: 44px; padding: .7rem; border: 1px solid #38627a; border-radius: .5rem; background: #081722; color: #f0f8fc; font: inherit; }
.companion-help, .companion-destination { color: #adc1d0; overflow-wrap: anywhere; font-size: .875rem; }
.companion-command { display: grid; gap: .5rem; padding: .7rem 0; }
.companion-command code { display: block; white-space: pre-wrap; overflow-wrap: anywhere; background: #06121c; color: #d6f5ff; padding: .75rem; border-radius: .5rem; font-size: .875rem; }
.companion-command button { justify-self: start; }
.companion-feedback { color: #9fe9f5; min-height: 1.4rem; }
.hud-start { display: grid; grid-template-columns: 1.25fr 1fr; gap: 1.2rem; padding: 1.5rem; margin: 1rem 0; border: 1px solid #31566b; border-radius: 1rem; background: linear-gradient(120deg, #102d3c, #0b1928); }
.hud-start h2 { font-size: 1.4rem; margin: 0 0 .5rem; }
.hud-start p { font-size: 1rem; line-height: 1.65; color: #bfd1dc; }
.hud-start .start-actions { display: flex; gap: .6rem; flex-wrap: wrap; align-items: center; }
.hud-start a { color: #91e4f5; }
.hud-start code { display: block; padding: 1rem; border-radius: .5rem; background: #05121b; color: #d5faff; overflow-wrap: anywhere; font-size: 1rem; }
.hud-start button, .hud-start .start-link { min-height: 44px; padding: .75rem 1rem; font-size: .95rem; border-radius: .5rem; border: 1px solid #38627a; background: #173849; color: #d9faff; cursor: pointer; text-decoration: none; }
.hud-start .start-link { background: #85e3f2; color: #092532; font-weight: 750; }
.hud-start details { margin-top: .7rem; color: #adc1d0; }
.hud-start summary { cursor: pointer; min-height: 44px; padding: .5rem 0; }
.hud-tool-search { display: flex; flex-wrap: wrap; gap: .8rem; align-items: end; margin: 1rem 0; }
.hud-tool-search label { display: grid; gap: .4rem; flex: 1 1 200px; font-size: .875rem; }
.hud-tool-search input, .hud-tool-search select { padding: .75rem; min-height: 44px; font: inherit; color: #def1f8; background: #102535; border: 1px solid #38627a; border-radius: .5rem; }
@media (max-width: 760px) { .hud-start { grid-template-columns: 1fr; padding: 1rem; } }
"""
