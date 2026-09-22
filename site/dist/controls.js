const toolAcquisition = {
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
  ossec: {
    source: "OSSEC Project",
    url: "https://www.ossec.net/ossec-downloads/",
    linkLabel: "Open OSSEC downloads",
    platforms: ["Windows agents", "macOS", "Linux", "Unix"],
    commandLabel: null,
    command: null,
    verificationLabel: "Default-path verification",
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
    note: "Nagios Core needs a host-specific installation and plugin plan. MEGALODON has no CGI, credential, or command-pipe access."
  }
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
  },
  "greenbone": {
    "note": "Optional separate scanner. Docker Engine and Compose are required for this container route, not for MEGALODON. Host gvmd absence does not prove containers are absent. This guide targets only the local rootful Docker socket and the documented Greenbone project; stop for a different existing setup.",
    "steps": [
      {
        "title": "Check Docker and Compose",
        "kind": "Client version check",
        "context": "Any directory. Does not contact a daemon or start a container.",
        "command": "command -v docker && docker --version && docker compose version",
        "expected": "Both version strings print. A missing docker group alone is not proof that Engine is absent."
      },
      {
        "title": "Review Docker installation",
        "kind": "Separate host-change decision",
        "context": "Only when the required client/plugin is missing. Use the official signed Ubuntu repository instructions.",
        "url": "https://docs.docker.com/engine/install/ubuntu/",
        "linkLabel": "Open Docker Engine Ubuntu installation",
        "expected": "Installing Docker may start a privileged service and change host networking. Docker-group membership grants root-level access; do not change permissions merely to clear an error."
      },
      {
        "title": "Check the local Docker daemon",
        "kind": "Local daemon read",
        "context": "Any directory; existing authorized access to /var/run/docker.sock is required. This is not a rootless/Desktop/Podman probe.",
        "command": "env -u DOCKER_CONTEXT -u DOCKER_HOST docker --host unix:///var/run/docker.sock info --format '{{.ServerVersion}}'",
        "expected": "Server version means the selected local daemon responded. Permission denied, stopped service and missing packages are different problems; no automatic sudo or service start."
      },
      {
        "title": "Get and review the Compose file",
        "kind": "Separate download and review",
        "context": "Follow the complete guide for $HOME/greenbone-community-edition/compose.yaml before the next check.",
        "expected": "Use the official file, not Markdown-escaped YAML. Review published ports, image sources, mounts and scanner privileges. Keep management ports loopback-only; do not overwrite an existing deployment."
      },
      {
        "title": "Validate reviewed configuration",
        "kind": "Configuration check",
        "context": "Any directory, after reviewing the exact file above. No images pulled or containers started.",
        "command": "env -u DOCKER_CONTEXT -u DOCKER_HOST docker --host unix:///var/run/docker.sock compose --env-file /dev/null --project-name greenbone-community-edition --file \"$HOME/greenbone-community-edition/compose.yaml\" config --quiet",
        "expected": "Silent zero exit means configuration validation only, not installation, health or safety. Stop on an error; do not continue with a partial download."
      },
      {
        "title": "Inspect existing project containers",
        "kind": "Local daemon read",
        "context": "Any directory, after configuration review. Startup is a separate operator decision in the guide, not a check button.",
        "command": "env -u DOCKER_CONTEXT -u DOCKER_HOST docker --host unix:///var/run/docker.sock compose --env-file /dev/null --project-name greenbone-community-edition --file \"$HOME/greenbone-community-edition/compose.yaml\" ps --all",
        "expected": "Rows describe this project only. Empty output is not absence everywhere. Initialization may finish with exit 0; feed readiness and secure login still need separate checks."
      }
    ]
  }
};

/* Shared local/hosted companion controls. Text copying and explicit navigation only. */
const MegalodonControls = (() => {
  const ids = ['core', 'tshark', 'zeek', 'suricata', 'scapy', 'nftables', 'clamav', 'osquery', 'qwen', 'nmap', 'ossec', 'greenbone', 'zabbix', 'nagios'];
  const storageKey = 'megalodon-console-links-v1';
  let memory = null;
  function consoleURL(raw) {
    if (typeof raw !== 'string' || raw.length > 2048 || /[\s\\]/.test(raw)) throw new Error('Use a complete http:// or https:// console address without spaces.');
    const url = new URL(raw);
    if (!['http:', 'https:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.search || url.hash) {
      throw new Error('Use an HTTP(S) address without a password, query, or fragment. Sign in inside the companion console.');
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
        if (data && typeof data === 'object' && !Array.isArray(data)) ids.forEach(id => {
          if (Object.hasOwn(data, id)) { try { memory[id] = consoleURL(data[id]); } catch (_) {} }
        });
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
    const destination = node('p', '', 'companion-destination');
    const editor = node('details', '', 'companion-editor');
    editor.append(node('summary', 'Set console link'));
    const label = node('label', `${name} console address`);
    const input = node('input'); input.type = 'url'; input.maxLength = 2048; input.placeholder = 'http://127.0.0.1:port/'; input.autocomplete = 'off';
    label.append(input);
    const saveButton = node('button', 'Save link'); saveButton.type = 'button';
    const removeButton = node('button', 'Remove link'); removeButton.type = 'button';
    if (typeof options.view === 'function') {
      const view = node('button', 'View in HUD', 'companion-button'); view.type = 'button';
      view.addEventListener('click', () => options.view(id, name, links()[id] || null));
      root.append(view);
    }
    const repaint = () => {
      const url = links()[id]; open.hidden = !url;
      if (url) open.href = url; else open.removeAttribute('href');
      input.value = url || '';
      destination.textContent = url ? `Saved destination: ${url}` : 'Have a web console for this tool? Add its address once.';
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
    root.append(open, destination, editor);
    const acquisition = toolAcquisition[id];
    const publisher = toolPublisherDownloads[id];
    const guide = node('a', `${publisher ? publisher.label : acquisition.linkLabel} ↗`, 'companion-download');
    guide.href = publisher ? publisher.url : acquisition.url; guide.target = '_blank'; guide.rel = 'noopener noreferrer';
    root.append(guide);
    if (publisher) {
      const recipe = node('a', 'MEGALODON setup guidance ↗'); recipe.href = acquisition.url; recipe.target = '_blank'; recipe.rel = 'noopener noreferrer'; root.append(recipe);
    }
    root.append(node('p', 'Opens the publisher or project page in a new tab. Downloading and installation happen outside this HUD.', 'companion-help'));
    if (typeof runLocalChecks === 'function') {
      const check = node('a', 'Check availability in Home →', 'companion-button'); check.href = '#setup-title';
      check.addEventListener('click', () => runLocalChecks(id)); root.append(check);
    }

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
    if (base.variants) {
      const label = node('label', 'Installed Zabbix role');
      const select = node('select'); const placeholder = node('option', 'Choose one role'); placeholder.value = ''; select.append(placeholder);
      Object.entries(base.variants).forEach(([value, entry]) => { const option = node('option', entry.label); option.value = value; select.append(option); });
      select.addEventListener('change', () => renderCommands(select.value)); label.append(select); lifecycle.append(label);
    }
    lifecycle.append(commands); root.append(lifecycle, feedback); parent.append(root);
    repaint(); renderCommands(); return root;
  }
  return {consoleURL, save, links, mount, ids};
})();
if (typeof module !== 'undefined') module.exports = MegalodonControls;
