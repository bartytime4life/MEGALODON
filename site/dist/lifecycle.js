/* Reference text only. Nothing in this module executes a command. */
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
      verify: "python3 -m pip show megalodon-defense",
      uninstall: "python3 -m pip uninstall megalodon-defense",
      reinstall: "python3 -m pip install --force-reinstall --no-deps .",
      note: "Activate your MEGALODON virtual environment in every new terminal before using these commands. A different python3 can report Package(s) not found even while the dashboard is running. For reinstall, first change into the reviewed MEGALODON checkout containing pyproject.toml; build dependencies may be downloaded. Package metadata does not verify SQLite support or operational acceptance."
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
    nmap: apt("nmap", "command -v nmap >/dev/null && nmap --version", "No scan is launched by the diagnostic."),
    ossec: {
      verify: "if test -x /var/ossec/bin/ossec-control || test -x /var/ossec/bin/ossec-agentd; then echo 'OSSEC candidate at default prefix'; else exit 1; fi",
      uninstall: null, reinstall: null,
      note: "OSSEC server, agent and source installs have different lifecycle procedures. The installation method and role are unknown here; use the vendor guide matching your installation instead of a combined guessed package list."
    },
    greenbone: {
      verify: "docker compose images",
      uninstall: "docker compose down",
      reinstall: "docker compose pull",
      labels: {verify: "Inspect project images", uninstall: "Remove containers; retain data/images", reinstall: "Refresh images; do not start"},
      note: "Run only in the reviewed Greenbone compose project. Image inventory is not service health or proof of an installed scanner. Down keeps images and named volumes; pull downloads images without starting containers. Neither is a complete uninstall/reinstall. Follow the vendor guide for data-aware removal."
    },
    zabbix: {
      verify: "command -v zabbix_agent2 || command -v zabbix_agentd || command -v zabbix_server",
      uninstall: null, reinstall: null,
      note: "Select the exact installed role first. Each selection targets one package only. Agent 2, classic agent and server are alternatives, not one installation. PATH absence does not prove absence elsewhere.",
      variants: {
        agent2: {...apt("zabbix-agent2", "zabbix_agent2 --version", "Agent 2 only."), label: "Agent 2"},
        agent: {...apt("zabbix-agent", "zabbix_agentd --version", "Classic agent only."), label: "Classic agent"},
        mysql: {...apt("zabbix-server-mysql", "zabbix_server --version", "MySQL server package only; database, frontend and data lifecycle are separate."), label: "Server with MySQL"}
      }
    },
    nagios: {
      verify: "if command -v nagios4 >/dev/null; then nagios4 --version; elif command -v nagios >/dev/null; then nagios --version; elif test -x /usr/local/nagios/bin/nagios; then /usr/local/nagios/bin/nagios --version; else exit 1; fi",
      uninstall: null, reinstall: null,
      note: "Checks the Ubuntu nagios4 executable first, then common source-install names. The linked Nagios Core guide and Ubuntu package represent different installations. Match the actual method and prefix; no generic removal/reinstall is supplied."
    }
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
