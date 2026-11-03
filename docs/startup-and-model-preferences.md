# Startup and saved model preferences

Setup → Overview → **After a restart** separates three things:

* **Enable at sign-in** enables the existing managed user HUD unit. It does not
  enable lingering or start a system-wide HUD before login. **Turn off** disables
  future sign-in startup without stopping the current HUD or removing its unit.
* Saved background monitoring resumes TShark and bounded Zeek sampling with the
  saved interface when the HUD starts. Configured Nmap, ClamAV scans and osquery
  resume through the existing collection scheduler. Missing tools, invalid
  scopes and capture-permission failures remain visible in their own status.
* A saved model name, provider digest, compute mode and timeout are restored from
  the private `qwen-profile.json`. Restoration does not require Ollama to answer.
  An invalid saved profile disables AI rather than activating a different
  default. It does not erase the invalid file.

**Check startup** performs bounded, read-only service-manager queries. Page
loads, polling and restart only read the cached startup result; they do not
start, enable, install or probe services through this panel.

**Enable service startup** is a deliberate protected action. It enables and
starts eligible installed Ollama, already-configured passive Suricata and, for
a configured ClamAV folder, the signature updater. That updater downloads virus
definitions according to its existing configuration. The OS may request
authorization. The action uses only compiled unit names and trusted system
executables, with bounded output. It does not install tools, unmask services,
change service contents, run desktop windows or change a firewall.

Ollama supports `ollama.service` and `snap.ollama.listener.service`. The startup
setup prefers the sole active service; ambiguous installations or unavailable
observations refuse selection. Post-action reads report each observed active
and persistent-enable state. Authorization cancellation or partial completion
does not roll back a successful system change or claim that all services worked.
The new protected actions are `startup_check`, `startup_enable`,
`startup_disable` and `startup_services`; each accepts only its action field.
They share the support-configuration origin/session/token and single-job gate.

Lynis/AIDE remain explicit checks, Scapy is the alternative capture backend,
and nftables is an on-demand CLI. They do not need a permanent process.

The model picker retains a labeled saved option until the installed catalog is
explicitly refreshed. That option alone cannot be submitted as a freshly
verified model. Changing selection still rechecks name/digest before saving;
dirty UI edits remain distinct from the durable choice. No localStorage copy,
provider catalog, diagnostic reply or loaded-memory observation is persisted.

Remembering a choice, starting Ollama, and loading/inference are separate.
This change does not alter the release's AI admission state. The existing
keep-ready lifecycle runs only when its admission requirements allow it.
An accepted fixed diagnostic does not supply that admission.

Validation uses isolated saved-profile and service-manager fixtures, protected
HTTP action tests, browser controller tests and synthetic native Chrome layout
checks. These are not evidence that a particular computer rebooted successfully.
After installation, check startup, enable the desired settings, sign out/reboot,
then verify the restored model and current capture/helper states on that PC.

Systemd semantics: [enable/disable and --now](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).
