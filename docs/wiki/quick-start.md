# Quick Start

> [See the interface first](visual-tour.md) · [Current scope and open gates](roadmap-and-limits.md). Commands below are run from the root of a reviewed checkout as your ordinary user.

The supported application is a local Linux HUD. Use an ordinary user and owner-private storage. Synthetic core evaluation does not require a cloud account, model, GPU, capture tool or firewall privilege.

## Install or open the Linux app

From a reviewed checkout:

```bash
./Start-MEGALODON.sh
```

The first run installs a private per-user application. Later runs open the existing workspace. The application-menu entry is **MEGALODON**. Normal installed launches start or reuse the user’s local HUD service; a machine without a user service manager uses a foreground fallback. Login autostart is a separate choice. Optional supporting tools are not installed by this entrypoint.

Use `./Start-MEGALODON.sh --check` for installation checks. A reviewed newer checkout can be installed with `./Start-MEGALODON.sh --update`; consult [the local PC guide](https://github.com/bartytime4life/MEGALODON/blob/main/docs/local-pc-setup.md) before upgrading or changing an existing workspace.

## Open a checkout

```bash
./scripts/start-local.sh
```

Use the printed localhost address on the same PC. Follow the launch output for the service/foreground mode and stop instructions. Do not expose the HUD through a tunnel or remote listener.

Start with **Setup** to inspect data/tool configuration and **Sensors** for observed tool status. **Start background tools** is an explicit collection/service workflow. It can start configured tools or ask for OS authorization; opening the HUD or viewing an installed-tool badge does not prove capture is running.

## Learn with synthetic data

Use the repository’s [synthetic installation recipes](https://github.com/bartytime4life/MEGALODON/blob/main/README.md#installation-and-first-run) in a fresh private environment. Sample metadata illustrates the fixed rules and is excluded from qualified network conclusions. Do not reuse real captures as a demo or replace an existing environment just to open the app.

Native Windows remains a separate evaluation target. [Platform baseline](../platform-baseline.md) and [software downloads](../software-downloads.md) describe prerequisites and optional tools.

Continue with the [operator guide](operator-guide.md) and [security boundaries](security-boundaries.md).
