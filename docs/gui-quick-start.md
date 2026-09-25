# Start with the visual workspace

Open MEGALODON, check what is available, then choose the task you need. You can
read saved data and make reports without installing every companion tool.

## 1. Install and open the workspace

From your reviewed Linux checkout, run `./scripts/install-local.sh`, then open
**MEGALODON** from the application menu. The desktop launcher opens the browser
after the loopback server binds. Keep its terminal open while you work;
**Ctrl+C** stops the server.

To try the checkout without installing it, run `./scripts/start-local.sh` and
open the printed local address (normally <http://127.0.0.1:8787/>).

If Python is missing or startup fails, use [software downloads](software-downloads.md)
and [startup troubleshooting](local-pc-setup.md#troubleshooting). The browser
interface becomes available after the local server starts.

## 2. Check this computer

On **Home**, open **Data and tools**. Every optional tool has a status light
next to its name, refreshed in the background while the tab is visible:

| Light | Meaning | Next step |
| --- | --- | --- |
| Green | Installed; a service tool is also running (the detail line shows uptime) | Nothing to do |
| Amber | Installed, but its service is stopped (for Qwen, possibly the model is not downloaded yet) | Select **Start service** or **Download Qwen model** |
| Red | Not installed | Select **Install**, or open the official guide for tools without a one-click package |
| Grey | Unknown on this computer | Use the official guide or the terminal checks under Apps |

This table and the one below cover the most common statuses. For every status
word MEGALODON shows, anywhere in the HUD, open **Help → Full status
glossary**.

See [tool heartbeat and one-click install](tool-heartbeat.md) for what each
button runs. For the environment and data file, select **Check this computer**:

| Result | What it tells you | Next step |
| --- | --- | --- |
| Python and SQLite versions | Which runtime is serving this workspace | Use these versions when troubleshooting an environment mismatch |
| Data available | The selected audit file passed a bounded read | Open Traffic or Findings to see whether it contains qualified observations |
| Data not configured | There was no data file when this HUD started | Use an existing configuration or authorized import, then restart the HUD |
| Data unavailable | The selected file could not pass the check | Preserve the file and follow the storage troubleshooting guide |
| Executable found | A known tool name was found on the server's PATH | Review that tool's workflow; presence alone does not connect its data |
| Not found / not checked | The check cannot establish availability | Open the official installation guide; a private or container install may be outside the check |
| Process observed | A known process name was seen | Treat this as an observation, not a health or configuration test |

The check runs when you click. It never launches the listed programs. Checks
within five seconds share a result; the displayed timestamp shows when the
observation was made. A failed check is shown as unavailable or stale. Download
the check report from the same panel when you need a local troubleshooting
record. The report includes runtime versions and tool states, not private paths
or traffic. It differs from the standalone readiness-only JSON import format.

## 3. Get only the software you need

The software list starts with essentials. Choose a workflow or search for a
program to see its purpose, status light and buttons. **Install** installs the
fixed Ubuntu package, or the Python package for this HUD, after your computer's
password prompt; MEGALODON never sees the password. Zeek, osquery, OSSEC and
Greenbone need a vendor repository, a role choice or a multi-container setup, so
they link to their official guides instead. Download links open the publisher's
page in a new tab.

Python is required. Git helps obtain and maintain a checkout. SQLite is included
with the standard Python runtime. Wireshark, Zeek, Suricata and the remaining
tools are optional. [The download directory](software-downloads.md) explains
which workflows are connected to MEGALODON and which are separate companions.

## 4. Choose your next task

| I want to… | Go here |
| --- | --- |
| Understand the current data source | **Home → Data and tools** |
| Inspect saved traffic and change the time range | **Traffic**; choose a range and apply it |
| Review linked detections | **Findings** |
| Find downloads or inspect an integration | **Home → Data and tools**, or **Apps** |
| Open a companion's saved web console | **Apps**; configure its explicit console link |
| Preview and download a local report | **Reports** |
| Inspect sample/unlinked audit history or offline evidence | **Evidence** |
| Understand a status or recover from a problem | **Help** |

**No qualified data** is a useful result: the current selection has no admitted
observations. A sample-only audit file can still be readable. Installing a tool
does not start collection or fill Traffic and Findings automatically.

## What you can do here, and what still needs a terminal

Use buttons to check the environment and tools, install supported companion
packages, start their services, refresh saved metadata, inspect time ranges,
look up reference data, preview/download reports and open official download
pages. These actions do not require copying diagnostic commands.

The one-time MEGALODON install, guided companion installs (Zeek, osquery, OSSEC,
Greenbone), importing data,
starting an authorized capture, and changing the server's source remain explicit
local operations. After installation, the application-menu entry handles normal
startup and browser opening. **Change data for the next launch** prepares and copies a
quoted command. It takes effect after you stop and relaunch the HUD; typing a
path into the form does not open that file.

The [hosted reference console](../site/README.md) has no connection to this PC.
Its download links and local report import are useful, but status lights,
installs and local machine checks run only in the localhost HUD. Linux is the reference platform; see the
[platform baseline](platform-baseline.md) for Windows evaluation and other limits.
