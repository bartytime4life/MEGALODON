# Setup controls and model readiness

Setup groups current controls into one selected category. Routine settings use
buttons, selectors and switches; terminal commands, reference material and
uncommon actions remain in Advanced disclosures. Existing Help and app links
open the relevant category and focus their destination.

| Category | Current task |
| --- | --- |
| Overview | Read this computer's status and choose **Check now** for a fresh local metadata check |
| Traffic | Review packet capture, background sensors, device discovery and IP-location settings |
| Local AI | Save a model preference; expand **Knowledge and automatic review** for public references and local-learning choices |
| Apps | Install or configure optional tools; inspect host security and installation-session options |
| Storage | Review evidence limits and retained-history policy |
| Advanced | Local sign-in, launch/data-source commands, installed-tool directories and software references |

If a configuration status refresh fails, the Overview's Traffic and Local AI
summaries show **Unavailable** until a successful check. The saved model choice
and the independently checked app-presence summary keep their own meanings.
An in-flight routine refresh preserves the last displayed status; it is distinct
from a failed check. A successful later check restores the current summaries.

Short exclusive settings use radio choices, saved boolean preferences use visible
On/Off switches, and dynamic lists use dropdowns. History and AI time limits have
sliders beside exact numeric entry. Storage budgets and report times offer common
values plus Custom entry; existing fractional budgets and uncommon times remain
exact. Discovery scopes can be checked individually or edited in Advanced.
Polling preserves unsaved choices. Save, Preview and Apply keep their existing
meaning; moving a slider alone does not apply a restrictive action.

The [Findings workbench](findings-review.md) keeps evidence, local AI interpretation,
assessment and optional response in separate controls.

## Installing a companion

Installed desktop HUD configurations enable `[dashboard] tool_management = true`.
Source launches retain observation mode unless explicitly enabled. The local
page obtains the enabled launch's temporary action nonce through a guarded
same-origin check; no terminal token paste is needed. Package installation still
uses the existing fixed recipes and the operating system's administrator prompt.
No password is sent to or retained by MEGALODON. Reloads reacquire the same
server launch's nonce; restarting the HUD rotates it. Known 403 rejection can
refresh the session and retry the same confirmed fixed install/start once;
ambiguous network failures do not automatically repeat installations.

Lynis installation includes Ubuntu's native daily audit timer. Installing its
package and running an on-demand HUD audit are separate actions. Package presence
is refreshed after an installation; it does not establish a completed audit.

## Keeping the selected model ready

The evaluation release remains `UNBOUND` for ordinary `local_model_runtime`. Saving a
preference, refreshing the fixed local model list or verifying staged files does
not admit model execution. **Keep model ready while HUD is running** cannot load
or renew a model while that binding is held. The separate, explicitly clicked
[Test selected model diagnostic](ollama-response-test.md) is a narrow exception:
it can load the saved model for the fixed READY reply, but it admits no operational
analysis or keep-ready lease. See
[model staging and its activation boundary](model-library.md#remaining-activation-boundary).

With an accepted runtime binding, the keep-ready policy loads the saved local model at startup
and retries after a lost provider connection. The saved model name, digest,
compute mode and response limit remain authoritative. Missing or changed models
are reported, never silently downloaded or replaced. Switching this preference
off restores on-demand loading.

One background worker shares the existing provider admission, request deadline,
concurrency and cancellation controls. Manual requests take priority. It loads
with an empty prompt, verifies the model's runtime allocation, and renews a
five-minute memory lease every two minutes. Retries back off to two minutes.
Stopping the HUD ends renewals; an existing lease can remain for up to five
minutes after the last request. Keeping a large model ready uses its normal RAM
or VRAM allocation; turn the switch off when that memory is needed elsewhere.

Loaded state and the last accepted inference response are shown separately.
Loading alone never claims a verified answer. A fresh successful metadata check
can clear an obsolete connection error while preserving its last-attempt record.

These requests use Ollama's documented [generate endpoint](https://docs.ollama.com/api/generate)
and [model preloading and memory lifetime controls](https://docs.ollama.com/faq).
They start no provider service and perform no model pulls.
