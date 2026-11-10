# Stage 0 source and installed-wheel projection comparison

The dedicated `stage0-package-parity.yml` workflow compares a bounded slice of
Stage 0 behavior at the exact candidate commit/tree. It builds one ephemeral
wheel with the existing hash-locked CPython 3.11 test/backend environment, then
installs that wheel without dependencies or index access into a disposable venv
without pip or system packages. Build and installation are CI setup; they do not
install MEGALODON on the owner's PC or authorize installation elsewhere.

`tools/stage0_package_parity.py` requires a clean, exact checkout before and after
collection. It compares the complete relative package-file/SHA-256 maps of the
source, wheel and installed package, excluding only interpreter caches. It
rejects changed, missing or extra files, symlinks, duplicate/aliased wheel paths,
oversized inputs and mutations observed by its final reread. The checkout must
be Git's top-level directory; its package files must match the tracked inventory,
so an ignored alternate package cannot inherit the repository's source identity.

The collector uses six fresh isolated Python processes: source and installed
identity, `--stage0-offline stage0-status`, and the refused
`--stage0-offline --help`. Every child runs outside the checkout with bytecode
writes disabled. Only the source child inserts the explicitly verified checkout
into its import path. Both lanes use the same interpreter version and isolate
project bytecode-cache lookup to an unused path, preventing existing excluded
caches from supplying project code. The installed child requires a venv, one installed
distribution, a package import under that venv's site-packages, no checkout on
its import path, matching loaded module origins, and pip's local-wheel archive
digest without editable-source provenance. It does not reuse repository tests
whose helpers can insert the source checkout into `sys.path`.

After trusted imports, the invocation guard refuses audited network/process,
database-connection and filesystem-write events, plus Python thread starts.
Both the CLI captures and child output streams are byte-bounded, and each command
has a deadline; failure kills the
disposable process group. These are Python-level regression guards, not an OS
sandbox or protection from arbitrary native code. Import-time setup, package
building, temporary venv installation and evidence-output writes are outside
the invocation guard.

The retained `megalodon-stage0-package-projection-parity-v1` receipt records the
source commit/tree, wheel filename/size/SHA-256, package version and file-map
digest, exact status/denial comparison and probe-output hashes. It contains no
absolute paths or raw child diagnostics. A missing, empty or failed receipt is
unavailable evidence. Partial artifacts are retained on workflow failure; their
presence does not establish a successful comparison.

This is **scoped synthetic projection parity**, not parity for every Stage 0
test, every guarded API or every installation format. No native analyzer,
model, sensor, HUD, service, firewall or owner-host workflow runs in this lane.
Aggregate tripwire counts remain `null`; native lanes and full-suite installed
package parity remain `NOT_RUN`. The separate `stage0-ci-receipt.json` continues
to report `source_package_parity: NOT_RUN`. Independent review, owner acceptance
and all release, deployment, installation, model, detector, response and host
authority remain ungranted. The receipt summarizes CI observations; it does not
authenticate its inputs or independently attest to the workflow.

Run the inert collector tests with the standard library:

```bash
python -I -B -m unittest discover -s tests -p test_stage0_package_parity.py
```

The actual collector additionally requires a clean reviewed checkout, an
ephemeral built wheel and its isolated installed interpreter. Its `--help`
lists those explicit inputs. Dependency downloads occur only during the
workflow's locked setup step; wheel building, installation and probes have no
package-index fallback. Python/pip bootstrap and the hosted runner image remain
outside the existing dependency lock's claims.
