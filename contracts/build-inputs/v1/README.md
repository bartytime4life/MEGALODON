# MEGALODON build-input inventory v1

inventory.json is a checked-in, deterministic inventory of selected committed
source build inputs. tools/build_input_inventory.py --check verifies it without
network, subprocess, package-resolution, or package-install activity.

The contract is deliberately bounded to the project metadata and the four
reviewed Linux CI requirement profiles. It is not an artifact SBOM, signed
provenance, release receipt, or reproducible-build claim. See
docs/build-input-inventory.md for the complete scope and maintenance rules.
