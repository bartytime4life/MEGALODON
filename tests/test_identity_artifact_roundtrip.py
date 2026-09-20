"""Execute the CI consumer verifier on synthetic transport cases, not host evidence."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / '.github/workflows/ci.yml').read_text()
SCRIPT = textwrap.dedent(WORKFLOW.split("python - <<'PYROUNDTRIP'\n", 1)[1].split('          PYROUNDTRIP', 1)[0])
FIXTURE = json.loads((ROOT / 'contracts/release-evidence/v1/fixtures/accepted/synthetic-incomplete.json').read_text())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


@pytest.mark.parametrize('case,expected', [
    ('valid', 'IDENTITY_ROUNDTRIP:VERIFIED_INCOMPLETE'),
    ('changed_bytes', 'IDENTITY_ROUNDTRIP:BYTES_MISMATCH'),
    ('missing_digest', 'IDENTITY_ROUNDTRIP:BYTES_MISMATCH'),
    ('extra_file', 'IDENTITY_ROUNDTRIP:FILE_SET'),
    ('missing_file', 'IDENTITY_ROUNDTRIP:FILE_SET'),
    ('symlink', 'IDENTITY_ROUNDTRIP:FILE_SET'),
    ('wrong_commit', 'SOURCE_MISMATCH'),
    ('wrong_tree', 'SOURCE_MISMATCH'),
    ('synthetic', 'IDENTITY_ROUNDTRIP:STATE_MISMATCH'),
    ('performed_check', 'IDENTITY_ROUNDTRIP:STATE_MISMATCH'),
    ('forged_manifest_digest', 'DIGEST_MISMATCH'),
])
def test_ci_consumer_verifies_transport_and_keeps_evidence_incomplete(tmp_path, case, expected):
    # Simulated identity only: this test never creates a real host receipt.
    manifest = deepcopy(FIXTURE)
    manifest['basis'] = 'local_checkout'
    if case == 'synthetic':
        manifest['basis'] = 'synthetic_contract_fixture'
    if case == 'performed_check':
        manifest['checks'][0].update(status='passed', result_sha256='sha256:' + 'a' * 64)
    wrapper = {
        'schema_version': 'ubuntu-24.04-evidence-validation-v1',
        'status': 'validated',
        'manifest_sha256': 'sha256:' + hashlib.sha256(canonical(manifest)).hexdigest(),
        'manifest': manifest,
    }
    if case == 'forged_manifest_digest':
        wrapper['manifest_sha256'] = 'sha256:' + '0' * 64
    directory = tmp_path / 'identity-roundtrip'
    directory.mkdir()
    packet = directory / 'ubuntu-24.04-incomplete-identity.json'
    raw = canonical(wrapper) + b'\n'
    packet.write_bytes(raw)
    env = {
        **os.environ,
        'RUNNER_TEMP': str(tmp_path),
        'EXPECTED_PACKET_SHA256': hashlib.sha256(raw).hexdigest(),
        'EXPECTED_COMMIT': manifest['source']['observed_commit'],
        'EXPECTED_TREE': manifest['source']['observed_tree'],
    }
    if case == 'changed_bytes':
        packet.write_bytes(raw + b' ')
    if case == 'missing_digest':
        env['EXPECTED_PACKET_SHA256'] = ''
    if case == 'extra_file':
        (directory / 'unexpected.json').write_text('{}')
    if case == 'missing_file':
        packet.unlink()
    if case == 'symlink':
        target = tmp_path / 'target.json'
        packet.rename(target)
        packet.symlink_to(target)
    if case == 'wrong_commit':
        env['EXPECTED_COMMIT'] = 'f' * 40
    if case == 'wrong_tree':
        env['EXPECTED_TREE'] = 'e' * 40
    result = subprocess.run(
        [sys.executable, '-c', SCRIPT], cwd=ROOT, env=env,
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5,
    )
    if case == 'valid':
        assert result.returncode == 0
        assert result.stdout.strip() == expected
        assert result.stderr == ''
    else:
        assert result.returncode != 0
        assert result.stdout == ''
        assert expected in result.stderr
