"""Check educational arithmetic against exact ratios and a score-test oracle."""
from fractions import Fraction
import json
from pathlib import Path
import random
import shutil
from statistics import NormalDist
import subprocess

import pytest

from megalodon.dashboard_assets import INDEX_HTML, DASHBOARD_JS
from megalodon.dashboard_security_lab import SECURITY_LAB_JS


def node_results(script):
    node = shutil.which('node')
    if not node:
        pytest.skip('Node is required for security mathematics')
    result = subprocess.run([node, '-e', script], input=SECURITY_LAB_JS,
                            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def score_interval(successes, total):
    """Invert the binomial score test by bisection, independently of the formula."""
    p = successes / total
    z2 = NormalDist().inv_cdf(.975) ** 2
    def accepted(q):
        return (p-q)**2 * total <= z2*q*(1-q)
    bounds = []
    for lo, hi, lower in [(0., p, True), (p, 1., False)]:
        for _ in range(100):
            mid = (lo+hi)/2
            if accepted(mid) == lower:
                hi = mid
            else:
                lo = mid
        bounds.append((lo+hi)/2)
    return bounds


def test_metrics_and_intervals_against_independent_oracles():
    rng = random.Random(20261117)
    rows = [[90,999,10,98901],[9000,900,1000,89100],[1,0,0,999],
            [0,0,0,0],[0,1,0,0],[1,0,0,0],[10**9]*4]
    rows += [[rng.randrange(10**9+1) for _ in range(4)] for _ in range(80)]
    script = "const vm=require('node:vm'),fs=require('node:fs');const c=vm.createContext({document:{getElementById(){return null;}}});vm.runInContext(fs.readFileSync(0,'utf8'),c);console.log(JSON.stringify(vm.runInContext(" + json.dumps(
        'const cases='+json.dumps(rows)+';cases.map(([tp,fp,fn,tn])=>MegalodonSecurityMath.summarize({tp,fp,fn,tn}));') + ",c)));"
    results = node_results(script)
    for (tp,fp,fn,tn), result in zip(rows, results, strict=True):
        total = tp+fp+fn+tn
        assert result['total'] == total and result['alerts'] == tp+fp
        for key, n, d in [('precision',tp,tp+fp),('recall',tp,tp+fn),
                          ('fpr',fp,fp+tn),('accuracy',tp+tn,total)]:
            if not d:
                assert result[key] is None
            else:
                assert result[key] == pytest.approx(float(Fraction(n,d)), abs=1e-15)
        if tp+fp:
            assert result['interval'] == pytest.approx(score_interval(tp,tp+fp), abs=1e-12)
        else:
            assert result['interval'] is None
    assert results[0]['precision'] == pytest.approx(float(Fraction(10,121)))
    assert results[0]['recall'] == results[1]['recall']
    assert results[0]['fpr'] == results[1]['fpr']
    assert results[0]['precision'] < results[1]['precision']
    assert results[2]['interval'][0] == pytest.approx(.20654931437723745)


def test_invalid_counts_and_nonzero_display_boundaries():
    values = node_results(r'''const vm=require('node:vm'),fs=require('node:fs');
const c=vm.createContext({document:{getElementById(){return null;}}});
vm.runInContext(fs.readFileSync(0,'utf8'),c);
console.log(JSON.stringify(vm.runInContext(`
const invalid=[-1,1.5,1000000001,NaN,Infinity,true,'1',null];
const rejected=invalid.every(tp=>{try{MegalodonSecurityMath.summarize({tp,fp:0,fn:0,tn:0});return false;}catch(_){return true;}});
({rejected,low:MegalodonSecurityMath.percent(1/1000000000),high:MegalodonSecurityMath.percent(1-1/1000000000),zero:MegalodonSecurityMath.percent(0),one:MegalodonSecurityMath.percent(1),undefined:MegalodonSecurityMath.percent(null)});
`,c)));''')
    assert values == dict(rejected=True,low='<0.01%',high='>99.99%',zero='0.00%',one='100.00%',undefined='Undefined · no denominator')


def test_lab_is_in_help_and_has_no_effect_interfaces():
    assert INDEX_HTML.count('id="security-lab-title"') == 1
    help_start = INDEX_HTML.index('id="workspace-help"')
    assert INDEX_HTML.index('id="security-lab-title"') > help_start
    assert "'security-lab-title': 'help'" in DASHBOARD_JS
    assert "'host-protection-title': 'live'" in DASHBOARD_JS
    for operation in ('fetch(', 'localStorage', 'sessionStorage', 'setTimeout(', 'innerHTML'):
        assert operation not in SECURITY_LAB_JS
    for target in ('T1046','T1110','T1190','prc241.htm','rfc4632'):
        assert target in INDEX_HTML
