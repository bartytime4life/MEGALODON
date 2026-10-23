"""Render saved model hypotheses as text, without invoking inference."""
import json
import shutil
import subprocess

import pytest

from megalodon.dashboard_intelligence import KNOWLEDGE_JS, KNOWLEDGE_CSS


def test_comparison_is_scoped_text_and_handles_missing_analysis():
    node = shutil.which('node')
    if node is None:
        pytest.skip('Node required for comparison rendering')
    code = KNOWLEDGE_JS.split(' function comparison(review)', 1)[1].split(' function details(review)', 1)[0]
    script = r'''
const assert=require('node:assert/strict');
function node(tag,text='',cls='') {
  return {tag,text,cls,children:[],append(...values){this.children.push(...values)},
    get textContent(){return this.text+this.children.map(v=>v.textContent).join(' ')},
    set innerHTML(value){throw Error('Unsafe rendering')}};
}
const code=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
eval('function comparison(review)'+code);
const review={what_you_can_do:'Review retained records',analysis:{state:'ready',
  explanation:'<img src=x onerror=alert(1)>',alternative:'Authorized inventory',
  missing:'Operator schedule',citations:['case-one','reference-one']}};
const result=comparison(review);
assert.match(result.textContent,/Authorized inventory/);
assert.match(result.textContent,/Operator schedule/);
assert.match(result.textContent,/case-one/);
assert.equal(result.children[2].children[0].children[1].text,'<img src=x onerror=alert(1)>');
assert.match(result.textContent,/not verified causes/);
for(const state of ['failed','running','cancelled']) {
  assert.doesNotMatch(comparison({...review,analysis:{...review.analysis,state}}).textContent,/Authorized inventory|case-one/);
}
assert.match(comparison({}).textContent,/No completed AI comparison/);
assert.match(comparison({analysis:{state:'ready'}}).textContent,/Not recorded/);
assert.doesNotMatch(comparison({analysis:{state:'ready',explanation:'Second case'}}).textContent,/case-one|Authorized inventory/);
'''
    result = subprocess.run([node, '-e', script], input=json.dumps(code), text=True,
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert 'Advanced · explanations, measurements and sources' in KNOWLEDGE_JS
    assert 'grid-template-columns:1fr' in KNOWLEDGE_CSS
