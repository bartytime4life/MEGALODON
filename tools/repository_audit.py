"""Reproducible file dispositions and static HUD controls, without host telemetry.

Reads tracked and non-ignored new files. This is an inventory/static review,
not a claim that every line received independent security or visual acceptance.
"""
from __future__ import annotations
import argparse
import ast
from collections import Counter
from hashlib import sha256
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT=Path(__file__).resolve().parents[1]
BASE='4b5f8f8'
OUTPUT='docs/audit/repository-files.json'
HISTORICAL=('review-2026','alignment-2026','source-alignment','evidence-alignment-review','ai-host-observation','owner-decision-packet','license-decision-','currentness','benchmarks/')

def git(*args):
    return subprocess.check_output(['git',*args],cwd=ROOT).decode()

def inspect_file(name,changed):
    path=ROOT/name
    if not path.exists():
        return dict(path=name,classification='retired',purpose='Former hosted UI or duplicate helper',dependencies=[],disposition='retired; recoverable in '+BASE,verification='Git preservation commit')
    raw=path.read_bytes();notes=[];deps=[];purpose=path.stem.replace('_',' ').replace('-',' ')
    kind=('historical' if name.endswith('.md') and any(x in name for x in HISTORICAL) else
          'fixture-or-contract' if name.startswith(('contracts/','examples/','megalodon/reference/')) else
          'test' if name.startswith('tests/') else 'documentation' if path.suffix=='.md' else
          'workflow' if name.startswith('.github/') else 'source' if path.suffix in {'.py','.js','.cjs','.mjs','.sh'} else
          'asset' if path.suffix in {'.svg','.png'} else 'configuration')
    try:
        if path.suffix=='.py':
            tree=ast.parse(raw,filename=name);notes.append('Python AST parsed')
            purpose=(ast.get_docstring(tree) or purpose).split('\n')[0][:240]
            deps=sorted({('.'*n.level+(n.module or '')) for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)}|{a.name for n in ast.walk(tree) if isinstance(n,ast.Import) for a in n.names})
        elif path.suffix in {'.json','.jsonl'}:
            # The example input explicitly permits comment lines; contract
            # fixtures still receive strict JSON parsing.
            values=[json.loads(line) for line in raw.splitlines() if line.strip() and not (name=='examples/events.jsonl' and line.lstrip().startswith(b'#'))] if path.suffix=='.jsonl' else [json.loads(raw)]
            notes.append('JSON syntax parsed; fixture validity remains intentional and is covered by contract tests')
            if values and isinstance(values[0],dict):deps=sorted(values[0].keys())[:30]
        elif path.suffix=='.toml':tomllib.loads(raw.decode());notes.append('TOML parsed')
        elif path.suffix=='.sh':
            subprocess.run(['bash','-n',str(path)],check=True,capture_output=True);notes.append('Shell syntax checked; not executed')
        elif path.suffix in {'.js','.cjs','.mjs'}:
            subprocess.run(['node','--check',str(path)],check=True,capture_output=True);notes.append('JavaScript syntax checked')
        elif path.suffix=='.md':
            text=raw.decode();purpose=next((line.lstrip('# ').strip() for line in text.splitlines() if line.startswith('#')),purpose)[:240]
            links=re.findall(r'\[[^\]]*\]\(([^\s)]+)(?:[^)]*)\)',text)
            deps=sorted(set(x for x in links if not re.match(r'[a-z]+:',x) and not x.startswith('#')))
            missing=[]
            for link in deps:
                target=link.split('#')[0]
                if target and not (path.parent/target).exists():missing.append(link)
            notes.append('Markdown read and relative links checked')
            if missing:notes.append('Historical references retained' if kind=='historical' else 'Missing relative links: '+', '.join(missing))
        else:notes.append('Content read, size and digest recorded; repository hygiene and package checks apply')
    except (ValueError,SyntaxError,UnicodeError,subprocess.CalledProcessError) as error:
        notes.append('REVIEW REQUIRED: '+type(error).__name__)
    relevant=[]
    if name.startswith('megalodon/'):
        stem=path.stem
        relevant=[str(p.relative_to(ROOT)) for p in sorted((ROOT/'tests').glob('test_*.py')) if stem in p.read_text()]
    return dict(path=name,classification=kind,purpose=purpose,bytes=len(raw),sha256=sha256(raw).hexdigest(),
                dependencies=deps,disposition='corrected' if name in changed else 'retained',
                review_basis='structured file inspection; see verification record for behavior coverage',
                verification=notes,related_tests=relevant)

class Controls(HTMLParser):
    def __init__(self):super().__init__();self.items=[];self.ids=[];self.links=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if 'id' in a:self.ids.append(a['id'])
        if tag=='a' and a.get('href','').startswith('#'):self.links.append(a['href'][1:])
        if tag in {'button','input','select','textarea'}:self.items.append(dict(element=tag,id=a.get('id'),type=a.get('type'),label=a.get('aria-label'),disabled='disabled' in a))

def collect():
    names=set(git('ls-files','-z','--cached','--others','--exclude-standard').split('\0'))-{''}
    names.update(git('ls-tree','-r','--name-only',BASE).splitlines())
    changed=set(git('diff','--name-only',BASE).splitlines())
    rows=[inspect_file(n,changed) for n in sorted(names) if n!=OUTPUT]
    sys.path.insert(0,str(ROOT))
    from megalodon.dashboard_assets import INDEX_HTML,DASHBOARD_JS
    c=Controls();c.feed(INDEX_HTML)
    for item in c.items:
        item['source_references']=DASHBOARD_JS.count(item['id']) if item['id'] else 0
        item['verification']='Static binding/form reference; dynamic behavior covered by browserless tests; rendered acceptance pending'
    return dict(schema='megalodon-repository-audit-v1',baseline=BASE,method='Every file is read and classified; machine checks are not a line-by-line independent audit.',
                counts=dict(Counter(r['classification'] for r in rows)),files=rows,
                controls=c.items,control_count=len(c.items),duplicate_ids=sorted(k for k,v in Counter(c.ids).items() if v>1),
                missing_anchors=sorted(set(c.links)-set(c.ids)),
                exclusions=['Ignored private runtime evidence and build environments','Ledger self-digest is intentionally omitted'],
                verification_record='docs/repository-audit.md')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--write',action='store_true');args=parser.parse_args()
    result=collect()
    if args.write:
        path=ROOT/OUTPUT;path.parent.mkdir(exist_ok=True);path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ['counts','control_count','duplicate_ids','missing_anchors']}))
    return int(bool(result['duplicate_ids'] or result['missing_anchors'] or any(any('REVIEW REQUIRED' in x or 'Missing relative' in x for x in r.get('verification',[])) for r in result['files'])))

if __name__=='__main__':raise SystemExit(main())
