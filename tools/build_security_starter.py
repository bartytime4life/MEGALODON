#!/usr/bin/env python3
"""Rebuild the bounded offline pack from downloaded, reviewed publisher artifacts.

Input directory is a build workspace, never a user-selected runtime download.
Review source/license diffs before shipping a regenerated pack.
"""
import argparse
from datetime import datetime, timezone
from html import unescape
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from megalodon.knowledge_sources import SOURCES, OWASP_FILES, OWASP, parse, digest, fetch,license_identity
from megalodon.security_patterns import REFERENCE_LINKS


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('directory',type=Path)
    args=parser.parse_args()
    root=args.directory
    owasp={}
    for name in OWASP_FILES:
        path=root/(name+'.md')
        if not path.exists(): path.write_bytes(fetch(OWASP+name+'.md',128*1024)[0])
        owasp[name]=path.read_text()
    (root/'owasp.json').write_text(json.dumps(owasp))
    names={'attack':'attack.json','atlas':'atlas.yaml','d3fend':'d3fend.json','owasp':'owasp.json','kev':'kev.json'}
    licenses={k:(root/(k+'-license.txt')).read_text() for k in ('attack','atlas','kev')}
    body=(root/'d3fend-license.html').read_text().split('<h1>Terms of Use</h1>',1)[1].split('</section>',1)[0]
    licenses['d3fend']=unescape(re.sub('<[^>]+>',' ',body)).strip()
    licenses['owasp']='OWASP GenAI Security Project contributors. Creative Commons Attribution-ShareAlike 4.0 International. https://creativecommons.org/licenses/by-sa/4.0/ . These excerpts have been selected and truncated for the MEGALODON offline pack. Adapted OWASP reference content remains CC-BY-SA-4.0; application code has its separate license.'
    all_rows=[];sources={}
    for key,name in names.items():
        raw=(root/name).read_bytes()
        rows,edition=parse(key,raw)
        # Search-oriented starter; the UI states its subset coverage. Current
        # full supported catalogs are admitted only by the runtime update path.
        terms=re.compile(r'inject|denial|network|traffic|scan|poison|exfil|credential|resource|service|anomal|agent|tool|permission|model',re.I)
        linked={pair for pairs in REFERENCE_LINKS.values() for pair in pairs}
        chosen=sorted(rows,key=lambda r:((r['source'],r['identifier']) not in linked,not bool(terms.search(r['title'])),r['id']))[:(10 if key=='owasp' else 48)]
        for row in chosen:row['text']=row['text'][:2000]
        all_rows+=chosen
        sources[key]=dict(name=SOURCES[key]['name'],url=SOURCES[key]['url'],edition=edition,
            retrieved_at=datetime.now(timezone.utc).isoformat(),sha256=digest(raw),entries=len(chosen),
            license=SOURCES[key]['license'],license_text=licenses[key],
            attribution='CISA, U.S. Government' if key=='kev' else 'OWASP GenAI Security Project contributors' if key=='owasp' else 'The MITRE Corporation',
            coverage=f'Offline starter subset: {len(chosen)} of {len(rows)} supported published records')
        license_file='d3fend-license.html' if key=='d3fend' else 'owasp-readme.md' if key=='owasp' else key+'-license.txt'
        sources[key]['license_sha256']=license_identity(key,(root/license_file).read_bytes())
    target=Path('megalodon/reference/security-v1');target.mkdir(exist_ok=True)
    raw=(json.dumps(dict(schema='megalodon-security-starter-v1',sources=sources,entries=all_rows),ensure_ascii=False,indent=2)+'\n').encode()
    (target/'starter.json').write_bytes(raw)
    (target/'starter.sha256').write_text(digest(raw)+'\n')
    print(f'{len(all_rows)} references; {len(raw)} bytes; SHA-256 {digest(raw)}')


if __name__=='__main__':main()
