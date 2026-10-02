"""Allowlisted public reference adapters. Downloaded text never supplies code or policy."""
from __future__ import annotations

import hashlib
import html
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

RAW = 'https://raw.githubusercontent.com/'
ATLAS = RAW + 'mitre-atlas/atlas-data/main/dist/v6/'
OWASP = RAW + 'GenAI-Security-Project/GenAI-LLM-Top10/main/2026/final/'
OWASP_FILES = ('LLM01_PromptInjection', 'LLM02_SensitiveInformationDisclosure',
               'LLM03_ExcessiveAgency', 'LLM04_SupplyChain', 'LLM05_DataModelPoisoning',
               'LLM06_UnboundedConsumption', 'LLM07_Misinformation', 'LLM08_HiddenContextExposure',
               'LLM09_VectorAndEmbeddingWeaknesses', 'LLM10_ImproperOutputHandling')
SOURCES = {
    'attack': dict(name='MITRE ATT&CK', url=RAW+'mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
                   license='MITRE ATT&CK license', limit=80*1024**2),
    'atlas': dict(name='MITRE ATLAS', url=ATLAS+'ATLAS-latest.yaml', license='Apache-2.0', limit=8*1024**2),
    'd3fend': dict(name='MITRE D3FEND', url='https://d3fend.mitre.org/ontologies/d3fend.json',
                   license='MITRE D3FEND license', limit=16*1024**2),
    'owasp': dict(name='OWASP GenAI', url=OWASP, license='CC-BY-SA-4.0', limit=1024**2),
    'kev': dict(name='CISA KEV', url=RAW+'cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
                license='CC0-1.0', limit=16*1024**2),
}
MAX_ENTRIES = 40000
LICENSE_URLS = {
    'attack': RAW+'mitre-attack/attack-stix-data/master/LICENSE.txt',
    'atlas': RAW+'mitre-atlas/atlas-data/main/LICENSE',
    'd3fend': 'https://d3fend.mitre.org/tou/',
    'kev': RAW+'cisagov/kev-data/develop/LICENSE',
    'owasp': RAW+'GenAI-Security-Project/GenAI-LLM-Top10/main/README.md',
}


def license_identity(source, raw):
    text=raw.decode('utf-8')
    if source=='d3fend':
        text=text.split('<h1>Terms of Use</h1>',1)[1].split('</section>',1)[0]
        text=html.unescape(re.sub('<[^>]+>',' ',text))
    elif source=='owasp':
        text=text.split('## License',1)[1].split('\n## ',1)[0]
    return digest(' '.join(text.split()).encode())


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def clean(value, maximum=8000):
    if not isinstance(value, str):
        return ''
    return ''.join(c for c in value if c.isprintable() or c in '\n\t')[:maximum]


def text_value(value):
    if isinstance(value, dict):
        return text_value(value.get('@value', ''))
    if isinstance(value, list):
        return ' '.join(text_value(v) for v in value)
    return clean(value)


def approved_url(url):
    fixed = {s['url'] for k, s in SOURCES.items() if k != 'owasp'}
    return (url in fixed or url in LICENSE_URLS.values() or url in {OWASP + f + '.md' for f in OWASP_FILES}
            or re.fullmatch(re.escape(ATLAS)+r'ATLAS-20[0-9]{2}\.(?:0[1-9]|1[0-2])\.yaml', url) is not None)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _fetch(url, limit, etag=None, *, stop=None):
    """Exact HTTPS destinations, no proxy/redirect, conditional reads, bounded time/size."""
    if not approved_url(url):
        raise ValueError('Unapproved knowledge source')
    headers = {'User-Agent': 'MEGALODON-public-reference/1', 'Accept-Encoding': 'identity'}
    if isinstance(etag, str) and len(etag) <= 256 and etag.isprintable():
        headers['If-None-Match'] = etag
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(urllib.request.Request(url, headers=headers), timeout=15)
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return None, etag
        raise ValueError('Public source is unavailable') from None
    with response:
        if response.status != 200 or response.headers.get('Content-Encoding', 'identity') != 'identity':
            raise ValueError('Unsupported source response')
        size = response.headers.get('Content-Length')
        if size and (not size.isdecimal() or int(size) > limit):
            raise ValueError('Public source exceeds its size limit')
        chunks, count, started = [], 0, time.monotonic()
        while True:
            if (stop and stop.is_set()) or time.monotonic()-started > 90:
                raise ValueError('Knowledge download cancelled or timed out')
            block = response.read1(min(65536, limit-count+1))
            if not block:
                break
            chunks.append(block)
            count += len(block)
            if count > limit:
                raise ValueError('Public source exceeds its size limit')
        tag = response.headers.get('ETag')
        return b''.join(chunks), tag if tag and len(tag) <= 256 and tag.isprintable() else None


def fetch(url, limit, etag=None, *, stop=None):
    """A disposable fixed worker gives connect, headers and body a hard deadline."""
    if not approved_url(url) or type(limit) is not int or not 1<=limit<=80*1024**2:
        raise ValueError('Unapproved knowledge request')
    if stop and stop.is_set():raise ValueError('Download cancelled')
    process=subprocess.Popen([sys.executable,'-m','megalodon.knowledge_sources',url,str(limit),etag or ''],
                             stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,stdin=subprocess.DEVNULL)
    deadline=time.monotonic()+90
    try:
        while True:
            if (stop and stop.is_set()) or time.monotonic()>=deadline:
                raise ValueError('Knowledge download cancelled or timed out')
            try:
                output,_=process.communicate(timeout=min(.25,max(.001,deadline-time.monotonic())))
                break
            except subprocess.TimeoutExpired:continue
        if process.returncode or len(output)>limit+1024:raise ValueError('Public source is unavailable')
        header,raw=output.split(b'\n',1)
        meta=json.loads(header)
        return (None if meta['unchanged'] else raw),meta['etag']
    finally:
        if process.poll() is None:process.kill()
        process.communicate()


def bounded_json(raw):
    # One encoding for the structural scanner and decoder. json.loads(bytes)
    # otherwise also accepts UTF-16/32, bypassing byte-level string boundaries.
    if b'\x00' in raw:raise ValueError('Knowledge JSON must use UTF-8')
    raw.decode('utf-8')
    # Count containers, fields and nesting before json.loads allocates objects.
    # Strings are skipped using bounded byte searches, without materializing them.
    punctuation=re.compile(rb'["{}\[\],:]')
    position=depth=containers=separators=escapes=0
    while match:=punctuation.search(raw,position):
        token=match.group();position=match.end()
        if token==b'"':
            start=position
            while True:
                finish=raw.find(b'"',position)
                if finish<0 or finish-start>1024*1024:raise ValueError('Invalid or oversized JSON string')
                slash=finish-1
                while slash>=start and raw[slash]==92:slash-=1
                escapes+=finish-slash-1
                if escapes>2000000:raise ValueError('JSON escape limit exceeded')
                position=finish+1
                if (finish-slash-1)%2==0:break
        elif token in (b'{',b'['):
            containers+=1;depth+=1
            if containers>300000 or depth>32:raise ValueError('JSON structure limit exceeded')
        elif token in (b'}',b']'):depth-=1
        else:
            separators+=1
            if separators>2000000:raise ValueError('JSON field limit exceeded')
    return json.loads(raw)


def entry(source, edition, identifier, title, body, url, *, links=()):
    if not re.fullmatch(r'[A-Za-z0-9._-]{1,100}', identifier) or not re.fullmatch(r'[A-Za-z0-9._-]{1,100}', edition):
        raise ValueError('Unsupported knowledge identity')
    if source not in SOURCES or urlsplit(url).scheme != 'https':
        raise ValueError('Invalid reference source')
    if not clean(title, 200) or not clean(body):
        raise ValueError('Reference has no readable content')
    return dict(id=f'{source}@{edition}:{identifier}', source=source, edition=edition,
                identifier=identifier, title=clean(title, 200), text=clean(body), url=url,
                links=list(links)[:128])


def parse(source, raw):
    """Return bounded normalized documents and their source edition; no dynamic adapters."""
    if source not in SOURCES or len(raw) > SOURCES[source]['limit']:
        raise ValueError('Unsupported or oversized knowledge source')
    if source == 'atlas':
        # No constructors, aliases or recursive graphs from remote YAML. Scan
        # first to bound work before building a safe, plain-data object tree.
        import yaml
        from yaml.tokens import AliasToken, AnchorToken, TagToken, BlockMappingStartToken, BlockSequenceStartToken, FlowMappingStartToken, FlowSequenceStartToken, BlockEndToken, FlowMappingEndToken, FlowSequenceEndToken
        depth=0
        for n, token in enumerate(yaml.scan(raw)):
            if n > 300000 or isinstance(token, (AliasToken, AnchorToken, TagToken)):
                raise ValueError('Unsupported YAML graph')
            if isinstance(token,(BlockMappingStartToken,BlockSequenceStartToken,FlowMappingStartToken,FlowSequenceStartToken)):depth+=1
            elif isinstance(token,(BlockEndToken,FlowMappingEndToken,FlowSequenceEndToken)):depth-=1
            if depth>32:raise ValueError('YAML nesting limit exceeded')
        value = yaml.safe_load(raw)
        if not isinstance(value, dict) or str(value.get('format-version')) != '6.0.0':
            raise ValueError('Unsupported ATLAS format')
        edition = value['collection']['version']
        result = []
        for kind in ('techniques', 'mitigations', 'case-studies'):
            for identifier, row in value[kind].items():
                links = []
                for relation, targets in value.get('relationships', {}).get(identifier, {}).items():
                    links += [(relation, r['target']) for r in targets if r.get('target')]
                result.append(entry(source, edition, identifier, row['name'], row['description'],
                                    f'https://atlas.mitre.org/{kind}/{identifier}', links=links))
    elif source == 'owasp':
        value = bounded_json(raw)
        if set(value) != set(OWASP_FILES):
            raise ValueError('Incomplete OWASP edition')
        edition = '2026'
        result = [entry(source, edition, name[:5], name[6:], body, OWASP+name+'.md')
                  for name, body in value.items()]
    else:
        value = bounded_json(raw)
        if source == 'attack':
            if value.get('type') != 'bundle' or not isinstance(value.get('objects'), list):
                raise ValueError('Unsupported ATT&CK bundle')
            objects = value['objects']
            edition = max(r.get('modified', '0')[:10] for r in objects)
            rows = [r for r in objects if r.get('type') in {'attack-pattern', 'course-of-action'}
                    and not r.get('revoked') and not r.get('x_mitre_deprecated')]
            ids = {r['id']:next((v['external_id'] for v in r.get('external_references', [])
                   if v.get('source_name') == 'mitre-attack' and v.get('external_id')), None) for r in rows}
            relations = {}
            for r in objects:
                if r.get('type') == 'relationship' and ids.get(r.get('target_ref')) and ids.get(r.get('source_ref')):
                    relations.setdefault(r['source_ref'], []).append((r['relationship_type'], ids[r['target_ref']]))
            result = [entry(source, edition, ids[r['id']], r['name'], r['description'],
                            'https://attack.mitre.org/'+('techniques/' if r['type']=='attack-pattern' else 'mitigations/')+
                            ids[r['id']].replace('.', '/')+'/', links=relations.get(r['id'], []))
                      for r in rows if ids[r['id']]]
        elif source == 'kev':
            rows = value['vulnerabilities']
            if value['count'] != len(rows) or not isinstance(value['catalogVersion'], str):
                raise ValueError('Incomplete KEV catalog')
            edition = value['catalogVersion']
            result = []
            for r in rows:
                if not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,8}', r['cveID']):
                    raise ValueError('Invalid CVE identity')
                body = (f"{r['vendorProject']} / {r['product']}. {r['shortDescription']}\n"
                        f"Required action: {r['requiredAction']}\nAdded: {r['dateAdded']}. "
                        'Applicability requires an explicit CVE or verified affected product and version; name similarity is insufficient.')
                result.append(entry(source, edition, r['cveID'], r['vulnerabilityName'], body,
                                    'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve='+r['cveID']))
        else:
            graph = value['@graph']
            edition = next((text_value(r['owl:versionInfo']) for r in graph if 'owl:versionInfo' in r), None)
            if not edition:
                raise ValueError('Missing D3FEND edition')
            result = []
            # Include D3FEND's own defined concepts, not copied third-party graphs.
            for r in graph:
                identifier = r.get('@id', '')
                body = text_value(r.get('d3f:definition', ''))
                if identifier.startswith('d3f:') and body and not re.match(r'd3f:(?:T[0-9]|AML\.|SPARTA)', identifier):
                    result.append(entry(source, edition, identifier[4:], text_value(r.get('rdfs:label')), body,
                                        'https://d3fend.mitre.org/technique/d3f:'+identifier[4:]+'/'))
    if not 1 <= len(result) <= MAX_ENTRIES or len({r['id'] for r in result}) != len(result):
        raise ValueError('Incomplete or duplicate source identities')
    return result, edition


if __name__=='__main__':
    # Fixed data download worker, no downloaded code or shell command execution.
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS,(384*1024**2,384*1024**2))
        resource.setrlimit(resource.RLIMIT_CPU,(60,60))
        body,tag=_fetch(sys.argv[1],int(sys.argv[2]),sys.argv[3] or None)
        sys.stdout.buffer.write(json.dumps(dict(unchanged=body is None,etag=tag)).encode()+b'\n'+(body or b''))
    except Exception:
        raise SystemExit(1)
