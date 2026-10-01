"""Fixed privileged helper for temporary containment on this PC only.

The helper is passed as reviewed source to the system Python through pkexec.
Only a public IP and a closed action enum are variable. It never loads code,
configuration, commands or policy from Qwen or an HTTP request.
"""

ROOT_PROGRAM = r'''
import fcntl, ipaddress, json, os, stat, subprocess, sys
TABLE='megalodon_guard'
MARK='MEGALODON temporary containment v1'
BASE={'family':'inet','table':TABLE}

def nft(args,body=None):
    path='/usr/sbin/nft'
    info=os.stat(path)
    if info.st_uid!=0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
        raise ValueError('System nft binary unavailable')
    p=subprocess.run([path,'-j',*args],input=json.dumps(body) if body else None,
                     text=True,capture_output=True,timeout=5,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    if len(p.stdout)>65536 or len(p.stderr)>4096:
        raise ValueError('Firewall response bound')
    return p.returncode,json.loads(p.stdout) if p.returncode==0 and p.stdout.strip() else None

def expression(protocol,field):
    return [{'match':{'op':'==','left':{'payload':{'protocol':protocol,'field':field}},
                      'right':'@blocked_v6' if protocol=='ip6' else '@blocked_v4'}},{'drop':None}]

def initial():
    commands=[{'add':{'table':{'family':'inet','name':TABLE,'comment':MARK}}}]
    for version in (4,6):
        commands.append({'add':{'set':{**BASE,'name':'blocked_v'+str(version),'type':'ipv'+str(version)+'_addr',
                                     'flags':['timeout'],'timeout':300,'size':64}}})
    for chain,field in (('input','saddr'),('output','daddr')):
        commands.append({'add':{'chain':{**BASE,'name':chain,'type':'filter','hook':chain,'prio':-110,'policy':'accept'}}})
        for protocol in ('ip','ip6'):
            commands.append({'add':{'rule':{**BASE,'chain':chain,'expr':expression(protocol,field)}}})
    return {'nftables':commands}

def validate(document):
    objects=document.get('nftables')
    if type(objects) is not list or len(objects)>16:
        raise ValueError('Unrecognized guard table')
    found={'table':[],'set':[],'chain':[],'rule':[]}
    for item in objects:
        if set(item)=={'metainfo'}: continue
        if len(item)!=1 or next(iter(item)) not in found: raise ValueError('Unrecognized guard object')
        kind=next(iter(item)); found[kind].append(item[kind])
    if [len(found[k]) for k in ('table','set','chain','rule')]!=[1,2,2,4]: raise ValueError('Unexpected guard structure')
    table=found['table'][0]
    if (set(table)-{'family','name','handle','comment'} or table.get('family')!='inet'
        or table.get('name')!=TABLE or table.get('comment')!=MARK): raise ValueError('Foreign table')
    values={}
    for version in (4,6):
        name='blocked_v'+str(version)
        matches=[s for s in found['set'] if s.get('name')==name]
        if len(matches)!=1: raise ValueError('Missing guard set')
        item=matches[0]
        if (set(item)-{'family','table','name','type','handle','flags','timeout','size','elem'}
            or any(item.get(k)!=v for k,v in BASE.items()) or item.get('type')!='ipv'+str(version)+'_addr'
            or item.get('flags')!=['timeout'] or item.get('timeout')!=300 or item.get('size')!=64):
            raise ValueError('Changed guard set')
        values[name]={}
        for wrapped in item.get('elem',[]):
            entry=wrapped.get('elem') if type(wrapped) is dict else None
            if type(entry) is not dict or set(entry)-{'val','timeout','expires','comment'}:
                raise ValueError('Unrecognized guard element')
            address=ipaddress.ip_address(entry.get('val'))
            if address.version!=version or not address.is_global or address.is_multicast or entry.get('timeout',item['timeout'])!=300:
                raise ValueError('Unrecognized guard address')
            if type(entry.get('expires')) not in (int,float) or not 0<=entry['expires']<=300:
                raise ValueError('Unexpected guard expiry')
            values[name][str(address)]=entry['expires']
        if len(values[name])>64: raise ValueError('Too many guards')
    for chain,field in (('input','saddr'),('output','daddr')):
        matches=[c for c in found['chain'] if c.get('name')==chain]
        if len(matches)!=1: raise ValueError('Missing guard chain')
        item=matches[0]
        expected={**BASE,'name':chain,'type':'filter','hook':chain,'prio':-110,'policy':'accept'}
        if set(item)-set(expected)-{'handle'} or any(item.get(k)!=v for k,v in expected.items()): raise ValueError('Changed guard chain')
        rules=[r for r in found['rule'] if r.get('chain')==chain]
        if len(rules)!=2 or any(any(r.get(k)!=v for k,v in BASE.items()) for r in rules): raise ValueError('Changed guard rules')
        if [r.get('expr') for r in rules]!=[expression('ip',field),expression('ip6',field)]: raise ValueError('Changed guard expressions')
    return values

def inspect():
    code,document=nft(['list','tables'])
    if code or type(document) is not dict: raise ValueError('Cannot inspect firewall')
    exists=any(r.get('table',{}).get('family')=='inet' and r.get('table',{}).get('name')==TABLE for r in document.get('nftables',[]))
    if not exists: return None
    code,document=nft(['list','table','inet',TABLE])
    if code or type(document) is not dict: raise ValueError('Cannot inspect guard')
    return validate(document)

def act(action,target):
    address=ipaddress.ip_address(target)
    if isinstance(address,ipaddress.IPv6Address) and address.ipv4_mapped:
        raise ValueError('Mapped target refused')
    if str(address)!=target or not address.is_global or address.is_multicast or address.is_unspecified:
        raise ValueError('Public single target required')
    if action not in ('apply','release','status'): raise ValueError('Unknown action')
    values=inspect()
    if values is None and action=='apply':
        code,_=nft(['-f','-'],initial())
        if code: raise ValueError('Guard creation failed')
        values=inspect()
    name='blocked_v'+str(address.version)
    exists=values is not None and target in values[name]
    if action=='apply' and not exists:
        element={**BASE,'name':name,'elem':[{'elem':{'val':target,'timeout':300}}]}
        code,_=nft(['-f','-'],{'nftables':[{'add':{'element':element}}]})
        if code: raise ValueError('Containment not applied')
    elif action=='release' and exists:
        code,_=nft(['-f','-'],{'nftables':[{'delete':{'element':{**BASE,'name':name,'elem':[target]}}}]})
        if code: raise ValueError('Release not applied')
    values=inspect()
    remaining=values[name].get(target) if values else None
    if action=='apply' and remaining is None: raise ValueError('Containment unverified')
    if action=='release' and remaining is not None: raise ValueError('Release unverified')
    return {'ip':target,'present':remaining is not None,'remaining_seconds':remaining,'verified':True}

def main():
    if os.geteuid()!=0 or len(sys.argv)!=3: raise ValueError('OS authorization required')
    fd=os.open('/run/lock/megalodon-guard.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(fd)
        if info.st_uid!=0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077: raise ValueError('Untrusted guard lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print(json.dumps(act(sys.argv[1],sys.argv[2])))
    finally: os.close(fd)

if __name__=='__main__':
    try: main()
    except Exception:
        print('Local containment action failed or could not be verified.',file=sys.stderr)
        sys.exit(2)
'''
