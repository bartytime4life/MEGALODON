"""Local-only routes for reference data and review proposals."""
import hmac
from ipaddress import ip_address
import json
import re
import sqlite3
from urllib.parse import parse_qs


def read(handler, route):
    from .dashboard import _tool_management_user
    provider=handler.knowledge if route.path.startswith('/api/knowledge') else handler.intelligence
    if provider is None or not _tool_management_user() or handler.headers.get_all('X-Megalodon-Check',[])!=['1']:
        handler._send_json({'error':'Explicit local intelligence check required'},status=403);return
    try:
        if len(route.query)>1024:raise ValueError('Query exceeds bounds')
        query=parse_qs(route.query,keep_blank_values=True,strict_parsing=True) if route.query else {}
        if any(len(v)!=1 for v in query.values()):raise ValueError('Duplicate query')
        if route.path=='/api/knowledge/search' and set(query)=={'q'}:
            value=dict(results=provider.search(query['q'][0]))
        elif route.path=='/api/knowledge' and not query:value=provider.snapshot(include_token=True)
        elif route.path=='/api/intelligence/context' and set(query)=={'device'}:
            if len(query['device'][0])>64:raise ValueError('Address exceeds bounds')
            address=str(ip_address(query['device'][0]))
            if '%' in address:raise ValueError('Scoped address unsupported')
            if not handler.context_read_lock.acquire(blocking=False):
                handler._send_json({'error':'A retained facts read is already running'},status=409);return
            try:
                value=provider.context_for_device(address)
            finally:
                handler.context_read_lock.release()
        elif route.path=='/api/intelligence' and not set(query)-{'device'}:
            value=provider.snapshot(include_token=True,device=query.get('device',[None])[0])
        else:raise ValueError('Unsupported knowledge query')
        handler._send_json(value)
    except (ValueError,OSError,sqlite3.Error):
        handler._send_json({'error':'Local knowledge or retained pattern data is unavailable'},status=422)


def action(handler):
    from .dashboard import _tool_management_user
    from .ai_provider import _strict_pairs
    provider=handler.knowledge if handler.path=='/api/knowledge' else handler.intelligence
    tokens=handler.headers.get_all('X-Megalodon-Intelligence-Token',[])
    if (provider is None or not _tool_management_user() or len(tokens)!=1 or len(tokens[0])!=32
            or not tokens[0].isascii() or not hmac.compare_digest(tokens[0],provider.token)
            or handler.headers.get_all('Origin',[])!=[f'http://{handler.headers.get("Host")}']
            or handler.headers.get_all('Content-Type',[])!=['application/json']
            or handler.headers.get_all('Transfer-Encoding',[]) or handler.headers.get_all('Content-Encoding',[])):
        handler._send_json({'error':'Same-origin local intelligence action required'},status=403);return
    lengths=handler.headers.get_all('Content-Length',[])
    if len(lengths)!=1 or not re.fullmatch(r'[0-9]{1,4}',lengths[0]) or not 2<=int(lengths[0])<=2048:
        handler._send_json({'error':'Invalid request length'},status=400);return
    try:
        handler.connection.settimeout(2)
        raw=handler.rfile.read(int(lengths[0]))
        if len(raw)!=int(lengths[0]):raise ValueError('Incomplete request')
        body=json.loads(raw.decode(),object_pairs_hook=_strict_pairs,
                        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Non-finite value')))
        if type(body) is not dict:raise ValueError('Expected an object')
        handler._send_json(provider.action(body))
    except (ValueError,OSError,sqlite3.Error,TypeError):
        handler._send_json({'error':'This action could not be completed. Refresh the status and review the current job or storage.'},status=422)
