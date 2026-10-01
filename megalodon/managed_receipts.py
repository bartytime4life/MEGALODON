"""Hash-linked AI/response receipts inside the reviewed evidence budget.

The catalog retains an explicit chain boundary when an entire completed ledger
segment expires. Like ReceiptStore, this detects corruption against a trusted
head, not an owner capable of rewriting both the records and their anchors.
"""
from collections import deque
from hashlib import sha256
import json
import re
import sqlite3

from .ai_broker import BrokerError, STATES, MAX_RESULT_BYTES
from .evidence_storage import utc


class ManagedReceipts:
    def __init__(self,manager,channel='qwen'):
        if channel not in {'qwen','defense'}:raise ValueError('Invalid receipt channel.')
        self.manager,self.channel=manager,channel

    def __enter__(self):return self
    def __exit__(self,*args):return False

    def _rows(self):
        """Stream retained units; memory is independent of retained ledger size."""
        entries=sorted((e for e in self.manager._catalog['entries'] if e['category']=='audit'
            and e['kind']=='generic' and e['state'] in {'open','closed'}),key=lambda e:e['created_at'])
        for entry in entries:
            with self.manager._db(entry) as db:
                for row in db.execute('SELECT data FROM records WHERE source=? ORDER BY id',(self.channel,)):
                    yield json.loads(row[0])

    def recent(self,limit=64):
        if type(limit) is not int or not 1<=limit<=256:raise ValueError('Invalid receipt page.')
        with self.manager.lock:return list(deque(self._rows(),maxlen=limit))

    @staticmethod
    def _valid_transition(prior,payload):
        state=payload.get('state')
        return (state in STATES and ((prior is None and (state=='not_attempted'
                or state=='observed' and payload.get('tool')=='megalodon.ai.doctor'))
            or prior=='not_attempted' and state in {'observed','applied','failed','awaiting_confirmation'}))

    def verify_chain(self,*,expected_head=None):
        with self.manager.lock:
            boundary=self.manager._catalog['audit_boundaries'].get('audit_'+self.channel,{})
            previous=boundary.get('head','0'*64);sequence=boundary.get('sequence',0)
            pending={};seen=set()
            try:
                for row in self._rows():
                    payload={k:v for k,v in row.items() if k not in {'receipt_id','timestamp','previous_hash','event_hash','sequence'}}
                    raw=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
                    identifier=row['receipt_id'];prior=pending.get(identifier)
                    digest=sha256((row['previous_hash']+identifier+row['timestamp']+raw).encode()).hexdigest()
                    if (len(raw.encode())>MAX_RESULT_BYTES or digest!=row['event_hash']
                            or previous!=row['previous_hash'] or row['sequence']!=sequence+1
                            or identifier in seen or not self._valid_transition(prior,payload)):
                        raise BrokerError('AUDIT_INTEGRITY')
                    if payload['state']=='not_attempted':pending[identifier]='not_attempted'
                    else:pending.pop(identifier,None);seen.add(identifier)
                    previous=digest;sequence=row['sequence']
                    # Actions are low-frequency, bounded workflows. Refuse a
                    # ledger requiring excessive replay rather than trust it.
                    if len(seen)>100000:raise BrokerError('AUDIT_UNAVAILABLE')
                anchor=self.manager.checkpoint('audit_'+self.channel) or dict(head='0'*64,sequence=0,pending=[])
                if anchor['head']!=previous or anchor['sequence']!=sequence or set(anchor.get('pending',[]))!=set(pending):
                    raise BrokerError('AUDIT_INTEGRITY')
                if expected_head is not None and expected_head!=previous:raise BrokerError('AUDIT_INTEGRITY')
                return dict(sequence=sequence,head=previous,incomplete_count=len(pending),pending=list(pending),
                    retained_boundary=boundary.get('head','0'*64))
            except (KeyError,TypeError,ValueError,OSError,sqlite3.Error) as exc:
                if isinstance(exc,BrokerError):raise
                raise BrokerError('AUDIT_INTEGRITY') from None

    def reconcile_interrupted(self):
        """Run only at exclusive startup, before workers; never rerun actions."""
        with self.manager.lock:
            for identifier in self.verify_chain()['pending']:
                prior=self.latest(identifier)
                self.append(identifier,dict(state='failed',action=prior.get('action'),tool=prior.get('tool'),
                    ip=prior.get('ip'),host_attempted=True,outcome='unknown_after_restart',
                    message='Interrupted workflow: outcome was not verified before restart. Review the retained attempt.',result=None))

    def latest(self,receipt_id):
        with self.manager.lock:
            result=None
            for row in self._rows():
                if row['receipt_id']==receipt_id:result=row
            return result

    def append(self,receipt_id,payload):
        if (type(receipt_id) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',receipt_id)
                or type(payload) is not dict or payload.get('state') not in STATES
                or {'receipt_id','timestamp','previous_hash','event_hash','sequence'} & payload.keys()):
            raise BrokerError('INVALID_RECEIPT_STATE')
        raw=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
        if len(raw.encode())>MAX_RESULT_BYTES:raise BrokerError('RESULT_TOO_LARGE')
        with self.manager.lock:
            head=self.verify_chain();prior=self.latest(receipt_id)
            if not self._valid_transition(prior['state'] if prior else None,payload):raise BrokerError('INVALID_RECEIPT_STATE')
            pending=set(head['pending'])
            if payload['state']=='not_attempted':pending.add(receipt_id)
            else:pending.discard(receipt_id)
            if len(pending)>16:raise BrokerError('AUDIT_UNAVAILABLE')
            stamp=utc(self.manager.clock())
            digest=sha256((head['head']+receipt_id+stamp+raw).encode()).hexdigest()
            row=dict(receipt_id=receipt_id,timestamp=stamp,previous_hash=head['head'],event_hash=digest,sequence=head['sequence']+1,**payload)
            self.manager.append_records('audit',[dict(observed_at=stamp,source=self.channel,data=row)],
                checkpoint=('audit_'+self.channel,dict(head=digest,sequence=row['sequence'],pending=sorted(pending))))
            return row
