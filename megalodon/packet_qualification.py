"""Common admission boundary for original and compacted packet evidence."""

QUALIFIED_RUN_SQL = """r.source IN ('jsonl','scapy') AND r.receipt_version=3 AND
 ((r.status='running' AND r.termination_reason IS NULL)
 OR (r.status='completed' AND r.termination_reason='source_exhausted')
 OR (r.status='incomplete' AND r.termination_reason='event_limit_reached')
 OR (r.status='failed' AND r.termination_reason IN ('failed','interrupted')))"""


def qualified_event_ids(db, first, last):
    return {row[0] for row in db.execute(
        'SELECT l.event_id FROM ingestion_run_events l JOIN ingestion_runs r ON r.id=l.run_id '
        'WHERE l.event_id>? AND l.event_id<=? AND '+QUALIFIED_RUN_SQL, (first,last))}


def qualified_receipt(receipt):
    pair=(receipt.get('status'),receipt.get('termination_reason'))
    return receipt.get('source') in {'jsonl','scapy'} and receipt.get('receipt_version')==3 and pair in {
        ('running',None),('completed','source_exhausted'),('incomplete','event_limit_reached'),
        ('failed','failed'),('failed','interrupted')}
