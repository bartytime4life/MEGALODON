"""CSV reports keep untrusted spreadsheet cells inert without changing evidence."""
import copy
import csv
import io
from megalodon.reporting import ReportService


def serialize(value):
    class Saved:
        def report(self, identifier): return value
    before=copy.deepcopy(value)
    content_type,data=ReportService.download(Saved(),'a'*32,'csv')
    assert content_type.startswith('text/csv')
    assert value==before
    return list(csv.reader(io.StringIO(data.decode())))


def test_formula_like_cells_are_text_and_original_evidence_is_unchanged():
    dangerous=['=1+1','+1+1','-1+1','@SUM(1,1)','\t=1+1','\r=1+1','\n=1+1','  =1+1','\ufeff=1+1','\x00=1+1']
    ordinary=['ordinary text','comma, and "quote"','two\nlines','','192.0.2.10','LOW']
    fields=('observed_at','source','title','severity','src_ip','dst_ip','evidence_reference')
    for value in dangerous+ordinary:
        rows=serialize({'findings':[dict.fromkeys(fields,value)]})
        expected="'"+value if value in dangerous else value
        assert rows[-1]==[expected]*7


def test_zero_and_empty_values_are_preserved_in_csv():
    rows=serialize({'findings':[dict(observed_at=None,source='sensor',title='test',severity=0,src_ip='',dst_ip=None,evidence_reference='segment:42')]})
    assert rows[-1]==['','sensor','test','0','','','segment:42']
