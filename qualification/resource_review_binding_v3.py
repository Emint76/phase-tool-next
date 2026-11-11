"""Exact resource plan attestation; never Phase runtime/profile authority."""
import hashlib,json
OWNER='sha256:dc6321e885175ea02e587286d52c18e6a41c026bd2a16a33824757058c2580f7'
def hash_value(value):
    return(type(value)is str and len(value)==71 and value.startswith('sha256:')
        and all(c in'0123456789abcdef'for c in value[7:]))
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
class ReviewedMatrix:
    __slots__=('_entries','digest','source_graph_digest')
    def permit(self,plan):
        value=self._entries.get(plan.binding)
        if value is None:raise ValueError('resource.unreviewed_scenario')
        expected={key:getattr(plan,key)for key in('scenario','lane','frontend','manifest_digest','source_digest','attempts','max_writers','control_cap')}
        if any(value[key]!=actual for key,actual in expected.items()):raise ValueError('resource.review_binding_mismatch')
        return True
def load_reviewed_matrix(raw,*,expected_digest,expected_source_graph):
    """Expected pins MUST come from fixed reviewed test-deployment code.

    Accepting this function's expected_digest from operation JSON, an env var
    or unreviewed CLI input defeats that boundary and is forbidden. No matrix
    is activated by this source-only module or by synthetic model attestations.
    """
    if type(raw)is not bytes or not 0<len(raw)<=2*1024**2:raise ValueError('resource.review_shape')
    if not hash_value(expected_digest)or not hash_value(expected_source_graph):raise ValueError('resource.review_pin_required')
    if 'sha256:'+hashlib.sha256(raw).hexdigest()!=expected_digest:raise ValueError('resource.review_digest')
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('resource.review_duplicate_key')
            result[key]=value
        return result
    def forbidden(value):raise ValueError('resource.review_noninteger')
    value=json.loads(raw,object_pairs_hook=pairs,parse_float=forbidden,parse_constant=forbidden)
    if(type(value)is not dict or set(value)!={'resource_review_version','owner_instruction_digest','source_graph_digest','plans'}
        or canonical(value)!=raw or value['resource_review_version']!='1.0'
        or value['owner_instruction_digest']!=OWNER or value['source_graph_digest']!=expected_source_graph
        or type(value['plans'])is not list or not value['plans']):raise ValueError('resource.review_shape')
    entries={};fields={'content_digest','scenario','lane','frontend','manifest_digest','source_digest','attempts','max_writers','control_cap','review_evidence_digests'}
    for row in value['plans']:
        if type(row)is not dict or set(row)!=fields:raise ValueError('resource.review_shape')
        if any(not hash_value(row[key])for key in('content_digest','manifest_digest','source_digest')):raise ValueError('resource.review_shape')
        if(type(row['review_evidence_digests'])is not list or len(row['review_evidence_digests'])<2
            or len(set(row['review_evidence_digests']))!=len(row['review_evidence_digests'])
            or any(not hash_value(v)for v in row['review_evidence_digests'])):raise ValueError('resource.independent_review_pending')
        if (any(type(row[key])is not int or row[key]<=0 for key in('attempts','max_writers','control_cap'))
            or row['max_writers']>8 or any(type(row[key])is not str or not row[key]for key in('scenario','lane','frontend'))):
            raise ValueError('resource.review_row_types')
        if row['content_digest']in entries:raise ValueError('resource.review_duplicate_plan')
        entries[row['content_digest']]={**row,'review_evidence_digests':tuple(row['review_evidence_digests'])}
    out=object.__new__(ReviewedMatrix)
    from types import MappingProxyType
    out._entries=MappingProxyType({key:MappingProxyType(row)for key,row in entries.items()})
    out.digest=expected_digest;out.source_graph_digest=expected_source_graph
    return out
