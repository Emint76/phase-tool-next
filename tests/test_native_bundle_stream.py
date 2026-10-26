"""Ordinary Linux DATA-only prerequisite oracles; no Windows qualification."""
import base64
from contextlib import contextmanager
import errno
import hashlib
import json
import os
import sys

import pytest

from phase_tool.bundle import MAX_TOTAL_BYTES, freeze_bundle, parse_manifest
from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bundle_stream as bundle
from phase_tool.streaming import FILE_LIMIT

pytestmark = pytest.mark.skipif(not sys.platform.startswith('linux'),
    reason='ordinary Linux snapshot prerequisite only; native remains NOT_VERIFIED')

_CONTEXT = canonical_bytes({'run_id':'bundle-data-test','intent_digest':'sha256:'+'1'*64,
    'installation_digest':'sha256:'+'2'*64,'operation_nonce':'3'*32})
_CHANNEL = '4'*32


def fixture(tmp_path, values=None):
    values = values if values is not None else {
        'a.bin':b'alpha','nested/b.bin':b'alpha','z.bin':b''}
    root=tmp_path/'input';root.mkdir()
    blobs=tmp_path/'blobs'
    for name,data in values.items():
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    frozen=freeze_bundle('payload',root,list(values),blobs,frozen_at='2026-10-26T00:00:00Z')
    metadata=frozen.blob_path.read_bytes()
    assert parse_manifest(metadata)['total_length']==sum(map(len,values.values()))
    return blobs,metadata,values


def receiver(metadata, channel=_CHANNEL):
    return bundle._BundleTwoPassReceiver(context_bytes=_CONTEXT,
        channel_id=channel,manifest_bytes=metadata)


def source(blobs, metadata):
    return bundle._bundle_verified_source(blobs,context_bytes=_CONTEXT,
        channel_id=_CHANNEL,manifest_bytes=metadata)


def first(src, dst):
    for raw in src.first_frames():
        assert dst.feed(raw) is None
    ready=dst.ready_frame()
    rewound=src.rewind_after_ready(ready)
    dst.accept_rewound(rewound)
    dst.accept_go(bundle._bundle_token(src._header_raw,'go'))


def test_bundle_actual_frozen_snapshots_zero_repeat_and_real_rewinds(tmp_path,monkeypatch):
    blobs,metadata,values=fixture(tmp_path)
    dst=receiver(metadata);released={}
    with source(blobs,metadata) as src:
        fds=tuple(s._fd for s in src._sources)
        assert len(set(fds))==len(values)
        assert all(os.fstat(fd).st_nlink==0 for fd in fds)
        assert len(set(src._headers))==len(values)  # Same bytes have distinct occurrences.
        for raw in src.first_frames():
            assert dst.feed(raw) is None
        calls=[];original=os.lseek
        def rewind(fd,offset,whence):
            calls.append((fd,offset,whence))
            return original(fd,offset,whence)
        monkeypatch.setattr(os,'lseek',rewind)
        ready=dst.ready_frame()
        token=src.rewind_after_ready(ready)
        assert calls==[(fd,0,os.SEEK_SET)for fd in fds]
        dst.accept_rewound(token)
        dst.accept_go(bundle._bundle_token(src._header_raw,'go'))
        for raw in src.replay_frames():
            item=dst.feed(raw)
            if item is not None:
                path,offset,data=item
                assert offset==len(released.get(path,b''))
                released[path]=released.get(path,b'')+data
        facts=dst.finish()
        assert facts=={'accepted_manifest_digest':digest_bytes(metadata),
            'accepted_members':3,'accepted_payload_length':10}
        assert src._state=='emitted'
    assert {name:released.get(name,b'')for name in values}==values
    for fd in fds:
        with pytest.raises(OSError) as error:os.fstat(fd)
        assert error.value.errno==errno.EBADF
    with pytest.raises(PhaseError):src.first_frames()


@pytest.mark.parametrize('channel', ['5'*32,'6'*32])
def test_bundle_outer_exchange_prevents_member_token_alias(tmp_path,channel):
    _,metadata,_=fixture(tmp_path)
    a=receiver(metadata);b=receiver(metadata,channel=channel)
    assert a._header_raw!=b._header_raw
    assert set(a._headers).isdisjoint(b._headers)
    with pytest.raises(PhaseError,match='ntfs.bundle_header_mismatch'):
        a.feed(b._header_raw)
    with pytest.raises(PhaseError):a.feed(a._header_raw)


@pytest.mark.parametrize('fault', ['order','truncated','duplicate','foreign','chunk_digest','offset','early_end','extra'])
def test_bundle_first_pass_member_fault_is_terminal(tmp_path,fault):
    blobs,metadata,_=fixture(tmp_path);dst=receiver(metadata)
    with source(blobs,metadata) as src:
        frames=list(src.first_frames())
    if fault=='order':frames[1],frames[2]=frames[2],frames[1]
    elif fault=='truncated':frames.pop(-2)
    elif fault=='duplicate':frames.insert(2,frames[1])
    elif fault=='foreign':
        bad=parse_json_bytes(frames[1]);bad['channel_id']='5'*32;frames[1]=canonical_bytes(bad)
    elif fault in ('chunk_digest','offset'):
        bad=parse_json_bytes(frames[2])
        if fault=='chunk_digest':bad['content_base64']=base64.b64encode(b'X'*5).decode()
        else:bad['offset']=1
        frames[2]=canonical_bytes(bad)
    elif fault=='early_end':frames=frames[:1]+frames[-1:]
    else:frames.insert(-1,frames[1])
    with pytest.raises(PhaseError):
        for raw in frames:dst.feed(raw)
        dst.ready_frame()
    assert dst._state=='failed'
    with pytest.raises(PhaseError):dst.feed(dst._header_raw)


@pytest.mark.parametrize('moment', ['before_first','before_rewound','wrong_rewound','wrong_go','twice_go'])
def test_bundle_replay_requires_complete_aggregate_rewind_and_single_go(tmp_path,moment):
    blobs,metadata,_=fixture(tmp_path);dst=receiver(metadata)
    with source(blobs,metadata) as src:
        if moment=='before_first':
            with pytest.raises(PhaseError):dst.accept_go(bundle._bundle_token(dst._header_raw,'go'))
        else:
            for raw in src.first_frames():dst.feed(raw)
            ready=dst.ready_frame()
            if moment=='before_rewound':
                with pytest.raises(PhaseError):dst.accept_go(bundle._bundle_token(dst._header_raw,'go'))
            elif moment=='wrong_rewound':
                with pytest.raises(PhaseError):dst.accept_rewound(b'{}')
            else:
                token=src.rewind_after_ready(ready);dst.accept_rewound(token)
                if moment=='wrong_go':
                    with pytest.raises(PhaseError):dst.accept_go(b'{}')
                else:
                    dst.accept_go(bundle._bundle_token(dst._header_raw,'go'))
                    with pytest.raises(PhaseError):dst.accept_go(bundle._bundle_token(dst._header_raw,'go'))
        with pytest.raises(PhaseError):dst.finish()


@pytest.mark.parametrize('phase', [1,2])
def test_bundle_source_end_yield_is_not_generator_exhaustion(tmp_path,phase):
    blobs,metadata,_=fixture(tmp_path);dst=receiver(metadata)
    with source(blobs,metadata) as src:
        if phase==2:first(src,dst)
        frames=src.first_frames()if phase==1 else src.replay_frames()
        expected=bundle._bundle_end(src._header_raw,src._manifest,phase)
        while True:
            raw=next(frames);dst.feed(raw)
            if raw==expected:break
        with pytest.raises(PhaseError):
            if phase==1:src.rewind_after_ready(dst.ready_frame())
            else:src.replay_frames()
        with pytest.raises(PhaseError):next(frames)
        assert src._state=='failed'


@pytest.mark.parametrize('position', ['header','member_end','outer_end'])
def test_bundle_early_generator_close_is_sticky(tmp_path,position):
    blobs,metadata,_=fixture(tmp_path);dst=receiver(metadata)
    with source(blobs,metadata) as src:
        frames=src.first_frames()
        while True:
            raw=next(frames);dst.feed(raw)
            value=parse_json_bytes(raw,maximum_bytes=bundle._HEADER_LIMIT)
            if position=='header' or (position=='member_end'and value['kind']=='end') \
                or (position=='outer_end'and raw==bundle._bundle_end(src._header_raw,src._manifest,1)):
                break
        frames.close()
        assert src._state=='failed'
        with pytest.raises(PhaseError):src.rewind_after_ready(bundle._bundle_token(src._header_raw,'ready'))


def test_bundle_retirement_invalidates_paused_generator(tmp_path):
    blobs,metadata,_=fixture(tmp_path)
    with source(blobs,metadata) as src:
        frames=src.first_frames();next(frames)
    assert src._state=='retired'
    with pytest.raises(PhaseError):next(frames)
    with pytest.raises(PhaseError):src.first_frames()


def test_bundle_late_corrupt_replay_chunk_never_reaches_consumer(tmp_path):
    blobs,metadata,_=fixture(tmp_path,{'a.bin':b'a','z.bin':b'z'*300000})
    dst=receiver(metadata);released=[];corrupted=False
    with pytest.raises(PhaseError,match='ntfs.file2_replay_mismatch'):
        with source(blobs,metadata) as src:
            first(src,dst)
            last=digest_bytes(src._headers[-1])
            for raw in src.replay_frames():
                frame=parse_json_bytes(raw,maximum_bytes=bundle._HEADER_LIMIT)
                if frame.get('kind')=='chunk'and frame.get('header_digest')==last:
                    frame['content_base64']=base64.b64encode(b'X'*len(base64.b64decode(frame['content_base64']))).decode()
                    raw=canonical_bytes(frame);corrupted=True
                item=dst.feed(raw)
                if item:released.append(item[0])
    assert corrupted and released==['a.bin'] and dst._state=='failed'


@pytest.mark.parametrize('phase', [1,2])
def test_bundle_trailing_frames_block_positive_summary(tmp_path,phase):
    blobs,metadata,_=fixture(tmp_path);dst=receiver(metadata)
    with source(blobs,metadata) as src:
        if phase==2:first(src,dst)
        for raw in (src.first_frames()if phase==1 else src.replay_frames()):dst.feed(raw)
        with pytest.raises(PhaseError):dst.feed(b'{}')
        with pytest.raises(PhaseError):
            if phase==1:dst.ready_frame()
            else:dst.finish()


def test_bundle_bad_last_actual_blob_is_rejected_and_prior_fds_closed(tmp_path,monkeypatch):
    blobs,metadata,_=fixture(tmp_path,{'a.bin':b'a','z.bin':b''})
    manifest=parse_manifest(metadata)
    (blobs/manifest['members'][-1]['digest'].removeprefix('sha256:')).write_bytes(b'actual unexpected bytes')
    original=bundle._file2_verified_source;seen=[]
    @contextmanager
    def captured(*args,**kw):
        with original(*args,**kw)as value:
            seen.append(value._fd);yield value
    monkeypatch.setattr(bundle,'_file2_verified_source',captured)
    with pytest.raises(PhaseError,match='ntfs.bundle_snapshot_acquisition_unavailable')as error:
        with source(blobs,metadata):pytest.fail('bad content admitted')
    graph=error.value.details['acquisition']['exceptions']
    assert any(n['code']=='mechanism.content_binding_mismatch'for n in graph)
    assert len(seen)==1
    with pytest.raises(OSError):os.fstat(seen[0])


@pytest.mark.parametrize('failing_ordinal', [0,1,2])
def test_bundle_acquisition_failure_preserves_primary_and_enter_cleanup_graph(tmp_path,monkeypatch,failing_ordinal):
    blobs,metadata,_=fixture(tmp_path)
    original=bundle._file2_verified_source;entered=[];closed=[];attempt=[]
    class Manager:
        def __init__(self,*args,**kw):self.inner=original(*args,**kw);self.ordinal=len(attempt);attempt.append(self.ordinal)
        def __enter__(self):
            if self.ordinal==failing_ordinal:
                try:raise PhaseError('test.acquisition_primary')
                except PhaseError as primary:raise PhaseError('test.enter_cleanup')from primary
            value=self.inner.__enter__();entered.append(value._fd);return value
        def __exit__(self,*args):
            closed.append(self.ordinal);return self.inner.__exit__(*args)
    monkeypatch.setattr(bundle,'_file2_verified_source',Manager)
    with pytest.raises(PhaseError,match='ntfs.bundle_snapshot_acquisition_unavailable')as error:
        with source(blobs,metadata):pytest.fail('fault admitted')
    nodes=error.value.details['acquisition']['exceptions']
    assert {n['code']for n in nodes}=={'test.acquisition_primary','test.enter_cleanup'}
    assert closed==list(reversed(range(failing_ordinal)))
    assert attempt==list(range(failing_ordinal+1))
    for fd in entered:
        with pytest.raises(OSError):os.fstat(fd)


@pytest.mark.parametrize('failing_ordinal', [0,1,2])
def test_bundle_rewind_failure_is_terminal_for_source(tmp_path,monkeypatch,failing_ordinal):
    blobs,metadata,_=fixture(tmp_path);dst=receiver(metadata)
    with source(blobs,metadata)as src:
        for raw in src.first_frames():dst.feed(raw)
        original=os.lseek;calls=[]
        selected=src._sources[failing_ordinal]._fd
        def broken(fd,offset,whence):
            calls.append(fd)
            if fd==selected:raise OSError(errno.EIO,'modeled rewind failure')
            return original(fd,offset,whence)
        monkeypatch.setattr(os,'lseek',broken)
        with pytest.raises(OSError):src.rewind_after_ready(dst.ready_frame())
        assert len(calls)==failing_ordinal+1
        with pytest.raises(PhaseError):src.replay_frames()
        with pytest.raises(PhaseError):dst.finish()


@pytest.mark.parametrize('with_primary', [False,True])
def test_bundle_all_context_closes_once_and_primary_survives(tmp_path,monkeypatch,with_primary):
    blobs,metadata,_=fixture(tmp_path)
    original=bundle._file2_verified_source;created=[];closed=[];fds=[]
    class Manager:
        def __init__(self,*args,**kw):
            self.inner=original(*args,**kw);self.ordinal=len(created);created.append(self.ordinal)
        def __enter__(self):
            value=self.inner.__enter__();fds.append(value._fd);return value
        def __exit__(self,*args):
            closed.append(self.ordinal)
            self.inner.__exit__(*args)  # Real close, then an explicitly modeled reported error.
            raise PhaseError('test.close_'+str(self.ordinal))
    monkeypatch.setattr(bundle,'_file2_verified_source',Manager)
    with pytest.raises(PhaseError,match='ntfs.bundle_source_finalization_unavailable')as error:
        with source(blobs,metadata)as src:
            if with_primary:raise PhaseError('test.body_primary')
    assert closed==[2,1,0] and src._state=='retired'
    details=error.value.details
    assert [n['member_ordinal']for n in details['finalization']]==[2,1,0]
    assert [n['error']['exceptions'][0]['code']for n in details['finalization']]==[
        'test.close_2','test.close_1','test.close_0']
    assert(details['primary']is None)==(not with_primary)
    if with_primary:assert details['primary']['exceptions'][0]['code']=='test.body_primary'
    for fd in fds:
        with pytest.raises(OSError):os.fstat(fd)


def test_bundle_fd_preflight_is_read_only_and_no_acquisition_on_low_limit(tmp_path,monkeypatch):
    import resource
    blobs,metadata,_=fixture(tmp_path);called=[]
    monkeypatch.setattr(resource,'getrlimit',lambda kind:(1,1))
    def forbidden(*args,**kw):called.append(True);pytest.fail('acquisition before FD check')
    monkeypatch.setattr(bundle,'_file2_verified_source',forbidden)
    with pytest.raises(PhaseError,match='ntfs.bundle_snapshot_fd_capacity'):
        with source(blobs,metadata):pytest.fail('low FD budget admitted')
    assert called==[]


def test_bundle_large_outer_header_keeps_existing_leaf_bound_and_resource_estimates():
    empty=digest_bytes(b'')
    members=[{'path':('/'.join(['a'*200]*4))+'/'+str(i).zfill(4)+'.bin','length':0,'digest':empty}
        for i in range(1024)]
    metadata=canonical_bytes({'bundle_version':'1.0','members':members,'total_length':0})
    assert 900000<len(metadata)<=1024**2
    manifest,header=bundle._bundle_header(context_bytes=_CONTEXT,channel_id=_CHANNEL,manifest_bytes=metadata)
    assert len(header)>512*1024 and len(header)<=bundle._HEADER_LIMIT
    dst=receiver(metadata)
    assert dst.feed(header)is None and len(dst._children)==1024
    bounds=bundle._bundle_source_bounds(metadata)
    assert bounds['snapshot_fds']==1024 and bounds['acquisition_fd_overhead']==2
    assert bounds['snapshot_payload_peak']==FILE_LIMIT and bounds['chunk_hashes']==0
    # Numerical bound only: no6GiB workload, RSS or FD reservation is asserted.
    members[0]['length']=members[1]['length']=FILE_LIMIT
    metadata=canonical_bytes({'bundle_version':'1.0','members':members,'total_length':MAX_TOTAL_BYTES})
    bounds=bundle._bundle_source_bounds(metadata)
    assert bounds['snapshot_payload_peak']==6*1024**3
    assert bounds['chunk_hashes']==16384<=17408
    assert parse_manifest(metadata)['total_length']==4*1024**3


@pytest.mark.parametrize('fault', ['noncanonical','bool_length','order','alias','too_many','per_member','total'])
def test_bundle_existing_manifest_owner_and_limits_remain_exact(fault):
    rows=[{'path':'a.bin','length':0,'digest':digest_bytes(b'')},
        {'path':'b.bin','length':0,'digest':digest_bytes(b'')}]
    value={'bundle_version':'1.0','members':rows,'total_length':0}
    if fault=='bool_length':rows[0]['length']=False
    elif fault=='order':rows.reverse()
    elif fault=='alias':rows[1]['path']='A.bin'
    elif fault=='too_many':
        value['members']=[{'path':str(i).zfill(4)+'.bin','length':0,'digest':digest_bytes(b'')}for i in range(1025)]
    elif fault=='per_member':rows[0]['length']=FILE_LIMIT+1;value['total_length']=FILE_LIMIT+1
    elif fault=='total':
        value['members']=[{'path':str(i)+'.bin','length':FILE_LIMIT,'digest':digest_bytes(b'')}for i in range(3)]
        value['total_length']=3*FILE_LIMIT
    data=canonical_bytes(value)
    if fault=='noncanonical':data=json.dumps(value).encode()
    with pytest.raises(PhaseError):receiver(data)


def test_bundle_diagnostic_graph_keeps_group_and_cycle_without_losing_nodes():
    a=PhaseError('test.primary');b=PhaseError('test.cleanup')
    a.__context__=b;b.__context__=a
    group=ExceptionGroup('modeled acquisition errors',[a,b])
    graph=bundle._bundle_failure(group)
    nodes=graph['exceptions']
    assert len(nodes)==3 and nodes[0]['group']==[1,2]
    assert nodes[1]['context']==2 and nodes[2]['context']==1
    assert {n['code']for n in nodes}=={None,'test.primary','test.cleanup'}


def test_bundle_literal_wire_binding_oracle(tmp_path):
    _,metadata,_=fixture(tmp_path)
    literal=lambda v:json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    digest=lambda b:'sha256:'+hashlib.sha256(b).hexdigest()
    manifest=json.loads(metadata)
    outer=literal({'protocol':'phase.native.bundle.bytes','version':'1.0','kind':'header',
        'context':json.loads(_CONTEXT),'channel_id':_CHANNEL,
        'manifest_digest':digest(metadata),'manifest_base64':base64.b64encode(metadata).decode()})
    dst=receiver(metadata)
    assert dst._header_raw==outer
    expected=[]
    for ordinal,item in enumerate(manifest['members']):
        channel=hashlib.sha256(literal({'domain':'phase.native.bundle.member.v1',
            'outer_header_digest':digest(outer),'ordinal':ordinal,'path':item['path']})).hexdigest()[:32]
        expected.append(literal({'protocol':'phase.native.file2.bytes','version':'1.0','kind':'header',
            'context':json.loads(_CONTEXT),'channel_id':channel,'content_digest':item['digest'],
            'content_length':item['length'],'chunk_bytes':262144,'chunk_count':(item['length']+262143)//262144}))
    assert dst._headers==tuple(expected)
    for phase in (1,2):
        assert dst._ends[phase]==literal({'protocol':'phase.native.bundle.bytes','version':'1.0','kind':'end',
            'header_digest':digest(outer),'pass':phase,'manifest_digest':digest(metadata),
            'member_count':len(manifest['members']),'total_length':manifest['total_length']})
    for kind in ('ready','rewound','go'):
        assert bundle._bundle_token(outer,kind)==literal({'protocol':'phase.native.bundle.bytes',
            'version':'1.0','kind':kind,'header_digest':digest(outer)})

@pytest.mark.parametrize('mode', ['cleanup','acquisition'])
def test_bundle_formatter_fault_cannot_skip_closes_or_replace_original(tmp_path,monkeypatch,mode):
    blobs,metadata,_=fixture(tmp_path)
    original=bundle._file2_verified_source;formatter=bundle._bundle_failure
    events=[];fds=[];created=[]
    primary=PhaseError('test.original_primary')
    class Manager:
        def __init__(self,*args,**kw):
            self.inner=original(*args,**kw);self.ordinal=len(created);created.append(self.ordinal)
        def __enter__(self):
            if mode=='acquisition'and self.ordinal==2:raise primary
            value=self.inner.__enter__();fds.append(value._fd);return value
        def __exit__(self,*args):
            events.append(('close',self.ordinal));self.inner.__exit__(*args)
            if mode=='cleanup':raise PhaseError('test.modeled_close_'+str(self.ordinal))
    def broken(error):
        events.append(('format',error.code))
        if mode=='acquisition'or error.code.startswith('test.modeled_close_'):
            raise PhaseError('test.diagnostic_failure')
        return formatter(error)
    monkeypatch.setattr(bundle,'_file2_verified_source',Manager)
    monkeypatch.setattr(bundle,'_bundle_failure',broken)
    with pytest.raises(PhaseError)as error:
        with source(blobs,metadata):
            raise primary
    outcome=error.value
    assert outcome.original_primary is primary and outcome.__cause__ is primary
    expected=[('close',2),('close',1),('close',0)]if mode=='cleanup'else[('close',1),('close',0)]
    assert events[:len(expected)]==expected
    assert [v for v in events if v[0]=='close']==expected
    assert outcome.details['diagnostic_complete']is False and outcome.diagnostic_errors
    assert len(outcome.finalization_errors)==(3 if mode=='cleanup'else 0)
    for fd in fds:
        with pytest.raises(OSError):os.fstat(fd)
