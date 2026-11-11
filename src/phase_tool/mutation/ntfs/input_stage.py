"""Closed Windows-input transport into the existing ext4 preparation owner.

No Core/evidence/queue/version implementation. Asset bytes use finite raw stdio
frames, never NativeChannel or a giant JSON/base64 value. A prepared result is
input data only. Existing Core must independently capture/freeze it.
"""
from __future__ import annotations
import hashlib,os,re,threading,time
from contextlib import contextmanager,closing
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path,PureWindowsPath
from ...canonical import canonical_bytes,digest_bytes,parse_json_bytes,profile_digest
from ...errors import PhaseError
from ...paths import safe_relative_locator
from ...bundle import validate_members,parse_manifest,MAX_TOTAL_BYTES,MAX_MEMBERS,MAX_DEPTH,_BundleLimitExceeded
from ...streaming import FILE_LIMIT,REQUEST_LIMIT
from .native import NativeIdentity,_require,_input_leaf

_SCOPE_FILE='native-input-scope.json'
_PROTOCOL='phase.native.input.stage'
_VERSION='1.0'
_CHUNK=256*1024
_CONTROL=2*1024**2
_MARKER=4*1024**2
_DIGEST=re.compile('sha256:[0-9a-f]{64}')
_ID=re.compile('[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*')
_OPERATION=ContextVar('phase_native_input_operation_deadline',default=None)


class _InputOperationDeadline:
    __slots__=('owner','deadline_ns','entered','finished')
    def __init__(self,*,_initial_deadline_ns=None):
        _require(os.name=='nt','input_stage.windows_owner_required')
        now=time.perf_counter_ns()
        _require(_initial_deadline_ns is None or(type(_initial_deadline_ns)is int
            and now<_initial_deadline_ns<=now+30_000_000_000),'input_stage.deadline_cap_required')
        self.owner=(os.getpid(),threading.get_ident());self.deadline_ns=now+30_000_000_000 if _initial_deadline_ns is None else _initial_deadline_ns
        self.entered=False;self.finished=False
    def check(self):
        _require(self.owner==(os.getpid(),threading.get_ident())and self.entered and not self.finished,
            'input_stage.deadline_owner_required')


@contextmanager
def _input_operation_scope(token):
    _require(type(token)is _InputOperationDeadline and not token.entered and _OPERATION.get()is None,
        'input_stage.deadline_consumed')
    _require(token.owner==(os.getpid(),threading.get_ident()),'input_stage.deadline_owner_required')
    token.entered=True;state=_OPERATION.set(token)
    try:yield token
    finally:
        token.finished=True
        _OPERATION.reset(state)


def _active_input_deadline_ns():
    token=_OPERATION.get()
    if token is None:return None
    token.check()
    return token.deadline_ns


def _cap_input_deadline(fallback_ns):
    deadline=_active_input_deadline_ns()
    if deadline is None:return fallback_ns
    _left(deadline)
    return min(fallback_ns,deadline)


def _input_observation_timeout_ms(fallback_ms):
    """Read-only close observation may use zero after expiry, never renews IO."""
    token=_OPERATION.get()
    if token is None:return fallback_ms
    token.check()
    return min(fallback_ms,max(0,(token.deadline_ns-time.perf_counter_ns())//1_000_000))


def _left(deadline_ns):
    now=time.perf_counter_ns()if os.name=='nt'else time.monotonic_ns()
    _require(type(deadline_ns)is int and now<deadline_ns,'input_stage.deadline')


def _control(raw,maximum_bytes=_CONTROL):
    _require(type(raw)is bytes and 0<len(raw)<=maximum_bytes,'input_stage.control_bound')
    value=parse_json_bytes(raw,maximum_bytes=maximum_bytes)
    _require(type(value)is dict and canonical_bytes(value)==raw,'input_stage.canonical_control_required')
    return value


def _input_scope_document(raw,*,config,manifest,scope_path,fixture_raw,owner_configuration_raw=None):
    """Closed installation-only data; full manifest digest deliberately absent.

    scope JSON -> artifact graph -> manifest is acyclic. The actual accepted
    manifest/channel/nonce is bound separately in the transfer header.
    """
    from .owner_semantic_contracts import semantic_owner_contract
    from .owner_semantic_fixture import semantic_fixture_document as fixture_document
    _require(type(raw)is bytes and 0<len(raw)<=65536,'input_stage.scope_bound')
    doc=parse_json_bytes(raw,maximum_bytes=65536)
    ordinary=config.get('native_launch_version')=='4.0'
    owner_field='owner_directory_scope_digest'if ordinary else'fixture_digest'
    fields={'native_input_scope_version','scope_id','owner_scope_id',owner_field,'installation_id','contract',
            'windows_root','volume','root_identity','preparation_root','preparation_identity'}
    _require(type(doc)is dict and set(doc)==fields and canonical_bytes(doc)==raw
        and doc['native_input_scope_version']==('2.0'if ordinary else'1.0')and type(doc['scope_id'])is str
        and _ID.fullmatch(doc['scope_id'])is not None,'input_stage.scope_shape')
    _require(config.get('native_launch_version')in {'3.0','4.0'}
        and config['dependency_file_digests'].get(str(scope_path))==digest_bytes(raw)
        and config['artifact_graph']['windows'if os.name=='nt'else'linux']['dependency_file_digests'].get(str(scope_path))==digest_bytes(raw),
        'input_stage.scope_graph_binding')
    if ordinary:
        from .owner_directory_launch import _owner_configuration_from_launch_config
        from .owner_directory import owner_directory_configuration,owner_directory_scope_digest
        accepted_raw,accepted_digest=_owner_configuration_from_launch_config(config)
        _require(fixture_raw is None and owner_configuration_raw==accepted_raw,'input_stage.scope_owner_binding')
        fixture=owner_directory_configuration(accepted_raw,accepted_digest)
        accepted_digest=owner_directory_scope_digest(fixture)
    else:
        _require(owner_configuration_raw is None,'input_stage.scope_owner_binding')
        fixture=fixture_document(fixture_raw)
        accepted_raw,accepted_digest=fixture_raw,digest_bytes(fixture_raw)
    roles=[role for role in ('File1','File2','Version1','Version2','Bundle1','Bundle2')
           if manifest['contract']==semantic_owner_contract(role)]
    _require(len(roles)==1 and (ordinary or fixture['experimental_admission_version']=='3.0')
        and doc['owner_scope_id']==fixture['owner_scope_id']and doc[owner_field]==accepted_digest
        and doc['installation_id']==manifest['installation_id']and doc['contract']==manifest['contract']
        and doc['preparation_root']==manifest['preparation_root']
        and doc['preparation_identity']==manifest['preparation_identity'],'input_stage.scope_owner_binding')
    _require(type(doc['windows_root'])is str,'input_stage.local_input_root_required')
    root=PureWindowsPath(doc['windows_root'])
    _require(root.is_absolute()and re.fullmatch('[A-Z]:',root.drive)is not None
        and str(root)==doc['windows_root']and len(root.parts)>=2
        and all(part not in {'.','..'}for part in root.parts),'input_stage.local_input_root_required')
    try:root_encoded=doc['windows_root'].encode('utf-16-le',errors='strict')
    except UnicodeError as error:raise PhaseError('input_stage.invalid_source_unicode')from error
    _require(len(root.parts)<=129 and len(root_encoded)<=65520,
        'input_stage.source_root_utf16_bound')
    for part in root.parts[1:]:_input_leaf(part)
    NativeIdentity.parse(doc['root_identity'])
    volume=doc['volume']
    _require(type(volume)is dict and set(volume)=={'device','volume_guid','volume_serial32','filesystem','flags'}
        and volume['filesystem']=='NTFS'and type(volume['device'])is str
        and re.fullmatch(r'\\Device\\HarddiskVolume[0-9]+',volume['device'])is not None
        and type(volume['volume_guid'])is str
        and re.fullmatch(r'\\\\\?\\volume\{[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\}\\',volume['volume_guid'])is not None
        and type(volume['volume_serial32'])is int and 0<=volume['volume_serial32']<2**32
        and type(volume['flags'])is int and 0<=volume['flags']<2**32,
        'input_stage.local_ntfs_scope_required')
    return doc,roles[0]


def _scope_for_launch(launch):
    from .bootstrap import _NativeAcceptedLaunch
    from ...evidence import _read_qualification_catalog_chunk
    _require(type(launch)is _NativeAcceptedLaunch,'input_stage.accepted_launch_required')
    launch.check_runtime()
    config=launch._config
    path=Path(config['windows_launcher']if os.name=='nt'else config['linux_launcher']).parent/_SCOPE_FILE
    admission=launch._experimental_admission_context
    ordinary=config.get('native_launch_version')=='4.0'
    owner_raw=None
    if ordinary:
        from .owner_directory_launch import _owner_configuration_from_launch_config,_owner_directory_installation_arguments
        _owner_directory_installation_arguments(launch)
        owner_raw,_=_owner_configuration_from_launch_config(config)
        _require(admission is None,'input_stage.owner_admission_required')
    else:
        _require(admission is not None,'input_stage.owner_admission_required')
    raw=_read_qualification_catalog_chunk(path,65536)
    doc,role=_input_scope_document(raw,config=config,manifest=launch.manifest,scope_path=path,
        fixture_raw=None if ordinary else admission.raw,owner_configuration_raw=owner_raw)
    launch.check_runtime()
    return doc,role,digest_bytes(raw)


def _role_bounds(role):
    # Immutable existing data limits, not request-selected policy.
    if role=='File1':return 1,1024**2,1024**2
    if role=='Version1':return 1,16*1024**2,16*1024**2
    if role=='File2':return 1,FILE_LIMIT,FILE_LIMIT
    if role=='Version2':return 1,512*1024,512*1024
    _require(role in {'Bundle1','Bundle2'},'input_stage.role_required')
    return MAX_MEMBERS,FILE_LIMIT,MAX_TOTAL_BYTES


def _safe_input_locator(value):
    _require(type(value)is str and value and not value.startswith('/')and '\\'not in value and ':'not in value,
        'input_stage.relative_source_required')
    try:encoded=value.encode('utf-16-le',errors='strict')
    except UnicodeError as error:raise PhaseError('input_stage.invalid_source_unicode')from error
    _require(len(encoded)<=2048,'input_stage.source_locator_utf16_bound')
    parts=value.split('/')
    _require(1<=len(parts)<=32,'input_stage.source_locator_depth')
    for part in parts:_input_leaf(part)
    return value


def _stage_request(scope_id,source_locator,members=None):
    _require(type(scope_id)is str and _ID.fullmatch(scope_id)is not None,'input_stage.scope_id_required')
    source_locator=_safe_input_locator(source_locator)
    if members is not None:members=validate_members(members)
    return {'operation':'stage_input','native_input_stage_request_version':'1.0','input_scope':scope_id,
            'source_locator':source_locator,'members':members}


class _InputFileTooLarge(PhaseError):
    """Validated metadata exceeds the installed file bound."""

    def __init__(self,role,length,maximum):
        super().__init__('input_stage.member_bound')
        self.role=role
        self.length=length
        self.maximum=maximum


@dataclass(frozen=True)
class _ClosedInputFileRefusal:
    role: str
    length: int
    maximum: int


@dataclass(frozen=True)
class _ClosedInputBundleRefusal:
    role: str
    code: str
    kind: str
    observed: int
    maximum: int
    source_finalization: str


def _bundle_manifest_bytes(rows,total):
    return canonical_bytes({'bundle_version':'1.0','members':rows,'total_length':total})


def _header(launch,scope,role,scope_digest,request,records):
    _require(request==_stage_request(request['input_scope'],request['source_locator'],request['members'])
        and request['input_scope']==scope['scope_id'],'input_stage.fixed_request_required')
    bundle=role in {'Bundle1','Bundle2'}
    _require((request['members']is not None)==bundle,'input_stage.input_kind_mismatch')
    wanted=request['members']if bundle else ['payload']
    maximum_files,maximum_file,maximum_total=_role_bounds(role)
    _require(type(records)is list and 1<=len(records)<=maximum_files
        and [row['path']for row in records]==wanted,'input_stage.exact_members_required')
    _require(len({canonical_bytes(row['native_identity'])for row in records})==len(records),
        'input_stage.source_physical_alias')
    total=0;longest=0
    file_create=role in {'File1','File2'}
    for row in records:
        _require(type(row)is dict and set(row)=={'path','length','native_identity','state'}
            and type(row['length'])is int and row['length']>=0
            and (file_create or bundle or row['length']<=maximum_file),'input_stage.member_bound')
        if role=='File1':_require(row['length']>0,'input_stage.empty_legacy_input')
        identity=NativeIdentity.parse(row['native_identity'])
        _require(identity.volume_serial==NativeIdentity.parse(scope['root_identity']).volume_serial,
            'input_stage.source_volume_binding')
        state=row['state']
        _require(type(state)is dict and set(state)=={'native_identity','length','attributes','links','creation_time','write_time','change_time'}
            and canonical_bytes(state['native_identity'])==canonical_bytes(row['native_identity'])
            and type(state['length'])is int and state['length']==row['length']
            and type(state['links'])is int and state['links']==1 and type(state['attributes'])is int
            and not state['attributes']&0x410 and all(type(state[name])is int for name in('creation_time','write_time','change_time')),
            'input_stage.source_state_binding')
        if file_create and row['length']>maximum_file:
            raise _InputFileTooLarge(role,row['length'],maximum_file)
        total+=row['length']
        longest=max(longest,row['length'])
    if bundle:
        if longest>maximum_file:
            raise _BundleLimitExceeded('input_stage.member_bound','member_bytes',longest,maximum_file)
        if total>maximum_total:
            raise _BundleLimitExceeded('input_stage.total_bound','total_bytes',total,maximum_total)
        # Every real digest adds exactly 71 unescaped ASCII bytes to the empty field.
        # These bytes are used only for the bound, before any receiver or payload read.
        rows=[{'path':row['path'],'length':row['length'],'digest':''}for row in records]
        manifest_length=len(_bundle_manifest_bytes(rows,total))+71*len(rows)
        if manifest_length>REQUEST_LIMIT:
            raise _BundleLimitExceeded('bundle.metadata_limit','manifest_bytes',manifest_length,REQUEST_LIMIT)
    _require(total<=maximum_total,'input_stage.total_bound')
    raw=canonical_bytes({'protocol':_PROTOCOL,'version':_VERSION,'kind':'header','run_id':launch.run_id,
        'installation_digest':launch.installation_digest,'channel_id':launch.channel_id,'operation_nonce':launch.operation_nonce,
        'input_scope_digest':scope_digest,'input_scope':scope['scope_id'],'role':role,
        'source_locator':request['source_locator'],'payload_kind':'bundle'if bundle else'file',
        'chunk_bytes':_CHUNK,'members':records,'member_count':len(records),'total_length':total})
    _require(len(raw)<=_CONTROL,'input_stage.header_bound')
    return raw


class _InputStageSender:
    """One-shot byte release from the existing read-only NativeIO snapshot."""
    def __init__(self,launch,scope,role,scope_digest,request,source,deadline_ns):
        self.owner=(os.getpid(),threading.get_ident());self.source=source;self.deadline=deadline_ns
        self.header=_header(launch,scope,role,scope_digest,request,source.records)
        self.header_digest=digest_bytes(self.header);self.started=False;self.footer=None
        self.inline_bytes=bytearray()if role=='Version2'else None

    def frames(self):
        _require(self.owner==(os.getpid(),threading.get_ident())and not self.started,'input_stage.sender_consumed')
        self.started=True;rows=[];primary=None;closed=False;close_attempted=False
        try:
            for index,row in enumerate(self.source.records):
                digest=hashlib.sha256();offset=0
                for part in self.source.chunks(index):
                    _left(self.deadline)
                    _require(type(part)is bytes and 0<len(part)<=_CHUNK and offset+len(part)<=row['length'],
                        'input_stage.source_chunk_bound')
                    _require(len(part)==min(_CHUNK,row['length']-offset),'input_stage.source_chunk_length')
                    if self.inline_bytes is not None:
                        _require(len(self.inline_bytes)+len(part)<=512*1024,'input_stage.version2_inline_bound')
                        self.inline_bytes.extend(part)
                    digest.update(part);offset+=len(part);yield part
                _require(offset==row['length'],'input_stage.source_length')
                checked={'path':row['path'],'length':offset,'digest':'sha256:'+digest.hexdigest()};rows.append(checked)
                yield canonical_bytes({'protocol':_PROTOCOL,'version':_VERSION,'kind':'member_end',
                    'header_digest':self.header_digest,'index':index,'member':checked})
            self.source.verify_complete()
            close_attempted=True
            self.source.close();closed=True
            _left(self.deadline)
            total=sum(row['length']for row in rows)
            if _control(self.header)['payload_kind']=='bundle':parse_manifest(_bundle_manifest_bytes(rows,total))
            self.footer={'protocol':_PROTOCOL,'version':_VERSION,'kind':'end','header_digest':self.header_digest,
                'members':rows,'total_length':total,'source_handles_closed':True}
            yield canonical_bytes(self.footer)
            _left(self.deadline)
        except BaseException as error:primary=error;raise
        finally:
            if not close_attempted:
                close_attempted=True
                try:self.source.close()
                except BaseException as close_error:
                    if primary is not None:raise BaseExceptionGroup('input source and finalization failed',[primary,close_error])
                    raise


class _InputStageReceiver:
    """Bounded state machine; sink IO is exclusively the existing Evidence owner.

    Caller creates the exact owned sink only after accepted launch/scope/header
    correlation. Data-role completion grants no Core or NTFS write authority.
    """
    def __init__(self,header_raw,sink,deadline_ns):
        self.header=_control(header_raw);self.header_digest=digest_bytes(header_raw);self.sink=sink
        self.deadline=deadline_ns;self.index=0;self.offset=0;self.hash=hashlib.sha256();self.rows=[];self.state='member'
        _require(self.header['protocol']==_PROTOCOL and self.header['version']==_VERSION
            and self.header['kind']=='header'and self.header['chunk_bytes']==_CHUNK,'input_stage.header_required')

    def wanted(self):
        _left(self.deadline)
        if self.index<len(self.header['members']):
            return min(_CHUNK,self.header['members'][self.index]['length']-self.offset)
        return 0

    def feed(self,raw):
        try:return self._feed(raw)
        except BaseException:
            self.state='failed'
            raise

    def _feed(self,raw):
        _left(self.deadline)
        _require(self.state in {'member','end'},'input_stage.receiver_consumed')
        if self.state=='member':
            row=self.header['members'][self.index];wanted=self.wanted()
            if wanted:
                _require(type(raw)is bytes and len(raw)==wanted,'input_stage.chunk_length')
                if self.offset==0:self.sink.begin_member(self.index,row['path'],row['length'])
                self.sink.write(raw);self.hash.update(raw);self.offset+=len(raw)
                return None
            value=_control(raw)
            actual={'path':row['path'],'length':self.offset,'digest':'sha256:'+self.hash.hexdigest()}
            _require(canonical_bytes(value)==canonical_bytes({'protocol':_PROTOCOL,'version':_VERSION,'kind':'member_end',
                'header_digest':self.header_digest,'index':self.index,'member':actual}),'input_stage.member_end_mismatch')
            if not self.offset:self.sink.begin_member(self.index,row['path'],row['length'])
            self.sink.finish_member(actual);self.rows.append(actual);self.index+=1;self.offset=0;self.hash=hashlib.sha256()
            if self.index==len(self.header['members']):self.state='end'
            return None
        footer=_control(raw)
        _require(canonical_bytes(footer)==canonical_bytes({'protocol':_PROTOCOL,'version':_VERSION,'kind':'end','header_digest':self.header_digest,
            'members':self.rows,'total_length':sum(row['length']for row in self.rows),'source_handles_closed':True}),
            'input_stage.footer_mismatch')
        _require(footer['total_length']==self.header['total_length'],'input_stage.total_mismatch')
        self.state='finalizing'
        result=self.sink.finish(self.header_digest,self.rows,self.header['payload_kind'],preparation_binding=self.header)
        _left(self.deadline);self.state='complete'
        return result


def run_linux_input_stage_startup(*,config_bytes,expected_config_digest,manifest_bytes,expected_manifest_digest,
        _experimental_admission_context):
    """One literal preparation role, same wheel/container, no Core invocation."""
    from .entrypoint import _linux_stdio_identity
    from .bootstrap import _NativeAcceptedLaunch
    from ...evidence import _InputStageFrames,_OwnedInputStageSink
    from ...installation import _native_read_binding_for_launch,_linux_filesystem_type,_require_native_no_descendant_mounts
    from ...installation import qualify_host_authority_roots
    _require(os.name!='nt','input_stage.linux_role_required')
    deadline=time.monotonic_ns()+30_000_000_000
    _linux_stdio_identity()
    frames=_InputStageFrames(deadline);sink=None;primary=None;result=None
    try:
        invocation=_control(frames.receive_frame(_CONTROL))
        launch=_NativeAcceptedLaunch(config_bytes=config_bytes,expected_config_digest=expected_config_digest,
            manifest_bytes=manifest_bytes,expected_manifest_digest=expected_manifest_digest,
            invocation_bytes=canonical_bytes(invocation),_inspection_only=False,
            _experimental_admission_context=_experimental_admission_context)
        request=launch.invocation['request']
        _require(type(request)is dict and set(request)=={'operation','native_input_stage_request_version','header'}
            and request['operation']=='stage_input'and request['native_input_stage_request_version']=='1.0',
            'input_stage.fixed_role_request')
        scope,role,scope_digest=_scope_for_launch(launch);header=request['header']
        normal=_stage_request(header['input_scope'],header['source_locator'],
            [row['path']for row in header['members']]if role in{'Bundle1','Bundle2'}else None)
        expected=_header(launch,scope,role,scope_digest,normal,header['members'])
        _require(canonical_bytes(header)==expected,'input_stage.accepted_header_binding')
        prep=Path(scope['preparation_root'])
        qualify_host_authority_roots({'phase_preparation_root':prep})
        _require(_linux_filesystem_type(prep)=='ext4','input_stage.ext4_preparation_required')
        _require_native_no_descendant_mounts(prep)
        _native_read_binding_for_launch(launch).check_evidence_root()
        stage_name='phase-native-input-'+digest_bytes(expected)[7:39]
        sink=_OwnedInputStageSink(prep,{key:scope['preparation_identity'][key]for key in('device','inode')},stage_name,deadline)
        receiver=_InputStageReceiver(expected,sink,deadline)
        while receiver.state!='complete':
            raw=frames.receive_frame(receiver.wanted()or _CONTROL)
            result=receiver.feed(raw)
        launch.check_runtime();_left(deadline)
        response={'protocol':_PROTOCOL,'version':_VERSION,'kind':'prepared','run_id':launch.run_id,
            'channel_id':launch.channel_id,'installation_digest':launch.installation_digest,
            'input_scope_digest':scope_digest,'header_digest':digest_bytes(expected),'prepared':result}
        frames.send_frame(canonical_bytes(response));frames.seal();return 0
    except BaseException as error:
        primary=error
        if sink is not None and not sink.close_attempted:sink.abort(error)
        raise
    finally:
        if not frames.sealed:frames.seal()


def _validate_prepared_input(response,*,launch,scope_digest,header,footer):
    fields={'protocol','version','kind','run_id','channel_id','installation_digest','input_scope_digest','header_digest','prepared'}
    _require(type(response)is dict and set(response)==fields and response['protocol']==_PROTOCOL
        and response['version']==_VERSION and response['kind']=='prepared'
        and response['run_id']==launch.run_id and response['channel_id']==launch.channel_id
        and response['installation_digest']==launch.installation_digest
        and response['input_scope_digest']==scope_digest and response['header_digest']==digest_bytes(header),
        'input_stage.preparation_response_binding')
    value=response['prepared'];h=_control(header)
    fields={'native_prepared_input_version','header_digest','payload_kind','source_locator','expected_digest','expected_length',
            'member_count','total_length','members','owned_preparation_descriptors_closed'}
    _require(type(value)is dict and set(value)==fields and value['native_prepared_input_version']=='1.0'
        and value['header_digest']==digest_bytes(header)
        and value['payload_kind']==h['payload_kind']and canonical_bytes(value['members'])==canonical_bytes(footer['members'])
        and type(value['member_count'])is int and value['member_count']==len(footer['members'])
        and type(value['total_length'])is int and value['total_length']==footer['total_length']
        and value['owned_preparation_descriptors_closed']is True,'input_stage.prepared_input_binding')
    name='phase-native-input-'+digest_bytes(header)[7:39]
    expected_locator=name+'/payload'+('/payload'if h['payload_kind']=='file'else'')
    _require(value['source_locator']==expected_locator,'input_stage.prepared_path_binding')
    if h['payload_kind']=='file':
        expected_digest=footer['members'][0]['digest'];expected_length=footer['members'][0]['length']
    else:
        data=_bundle_manifest_bytes(footer['members'],footer['total_length'])
        parse_manifest(data);expected_digest=digest_bytes(data);expected_length=len(data)
    _require(type(value['expected_length'])is int and value['expected_digest']==expected_digest
        and value['expected_length']==expected_length,'input_stage.prepared_digest_binding')
    return parse_json_bytes(canonical_bytes(value))


def run_windows_input_stage(owner,run_id,input_scope,source_locator,members,deadline_ns,*,request_id,target_locator,expected_current_digest):
    """Return prepared data or a closed source-size refusal; no Core call.

    Only the existing finite MCP/CLI owner calls this while holding its gate.
    It retains actual launch/process on every uncertain cleanup path.
    """
    from .bootstrap import _NativeAcceptedLaunch
    from .native import NativeIO,_NativeInputSnapshot
    from .process_witness import WindowsProcessWitness
    import secrets
    _require(os.name=='nt','input_stage.windows_owner_required');_left(deadline_ns)
    probe_request=_stage_request(input_scope,source_locator)
    invocation={'run_id':run_id,'request':probe_request,'channel_id':secrets.token_hex(16),'operation_nonce':secrets.token_hex(16)}
    probe=_NativeAcceptedLaunch(**owner._startup,invocation_bytes=canonical_bytes(invocation),_inspection_only=True)
    scope,role,scope_digest=_scope_for_launch(probe)
    _require(scope['scope_id']==input_scope,'input_stage.foreign_scope')
    try:
        _publication_candidate(role,request_id,target_locator,members,expected_current_digest,
            ''if role=='Version2'else None)  # Pure caller literals BEFORE source IO.
    except _BundleLimitExceeded as error:
        _require(role in {'Bundle1','Bundle2'} and error.kind in {'member_count','member_depth','candidate_bytes'}
            and owner._held_launch is None and owner._held_input_source is None and owner._held_input_io is None,
            'input_stage.source_finalization_unknown')
        _left(deadline_ns)
        return _ClosedInputBundleRefusal(role,error.code,error.kind,error.observed,error.maximum,'not_opened')
    request=_stage_request(input_scope,source_locator,members)
    source=None;sender=None;process=None;pipe=None;witness=None;primary=None;result=None;fact=None;closed=False
    refusal=None
    try:
        api=object.__new__(NativeIO)
        owner._held_input_io=api  # Retain before the first native constructor call.
        NativeIO.__init__(api)
        source=api.input_snapshot(scope,source_locator,members,deadline_ns)
        owner._held_input_source=source
        _require(type(source)is _NativeInputSnapshot,'input_stage.closed_source_required')
        try:
            sender=_InputStageSender(probe,scope,role,scope_digest,request,source,deadline_ns)
        except _InputFileTooLarge as error:
            source.verify_complete()
            refusal=_ClosedInputFileRefusal(error.role,error.length,error.maximum)
        except _BundleLimitExceeded as error:
            _require(role in {'Bundle1','Bundle2'} and error.kind in {'member_bytes','total_bytes','manifest_bytes'},
                'input_stage.source_finalization_unknown')
            source.verify_complete()
            refusal=_ClosedInputBundleRefusal(role,error.code,error.kind,error.observed,error.maximum,'closed')
        else:
            invocation['request']={'operation':'stage_input','native_input_stage_request_version':'1.0','header':_control(sender.header)}
            launch=_NativeAcceptedLaunch(**owner._startup,invocation_bytes=canonical_bytes(invocation),_inspection_only=False)
            owner._held_launch=launch
            _left(deadline_ns);process=launch.spawn_input_stage()
            witness=WindowsProcessWitness(process);pipe=launch._pipe(process)
            pipe.send_frame(launch._invocation_bytes,deadline_ns)
            with closing(sender.frames())as frames:
                for raw in frames:
                    _left(deadline_ns);pipe.send_frame(raw,deadline_ns)
            closed=True
            raw,_=pipe.receive_frame(deadline_ns,maximum_bytes=_CONTROL)
            result=_validate_prepared_input(_control(raw),launch=launch,scope_digest=scope_digest,header=sender.header,footer=sender.footer)
            pipe._expect_eof(deadline_ns)
            stderr=bytearray()
            while True:
                _left(deadline_ns)
                try:raw=os.read(process.stderr.fileno(),min(65536,65537-len(stderr)))
                except BlockingIOError:continue
                if not raw:break
                stderr.extend(raw);_require(len(stderr)<=65536,'input_stage.stderr_bound')
            _require(not stderr,'input_stage.preparation_stderr')
    except BaseException as error:
        primary=error;owner._unavailable=True
    finally:
        if source is not None and not source.close_attempted:
            try:source.close()
            except BaseException as error:
                if primary is None:primary=error
                else:primary=BaseExceptionGroup('input staging and source close failed',[primary,error])
        if process is not None:
            try:
                _require(witness is not None,'input_stage.process_witness_unknown')
                timeout=max(0,min(30000,(deadline_ns-time.perf_counter_ns())//1_000_000))
                fact=witness.wait_for_exit(timeout)
                _require(fact['worker_exit_established']is True,'input_stage.preparation_process_exit_unknown')
                launch._finalize_exited(process,pipe)
            except BaseException as error:
                owner._unavailable=True
                if primary is None:primary=error
                else:primary=BaseExceptionGroup('input staging and preparation finalization failed',[primary,error])
    if primary is not None:raise primary
    _left(deadline_ns)
    if refusal is not None:
        _require(source.close_attempted and not api._handles and owner._held_launch is None,
            'input_stage.source_finalization_unknown')
        owner._held_input_source=None;owner._held_input_io=None
        return refusal
    _require(result is not None and fact['exit_code']==0 and closed,'input_stage.preparation_delivery_unknown')
    _require(not api._handles,'input_stage.source_finalization_unknown')
    owner._held_launch=None
    owner._held_input_source=None;owner._held_input_io=None
    content=None if sender.inline_bytes is None else bytes(sender.inline_bytes).decode('utf-8',errors='strict')
    return result,role,scope,content


def _publication_candidate(role,request_id,target_locator,members,expected_current_digest,content_utf8=None):
    """Existing six candidate formulas; role comes only from fixed installation."""
    _require(type(request_id)is str and len(request_id)<=128 and _ID.fullmatch(request_id)is not None,
        'input_stage.request_id_required')
    target_locator=safe_relative_locator(target_locator)
    if role=='Version1':
        from .preparation import _version1_publication_candidate
        _require(members is None and content_utf8 is None,'input_stage.unexpected_members')
        return _version1_publication_candidate(request_id,target_locator,expected_current_digest)
    if role in{'Bundle1','Bundle2'}:
        from ...publish_bundle import _bundle_publication_candidate
        _require(expected_current_digest is None and content_utf8 is None,'input_stage.unexpected_current_digest')
        return _bundle_publication_candidate(request_id,target_locator,members)
    _require(members is None,'input_stage.unexpected_members')
    candidate={'operation_id':request_id,'idempotency_key':request_id,'target_locator':target_locator}
    if role=='Version2':
        from ...contracts.publish_new_version_v2 import inline_content
        _require(type(content_utf8)is str,'input_stage.version2_utf8_required')
        candidate['content_utf8']=content_utf8
        candidate['media_type']='text/plain; charset=utf-8'
        inline_content(candidate)
    else:
        _require(content_utf8 is None,'input_stage.unexpected_inline_content')
        candidate['input_binding']='payload'
    if role in{'Version1','Version2'}:
        _require(type(expected_current_digest)is str and _DIGEST.fullmatch(expected_current_digest)is not None,
            'input_stage.current_digest_required')
        candidate['expected_current_digest']=expected_current_digest
    else:
        _require(role in{'File1','File2'}and expected_current_digest is None,'input_stage.fixed_role_required')
    return candidate,canonical_bytes(candidate)


def _staged_publication_request(*,role,prepared,input_scope,request_id,target_locator,members,expected_current_digest,content_utf8=None):
    candidate,raw=_publication_candidate(role,request_id,target_locator,members,expected_current_digest,content_utf8)
    source_locator=safe_relative_locator(prepared['source_locator'])
    request={'operation':'execute','native_staged_publication_request_version':'1.0','input_scope':input_scope,
        'stage_header_digest':prepared['header_digest'],'source_locator':source_locator,
        'source_digest':prepared['expected_digest'],'source_length':prepared['expected_length'],
        'request_id':request_id,'target_locator':candidate['target_locator'],
        'members':candidate['members']if role in{'Bundle1','Bundle2'}else None,
        'expected_current_digest':expected_current_digest,'content_utf8':content_utf8}
    return _require_staged_publication_request(request,role=role)


def _require_staged_publication_request(request,*,role):
    fields={'operation','native_staged_publication_request_version','input_scope','stage_header_digest',
        'source_locator','source_digest','source_length','request_id','target_locator','members','expected_current_digest','content_utf8'}
    _require(type(request)is dict and set(request)==fields and request['operation']=='execute'
        and request['native_staged_publication_request_version']=='1.0'
        and type(request['input_scope'])is str and _ID.fullmatch(request['input_scope'])is not None
        and all(type(request[name])is str and _DIGEST.fullmatch(request[name])is not None
            for name in('stage_header_digest','source_digest'))
        and type(request['source_length'])is int and 0<=request['source_length']<=FILE_LIMIT,
        'input_stage.staged_request_shape')
    source=safe_relative_locator(request['source_locator'])
    prefix='phase-native-input-'+request['stage_header_digest'][7:39]+'/payload'
    _require(source==prefix+('/payload'if role not in{'Bundle1','Bundle2'}else''),
        'input_stage.staged_path_binding')
    candidate,raw=_publication_candidate(role,request['request_id'],request['target_locator'],request['members'],request['expected_current_digest'],request['content_utf8'])
    _require(candidate['target_locator']==request['target_locator']
        and(role not in{'Bundle1','Bundle2'}or candidate['members']==request['members']),
        'input_stage.staged_candidate_binding')
    maximum_files,maximum_file,maximum_total=_role_bounds(role)
    if role not in{'Bundle1','Bundle2'}:
        _require(request['source_length']<=maximum_file and(role!='File1'or request['source_length']>0),
            'input_stage.staged_file_bound')
    if role=='Version2':
        content=request['content_utf8'].encode('utf-8',errors='strict')
        _require(len(content)==request['source_length']and digest_bytes(content)==request['source_digest'],
            'input_stage.version2_source_digest')
    return parse_json_bytes(canonical_bytes(request))


def _read_staged_input_marker(launch,request):
    """Read fixed prep marker; it supplies input assertions, never authority."""
    from ...evidence import _read_qualification_catalog_chunk
    scope,role,scope_digest=_scope_for_launch(launch)
    request=_require_staged_publication_request(request,role=role)
    _require(scope['scope_id']==request['input_scope'],'input_stage.foreign_scope')
    name='phase-native-input-'+request['stage_header_digest'][7:39]
    marker=_control(_read_qualification_catalog_chunk(Path(scope['preparation_root'])/name/'input-stage.json',_MARKER),_MARKER)
    _require(set(marker)=={'native_prepared_input_version','header_digest','payload_kind','source_locator','expected_digest',
        'expected_length','member_count','total_length','members','source_header','telemetry_stage','final_acceptance'}
        and marker['native_prepared_input_version']=='1.0'and marker['header_digest']==request['stage_header_digest']
        and marker['telemetry_stage']=='PRE_RETURN_PREPARATION_DATA'and marker['final_acceptance']is None
        and marker['source_locator']==request['source_locator']and marker['expected_digest']==request['source_digest']
        and type(marker['expected_length'])is int and marker['expected_length']==request['source_length'],
        'input_stage.prepared_marker_binding')
    header=marker['source_header']
    _require(type(header)is dict and digest_bytes(canonical_bytes(header))==request['stage_header_digest']
        and header['run_id']==launch.run_id and header['installation_digest']==launch.installation_digest
        and header['input_scope_digest']==scope_digest and header['input_scope']==scope['scope_id']and header['role']==role
        and all(type(header[name])is str and re.fullmatch('[0-9a-f]{32}',header[name])is not None for name in('channel_id','operation_nonce')),
        'input_stage.source_header_binding')
    context=type('_InputHeaderData',(),{'run_id':header['run_id'],'installation_digest':header['installation_digest'],
        'channel_id':header['channel_id'],'operation_nonce':header['operation_nonce']})()
    original=_stage_request(scope['scope_id'],header['source_locator'],request['members'])
    _require(_header(context,scope,role,scope_digest,original,header['members'])==canonical_bytes(header),
        'input_stage.prepared_header_shape')
    rows=marker['members']
    _require(type(rows)is list and [row['path']for row in rows]==[row['path']for row in header['members']]
        and type(marker['member_count'])is int and marker['member_count']==len(rows)
        and type(marker['total_length'])is int and marker['total_length']==sum(row['length']for row in rows),
        'input_stage.prepared_membership')
    for row,source in zip(rows,header['members']):
        _require(type(row)is dict and set(row)=={'path','length','digest'}and type(row['length'])is int
            and row['length']==source['length']and type(row['digest'])is str and _DIGEST.fullmatch(row['digest'])is not None,
            'input_stage.prepared_member_binding')
    if role in{'Bundle1','Bundle2'}:
        raw=canonical_bytes({'bundle_version':'1.0','members':rows,'total_length':marker['total_length']});parse_manifest(raw)
        _require(marker['payload_kind']=='bundle'and request['source_digest']==digest_bytes(raw)
            and request['source_length']==len(raw),'input_stage.bundle_manifest_binding')
    else:
        _require(marker['payload_kind']=='file'and len(rows)==1 and rows[0]['digest']==request['source_digest']
            and rows[0]['length']==request['source_length'],'input_stage.file_binding')
    return scope,role,marker


def _require_staged_original(*,launch,request,intent,plan,parsed,binding):
    """Additional literal assertions AFTER the same full Original parser read."""
    from .handoff import ParsedNativeFileCreate,ParsedNativeVersion1,ParsedNativeVersion2,_OriginalControlProjection,_BundleControlProjection
    scope,role,marker=_read_staged_input_marker(launch,request)
    kinds={'File1':ParsedNativeFileCreate,'File2':_OriginalControlProjection,'Version1':ParsedNativeVersion1,
        'Version2':ParsedNativeVersion2,'Bundle1':_BundleControlProjection,'Bundle2':_BundleControlProjection}
    _require(type(parsed)is kinds[role],'input_stage.genuine_original_required')
    candidate,_=_publication_candidate(role,request['request_id'],request['target_locator'],request['members'],request['expected_current_digest'],request['content_utf8'])
    _require(intent['run_id']==plan['run_id']==launch.run_id and intent['contract']==plan['contract']==launch.manifest['contract']
        and canonical_bytes(intent['candidate']['storage']['value'])==canonical_bytes(candidate)
        and intent['candidate']['digest']==profile_digest('candidate',candidate)
        and intent['idempotency']['key']==request['request_id']and len(plan['effects'])==1
        and len(intent['inputs'])==(0 if role=='Version2'else 1),'input_stage.original_candidate_mismatch')
    effect=plan['effects'][0]
    if role!='Version2':
        frozen=intent['inputs'][0]
        # FrozenInput.intent_record deliberately has no length field. The
        # mandatory binding.read verified actual content before this function;
        # the effect length binds that verified content to the request below.
        _require(frozen['binding_id']=='payload'and frozen['digest']==frozen.get('blob_digest')==request['source_digest'],
            'input_stage.original_payload_mismatch')
    root_binding='current_root'if role=='Version2'else next(iter(launch.manifest['root_projections']))
    _require(effect['content_digest']==request['source_digest']and effect['content_length']==request['source_length']
        and effect['target']=={'root_binding':root_binding,'relative_locator':request['target_locator']},
        'input_stage.original_payload_mismatch')
