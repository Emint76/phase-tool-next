"""Private fixed first-C05 Windows transport evidence. No execution authority."""
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import re
import sys
import threading
import time

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes


CASE = '51c05d17-7e2b-4c45-9273-15aa66bdab75'
CASE_HOST = Path(r'C:\Users\Gennady\CodexWorkspace\phase-tool-codex-app\work\native-owner3-c05-ci169-51c05d17')
RAW_ROOT = CASE_HOST/'c05'/'transport'/'round-000'
LAUNCHER = CASE_HOST/'install'/'artifacts'/'file1'/'windows'/'launcher.py'
LAUNCHER_DIGEST = 'sha256:a67ef749032b0f779ead901250232278bf8522ffcf3041bf9e4a30f51d65c397'
POLICY = LAUNCHER.with_name('c05-windows-transport-capture.json')
INPUT = 'owner3-input-'+CASE+'-file1'
TARGET = 'c05-r000.bin'
SPECS = {'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p0': 'sha256:4a9cda3af363bfd566f3d7cb6a178f10b365b38fc43df1b3cbd1ef647b9f9ad8', 'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p1': 'sha256:d798b97811562b7a5c5f0174ca0e7aa149dd7a2ac72d06939bdb22f5b3381fae', 'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p2': 'sha256:eb220d7611374b87db771e561bcf10d45ca5d6907a8662094e6f6ebd254eadd5', 'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p3': 'sha256:a7ab795cebd7a87130d415b43ad2102694f085b07a62c8c3ef4dd2957e6dbb67', 'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p4': 'sha256:cdd7e566b6906d09e6de40f5a1c78a809f067386b935092e19cd57203564454d', 'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p5': 'sha256:3ae651133743b63f5a111621190e663a9af2ee1088748a281e56c4e6fa7c7010', 'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p6': 'sha256:47876af8f47bd2cc2aa6d9692a137320920331097dbe0ca35fc70c4cbd932dfa', 'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p7': 'sha256:0243d61a052238a600d6e54bb9c1ebe09e4a53f03e471e23b9c4fb8025f0c166'}
RUNS = tuple(SPECS)
MEMBERS = {'invocation.json':2048,'core-frame.json':2*1024**2,'windows-transport.json':8192}
ROLE_API = {'publish-input':'cli','input-mcp':'mcp'}
_FIXED_FIXTURE_SELECTION = object()


def need(condition,message):
    if not condition:
        raise ValueError(message)


def _digest(value):
    return type(value) is str and re.fullmatch('sha256:[0-9a-f]{64}',value) is not None


def _uint(value,bits):
    return type(value) is int and 0<=value<2**bits


def _identity(value):
    return (type(value) is dict and set(value)=={'volume_serial','file_id'}
            and _uint(value['volume_serial'],64) and type(value['file_id']) is str
            and re.fullmatch('[0-9a-f]{32}',value['file_id']) is not None)


def _parent(slot):
    return RAW_ROOT/('p'+str(slot))


def _raw_member_allowed(path,data):
    return (os.name=='nt' and type(path) is type(Path()) and path.parent.parent==RAW_ROOT
            and path.parent.name in {f'p{slot}' for slot in range(8)} and path.name in MEMBERS
            and type(data) is bytes and 0<len(data)<=MEMBERS[path.name])


def _policy(raw):
    value = parse_json_bytes(raw,maximum_bytes=16384)
    need(type(value) is dict and canonical_bytes(value)==raw
         and set(value)=={'schema','case','v4_policy_digest','v4_slot_binding_sha256','volume','slots'}
         and value['schema']=='phase.c05.windows-transport-capture/1' and value['case']==CASE
         and _digest(value['v4_policy_digest']) and _digest(value['v4_slot_binding_sha256']),
         'exact immutable C05 Raw resource policy')
    volume,slots = value['volume'],value['slots']
    need(type(volume) is dict and set(volume)=={'device','volume_guid','volume_serial32','filesystem','flags'}
         and type(volume['device']) is str and re.fullmatch(r'\\Device\\HarddiskVolume[0-9]+',volume['device'])
         and type(volume['volume_guid']) is str and re.fullmatch(r'\\\\\?\\volume\{[0-9a-f-]{36}\}\\',volume['volume_guid'])
         and volume['filesystem']=='NTFS' and _uint(volume['volume_serial32'],32) and _uint(volume['flags'],32)
         and type(slots) is list and len(slots)==8,'exact eight named C Raw owners')
    identities,nonces = set(),set()
    for index,(run,slot) in enumerate(zip(RUNS,slots,strict=True)):
        need(type(slot) is dict and set(slot)=={'run_id','api','parent_full128','completion_nonce'}
             and slot['run_id']==run and slot['api']==('mcp' if index%2 else 'cli')
             and _identity(slot['parent_full128']),'one exact typed C05 actor slot')
        nonce = slot['completion_nonce']
        need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce) and int(nonce,16)!=0
             and nonce not in nonces,'distinct exact C05 completion nonce')
        nonces.add(nonce)
        key = slot['parent_full128']['file_id']
        need(key not in identities,'distinct owned C parents')
        identities.add(key)
    need(len({slot['parent_full128']['volume_serial'] for slot in slots})==1,'same C Full128 volume')
    slots_digest = digest_bytes(canonical_bytes({'policy_digest':value['v4_policy_digest'],'case':CASE,
        'members':[[f'c05/transport/round-000/p{index}/{name}',cap] for index in range(8)
                   for name,cap in MEMBERS.items()]}))
    need(slots_digest==value['v4_slot_binding_sha256'],'exact existing V4 Raw occurrence binding')
    return value


def _load_c05_windows_transport(outer,config_raw,manifest_raw,admission,role):
    """Called only by the fixed fixture. Other roles use their stock path."""
    from .owner_directory_fixture import _kinds, fixture_document
    from .owner_semantic_contracts import semantic_owner_contract
    from ...evidence import _read_qualification_catalog_chunk

    if os.name!='nt' or outer['native_fixed_startup_version']!='3.0' or type(admission) is not _kinds()['File1']:
        return None
    fixture = fixture_document(admission.raw)
    if fixture['fixture_uuid']!=CASE:
        return None
    cfg,manifest = (parse_json_bytes(raw,maximum_bytes=2*1024**2) for raw in (config_raw,manifest_raw))
    graph = cfg['artifact_graph']
    need(role in ROLE_API and sys.argv[1:]==[role] and Path(sys.argv[0]).absolute()==LAUNCHER
         and cfg['windows_launcher']==str(LAUNCHER) and cfg['native_launch_version']=='3.0'
         and fixture['experimental_admission_version']=='3.0' and 'c02_current_root_alias' not in fixture
         and manifest['contract']==semantic_owner_contract('File1') and graph['launcher_digest']==LAUNCHER_DIGEST
         and digest_bytes(config_raw)==outer['config_digest'] and digest_bytes(manifest_raw)==outer['manifest_digest'],
         'exact fixed C05 Windows fixture and role')
    raw = _read_qualification_catalog_chunk(POLICY,16384)
    need(digest_bytes(raw)==cfg['dependency_file_digests'].get(str(POLICY))
         ==graph['windows']['dependency_file_digests'].get(str(POLICY)),
         'same immutable artifact-graph C05 Raw policy')
    return _C05WindowsTransport(_FIXED_FIXTURE_SELECTION,ROLE_API[role],config_raw,manifest_raw,admission,_policy(raw),digest_bytes(raw))


class _C05WindowsTransport:
    """One fixed actor, one accepted staged invoke and one passive capture."""
    __slots__ = ('_api','_config_raw','_manifest_raw','_admission','_policy','_owner','_slot','_launch','_deadline',
                 '_observation_started','_flushed','_pending','_policy_digest','_signal_handle')

    def __init__(self,selection,api,config_raw,manifest_raw,admission,policy,policy_digest):
        need(selection is _FIXED_FIXTURE_SELECTION and api in ROLE_API.values(),'fixed launcher owns C05 selection')
        self._api,self._config_raw,self._manifest_raw,self._admission = api,config_raw,manifest_raw,admission
        self._policy,self._policy_digest,self._signal_handle = policy,policy_digest,None
        self._owner,self._slot,self._launch,self._deadline = None,None,None,None
        self._observation_started,self._flushed,self._pending = False,False,None

    def begin(self,startup,run_id,input_scope,source_locator,target_locator,request_id,assertions,deadline_ns):
        from .input_stage import _FileInputAssertions, _active_input_deadline_ns
        need(self._owner is None and run_id in SPECS,'one fixed C05 actor use')
        self._owner = (os.getpid(),threading.get_ident())
        slot = RUNS.index(run_id)
        need(startup['config_bytes']==self._config_raw and startup['manifest_bytes']==self._manifest_raw
             and startup.get('_experimental_admission_context') is self._admission
             and self._policy['slots'][slot]['api']==self._api and input_scope==INPUT and target_locator==TARGET
             and source_locator==f'c05-r000-p{slot}.bin' and request_id==run_id
             and type(assertions) is _FileInputAssertions and assertions.publication_version=='1.0'
             and assertions.expected_digest==SPECS[run_id] and assertions.root_binding=='phase_result_root'
             and type(deadline_ns) is int and _active_input_deadline_ns()==deadline_ns and time.perf_counter_ns()<deadline_ns,
             'exact stage caller and existing C05 operation deadline')
        self._slot,self._deadline = slot,deadline_ns

    def check_launch(self,launch):
        from .bootstrap import _NativeAcceptedLaunch
        from .input_stage import _active_input_deadline_ns, _require_staged_publication_request
        need(type(launch) is _NativeAcceptedLaunch and self._slot is not None and self._launch is None
             and self._owner==(os.getpid(),threading.get_ident()) and launch._owner==self._owner
             and _active_input_deadline_ns()==self._deadline and not launch._inspection_only
             and launch._config_bytes==self._config_raw and launch._manifest_bytes==self._manifest_raw
             and launch._experimental_admission_context is self._admission
             and launch.run_id==RUNS[self._slot] and launch.installation_digest==digest_bytes(self._manifest_raw),
             'same retained admitted C05 execution launch')
        request = _require_staged_publication_request(launch.invocation['request'],role='File1')
        need(request['request_id']==launch.run_id and request['target_locator']==TARGET and request['input_scope']==INPUT
             and request['source_digest']==SPECS[launch.run_id] and request['source_length']==65536,
             'exact fixed staged C05 execution request')
        self._launch = launch

    def observe(self,launch,process,witness,first,closing,frame):
        """One event after the stock parent and both same-HANDLE waits."""
        if self._observation_started:
            return
        self._observation_started = True
        try:
            need(launch is self._launch and self._owner==(os.getpid(),threading.get_ident()),
                 'same current C05 capture launch and thread')
            raw = canonical_bytes(frame)  # Stock parent already checked equality to the exact received bytes.
            report = _projection(launch,process,witness,first,closing,raw,frame,time.perf_counter_ns(),self._deadline)
            self._pending = {'invocation.json':launch._invocation_bytes,'core-frame.json':raw,
                             'windows-transport.json':canonical_bytes(report)}
        except Exception:
            pass

    def flush(self):
        """After result classification. Missing or partial Raw is qualification-only."""
        if self._flushed:
            return
        self._flushed = True
        data,self._pending = self._pending,None
        if data is not None and self._owner==(os.getpid(),threading.get_ident()):
            try:
                _capture(_parent(self._slot),volume=self._policy['volume'],
                    identity=self._policy['slots'][self._slot]['parent_full128'],captures=data,
                    deadline_ns=self._deadline,clock_ns=time.perf_counter_ns)
                _signal_c05_raw_completion(self)
            except Exception:
                pass


def _projection(launch, process, witness, first, closing, raw, frame, observed, deadline):
    from phase_tool.canonical import canonical_bytes, digest_bytes, parse_json_bytes
    from phase_tool.mutation.ntfs.process_witness import WindowsProcessWitness

    need(type(witness) is WindowsProcessWitness and witness._popen is True and witness.process is process
         and witness._handle_object is process._handle
         and process._handle.closed and all(stream.closed for stream in (process.stdin, process.stdout, process.stderr)),
         'same actual Windows process and closure')
    for fact in (first, closing):
        need(fact['pid'] == witness.pid == process.pid and fact['creation_filetime'] == witness.creation_filetime
             and fact['worker_exit_established'] is True and fact['wait_result'] == 0
             and type(fact['exit_code']) is int and fact['exit_code'] == process.returncode == frame['exit_code'],
             'two known retained creation-handle waits')
    need(first['events'] == witness.events and first['events'][-1]['returned_ns'] <= closing['events'][0]['started_ns']
         and observed < deadline,
         'observed ordered completion inside existing deadline')
    need(0 < len(raw) <= 2*1024**2 and canonical_bytes(frame) == raw and parse_json_bytes(raw) == frame
         and frame['protocol'] == 'phase.native.command' and frame['version'] == '1.0'
         and frame['run_id'] == launch.run_id and frame['channel_id'] == launch.channel_id,
         'exact Core command projection')
    invocation = launch._invocation_bytes
    request = launch.invocation['request']
    need(0 < len(invocation) <= 2048, 'bounded invocation')
    binding = {'run_id': launch.run_id, 'installation_digest': launch.installation_digest,
               'staged_request_sha256': digest_bytes(canonical_bytes(request)),
               'invocation_sha256': digest_bytes(invocation), 'channel_id': launch.channel_id,
               'operation_nonce': launch.operation_nonce}
    report = {'scope': 'OWNED_WINDOWS_DOCKER_CLI_ONLY', 'binding': binding,
              'core_frame_sha256': digest_bytes(raw), 'process_witness': first,
              'streams_closed': ['stdin', 'stdout', 'stderr'], 'handle_closed': True}
    need(len(canonical_bytes(report)) <= 8192, 'bounded nested transport projection')
    return report


@contextmanager
def _opened_parent(root, *, expected_volume=None, expected_identity=None):
    from phase_tool.mutation.ntfs.native import NativeIO

    need(type(root) is type(Path()) and root.drive == 'C:' and root.is_absolute()
         and '..' not in root.parts and len(root.parts) >= 3, 'fixed absolute C: Raw parent')
    native = NativeIO()
    volume = native.input_volume('C:')
    need(expected_volume is None or expected_volume == volume, 'current C: mapping')
    with ExitStack() as stack:
        current = stack.enter_context(native._open(volume['device'] + '\\', parent=None, directory=True))
        pins = [(current, native.identity(current))]
        for part in root.parts[1:]:
            current = stack.enter_context(native._open(part, parent=current, directory=True, sharing=1, _input_name=True))
            identity = native.identity(current)
            need(identity.volume_serial == pins[0][1].volume_serial, 'one C: volume through every ancestor')
            pins.append((current, identity))
        need(expected_identity is None or identity.as_dict() == expected_identity, 'exact pre-bound Raw Full128 parent')

        def check():
            need(native.input_volume('C:') == volume, 'retained current C: mapping')
            for handle, initial in pins:
                native.assert_object(handle, directory=True, expected=initial)

        check()
        yield native, current, volume, identity, check
        check()
    need(not native._handles, 'all actual NativeIO handles closed')


def _capture(root, *, volume, identity, captures, deadline_ns, clock_ns):
    """Consume one already priced invocation. Keep a partial attempt on failure."""
    need(type(volume) is dict and type(identity) is dict, 'owner prebound C: volume and Full128 identity')
    need(type(captures) is dict and captures.keys() == MEMBERS.keys()
         and all(type(captures[name]) is bytes and 0 < len(captures[name]) <= cap for name, cap in MEMBERS.items()),
         'all three prewrite capture bounds')
    need(type(deadline_ns) is int and clock_ns() < deadline_ns, 'existing capture deadline')
    from ...evidence import _write_c05_fixture_raw_member
    observed = {}
    with _opened_parent(root, expected_volume=volume, expected_identity=identity) as (native, parent, _, parent_identity, check):
        # The fixture uses only the fixed drive, an exact owned case directory,
        # no-delete no-reparse ancestor pins and exclusive ordinary file create.
        # The independent reader will reopen below the retained native parent.
        need(native.entries(parent, len(MEMBERS)) == {}, 'fresh exact empty Raw parent')
        for name in MEMBERS:
            data = captures[name]
            check()
            need(clock_ns() < deadline_ns, 'existing capture deadline')
            _write_c05_fixture_raw_member(root / name,data,native=native,parent=parent,identity=parent_identity)
            with native._open(name, parent=parent, directory=False, sharing=1, _input_name=True) as child:
                child_facts = native.input_state(child)
                need(child_facts['links'] == 1 and child_facts['length'] == len(data), 'one exact Raw link and length')
                readback = b''.join(native.read_chunks(child, len(data)))
                need(readback == data and native.input_state(child) == child_facts, 'same retained Raw bytes and state')
            check()
            observed[name] = {'bytes': len(data), 'sha256': digest_bytes(data)[7:],
                              'native_identity': child_facts['native_identity']}
        need(native.entries(parent, len(MEMBERS)) == {
            name: {'directory': False, 'file_id': row['native_identity']['file_id']} for name, row in observed.items()},
            'same exact named Raw files')
    need(clock_ns() < deadline_ns, 'existing capture deadline')
    return observed


def _c05_completion_binding(case,run,api,slot,nonce,installation,policy):
    from hashlib import sha256
    import re
    from uuid import UUID

    if (type(case) is not str or str(UUID(case))!=case or type(slot) is not int or not 0<=slot<8
            or run!=f'od3-{case}-c05-file1-r000-p{slot}' or api!=('mcp' if slot%2 else 'cli')
            or type(nonce) is not str or re.fullmatch('[0-9a-f]{32}',nonce) is None or int(nonce,16)==0
            or any(type(pin) is not str or re.fullmatch('sha256:[0-9a-f]{64}',pin) is None
                   for pin in (installation,policy))):
        raise ValueError('exact C05 Raw completion actor and startup')
    key = sha256('\n'.join((case,run,api,nonce,installation,policy)).encode('ascii')).hexdigest()
    return 'Local\\Phase-C05-Raw-'+key


def _signal_c05_raw_completion(owner):
    """One signal after actual Raw file/readback/parent close, inside the active invocation."""
    import ctypes

    need(owner._signal_handle is None and time.perf_counter_ns()<owner._deadline,
         'one timely C05 completion reference')
    slot = owner._policy['slots'][owner._slot]
    name = _c05_completion_binding(CASE,slot['run_id'],owner._api,owner._slot,slot['completion_nonce'],
                                   digest_bytes(owner._manifest_raw),owner._policy_digest)
    kernel = ctypes.WinDLL('kernel32.dll',use_last_error=True)
    open_event,set_event = kernel.OpenEventW,kernel.SetEvent
    open_event.argtypes,open_event.restype = [ctypes.c_uint32,ctypes.c_int32,ctypes.c_wchar_p],ctypes.c_void_p
    set_event.argtypes,set_event.restype = [ctypes.c_void_p],ctypes.c_int32
    # EVENT_MODIFY_STATE only. One non-inherited reference is retired by the
    # exact fixture process exit, whose independently owned observation is mandatory.
    owner._signal_handle = open_event(0x0002,False,name)
    need(owner._signal_handle and time.perf_counter_ns()<owner._deadline,
         'current owned C05 event and remaining deadline')
    need(set_event(owner._signal_handle)==1,'actual C05 Raw SetEvent result')
