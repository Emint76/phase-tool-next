"""Real six registry/class metadata with in-memory fixture/capture negatives.

No accepted launch, authority, worker, NativeIO, target or Phase operation runs.
The draft is explicitly not installed and supplies no proof/qualification.
"""
import importlib.util,sys,threading,unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path,PureWindowsPath

from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.candidate import CapturedCandidate
from phase_tool.freeze import FrozenInput
from tests.test_native_mixed_experimental_history import bindings_fixture

HERE=Path(__file__).absolute().parent
from phase_tool.mutation.ntfs import owner_directory_fixture as m
_REAL_BUDGET=m.enforce_owner_evidence_budget
LEGACY=bindings_fixture()


def fixture():
    manifests=[parse_json_bytes(row.manifest_bytes) for row in LEGACY]
    docs=[row.experimental_admission.document() for row in LEGACY]
    current,objects=deepcopy(manifests[3]['root_grants'])
    root=PureWindowsPath(docs[3]['windows_roots']['current_root']);uuid=root.parts[2]
    value={'experimental_admission_version':'2.0','authorization_digest':docs[0]['authorization_digest'],
        'fixture_uuid':uuid,'owner_scope_id':'phase.qualification.owner.'+uuid,'wheel_digest':docs[0]['wheel_digest'],
        'core':deepcopy(manifests[0]['core']),'windows_roots':deepcopy(docs[3]['windows_roots']),
        'root_grants':[current,objects],'root_projections':{'current_root':'/ntfs-result','objects_root':'/ntfs-objects'},
        'evidence_root':manifests[0]['evidence_root'],'evidence_identity':deepcopy(docs[0]['evidence_identity']),
        'preparation_root':manifests[0]['preparation_root'],'preparation_identity':deepcopy(docs[0]['preparation_identity']),
        'roles':[{'role':role,'contract':deepcopy(manifest['contract']),
            'native_read_installation_version':manifest['native_read_installation_version'],
            'registry_snapshot_digest':manifest['registry_snapshot_digest'],'authority':deepcopy(manifest['authority']),
            'root_binding':manifest['root_grants'][0]['root_binding']}
            for role,manifest in zip(m._ROLES,manifests,strict=True)],
        'request_limits':{'run_prefix':'od2-'+uuid+'-','maximum_attempts':2048,'maximum_retained_bytes':2*1024**3},
        'qualification':{'A05':'NOT_VERIFIED','G01':'NOT_VERIFIED'},'release_eligible':False}
    return value


def rows(raw):
    result=[]
    for row in LEGACY:
        kind=type(row.experimental_admission);manifest=parse_json_bytes(row.manifest_bytes)
        manifest['installation_id']=m.installation_id(kind,raw)
        manifest_raw=canonical_bytes(manifest)
        result.append(replace(row,manifest_bytes=manifest_raw,manifest_digest=digest_bytes(manifest_raw),
            experimental_admission=kind(raw)))
    return tuple(result)


def capture(raw,role='File1',run_suffix='one',candidate_change=None,input_change=None):
    kind=m._kinds()[role];doc=m.fixture_document(raw);run=doc['request_limits']['run_prefix']+run_suffix
    value={'idempotency_key':'owner-one','target_locator':'data.txt','input_binding':'payload'}
    record={'binding_id':'payload','freeze_strategy':'manifest_and_hash' if role.startswith('Bundle') else 'copy_and_hash',
        'digest':'sha256:'+'a'*64,'blob_digest':'sha256:'+'a'*64,'manifest_digest':'sha256:'+'a'*64 if role.startswith('Bundle') else None,
        'provenance_ref':None,'frozen_at':'2026-11-07T00:00:00Z','revalidation_token':None}
    inputs=[record];length=12
    if role=='Version2':value={'idempotency_key':'owner-one','target_locator':'data.txt','content_utf8':'version two'};inputs=[];length=None
    if candidate_change:candidate_change(value)
    if input_change:input_change(inputs)
    return m.captured_attempt(kind,raw,run,canonical_bytes(value),inputs,length)


def core_capture(row,*,bad_candidate=False):
    raw=row.experimental_admission.raw;role=next(name for name,kind in m._kinds().items() if type(row.experimental_admission) is kind)
    state=capture(raw,role);record=state.document()
    value={'idempotency_key':'owner-one','target_locator':'data.txt','input_binding':'payload'}
    if role=='Version2':value={'idempotency_key':'owner-one','target_locator':'data.txt','content_utf8':'version two'}
    body=canonical_bytes(value);candidate=CapturedCandidate('structured_json',body,body,digest_bytes(body),len(body),value)
    frozen={} if role=='Version2' else {'payload':FrozenInput('payload',record['captured_inputs'][0]['freeze_strategy'],
        record['payload_digest'],record['payload_length'],'2026-11-07T00:00:00Z',blob_digest=record['payload_digest'],
        manifest_digest=record['payload_digest'] if role.startswith('Bundle') else None)}
    return record['run_id'],object() if bad_candidate else candidate,frozen


def original(row,state):
    manifest=parse_json_bytes(row.manifest_bytes);capture=state.document()
    value={'idempotency_key':capture['request_id'],'target_locator':capture['target_locator'],'input_binding':'payload'}
    if state.role=='Version2':value={'idempotency_key':capture['request_id'],'target_locator':capture['target_locator'],'content_utf8':'version two'}
    intent={'run_id':capture['run_id'],'contract':manifest['contract'],'core':manifest['core'],
        'registry_snapshot_digest':manifest['registry_snapshot_digest'],
        'native_binding':{'installation':{'id':manifest['installation_id'],'descriptor_digest':row.manifest_digest}},
        'inputs':capture['captured_inputs'],'candidate':{'storage':{'value':value}}}
    plan={'run_id':capture['run_id'],'contract':manifest['contract'],'effects':[{'target':{'root_binding':manifest['root_grants'][0]['root_binding'],
        'relative_locator':capture['target_locator']},'content_length':capture.get('payload_length',capture.get('content_length'))}]}
    return intent,plan


class OwnerFixtureSourceTests(unittest.TestCase):
    def setUp(self):
        # Isolate resource IO only for capture/selector component models.
        # Cleanup restores the real helper before every other test/suite.
        from unittest.mock import patch
        resource=patch.object(m,'enforce_owner_evidence_budget',return_value=None)
        resource.start();self.addCleanup(resource.stop)

    def test_six_real_class_contract_profiles_stable_across_attempts(self):
        raw=canonical_bytes(fixture());checked=m.fixture_document(raw)
        self.assertEqual([row['role'] for row in checked['roles']],list(m._ROLES))
        identifiers={m.installation_id(kind,raw) for kind in m._kinds().values()}
        self.assertEqual(len(identifiers),6)
        first=capture(raw);second=capture(raw,run_suffix='two')
        self.assertNotEqual(first.capture_bytes,second.capture_bytes)
        self.assertEqual(m.installation_id(m._kinds()['File1'],raw),m.installation_id(m._kinds()['File1'],raw))

    def test_missing_duplicate_foreign_role_closed(self):
        for which in ('missing','duplicate','foreign'):
            value=fixture()
            if which=='missing':value['roles'].pop()
            elif which=='duplicate':value['roles'][-1]=deepcopy(value['roles'][0])
            else:value['roles'][0]['role']='Other'
            with self.assertRaises(PhaseError):m.fixture_document(canonical_bytes(value))

    def test_foreign_contract_profile_version_rejected(self):
        for change in ('contract','profile','manifest'):
            value=fixture()
            if change=='contract':value['roles'][0]['contract']['package_digest']='sha256:'+'0'*64
            elif change=='profile':value['roles'][0]['authority']['profile']['id']='foreign'
            else:value['roles'][0]['native_read_installation_version']='9.0'
            with self.assertRaises(PhaseError):m.fixture_document(canonical_bytes(value))

    def test_no_owner_root_widening_or_extra_policy_field(self):
        for change in ('path','extra','qualified','release'):
            value=fixture()
            if change=='path':value['windows_roots']['current_root']='S:\\unowned'
            elif change=='extra':value['semantic_policy']='semantic_v2'
            elif change=='qualified':value['qualification']['G01']='PASS'
            else:value['release_eligible']=True
            with self.assertRaises(PhaseError):m.fixture_document(canonical_bytes(value))

    def test_explicit_current_and_objects_no_alias_or_omission(self):
        for change in ('missing','same','nested','foreignvolume'):
            value=fixture()
            if change=='missing':value['root_grants'].pop()
            elif change=='same':value['root_grants'][1]['native_identity']=deepcopy(value['root_grants'][0]['native_identity'])
            elif change=='nested':value['root_grants'][1]['components']=value['root_grants'][0]['components']+['nested']
            else:value['root_grants'][1]['volume_guid']='\\\\?\\volume{00000000-0000-0000-0000-000000000000}\\'
            with self.assertRaises(PhaseError):m.fixture_document(canonical_bytes(value))

    def test_evidence_preparation_separate_and_fixed_opaque_projection(self):
        for change in ('overlap','identity','projection'):
            value=fixture()
            if change=='overlap':value['preparation_root']=value['evidence_root']+'/nested'
            elif change=='identity':value['preparation_identity']=deepcopy(value['evidence_identity'])
            else:value['root_projections']['current_root']='S:/physical-bind'
            with self.assertRaises(PhaseError):m.fixture_document(canonical_bytes(value))

    def test_all_six_manifests_validate_fixed_role_grants_and_static_identity(self):
        raw=canonical_bytes(fixture())
        for row in rows(raw):
            m.check_manifest(type(row.experimental_admission),raw,parse_json_bytes(row.manifest_bytes),row.manifest_digest)

    def test_same_path_foreign_native_id_or_registry_fails_actual_manifest(self):
        raw=canonical_bytes(fixture());row=rows(raw)[0]
        for key in ('native','registry','wheel'):
            manifest=parse_json_bytes(row.manifest_bytes)
            if key=='native':manifest['root_grants'][0]['native_identity']['file_id']='e'*32
            elif key=='registry':manifest['registry_snapshot_digest']='sha256:'+'f'*64
            else:manifest['preparation_identity']['inode']+=1
            with self.assertRaises(PhaseError):m.check_manifest(type(row.experimental_admission),raw,manifest,row.manifest_digest)

    def test_capture_uses_exact_candidate_actual_input_record_all_roles(self):
        raw=canonical_bytes(fixture())
        for role in m._ROLES:
            observed=capture(raw,role=role).document()
            self.assertEqual(observed['target_locator'],'data.txt')
            self.assertEqual(len(observed['captured_inputs']),0 if role=='Version2' else 1)

    def test_capture_foreign_run_target_key_input_closed(self):
        raw=canonical_bytes(fixture());kind=m._kinds()['File1']
        with self.assertRaises(PhaseError):m.captured_attempt(kind,raw,'foreign-run',b'{}',[],0)
        for key,value in (('target_locator','../outside'),('idempotency_key','BAD KEY')):
            with self.assertRaises(PhaseError):capture(raw,candidate_change=lambda v:v.update({key:value}))
        with self.assertRaises(PhaseError):capture(raw,input_change=lambda inputs:inputs[0].update(blob_digest='sha256:'+'b'*64))

    def test_context_exact_owner_and_no_returned_mutable_alias(self):
        raw=canonical_bytes(fixture());state=capture(raw);observed=state.document();observed['request_id']='poison'
        self.assertEqual(state.document()['request_id'],'owner-one')
        errors=[]
        thread=threading.Thread(target=lambda:self._foreign_thread(state,errors));thread.start();thread.join()
        self.assertEqual(errors,['ntfs.owner_fixture_context_owner'])

    @staticmethod
    def _foreign_thread(state,errors):
        try:state.document()
        except PhaseError as error:errors.append(error.code)

    def test_full_original_tuple_selects_exact_static_reader(self):
        raw=canonical_bytes(fixture());bindings=rows(raw)
        for row in bindings:
            manifest=parse_json_bytes(row.manifest_bytes)
            self.assertIs(m.select_original_tuple(bindings,contract=manifest['contract'],core=manifest['core'],
                installation={'id':manifest['installation_id'],'descriptor_digest':row.manifest_digest},
                registry_snapshot_digest=manifest['registry_snapshot_digest']),row)

    def test_unknown_missing_ambiguous_or_foreign_tuple_never_falls_back_by_run(self):
        raw=canonical_bytes(fixture());bindings=rows(raw);row=bindings[0];manifest=parse_json_bytes(row.manifest_bytes)
        args=dict(contract=manifest['contract'],core=manifest['core'],installation={'id':manifest['installation_id'],
            'descriptor_digest':row.manifest_digest},registry_snapshot_digest=manifest['registry_snapshot_digest'])
        for other in (bindings[:-1],bindings[:-1]+(bindings[0],)):
            with self.assertRaises(PhaseError):m.select_original_tuple(other,**args)
        for name in args:
            changed=deepcopy(args);changed[name]='foreign'
            with self.assertRaises(PhaseError):m.select_original_tuple(bindings,**changed)

    def test_root_core_capture_seam_uses_actual_types_six_roles_and_spends_once(self):
        raw=canonical_bytes(fixture())
        for row in rows(raw):
            admission=row.experimental_admission
            object.__setattr__(admission,'_owner_fixture_owner',(m.os.getpid(),threading.get_ident()))
            run,candidate,frozen=core_capture(row)
            m.bind_captured_owner_attempt(row,run_id=run,candidate=candidate,frozen=frozen)
            view=m.captured_binding_view(admission,m.role_projection(type(admission),raw))
            self.assertEqual(view['run_id'],run)
            with self.assertRaisesRegex(PhaseError,'capture_consumed'):m.bind_captured_owner_attempt(row,run_id=run,candidate=candidate,frozen=frozen)

    def test_failed_capture_slot_sticky_foreign_owner_and_duck_types_rejected(self):
        raw=canonical_bytes(fixture());row=rows(raw)[0];admission=row.experimental_admission
        run,candidate,frozen=core_capture(row)
        object.__setattr__(admission,'_owner_fixture_owner',(m.os.getpid()+1,threading.get_ident()))
        with self.assertRaisesRegex(PhaseError,'context_owner'):m.bind_captured_owner_attempt(row,run_id=run,candidate=candidate,frozen=frozen)
        object.__setattr__(admission,'_owner_fixture_owner',(m.os.getpid(),threading.get_ident()))
        with self.assertRaisesRegex(PhaseError,'capture_required'):m.bind_captured_owner_attempt(row,run_id=run,candidate=object(),frozen=frozen)
        with self.assertRaisesRegex(PhaseError,'capture_consumed'):m.bind_captured_owner_attempt(row,run_id=run,candidate=candidate,frozen=frozen)
        with self.assertRaisesRegex(PhaseError,'capture_required'):m.captured_binding_view(admission,{})

    def test_root_core_actual_intent_record_roundtrip_preserves_natural_input_record(self):
        raw=canonical_bytes(fixture())
        for row in rows(raw):
            admission=row.experimental_admission
            object.__setattr__(admission,'_owner_fixture_owner',(m.os.getpid(),threading.get_ident()))
            run,candidate,frozen=core_capture(row)
            m.bind_captured_owner_attempt(row,run_id=run,candidate=candidate,frozen=frozen)
            state=admission._owner_fixture_capture;intent,plan=original(row,state)
            record=m.owner_attempt_document(row,intent=intent,plan=plan)
            self.assertEqual(record['capture']['captured_inputs'],intent['inputs'])
            checked=m.verify_attempt_record(type(admission),raw,row.manifest_digest,attempt_bytes=canonical_bytes(record),intent=intent,plan=plan)
            self.assertEqual(checked,record)

    def test_missing_corrupt_foreign_original_record_never_repaired_or_rekeyed(self):
        raw=canonical_bytes(fixture());row=rows(raw)[0];state=capture(raw);intent,plan=original(row,state)
        record=m.attempt_record(type(row.experimental_admission),raw,row.manifest_digest,state,intent,plan)
        for key in ('run_id','candidate_digest','request_id','target_locator'):
            foreign=deepcopy(record);foreign['capture'][key]='foreign'
            with self.assertRaises(PhaseError):m.verify_attempt_record(type(row.experimental_admission),raw,row.manifest_digest,
                attempt_bytes=canonical_bytes(foreign),intent=intent,plan=plan)
        with self.assertRaises(PhaseError):m.verify_attempt_record(type(row.experimental_admission),raw,row.manifest_digest,attempt_bytes=b'',intent=intent,plan=plan)
        drift=deepcopy(intent);drift['inputs'][0]['frozen_at']='2026-11-07T00:00:01Z'
        with self.assertRaises(PhaseError):m.verify_attempt_record(type(row.experimental_admission),raw,row.manifest_digest,attempt_bytes=canonical_bytes(record),intent=drift,plan=plan)

    def test_actual_candidate_plan_and_native_installation_drift_rejected(self):
        raw=canonical_bytes(fixture());row=rows(raw)[0];state=capture(raw);intent,plan=original(row,state)
        for change in ('candidate','installation','target','registry'):
            i,p=deepcopy(intent),deepcopy(plan)
            if change=='candidate':i['candidate']['storage']['value']['idempotency_key']='other-key'
            elif change=='installation':i['native_binding']['installation']['descriptor_digest']='sha256:'+'e'*64
            elif change=='target':p['effects'][0]['target']['relative_locator']='outside.txt'
            else:i['registry_snapshot_digest']='sha256:'+'e'*64
            with self.assertRaises(PhaseError):m.attempt_record(type(row.experimental_admission),raw,row.manifest_digest,state,i,p)

    def test_real_admission_fixture_branches_preserve_exact_profile_classification(self):
        raw=canonical_bytes(fixture())
        for row in rows(raw):
            admission=row.experimental_admission
            # Requires staged branches; absent old branches must fail this test.
            self.assertEqual(admission.document(),fixture())
            view=admission.check_binding(row)
            self.assertEqual(view['experimental_admission_version'],'2.0')
            self.assertEqual(view['contract'],parse_json_bytes(row.manifest_bytes)['contract'])
            profile=admission.profile(row)
            descriptor=row.registry.resolve_guarantee_profile(profile.as_dict())
            self.assertEqual(descriptor['classification'],'qualification_candidate')
            self.assertEqual(descriptor['provided_guarantees'],[])
            self.assertEqual(descriptor['conformance'],[])

    def test_real_admission_legacy_raw_digest_id_and_checks_unchanged(self):
        for row in LEGACY:
            admission=row.experimental_admission;manifest=parse_json_bytes(row.manifest_bytes)
            self.assertEqual(canonical_bytes(admission.document()),admission.raw)
            self.assertEqual(admission.digest,digest_bytes(admission.raw))
            self.assertEqual(manifest['installation_id'],admission._installation_prefix+admission.digest[7:])
            self.assertEqual(admission.check_binding(row),admission.document())
            self.assertNotIn('_owner_fixture_owner',admission.document())

    def test_candidate_profiles_still_refused_by_ordinary_qualified_profile_gate(self):
        from phase_tool.installation import _native_qualified_profile
        raw=canonical_bytes(fixture())
        for row in rows(raw):
            with self.assertRaises(PhaseError):
                _native_qualified_profile(row.registry,parse_json_bytes(row.manifest_bytes)['authority']['profile'])

    def test_history2_one_fixture_six_manifests_resolve_real_closed_registries(self):
        import base64
        from phase_tool import installation
        from phase_tool.mutation.ntfs.experimental_history_set import mixed_history_buffers,validate_mixed_history_bindings
        raw=canonical_bytes(fixture());bindings=rows(raw)
        history={'history_manifest_set_version':'2.0','fixture_base64':base64.b64encode(raw).decode(),
            'fixture_digest':digest_bytes(raw),'manifests':[{'role':role,'manifest_base64':base64.b64encode(row.manifest_bytes).decode(),
                'manifest_digest':row.manifest_digest} for role,row in zip(m._ROLES,bindings,strict=True)]}
        body=canonical_bytes(history)
        for active in bindings:
            buffers=mixed_history_buffers(body,digest_bytes(body),active_bytes=active.manifest_bytes,active_digest=active.manifest_digest)
            self.assertEqual(len(buffers),6)
            checked=installation._resolve_native_history_bindings(active,body,digest_bytes(body))
            self.assertEqual(len(checked),6)
            validate_mixed_history_bindings(active,checked)
        self.assertEqual(len(body),len(canonical_bytes(history)))

    def test_installed_tuple_selector_and_legacy_for_run_barrier(self):
        from phase_tool import installation
        raw=canonical_bytes(fixture());bindings=rows(raw)
        for row in bindings:
            manifest=parse_json_bytes(row.manifest_bytes)
            selected=installation._native_history_binding_for_original(bindings,run_id='ignored-for-full-tuple',
                contract=manifest['contract'],core=manifest['core'],installation={'id':manifest['installation_id'],
                    'descriptor_digest':row.manifest_digest},registry_snapshot_digest=manifest['registry_snapshot_digest'])
            self.assertIs(selected,row)
            selected=installation._native_history_binding_for_original(bindings,run_id='ignored-for-rejection',
                contract=manifest['contract'],core=manifest['core'],_pre_intent_rejection=True)
            self.assertIs(selected,row)
        with self.assertRaises(PhaseError):installation._native_experimental_history_binding_for_run(bindings,'foreign')
        first=parse_json_bytes(bindings[0].manifest_bytes)
        with self.assertRaises(PhaseError):installation._native_history_binding_for_original(bindings,run_id='foreign',
            contract=first['contract'],core=first['core']) # malformed Original never becomes no-effect exception

    def test_new_fixed_admission_six_roles_old_startup_fixture_refusal(self):
        import ast,hashlib,json
        path=HERE.parent/'src/phase_tool/data/native/native_phase_candidate_launcher_v1.py.in'
        tree=ast.parse(path.read_bytes());names={'fixed_startup_version','fixed_admission','need'}
        nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names]
        scope={'hashlib':hashlib,'json':json};exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),scope)
        raw=canonical_bytes(fixture())
        for row in rows(raw):
            manifest=parse_json_bytes(row.manifest_bytes)
            admission=scope['fixed_admission']({'native_launch_version':'2.0'},manifest,raw)
            self.assertIs(type(admission),type(row.experimental_admission))
        common={'native_fixed_startup_version':'2.0','config_base64':'','config_digest':'','manifest_base64':'','manifest_digest':'','dependency_roots':[]}
        self.assertEqual(scope['fixed_startup_version'](dict(common,owner_directory_fixture_base64='')),'2.0')
        with self.assertRaises(RuntimeError):scope['fixed_startup_version'](dict(common,experimental_admission_base64=''))
        for version in ('1.1','1.2'):
            with self.assertRaises(RuntimeError):scope['fixed_startup_version'](dict(common,native_fixed_startup_version=version,owner_directory_fixture_base64=''))

    def test_actual_bootstrap_rejects_legacy_config_fixture_or_new_config_legacy_admission_before_runtime(self):
        from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch
        raw=canonical_bytes(fixture());row=rows(raw)[0]
        invocation=canonical_bytes({'run_id':fixture()['request_limits']['run_prefix']+'one','channel_id':'1'*32,
            'operation_nonce':'2'*32,'request':{}})
        for version,admission in (('1.3',row.experimental_admission),('2.0',LEGACY[0].experimental_admission)):
            config=canonical_bytes({'native_launch_version':version})
            with self.assertRaisesRegex(PhaseError,'owner_fixture_startup_required'):
                _NativeAcceptedLaunch(config_bytes=config,expected_config_digest=digest_bytes(config),manifest_bytes=row.manifest_bytes,
                    expected_manifest_digest=row.manifest_digest,invocation_bytes=invocation,_experimental_admission_context=admission)

class EvidenceMemoryIO:
    uid=1000
    def __init__(self):self.nodes={};self.next_inode=1;self.hook=None;self.calls=[]
    def put(self,path,body=None,**kw):
        path=Path(path)
        for parent in reversed(path.parents):
            if parent not in self.nodes:self.nodes[parent]={'directory':True,'body':b'','inode':self.next_inode,'mode':0o40700,'uid':1000,'links':2,'mtime':1,'ctime':1};self.next_inode+=1
        self.nodes[path]={'directory':body is None,'body':b'' if body is None else body,'inode':self.next_inode,
            'mode':0o40700 if body is None else 0o100600,'uid':1000,'links':2 if body is None else 1,'mtime':1,'ctime':1,**kw};self.next_inode+=1
    def event(self,op,path):
        self.calls.append((op,path))
        if self.hook:self.hook(self,op,path)
    def lstat(self,path):
        from types import SimpleNamespace
        self.event('lstat',path)
        if path not in self.nodes:raise FileNotFoundError(str(path))
        x=self.nodes[path]
        return SimpleNamespace(st_dev=7,st_ino=x['inode'],st_mode=x['mode'],st_uid=x['uid'],st_nlink=x['links'],
            st_size=len(x['body']),st_mtime_ns=x['mtime'],st_ctime_ns=x['ctime'],st_file_attributes=0)
    def names(self,path):self.event('names',path);return tuple(p.name for p in self.nodes if p.parent==path and p!=path)
    def read_bounded(self,path,cap):
        self.event('read',path);body=self.nodes[path]['body']
        if len(body)>cap:raise PhaseError('stream.too_large')
        return body


class OwnerEvidenceIOModels(unittest.TestCase):
    ROOT=HERE/'MODEL_ONLY_NO_DIRECTORY_CREATED'
    def setup_io(self,*,limits=None):
        value=fixture()
        if limits:value['request_limits'].update(limits)
        raw=canonical_bytes(value);row=rows(raw)[0];run=value['request_limits']['run_prefix']+'one'
        io=EvidenceMemoryIO();root=self.ROOT
        io.put(root);io.put(root/'.phase');io.put(root/'.phase'/'runs');io.put(root/'.phase'/'runs'/run)
        io.put(root/'.phase'/'runs'/run/'attachments');io.put(root/'.phase'/'runs'/run/'blobs')
        return raw,row,run,io
    def budget(self,row,run,io):
        from unittest.mock import patch
        with patch.object(type(row),'check_evidence_root',return_value=self.ROOT):
            return _REAL_BUDGET(row,run_id=run,_io=io)
    def original_io(self):
        raw,row,run,io=self.setup_io();state=capture(raw);intent,plan=original(row,state)
        record=m.attempt_record(type(row.experimental_admission),raw,row.manifest_digest,state,intent,plan)
        base=self.ROOT/'.phase'/'runs'/run
        io.put(base/'attachments'/'experimental-admission.json',raw)
        io.put(base/'attachments'/'experimental-attempt.json',canonical_bytes(record))
        io.put(base/'attachments'/'effect-plan.json',canonical_bytes(plan));io.put(base/'intent.json',canonical_bytes(intent))
        receipt={'evidence':{'attachment_digests':[digest_bytes(raw),digest_bytes(canonical_bytes(record))]}}
        return raw,row,run,io,receipt
    def verify(self,row,run,io,receipt=None):
        from unittest.mock import patch
        with patch.object(type(row),'check_evidence_root',return_value=self.ROOT):
            return m.verify_fixture_attachments(row.experimental_admission,row,run,receipt,_io=io)
    def test_complete_budget_counts_foreign_and_negative_runs_without_filter(self):
        raw,row,run,io=self.setup_io();foreign=self.ROOT/'.phase'/'runs'/'foreign-negative'
        io.put(foreign);io.put(foreign/'raw-negative.bin',b'original-negative')
        found=self.budget(row,run,io)
        self.assertEqual(found['run_count'],2);self.assertEqual(found['logical_bytes'],17)
        self.assertFalse(found['foreign_or_negative_runs_filtered']);self.assertFalse(found['authoritative_counter_created'])
    def test_budget_attempt_limit_includes_current_and_foreign_run(self):
        raw,row,run,io=self.setup_io(limits={'maximum_attempts':1});io.put(self.ROOT/'.phase'/'runs'/'foreign')
        with self.assertRaisesRegex(PhaseError,'budget_exceeded'):self.budget(row,run,io)
    def test_budget_logical_plus_remaining_control_reserve_exact_and_plus1(self):
        for n,success in ((10,True),(11,False)):
            raw,row,run,io=self.setup_io(limits={'maximum_retained_bytes':m._REMAINING_CORE_CONTROL_BYTES+10})
            io.put(self.ROOT/'.phase'/'runs'/run/'blobs'/'blob',b'x'*n)
            if success:self.assertEqual(self.budget(row,run,io)['logical_bytes'],10)
            else:
                with self.assertRaisesRegex(PhaseError,'budget_exceeded'):self.budget(row,run,io)
    def test_budget_reparse_hardlink_permissions_owner_no_traversal(self):
        for kw in ({'mode':0o120777},{'links':2},{'mode':0o100622},{'uid':999}):
            raw,row,run,io=self.setup_io();path=self.ROOT/'.phase'/'runs'/run/'blobs'/'unsafe';io.put(path,b'data',**kw)
            with self.assertRaisesRegex(PhaseError,'budget_unsafe'):self.budget(row,run,io)
            self.assertNotIn(('names',path),io.calls)
    def test_budget_during_scan_added_entry_and_file_identity_drift(self):
        for mutation in ('membership','file'):
            raw,row,run,io=self.setup_io();path=self.ROOT/'.phase'/'runs'/run/'blobs'/'data';io.put(path,b'data')
            def hook(fs,op,p):
                if mutation=='membership' and op=='names' and p==self.ROOT and sum(a=='names' and b==p for a,b in fs.calls)==2:
                    fs.put(self.ROOT/'late',b'new')
                if mutation=='file' and op=='lstat' and p==path and sum(a=='lstat' and b==p for a,b in fs.calls)==2:fs.nodes[p]['inode']+=1
            io.hook=hook
            with self.assertRaisesRegex(PhaseError,'budget_drift'):self.budget(row,run,io)
    def test_actual_attachment_bytes_record_receipt_roundtrip_and_missing_tamper_refused(self):
        raw,row,run,io,receipt=self.original_io();self.verify(row,run,io,receipt)
        base=self.ROOT/'.phase'/'runs'/run/'attachments'
        io.nodes[base/'experimental-attempt.json']['body']=b'{}'
        with self.assertRaises(PhaseError):self.verify(row,run,io,receipt)
        raw,row,run,io,receipt=self.original_io();receipt['evidence']['attachment_digests'].pop()
        with self.assertRaises(PhaseError):self.verify(row,run,io,receipt)
    def test_partial_attempt_without_original_sticky_unknown_and_missing_original_receipt_narrow(self):
        raw,row,run,io,receipt=self.original_io();del io.nodes[self.ROOT/'.phase'/'runs'/run/'intent.json']
        with self.assertRaisesRegex(PhaseError,'orphan_attempt_unresolved'):self.verify(row,run,io,receipt)
        del io.nodes[self.ROOT/'.phase'/'runs'/run/'attachments'/'experimental-attempt.json']
        self.verify(row,run,io,None) # Only attachment correlation; strict no-effect receipt remains existing Core's obligation.
    def test_attachment_read_time_identity_mutation_and_hardlink_refused(self):
        raw,row,run,io,receipt=self.original_io();path=self.ROOT/'.phase'/'runs'/run/'attachments'/'experimental-admission.json'
        def mutate(fs,op,p):
            if op=='read' and p==path:fs.nodes[p]['inode']+=1
        io.hook=mutate
        with self.assertRaisesRegex(PhaseError,'evidence_drift'):self.verify(row,run,io,receipt)
        raw,row,run,io,receipt=self.original_io();io.nodes[path]['links']=2
        with self.assertRaisesRegex(PhaseError,'evidence_mismatch'):self.verify(row,run,io,receipt)

class RecoveryAttachmentBridgeModels(unittest.TestCase):
    ROOT=OwnerEvidenceIOModels.ROOT
    def block(self,binding,run_id,names,io):
        import ast
        from unittest.mock import patch
        source=HERE.parent/'src/phase_tool/mutation/ntfs/bundle_recovery_original.py'
        fn=next(node for node in ast.parse(source.read_bytes()).body if isinstance(node,ast.FunctionDef) and node.name=='verify_original')
        start=next(index for index,node in enumerate(fn.body) if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='required' for t in node.targets))
        end=next(index for index,node in enumerate(fn.body[start:],start) if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call)
            and isinstance(node.value.func,ast.Name) and node.value.func.id=='_require')
        code=compile(ast.Module(body=fn.body[start:end+1],type_ignores=[]),str(source),'exec')
        globals={'__package__':'phase_tool.mutation.ntfs','binding':binding,'run_id':run_id,'files':{'attachments/'+name:None for name in names},'_require':m._need}
        def verified(actual,run):
            with patch.object(type(actual),'check_evidence_root',return_value=self.ROOT):
                return m.verify_fixture_attachments(actual.experimental_admission,actual,run,_io=io)
        with patch.object(type(binding.experimental_admission),'verify_attachment',side_effect=verified):exec(code,globals)
        return globals['required']
    def fixture_b2(self):
        value=fixture();raw=canonical_bytes(value);row=rows(raw)[5];state=capture(raw,role='Bundle2');intent,plan=original(row,state)
        record=m.attempt_record(type(row.experimental_admission),raw,row.manifest_digest,state,intent,plan)
        run=state.document()['run_id'];io=EvidenceMemoryIO();base=self.ROOT/'.phase'/'runs'/run
        io.put(base/'attachments'/'experimental-admission.json',raw);io.put(base/'attachments'/'experimental-attempt.json',canonical_bytes(record))
        io.put(base/'intent.json',canonical_bytes(intent));io.put(base/'attachments'/'effect-plan.json',canonical_bytes(plan))
        return row,run,io
    def test_recovery_old_extra_attachment_refused_new_fixture_exact_verified_name_allowed(self):
        old=LEGACY[5];run=old.experimental_admission.document()['run_id']
        required={'effect-plan.json','pre-validator-results.json','prepared-stage.json','native-parent-failure.json','experimental-admission.json'}
        self.assertEqual(self.block(old,run,required,EvidenceMemoryIO()),required)
        with self.assertRaises(PhaseError):self.block(old,run,required|{'experimental-attempt.json'},EvidenceMemoryIO())
        row,run,io=self.fixture_b2()
        self.assertEqual(self.block(row,run,required|{'experimental-attempt.json'},io),required|{'experimental-attempt.json'})
    def test_recovery_fixture_missing_or_tampered_attempt_refused_before_name_extension(self):
        required={'effect-plan.json','pre-validator-results.json','prepared-stage.json','native-parent-failure.json','experimental-admission.json','experimental-attempt.json'}
        for change in ('missing','tampered'):
            row,run,io=self.fixture_b2();path=self.ROOT/'.phase'/'runs'/run/'attachments'/'experimental-attempt.json'
            if change=='missing':del io.nodes[path]
            else:io.nodes[path]['body']=b'{}'
            with self.assertRaises((PhaseError,FileNotFoundError)):self.block(row,run,required,io)


if __name__=='__main__':unittest.main(verbosity=2)
