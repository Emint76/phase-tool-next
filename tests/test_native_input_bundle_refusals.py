"""Exact Bundle boundary and owner models, without Phase or Native effects."""
import asyncio
import base64
from contextlib import ExitStack, contextmanager
import hashlib
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool import installation
from phase_tool.application import PhaseApplication
from phase_tool.bundle import MAX_MEMBERS, MAX_DEPTH, MAX_TOTAL_BYTES, _BundleLimitExceeded, parse_manifest
from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.command_result import validate_command_result
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bootstrap, input_stage, inspection_mcp, native, process_witness
from phase_tool.mutation.ntfs import owner_directory_installation
from phase_tool.streaming import FILE_LIMIT, REQUEST_LIMIT

from . import test_native_input_mcp_closed_schema as mcp_models
from . import test_native_input_stage_protocol as stage_models
from .owner_directory_test_data import owner_document, synthetic_catalog


REQUEST_ID = 'd07-metadata'
TARGET = 'result-bundle'
MEMBER_SIZE = 64*1024
SCOPE_DIGEST = 'sha256:'+'4'*64
ROLES = ('Bundle1','Bundle2')


def exact_paths(size, encode):
    names = [f'm{i:04d}.bin' for i in range(MAX_MEMBERS)]
    per_path, remainder = divmod(size-len(encode(names)), len(names))
    paths = []
    for index, name in enumerate(names):
        remaining = per_path+(index<remainder)
        while remaining>1:
            width = min(200,remaining-1)
            name = 'd'*width+'/'+name
            remaining -= width+1
        if remaining:
            name = 'x'+name
        paths.append(name)
    assert len(encode(paths))==size
    return sorted(paths)


def candidate_bytes(paths):
    return canonical_bytes({'operation_id':REQUEST_ID,'idempotency_key':REQUEST_ID,
        'input_binding':'payload','target_locator':TARGET,'members':sorted(paths)})


def manifest_bytes(paths, seed):
    rows = []
    for index, path in enumerate(sorted(paths)):
        block = hashlib.sha256(f'phase-ntfs-qual-v1|{seed}|d07.metadata.{index}|0'.encode()).digest()
        rows.append({'path':path,'length':MEMBER_SIZE,'digest':digest_bytes(block*(MEMBER_SIZE//len(block)))})
    return canonical_bytes({'bundle_version':'1.0','members':rows,'total_length':len(rows)*MEMBER_SIZE})


def header_for(role, sizes):
    request = input_stage._stage_request('owner.inputs','incoming',list(sizes))
    records = []
    for path in request['members']:
        record = stage_models.record(path,b'a')
        record['length'] = record['state']['length'] = sizes[path]
        records.append(record)
    return input_stage._header(stage_models.launch,stage_models.scope,role,SCOPE_DIGEST,request,records)


@contextmanager
def stage_model(role, sizes, *, fault=None, installed_scope='owner.inputs'):
    original, scope, _, _ = stage_models.native_fixture(bundle=True)
    scope['scope_id'] = installed_scope
    leaf = next(path for path in original.tree if path.endswith('/incoming/a'))
    folder = leaf.removesuffix('/a')
    del original.tree[leaf]
    for path, length in sizes.items():
        full = folder
        for component in path.split('/')[:-1]:
            full += '/'+component
            original.tree[full] = dict(directory=True,id=hashlib.md5(full.encode(),usedforsecurity=False).hexdigest())
        full += '/'+path.split('/')[-1]
        original.tree[full] = dict(directory=False,id=hashlib.md5(full.encode(),usedforsecurity=False).hexdigest(),length=length)
    opened = []
    body_reads = []

    class ModelIO(stage_models.NativeModel):
        def __init__(self):
            super().__init__(original.tree)
            self.fail_close = folder+'/'+next(iter(sizes)) if fault=='close' else None
            self.states = {}
            opened.append(self)

        @property
        def _handles(self):
            return [handle for handle in self.handles if handle not in self.closed]

        def input_snapshot(self,*args):
            return native._NativeInputSnapshot(self,*args)

        def input_state(self,handle):
            state = super().input_state(handle)
            state['length'] = self.tree[handle.name]['length']
            self.states[handle.name] = self.states.get(handle.name,0)+1
            if fault=='drift' and self.states[handle.name]==3:
                state['write_time'] += 1
            return state

        def read_chunks(self,*args):
            body_reads.append(args)
            raise AssertionError('refusal model must never read a body')

    probe = SimpleNamespace(**vars(stage_models.launch),_invocation_bytes=b'model')
    pending = _BundleLimitExceeded('input_stage.member_bound','member_bytes',FILE_LIMIT+1,FILE_LIMIT)
    receiver = SimpleNamespace(send_frame=lambda *args: (_ for _ in ()).throw(pending))
    witness = SimpleNamespace(wait_for_exit=lambda timeout:{'worker_exit_established':False})
    with ExitStack() as stack:
        stack.enter_context(patch.object(input_stage,'os',SimpleNamespace(name='nt',getpid=os.getpid)))
        stack.enter_context(patch.object(native,'NativeIO',ModelIO))
        stack.enter_context(patch.object(input_stage,'_scope_for_launch',return_value=(scope,role,SCOPE_DIGEST)))
        startup = stack.enter_context(patch.object(bootstrap,'_NativeAcceptedLaunch',return_value=probe))
        registry = stack.enter_context(patch('phase_tool.installation._native_registry_for_launch',
            return_value=PhaseApplication().registry))
        stack.enter_context(patch.object(process_witness,'WindowsProcessWitness',return_value=witness))
        spawn = stack.enter_context(patch.object(probe,'spawn_input_stage',create=True))
        stack.enter_context(patch.object(probe,'_pipe',return_value=receiver,create=True))
        if fault!='late':
            spawn.side_effect = AssertionError('receiver spawn attempted')
        yield SimpleNamespace(opened=opened,spawn=spawn,body_reads=body_reads,startup=startup,registry=registry)


def stage_arguments(members):
    return dict(run_id='run-a',input_scope='owner.inputs',source_locator='incoming',members=members,
        request_id=REQUEST_ID,target_locator=TARGET,expected_current_digest=None)


def new_model_owner():
    return SimpleNamespace(_startup={},_held_launch=None,_held_input_source=None,_held_input_io=None,_unavailable=False)


class BundleInputBoundaryTests(unittest.TestCase):
    def test_exact_metadata_size_uses_actual_wire_encoding_and_unchanged_real_digests(self):
        for delta in (-1,0,1):
            expected = REQUEST_LIMIT+delta
            paths = exact_paths(expected,lambda rows:manifest_bytes(rows,110022))
            first = manifest_bytes(paths,110022)
            second = manifest_bytes(paths,110023)
            self.assertNotEqual(first,second)
            self.assertEqual((len(first),len(second)),(expected,expected))
            self.assertLess(len(candidate_bytes(paths)),REQUEST_LIMIT)
            sizes = dict.fromkeys(paths,MEMBER_SIZE)
            for role in ROLES:
                with self.subTest(role=role,delta=delta):
                    if delta<=0:
                        self.assertEqual(input_stage._control(header_for(role,sizes))['member_count'],MAX_MEMBERS)
                        self.assertEqual(len(parse_manifest(first)['members']),MAX_MEMBERS)
                    else:
                        with self.assertRaises(_BundleLimitExceeded) as error:
                            header_for(role,sizes)
                        self.assertEqual((error.exception.kind,error.exception.observed),('manifest_bytes',expected))
        source = stage_models.Source([('member.bin',b'actual body')])
        request = input_stage._stage_request('owner.inputs','incoming',['member.bin'])
        sender = input_stage._InputStageSender(stage_models.launch,stage_models.scope,'Bundle2',
            SCOPE_DIGEST,request,source,stage_models.deadline())
        frames = list(sender.frames())
        self.assertIn(digest_bytes(b'actual body').encode(),frames[-1])
        self.assertNotIn(b'"digest":""',b''.join(frames))

    def test_pure_upper_bounds_leave_no_source_or_receiver_and_at_values_are_unchanged(self):
        candidates = exact_paths(REQUEST_LIMIT+1,candidate_bytes)
        candidate_at = exact_paths(REQUEST_LIMIT,candidate_bytes)
        self.assertEqual(len(input_stage._publication_candidate('Bundle1',REQUEST_ID,TARGET,candidate_at,None)[1]),REQUEST_LIMIT)
        at_depth = '/'.join(['d']*(MAX_DEPTH-1)+['member.bin'])
        self.assertEqual(input_stage._stage_request('owner.inputs','incoming',[at_depth])['members'],[at_depth])
        at_count = [f'm{i}' for i in range(MAX_MEMBERS)]
        self.assertEqual(len(input_stage._stage_request('owner.inputs','incoming',at_count)['members']),MAX_MEMBERS)
        cases = ((at_count+['last'],'bundle.member_count_limit','member_count',MAX_MEMBERS),
                 (['d/'+at_depth],'bundle.reserved_or_deep_path','member_depth',MAX_DEPTH),
                 (candidates,'bundle.request_too_large','candidate_bytes',REQUEST_LIMIT))
        for role in ROLES:
            for members,code,kind,maximum in cases:
                with self.subTest(role=role,kind=kind),stage_model(role,{}) as model:
                    owner = new_model_owner()
                    result = input_stage.run_windows_input_stage(owner,deadline_ns=stage_models.deadline(),**stage_arguments(members))
                    self.assertEqual(result,input_stage._ClosedInputBundleRefusal(
                        role,code,kind,maximum+1,maximum,'not_opened',model.registry.return_value))
                    model.registry.assert_called_once_with(model.startup.return_value)
                    model.spawn.assert_not_called()
                    self.assertEqual(model.opened,[])
                    self.assertTrue(model.startup.call_args.kwargs['_inspection_only'])

    def test_metadata_upper_bounds_recheck_and_close_before_receiver(self):
        large_manifest = dict.fromkeys(exact_paths(REQUEST_LIMIT+1,lambda rows:manifest_bytes(rows,110022)),MEMBER_SIZE)
        cases = (({'member':FILE_LIMIT+1},'input_stage.member_bound','member_bytes',FILE_LIMIT),
                 ({'first':FILE_LIMIT,'second':FILE_LIMIT,'third':1},'input_stage.total_bound','total_bytes',MAX_TOTAL_BYTES),
                 (large_manifest,'bundle.metadata_limit','manifest_bytes',REQUEST_LIMIT))
        for role in ROLES:
            for sizes,code,kind,maximum in cases:
                with self.subTest(role=role,kind=kind),stage_model(role,sizes) as model:
                    owner = new_model_owner()
                    result = input_stage.run_windows_input_stage(owner,deadline_ns=stage_models.deadline(),
                        **stage_arguments(list(sizes)))
                    self.assertEqual(result,input_stage._ClosedInputBundleRefusal(
                        role,code,kind,maximum+1,maximum,'closed',model.registry.return_value))
                    model.registry.assert_called_once_with(model.startup.return_value)
                    self.assertEqual(model.body_reads,[])
                    self.assertEqual(model.opened[0]._handles,[])
                    self.assertTrue(all(handle.close_count==1 for handle in model.opened[0].handles))
                    self.assertTrue(all(value>=3 for value in model.opened[0].states.values()))
                    self.assertIsNone(owner._held_input_source)
                    self.assertIsNone(owner._held_input_io)
                    model.spawn.assert_not_called()
        for role in ROLES:
            for total in (MAX_TOTAL_BYTES-1,MAX_TOTAL_BYTES):
                self.assertEqual(input_stage._control(header_for(role,{'first':FILE_LIMIT,'second':total-FILE_LIMIT}))['total_length'],total)

    def test_unrelated_errors_failed_recheck_and_late_typed_error_have_no_known_refusal(self):
        for members in ([],['phase-bundle.json/member'],['../outside']):
            with self.subTest(members=members),stage_model('Bundle1',{}) as model:
                with self.assertRaises(PhaseError) as error:
                    input_stage.run_windows_input_stage(new_model_owner(),deadline_ns=stage_models.deadline(),
                        **stage_arguments(members))
                self.assertNotIsInstance(error.exception,_BundleLimitExceeded)
                self.assertEqual(model.opened,[])
                model.spawn.assert_not_called()
        for fault in ('close','drift','late'):
            sizes = {'member':FILE_LIMIT+(fault!='late')}
            with self.subTest(fault=fault),stage_model('Bundle2',sizes,fault=fault) as model:
                owner = new_model_owner()
                with self.assertRaises(Exception):
                    input_stage.run_windows_input_stage(owner,deadline_ns=stage_models.deadline(),
                        **stage_arguments(list(sizes)))
                self.assertEqual(model.spawn.call_count,int(fault=='late'))
                self.assertIs(owner._held_input_io,model.opened[0])
                self.assertEqual(bool(model.opened[0]._handles),fault=='close')

    def test_actual_mcp_sdk_delivers_real_owner_refusals_and_retains_unknown_for_plain_error(self):
        registry = PhaseApplication().registry
        for role in ROLES:
            tool = mcp_models.NativeInputMCPClosedSchemaTests().server(role)._tool_manager._tools['phase_publish_input']
            for members,sizes,finalization in ((['d/'*MAX_DEPTH+'member'],{},'not_opened'),
                                                (['member'],{'member':FILE_LIMIT+1},'closed')):
                with self.subTest(role=role,finalization=finalization),stage_model(role,sizes),\
                        patch.object(inspection_mcp._InspectionMCPCallOwner,'_call_locked') as dispatch:
                    args = stage_arguments(members)
                    self.assertEqual(inspection_mcp._native_input_cli_request({'run_id':args['run_id'],
                        'request':{'operation':'publish_input',**{k:v for k,v in args.items() if k!='run_id'}}}),args)
                    result = asyncio.run(tool.run(args))
                    for key in ('run_id','input_scope','source_locator','target_locator','request_id'):
                        self.assertEqual(result[key],args[key])
                    self.assertEqual(result['native_input_publication_refusal_version'],'1.1')
                    self.assertEqual(result['role'],role)
                    self.assertEqual(result['source_finalization'],finalization)
                    self.assertEqual(result['exit_code'],10)
                    self.assertFalse(result['preparation_started'])
                    self.assertFalse(result['retry_authorized'])
                    self.assertNotIn('command_ack',result)
                    validate_command_result(result['refusal'],registry)
                    self.assertIsNone(result['refusal']['receipt_digest'])
                    dispatch.assert_not_called()
                    self.assertFalse(tool.fn.__self__.unknown)
                    self.assertEqual(tool.fn.__self__.held,[])
            with patch.object(input_stage,'os',SimpleNamespace(name='nt',getpid=os.getpid)),\
                    patch.object(input_stage,'run_windows_input_stage',side_effect=PhaseError('input_stage.total_bound')):
                with self.assertRaisesRegex(Exception,'input_stage.total_bound'):
                    asyncio.run(tool.run(stage_arguments(['member'])))
            self.assertTrue(tool.fn.__self__.unknown)

    def test_modern_bundle_refusals_use_the_installed_registry(self):
        catalog = synthetic_catalog()
        owner = owner_document(catalog)
        owner_bytes = canonical_bytes(owner)
        config = {
            'native_launch_version': '4.0',
            'phase_wheel_digest': 'sha256:'+'3'*64,
            'owner_directory_configuration_base64': base64.b64encode(owner_bytes).decode(),
            'owner_directory_configuration_digest': digest_bytes(owner_bytes),
        }
        config_bytes = canonical_bytes(config)
        resolve_registry = installation._native_registry_for_launch
        cases = (
            (['d/'*MAX_DEPTH+'member'], {}, 'not_opened', 'member_depth'),
            (['member'], {'member':FILE_LIMIT+1}, 'closed', 'member_bytes'),
        )
        for role in ROLES:
            row = next(row for row in owner['manifests'] if row['role']==role)
            manifest_bytes = base64.b64decode(row['manifest_base64'])
            manifest_digest = row['manifest_digest']
            for members, sizes, finalization, kind in cases:
                with (
                    self.subTest(role=role, finalization=finalization),
                    stage_model(role,sizes) as model,
                    patch.object(installation,'_native_registry_for_launch',wraps=resolve_registry) as resolve,
                    patch.object(owner_directory_installation,'_fixed_owner_directory_catalog',return_value=catalog),
                    patch.object(inspection_mcp.FastMCP,'run',autospec=True) as run_server,
                    patch.object(inspection_mcp._InspectionMCPCallOwner,'_call_locked') as dispatch,
                ):
                    args = stage_arguments(members)
                    model.startup.return_value = SimpleNamespace(
                        _manifest_bytes=manifest_bytes, installation_digest=manifest_digest, _config=config,
                        _experimental_admission_context=None, run_id=args['run_id'],
                    )
                    inspection_mcp.run_native_input_mcp(
                        config_bytes=config_bytes, expected_config_digest=digest_bytes(config_bytes),
                        manifest_bytes=manifest_bytes, expected_manifest_digest=manifest_digest,
                    )
                    tool = run_server.call_args.args[0]._tool_manager._tools['phase_publish_input']
                    result = asyncio.run(tool.run(args))
                    self.assertEqual(result['exit_code'],10)
                    self.assertEqual(result['source_finalization'],finalization)
                    self.assertEqual(result['bound']['kind'],kind)
                    self.assertFalse(result['preparation_started'])
                    self.assertFalse(result['retry_authorized'])
                    self.assertIsNone(result['refusal']['intent_digest'])
                    self.assertIsNone(result['refusal']['receipt_digest'])
                    validate_command_result(result['refusal'],catalog.registry)
                    resolve.assert_called_once_with(model.startup.return_value)
                    self.assertFalse(model.body_reads)
                    self.assertEqual(len(model.opened),int(bool(sizes)))
                    if model.opened:
                        self.assertEqual(model.opened[0]._handles,[])
                    model.spawn.assert_not_called()
                    dispatch.assert_not_called()


if __name__=='__main__':
    unittest.main()
