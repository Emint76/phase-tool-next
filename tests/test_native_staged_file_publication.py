"""Closed installed high-level alias models. Native effects are not exercised."""
import asyncio
from contextlib import contextmanager, nullcontext
import os
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bootstrap, input_stage, inspection_mcp, native, scoped
from phase_tool.mutation.ntfs.owner_semantic_contracts import semantic_owner_contract
from .test_native_input_stage_protocol import NativeModel, native_fixture


RUN = 'b07-model-run'
DIGEST = digest_bytes(b'payload')
OTHER = digest_bytes(b'different')
HEADER = digest_bytes(b'header')
TARGET_ROOT = 'phase_result_root'


def arguments(role, **changes):
    value = {'run_id': RUN, 'input_scope': 'owner.inputs', 'source_locator': 'incoming.bin',
             'target_locator': 'result.bin', 'request_id': 'request-a',
             'publication_version': '1.0' if role == 'File1' else '2.0',
             'expected_digest': DIGEST, 'root_binding': TARGET_ROOT}
    value.update(changes)
    return value


def startup(role):
    manifest = canonical_bytes({'contract': semantic_owner_contract(role), 'evidence_root': '/work/evidence',
                               'root_grants': [grant().as_dict()]})
    return dict(config_bytes=b'', expected_config_digest=None, manifest_bytes=manifest,
                expected_manifest_digest=digest_bytes(manifest))


def identity(index):
    return native.NativeIdentity.parse({'volume_serial': 7, 'file_id': f'{index:032x}'})


def grant():
    return scoped.NativeRootGrant(TARGET_ROOT, r'\Device\HarddiskVolume7',
        '\\\\?\\volume{fedcba98-7654-3210-fedc-ba9876543210}\\', 7, ('test-output',), identity(12))


class NativeStagedFilePublicationTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(input_stage,'os',SimpleNamespace(name='nt',getpid=os.getpid)))

    def test_closed_cli_and_sdk_shapes_preserve_existing_unary_inspect(self):
        for role in ('File1','File2'):
            with self.subTest(role=role),patch.object(inspection_mcp.FastMCP,'run',autospec=True) as run:
                inspection_mcp.run_native_input_mcp(**startup(role))
                tools=run.call_args.args[0]._tool_manager._tools
                self.assertEqual(set(tools),{'phase_publish_file','phase_publish_input','phase_inspect'})
                self.assertEqual(tools['phase_inspect'].parameters['required'],['run_id'])
                tool=tools['phase_publish_file']
                args=arguments(role)
                wire={'run_id':RUN,'request':{'operation':'publish_file',**{k:v for k,v in args.items() if k!='run_id'}}}
                self.assertEqual(inspection_mcp._native_staged_file_cli_request(wire),args)
                with patch.object(inspection_mcp._InputScopeSession,'_invoke',return_value={'closed':True}) as invoke:
                    self.assertEqual(asyncio.run(tool.run(args)),{'closed':True})
                    invoke.assert_called_once_with('publish_staged_file',args)
                    for change in ({'expected_digest':'malformed'},{'root_grants':[]},{'publication_version':None}):
                        with self.assertRaises(Exception):
                            asyncio.run(tool.run(dict(args,**change)))
                    invoke.assert_called_once()
                for change in ({'expected_digest':'malformed'},{'root_grants':[]},{'operation':'publish_input'}):
                    with self.assertRaises(PhaseError):
                        inspection_mcp._native_staged_file_cli_request(dict(wire,request=dict(wire['request'],**change)))
                with patch.object(inspection_mcp._InputScopeSession,'_invoke',return_value={'read':True}) as invoke:
                    inspect=tools['phase_inspect']
                    self.assertEqual(asyncio.run(inspect.run({'run_id':RUN})),{'read':True})
                    self.assertEqual(asyncio.run(inspect.run({'run_id':RUN,'root_binding':TARGET_ROOT})),{'read':True})
                    with self.assertRaises(Exception):
                        asyncio.run(inspect.run({'run_id':RUN,'root_binding':'objects_root'}))
                    self.assertEqual(invoke.call_count,2)
                    for call in invoke.call_args_list:
                        self.assertEqual(call.args,('inspect',{'run_id':RUN}))

    def test_real_pre_source_gate_refuses_both_cross_versions_and_foreign_root(self):
        g=grant()
        cases=(('File1','2.0',TARGET_ROOT,'publish_file.wrong_contract'),
               ('File2','1.0',TARGET_ROOT,'publish_file.wrong_contract'),
               ('File1','1.0','objects_root','publish_file.wrong_root_binding'),
               ('File2','2.0','objects_root','publish_file.wrong_root_binding'))
        for role,version,root,code in cases:
            with self.subTest(role=role,version=version,root=root), \
                    patch.object(bootstrap,'_NativeAcceptedLaunch',return_value=SimpleNamespace(root_grant=g.as_dict())), \
                    patch.object(input_stage,'_scope_for_launch',return_value=({'scope_id':'owner.inputs'},role,DIGEST)), \
                    patch.object(native,'NativeIO') as io,patch.object(inspection_mcp,'run_native_parent') as parent:
                session=inspection_mcp._InputScopeSession(**startup(role))
                result=session.publish_staged_file(**arguments(role,publication_version=version,root_binding=root))
                self.assertEqual((result['error'],result['status'],result['exit_code']),(code,'rejected_before_write',10))
                self.assertEqual(result['contract_digest'],semantic_owner_contract(role)['package_digest'])
                self.assertIs(result['mutation_attempted'],False)
                self.assertIsNone(result['receipt_digest'])
                self.assertFalse(session.unknown)
                self.assertEqual(session.held,[])
                io.assert_not_called()
                parent.assert_not_called()

    def test_wrong_digest_after_closed_stage_leaves_session_usable_and_never_enters_core(self):
        for role in ('File1','File2'):
            prepared={'expected_digest':DIGEST,'expected_length':7}
            with self.subTest(role=role), \
                    patch.object(input_stage,'run_windows_input_stage',return_value=(prepared,role,{},None)) as stage, \
                    patch.object(inspection_mcp,'run_native_parent') as parent:
                session=inspection_mcp._InputScopeSession(**startup(role))
                result=session.publish_staged_file(**arguments(role,expected_digest=OTHER))
                self.assertEqual(result['error'],'publish_file.source_digest_mismatch')
                self.assertEqual((result['content_digest'],result['content_length']),(DIGEST,7))
                self.assertFalse(result['success'])
                self.assertFalse(result['mutation_attempted'])
                self.assertIsNone(result['receipt_digest'])
                self.assertFalse(session.unknown)
                self.assertEqual(session.held,[])
                self.assertEqual(stage.call_args.kwargs['_file_assertions'].expected_digest,OTHER)
                parent.assert_not_called()

    def test_match_correlates_execute_and_fresh_inspection_then_projects_exact_role(self):
        for role in ('File1','File2'):
            prepared={'source_locator':'phase-native-input-'+HEADER[7:39]+'/payload/payload',
                      'header_digest':HEADER,'expected_digest':DIGEST,'expected_length':7}
            def response(command):
                return PhaseApplication._command_payload(command,success=True,run_id=RUN,
                    terminal_status='succeeded_verified',execution_disposition='executed',mutation_attempted=True,
                    effect_plan_digest=digest_bytes(b'plan'),intent_digest=digest_bytes(b'intent'),
                    receipt_digest=digest_bytes(b'receipt'),target_verified=True if command=='inspect'else None,
                    blockers=[],error=None,exit_code=0)
            ack=response('execute')
            inspected=response('inspect')
            owner=inspection_mcp._InspectionMCPCallOwner(**startup(role))
            with self.subTest(role=role), \
                    patch.object(input_stage,'run_windows_input_stage',return_value=(prepared,role,{},None)), \
                    patch.object(owner,'_call_locked',side_effect=[ack,inspected]) as call:
                result=owner.publish_staged_file(**arguments(role))
                self.assertEqual(result['status'],'verified')
                self.assertEqual(result['content_digest'],DIGEST)
                self.assertEqual(result['receipt_digest'],ack['receipt_digest'])
                self.assertEqual(result['contract_digest'],semantic_owner_contract(role)['package_digest'])
                self.assertEqual(call.call_count,2)
                self.assertEqual(call.call_args_list[1].args,(RUN,{'operation':'inspect'}))
                self.assertIs(call.call_args_list[1].kwargs['inspection_only'],True)

    def test_physical_root_comparison_with_full_file_id_and_volume(self):
        g=grant()
        volume=dict(device=g.device,volume_guid=g.volume_guid,volume_serial32=g.volume_serial32)
        target_path=(identity(1),identity(2),g.root_identity)
        for source_path,overlap in (((identity(1),identity(2),g.root_identity),True),
                                    ((identity(1),identity(2)),True),
                                    ((*target_path,identity(13)),True),
                                    ((identity(1),identity(2),identity(14)),False),
                                    ((identity(1),identity(2),identity(12+2**64)),False)):
            source=object.__new__(native._NativeInputSnapshot)
            source.api=object()
            source.scope={'volume':volume}
            source.anchors=[(None,value) for value in source_path]
            source.owner=(os.getpid(),native.threading.get_ident())
            source.close_attempted=False
            source.deadline=time.perf_counter_ns()+5_000_000_000
            target=SimpleNamespace(_pinned_root_ancestry=lambda:target_path)
            expected=self.assertRaises(native._InputPublicationRootOverlap) if overlap else nullcontext()
            with self.subTest(source=source_path), \
                    patch.object(source,'verify_complete') as verify, \
                    patch.object(scoped,'NativeScopedTarget',return_value=nullcontext(target)) as pin,expected:
                source._check_publication_root(g,'unopened/leaf.bin')
            pin.assert_called_once_with(source.api,g,'leaf.bin')
            self.assertEqual(verify.call_count,2)
        source.anchors=[(None,identity(7)),(None,identity(14))]
        with patch.object(source,'verify_complete'), \
                patch.object(scoped,'NativeScopedTarget',return_value=nullcontext(target)), \
                self.assertRaises(PhaseError) as caught:
            source._check_publication_root(g,'leaf.bin')
        self.assertEqual(caught.exception.code,'input_stage.publication_volume_identity_mismatch')

    def test_overlapping_root_closes_before_known_refusal_and_failed_close_stays_unknown(self):
        fixture,scope,source_locator,_=native_fixture()
        scope['scope_id']='owner.inputs'
        root_identity=native.NativeIdentity.parse(scope['root_identity'])
        accepted=scoped.NativeRootGrant(TARGET_ROOT,grant().device,grant().volume_guid,
            99,('owned',),root_identity)
        scope['volume']['volume_guid']=accepted.volume_guid
        device_identity=native.NativeIdentity(99,'0'*31+'1')
        for fail_close in (False,True):
            opened=[]
            source_names=[]
            target_closures=[]

            class InputModel(NativeModel):
                def __init__(self):
                    super().__init__(fixture.tree)
                    self.volume=scope['volume']
                    self.fail_close=next(name for name in fixture.tree if name.endswith('/owned')) if fail_close else None
                    self.hook=lambda api,event,*args: source_names.extend(args) if event=='open' else None
                    opened.append(self)

                @property
                def _handles(self):
                    return [handle for handle in self.handles if handle not in self.closed]

                def input_snapshot(self,*args,**kwargs):
                    return native._NativeInputSnapshot(self,*args,**kwargs)

            @contextmanager
            def target(*args):
                try:
                    yield SimpleNamespace(_pinned_root_ancestry=lambda:(device_identity,root_identity))
                finally:
                    target_closures.append(True)

            session=inspection_mcp._InputScopeSession(**startup('File1'))
            with self.subTest(fail_close=fail_close), \
                    patch.object(bootstrap,'_NativeAcceptedLaunch',return_value=SimpleNamespace(root_grant=accepted.as_dict())), \
                    patch.object(input_stage,'_scope_for_launch',return_value=(scope,'File1',DIGEST)), \
                    patch.object(native,'NativeIO',InputModel),patch.object(scoped,'NativeScopedTarget',side_effect=target), \
                    patch.object(inspection_mcp,'run_native_parent') as parent:
                args=arguments('File1',source_locator=source_locator)
                if fail_close:
                    with self.assertRaises(BaseExceptionGroup):
                        session.publish_staged_file(**args)
                    self.assertTrue(session.unknown)
                    self.assertIs(session.held[0]._held_input_io,opened[0])
                    self.assertEqual(len(opened[0]._handles),1)
                else:
                    result=session.publish_staged_file(**args)
                    self.assertEqual(result['error'],'publish_file.overlapping_roots')
                    self.assertFalse(session.unknown)
                    self.assertEqual(opened[0]._handles,[])
                parent.assert_not_called()
                self.assertEqual(target_closures,[True])
                self.assertNotIn(source_locator,source_names)
                self.assertTrue(all(handle.close_count==1 for handle in opened[0].handles))


if __name__=='__main__':
    unittest.main()
