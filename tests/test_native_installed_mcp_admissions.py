"""Fixed-installation MCP adapter component regressions.

Exact admission identity/forwarding, closed tool schemas, registry correlation
and finite-owner behavior are modeled here. Native launch/process boundaries
are explicitly mocked. The b'{}' objects exercise type/forwarding only; they
are not valid native capabilities. These tests do not establish an accepted
installation, actual native worker/receipt success, NTFS, A05 or G01 guarantees.
Existing genuine admission/registry tests and B2 route regressions remain required.
"""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool import installation
from phase_tool.canonical import canonical_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import inspection_mcp
from phase_tool.mutation.ntfs.experimental_file1 import _ExperimentalFile1Admission
from phase_tool.mutation.ntfs.experimental_file2 import _ExperimentalFile2Admission
from phase_tool.mutation.ntfs.experimental_version1 import _ExperimentalVersion1Admission
from phase_tool.mutation.ntfs.experimental_version2 import _ExperimentalVersion2Admission
from phase_tool.mutation.ntfs.experimental_bundle1 import _ExperimentalBundle1Admission
from phase_tool.mutation.ntfs.experimental_bundle2_v3 import _ExperimentalBundle2AdmissionV3
from phase_tool.mutation.ntfs.experimental_history import (
    _ExperimentalHistoryFile1Admission, _ExperimentalHistoryVersion1Admission)
from phase_tool.application import PhaseApplication
from phase_tool.mutation.ntfs.uncertainty import _NativeLifecycleUnresolved


class _MCPResultModels:
    'Pure portable copies of the existing args/failure/unknown result builders.'
    def args(self,run='synthetic-prepared'):
        return {'run_id':run,'candidate_path':'/synthetic/prepared/candidate.json',
            'input_paths':{'source':'/synthetic/prepared/source.bin'},
            'expected_inputs':{'source':('sha256:'+'a'*64,17)},'maximum_candidate_bytes':1234}
    def failure(self,command='execute'):
        return PhaseApplication()._failure(command,PhaseError('synthetic.preinstallation.refused')).payload
    def unknown(self,run='synthetic-prepared'):
        return _NativeLifecycleUnresolved(request=SimpleNamespace(run_id=run),
            context=SimpleNamespace(intent_recording_started=True,proof_publication_attempted=False,
                publication_attempted=True,common_guard_finalized=False,
                original_intent_digest='sha256:'+'b'*64,
                prepared=SimpleNamespace(effect_plan_digest='sha256:'+'c'*64)),
            authority=SimpleNamespace(channel=SimpleNamespace(possible_dispatch=True)),
            primary=OSError('synthetic native completion unknown')).command_result('execute')


class NativeInstalledMCPAdmissionTests(unittest.TestCase):
    """Adapter identity/schema/lifetime model only; no native guard is patched."""
    def rows(self):
        return (
            (_ExperimentalFile1Admission, installation._native_experimental_file1_registry),
            (_ExperimentalFile2Admission, installation._native_experimental_file2_registry),
            (_ExperimentalVersion1Admission, installation._native_experimental_version1_registry),
            (_ExperimentalVersion2Admission, installation._native_experimental_version2_registry),
            (_ExperimentalBundle1Admission, installation._native_experimental_bundle1_registry),
            (_ExperimentalBundle2AdmissionV3, installation._native_experimental_bundle2_registry_v3),
            (_ExperimentalHistoryFile1Admission, installation._native_experimental_history_registry),
            (_ExperimentalHistoryVersion1Admission, installation._native_experimental_history_registry),
        )

    def startup(self, admission=None):
        result=dict(config_bytes=b'', expected_config_digest=None,
            manifest_bytes=b'', expected_manifest_digest=None)
        if admission is not None:
            result['_experimental_admission_context']=admission
        return result

    def args(self):
        return _MCPResultModels().args('synthetic-installed-mcp')

    def test_exact_eight_types_are_retained_without_constructing_a_launch(self):
        with patch.object(inspection_mcp, '_NativeAcceptedLaunch') as launch:
            for kind, _ in self.rows():
                admission=kind(b'{}')
                with self.subTest(kind=kind.__name__):
                    owner=inspection_mcp._InspectionMCPCallOwner(**self.startup(admission))
                    self.assertIs(owner._startup['_experimental_admission_context'], admission)
                    self.assertIsNone(owner._held_launch)
                    self.assertFalse(owner._unavailable)
            launch.assert_not_called()

    def test_foreign_objects_and_subclasses_fail_before_server_nonce_or_launch(self):
        foreign=[object(), {}]
        foreign.extend(type('Foreign'+kind.__name__, (kind,), {})(b'{}')
            for kind, _ in self.rows())
        with (patch.object(inspection_mcp, '_NativeAcceptedLaunch') as launch,
                patch.object(inspection_mcp, 'FastMCP') as server,
                patch('secrets.token_hex') as nonce):
            for value in foreign:
                for factory in (inspection_mcp._prepared_server, inspection_mcp._inspection_server):
                    with self.subTest(kind=type(value).__name__, server=factory.__name__):
                        with self.assertRaisesRegex(PhaseError, 'ntfs.experimental_admission_required'):
                            factory(**self.startup(value))
            launch.assert_not_called(); server.assert_not_called(); nonce.assert_not_called()

    def test_admitted_servers_expose_exact_role_bound_tools_and_unary_read(self):
        with patch.object(inspection_mcp, '_NativeAcceptedLaunch') as launch:
            for kind, _ in self.rows():
                with self.subTest(kind=kind.__name__):
                    startup=self.startup(kind(b'{}'))
                    prepared=inspection_mcp._prepared_server(**startup)._tool_manager.list_tools()
                    reader=inspection_mcp._inspection_server(**startup)._tool_manager.list_tools()
                    expected=['phase_execute_prepared']
                    if kind in (_ExperimentalBundle1Admission,_ExperimentalBundle2AdmissionV3):
                        expected+=['phase_execute_bundle_publication','phase_publish_bundle']
                    expected+=['phase_inspect']
                    self.assertEqual([tool.name for tool in prepared],expected)
                    self.assertEqual([tool.name for tool in reader], ['phase_inspect'])
                    self.assertEqual(set(prepared[0].parameters['properties']),
                        {'run_id', 'candidate_path', 'input_paths', 'expected_inputs', 'maximum_candidate_bytes'})
                    inspect_tool=next(tool for tool in prepared if tool.name=='phase_inspect')
                    self.assertEqual(set(inspect_tool.parameters['properties']), {'run_id'})
                    self.assertEqual(set(reader[0].parameters['properties']), {'run_id'})
                    for tool in (*prepared, *reader):
                        self.assertIs(tool.parameters['additionalProperties'], False)
                        self.assertNotIn('_experimental_admission_context', tool.parameters['properties'])
            launch.assert_not_called()

    def test_none_startup_preserves_legacy_tools_and_omits_context_key(self):
        startup=self.startup()
        for supplied in (startup, startup|{'_experimental_admission_context':None}):
            with self.subTest(explicit_none=len(supplied)>len(startup)):
                tools=inspection_mcp._prepared_server(**supplied)._tool_manager.list_tools()
                self.assertEqual([tool.name for tool in tools], [
                    'phase_execute_prepared', 'phase_execute_file_publication', 'phase_publish_file',
                    'phase_execute_version1_publication', 'phase_inspect_version1_publication', 'phase_inspect'])
                self.assertEqual(set(tools[-1].parameters['properties']), {
                    'run_id', 'request_id', 'target_locator', 'expected_digest', 'expected_receipt_digest'})
                owner_type=inspection_mcp._InspectionMCPCallOwner
                with patch.object(inspection_mcp, '_InspectionMCPCallOwner', wraps=owner_type) as owner:
                    reader=inspection_mcp._inspection_server(**supplied)
                    owner.assert_called_once_with(**startup)
                    tools=reader._tool_manager.list_tools()
                    self.assertEqual([tool.name for tool in tools], ['phase_inspect'])
                    self.assertEqual(set(tools[0].parameters['properties']), {'run_id'})

    def test_new_context_paths_use_the_exact_actual_launch_registry(self):
        # B2's existing special branch has its own six exact regressions;
        # exercise the seven newly admitted paths without replacing that branch.
        for kind, registry_factory in self.rows():
            if kind is _ExperimentalBundle2AdmissionV3:
                continue
            for operation in ('execute', 'inspect'):
                admission=kind(b'{}'); owner=inspection_mcp._InspectionMCPCallOwner(**self.startup(admission))
                launch=object(); registry=registry_factory(); run=self.args()['run_id']
                value=_MCPResultModels().failure(operation); value['run_id']=run
                before=canonical_bytes(value)
                with (self.subTest(kind=kind.__name__, operation=operation),
                        patch.object(inspection_mcp, '_NativeAcceptedLaunch', return_value=launch) as created,
                        patch.object(inspection_mcp, 'run_native_parent', return_value={'result':value, 'exit_code':10}),
                        patch.object(installation, '_native_registry_for_launch', return_value=registry) as selected,
                        patch.object(inspection_mcp, '_native_registry_for_manifest',
                            side_effect=AssertionError('admitted path fell back to ordinary manifest registry'))):
                    result=(owner.execute_prepared(**self.args()) if operation=='execute' else owner.inspect(run))
                    self.assertIs(result, value); self.assertEqual(canonical_bytes(result), before)
                    selected.assert_called_once_with(launch)
                    self.assertIs(created.call_args.kwargs['_experimental_admission_context'], admission)
                    self.assertIs(created.call_args.kwargs['_inspection_only'], operation=='inspect')
                    self.assertIsNone(owner._held_launch); self.assertFalse(owner._unavailable)

    def test_new_context_nullable_uncertainty_keeps_the_same_launch_and_blocks_reentry(self):
        for kind, registry_factory in self.rows():
            if kind is _ExperimentalBundle2AdmissionV3:
                continue
            admission=kind(b'{}'); owner=inspection_mcp._InspectionMCPCallOwner(**self.startup(admission))
            launch=object(); registry=registry_factory()
            value=_MCPResultModels().unknown(self.args()['run_id']); value['run_id']=None
            before=canonical_bytes(value)
            with (self.subTest(kind=kind.__name__),
                    patch.object(inspection_mcp, '_NativeAcceptedLaunch', return_value=launch) as created,
                    patch.object(inspection_mcp, 'run_native_parent', return_value={'result':value, 'exit_code':40}),
                    patch.object(installation, '_native_registry_for_launch', return_value=registry)):
                self.assertIs(owner.execute_prepared(**self.args()), value)
                self.assertEqual(canonical_bytes(value), before)
                self.assertIs(owner._held_launch, launch); self.assertTrue(owner._unavailable)
                for call in (lambda:owner.execute_prepared(**self.args()),
                        lambda:owner.inspect(self.args()['run_id'])):
                    with self.assertRaisesRegex(PhaseError, 'ntfs.inspection_mcp_unavailable'):
                        call()
                created.assert_called_once()

    def test_registry_selection_failure_retains_launch_and_refuses_another_call(self):
        owner=inspection_mcp._InspectionMCPCallOwner(**self.startup(_ExperimentalFile1Admission(b'{}')))
        launch=object(); primary=PhaseError('synthetic.fixed_registry_refused')
        value=_MCPResultModels().failure()
        with (patch.object(inspection_mcp, '_NativeAcceptedLaunch', return_value=launch) as created,
                patch.object(inspection_mcp, 'run_native_parent', return_value={'result':value, 'exit_code':10}),
                patch.object(installation, '_native_registry_for_launch', side_effect=primary)):
            with self.assertRaises(PhaseError) as caught:
                owner.execute_prepared(**self.args())
            self.assertIs(caught.exception, primary)
            self.assertIs(owner._held_launch, launch); self.assertTrue(owner._unavailable)
            with self.assertRaisesRegex(PhaseError, 'ntfs.inspection_mcp_unavailable'):
                owner.inspect(self.args()['run_id'])
            created.assert_called_once()

    def test_unary_entrypoint_forwards_only_an_explicit_fixed_context(self):
        cases=[self.startup(), self.startup()|{'_experimental_admission_context':None}]
        cases.extend(self.startup(kind(b'{}')) for kind, _ in self.rows())
        for startup in cases:
            expected={key:value for key,value in startup.items()
                if key!='_experimental_admission_context' or value is not None}
            with (self.subTest(context=type(startup.get('_experimental_admission_context')).__name__),
                    patch.object(inspection_mcp, '_inspection_server') as factory):
                self.assertEqual(inspection_mcp.run_native_inspection_mcp(**startup), 0)
                factory.assert_called_once_with(**expected)
                factory.return_value.run.assert_called_once_with(transport='stdio')
