"""Prepared C01 entry-to-Core binding with synthetic installation and effects."""
from contextlib import contextmanager
import os
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch

from phase_tool import evidence, installation
from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.core import PhaseCore
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import common_flock_test, entrypoint, input_stage
from phase_tool.mutation.ntfs.owner_directory_fixture import _kinds
from phase_tool.mutation.ntfs.owner_semantic_fixture import semantic_owner_registry

from ._native_startup_shell import legacy_data_launch
from .native_staged_original14_data import fixture


class PreparedC01CoreBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        document = fixture('3.0')
        previous = document['fixture_uuid']
        case = common_flock_test._PREPARED_NORMAL_CASE
        document.update(fixture_uuid=case, owner_scope_id='phase.qualification.owner.'+case)
        document['windows_roots'] = {name:root.replace(previous,case) for name,root in document['windows_roots'].items()}
        for grant in document['root_grants']:
            grant['components'][1] = case
        document['request_limits']['run_prefix'] = 'od3-'+case+'-'
        cls.kind = _kinds()['File1']
        cls.admission = cls.kind(canonical_bytes(document))
        cls.registry = semantic_owner_registry(cls.kind)
        row = document['roles'][0]
        cls.manifest = canonical_bytes({'contract':row['contract'], 'evidence_root':document['evidence_root'],
            'root_projections':{'phase_result_root':'/ntfs-result'}})
        cls.config = canonical_bytes({'native_launch_version':'3.0',
            'artifact_graph':{'launcher_digest':common_flock_test._PREPARED_NORMAL_LAUNCHER}})
        cls.run_id = document['request_limits']['run_prefix']+'c01-holder-000'
        cls.candidate = canonical_bytes({'request_id':'c01.model','target_locator':'out.bin'})
        cls.expected = (digest_bytes(b'body'),4)

    def launch(self,request):
        launch = legacy_data_launch(manifest_bytes=self.manifest,invocation={
            'run_id':self.run_id,'operation_nonce':'a'*32,'channel_id':'b'*32,'request':request})
        launch._config_bytes = self.config
        launch._experimental_admission_context = self.admission
        return launch

    def prepared_launch(self):
        return self.launch({'operation':'execute','candidate_path':'/qualification/preparation/candidate.json',
            'input_paths':{'source':'/qualification/preparation/body.bin'},
            'expected_inputs':{'source':list(self.expected)},'maximum_candidate_bytes':len(self.candidate)})

    @contextmanager
    def selected(self,launch):
        self.assertEqual(common_flock_test._require_prepared_normal_startup(self.config,self.manifest,self.admission),'File1')
        kind = common_flock_test._CommonCoreFlockTest
        token = object.__new__(kind)
        token._owner = (os.getpid(),threading.get_ident())
        token._finished = token._selected = token._taken = False
        token._launch,token._prepared_candidate = launch,self.candidate
        token._deadline = time.monotonic()+10
        # This component exercises actual token selection and launch identity.
        # The controller socket, lock and terminal telemetry belong to their own tests.
        with patch.object(kind,'finish',autospec=True) as finish:
            with common_flock_test._common_flock_qualification_scope(token):
                yield token
            finish.assert_called_once_with(token)

    @contextmanager
    def product_boundary(self):
        native = object.__new__(installation._NativeFileCreateInstallation)
        with (patch.object(entrypoint,'_linux_stdio_identity',return_value='component-pipes'),
              patch.object(entrypoint,'_deliver_linux_frame') as deliver,
              patch.object(installation,'_native_registry_for_launch',return_value=self.registry),
              patch.object(installation,'_native_installation_for_manifest',return_value=(self.registry,native)) as admit,
              patch.object(PhaseCore,'run',autospec=True,side_effect=PhaseError('component.core_boundary')) as core,
              patch.object(evidence.EvidenceStore,'__init__',side_effect=AssertionError('unexpected evidence'))):
            yield native,admit,core,deliver

    def test_prepared_selected_bytes_reach_the_actual_phase_request(self):
        launch = self.prepared_launch()
        with self.selected(launch), self.product_boundary() as (native,admit,core,deliver):
            self.assertEqual(entrypoint.run_native_core(launch),10)
        admit.assert_called_once()
        self.assertIs(admit.call_args.kwargs['_experimental_admission_context'],self.admission)
        core.assert_called_once()
        engine,request = core.call_args.args
        self.assertIs(engine.installation,native)
        self.assertEqual(core.call_args.kwargs,{'execute':True})
        self.assertIs(request._expected_candidate_bytes,self.candidate)
        self.assertEqual(request.maximum_candidate_bytes,len(self.candidate))
        self.assertEqual(request.expected_inputs,{'source':self.expected})
        self.assertEqual(request.candidate_path,Path('/qualification/preparation/candidate.json'))
        self.assertEqual(deliver.call_args.args[0]['result']['error'],'component.core_boundary')

    def test_ordinary_prepared_keeps_path_only_and_foreign_selection_refuses(self):
        launch = self.prepared_launch()
        actual_run = PhaseApplication.run
        with (self.product_boundary() as (_,_,core,_),
              patch.object(PhaseApplication,'run',autospec=True,side_effect=actual_run) as app):
            self.assertEqual(entrypoint.run_native_core(launch),10)
        self.assertNotIn('_expected_candidate_bytes',app.call_args.kwargs)
        self.assertIsNone(core.call_args.args[1]._expected_candidate_bytes)
        with self.selected(self.prepared_launch()), self.product_boundary() as (_,_,core,deliver):
            with self.assertRaisesRegex(PhaseError,'ntfs.c01_prepared_candidate'):
                entrypoint.run_native_core(launch)
            core.assert_not_called()
            deliver.assert_not_called()

    def test_staged_branch_uses_its_own_prepared_bytes(self):
        from phase_tool.mutation.ntfs import preparation

        header = 'sha256:'+'f'*64
        request = {'operation':'execute','native_staged_publication_request_version':'1.0','input_scope':'component-scope',
            'stage_header_digest':header,'source_locator':'phase-native-input-'+header[7:39]+'/payload/payload',
            'source_digest':self.expected[0],'source_length':self.expected[1],'request_id':'staged.model',
            'target_locator':'staged.bin','members':None,'expected_current_digest':None,'content_utf8':None}
        launch = self.launch(request)
        _,staged_bytes = input_stage._publication_candidate('File1','staged.model','staged.bin',None,None,None)
        path = Path('/qualification/preparation/staged.json')
        with (self.selected(self.prepared_launch()), self.product_boundary() as (_,_,core,_),
              patch.object(input_stage,'_scope_for_launch',return_value=({},'File1',header)),
              patch.object(preparation,'_prepare_staged_publication',return_value=(path,{},None,staged_bytes)) as prepare):
            self.assertEqual(entrypoint.run_native_core(launch),10)
        prepare.assert_called_once()
        self.assertIs(prepare.call_args.args[1],launch)
        self.assertEqual(prepare.call_args.args[2],request)
        core.assert_called_once()
        self.assertIs(core.call_args.args[1]._expected_candidate_bytes,staged_bytes)
