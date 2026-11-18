"""Composed transport-owner regressions, not Windows or NTFS qualification.

Only existing Python orchestration/seal/comparison code is real here. Accepted
runtime, spawn, framed I/O, process-exit witness and HANDLE acquisition are
explicit synthetic shells. No admission/profile/registry guard is patched, no
native call occurs, and a delivered token is never a successful Phase receipt.
"""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import io
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from ._native_startup_shell import startup_shell, legacy_config_bytes
from unittest.mock import Mock, call, patch

from phase_tool.application import PhaseApplication
from phase_tool.canonical import canonical_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bootstrap, entrypoint, input_stage, parent, parent_result, process_witness
from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch
from phase_tool.mutation.ntfs.windows_pipe import WindowsPipeFrames


class NativeComposedDeliveryTests(unittest.TestCase):
    def test_bundle_capture_seals_and_validates_exact_inspection_with_candidate_assertion(self):
        run_id='bundle-capture-missing'
        request={'operation':'inspect','native_bundle_publication_inspection_request_version':'1.0',
            'request_id':'request-a','target_locator':'bundle','members':['member.bin'],
            'expected_receipt_digest':'sha256:'+'1'*64}
        capture=parent_result._native_bundle_inspection_expectations(request)
        app=PhaseApplication()
        context=dict(request=request,channel_id='a'*32,read_binding=None,
            expected_manifest_digest='sha256:'+'2'*64,registry=app.registry)
        authority=Mock()
        # Real application method and actual frame validator. A modeled absent
        # Original stops before a reference can acquire independent proof.
        with patch('phase_tool.application.inspect_run',
                   side_effect=PhaseError('inspection.run_unavailable')) as inspect:
            result,reference,projection=entrypoint._inspect_with_channel_seal(
                app,authority,evidence_root=Path('unused-bundle-capture'),run_id=run_id,
                root_bindings={},_bundle_result_context=context,**capture)
        self.assertEqual((result.exit_code,result.payload['error']),(10,'inspection.run_unavailable'))
        self.assertIsNone(reference)
        self.assertIsNone(projection)
        self.assertEqual(inspect.call_args.kwargs['_expected_candidate_digest'],capture['_expected_candidate_digest'])
        authority.seal.assert_called_once_with(intent_digest=None)

        authority.reset_mock()
        with self.assertRaisesRegex(PhaseError,'ntfs.fixed_inspection_role_required'):
            entrypoint._inspect_with_channel_seal(app,authority,evidence_root=Path('unused-bundle-capture'),
                run_id=run_id,root_bindings={},_bundle_result_context=context,
                _expected_frozen_input=('payload','sha256:'+'3'*64),**capture)
        authority.seal.assert_called_once_with(intent_digest=None)

    @contextmanager
    def delivery(self, *, inspection=False, receive_error=None, seal_failure=False, closed_reader=False):
        """Real orchestration and strict seal, synthetic OS/process boundary."""
        launch=object.__new__(_NativeAcceptedLaunch)
        launch._config_bytes=(canonical_bytes({'native_launch_version':'4.0'}) if closed_reader else legacy_config_bytes())
        launch._inspection_only=inspection
        launch._manifest_bytes,launch._manifest_digest=startup_shell()
        launch._finalization_attempted=set()
        launch._invocation_bytes=canonical_bytes({'run_id':'synthetic-delivery',
            'channel_id':'a'*32,'operation_nonce':'b'*32,'request':{'operation':'inspect'} if closed_reader else {}})
        # Execute token tests ONLY delivery: deliberately no success/receipt
        # claim. Inspection uses an actual complete ordinary failure schema.
        result=(PhaseApplication()._failure('inspect',PhaseError('synthetic.refused')).payload
            if inspection else {'command':'execute','run_id':launch.run_id,'exit_code':0})
        frame={'protocol':'phase.native.command','version':'1.0','channel_id':launch.channel_id,
            'run_id':launch.run_id,'result':result,'exit_code':result['exit_code']}
        pipe=object.__new__(WindowsPipeFrames)
        pipe._owner=os.getpid(),threading.get_ident()
        pipe._gate=threading.Lock()
        pipe._failed=pipe._sealed=False
        pipe.send_frame=Mock()
        pipe.receive_frame=Mock(return_value=(canonical_bytes(frame),None),side_effect=receive_error)
        class HandleShell:
            def __init__(self):self.closed=False;self.close_count=0
            def Close(self):self.close_count+=1;self.closed=True
        handle=HandleShell()
        with tempfile.TemporaryDirectory() as root:
            streams=[io.FileIO(Path(root)/name,'w+b') for name in ('stdin','stdout','stderr')]
            process=SimpleNamespace(stdin=streams[0],stdout=streams[1],stderr=streams[2],
                _handle=handle,returncode=None,pid=705)
            fact={'worker_exit_established':True,'exit_code':frame['exit_code'],
                'pid':process.pid,'creation_filetime':1234,'wait_result':0}
            witness=SimpleNamespace(wait_for_exit=Mock(return_value=fact),process=process,
                _handle_object=handle,creation_filetime=fact['creation_filetime'])
            if seal_failure:pipe._gate.acquire()  # Synthetic first-seal failure.
            try:
                with ExitStack() as stack:
                    # Replace only the module's OS facade, not global os.name.
                    stack.enter_context(patch.object(parent,'os',SimpleNamespace(name='nt',getpid=os.getpid)))
                    stack.enter_context(patch.object(_NativeAcceptedLaunch,'check_runtime'))
                    core=stack.enter_context(patch.object(launch,'spawn_core',return_value=process))
                    reader=stack.enter_context(patch.object(launch,'spawn_inspection',return_value=process))
                    stack.enter_context(patch.object(launch,'_pipe',return_value=pipe))
                    witness_factory=stack.enter_context(patch.object(process_witness,'WindowsProcessWitness',return_value=witness))
                    stack.enter_context(patch.object(bootstrap.subprocess,'Handle',HandleShell,create=True))
                    seal=stack.enter_context(patch.object(pipe,'seal',wraps=pipe.seal))
                    yield SimpleNamespace(launch=launch,pipe=pipe,process=process,streams=streams,
                        handle=handle,witness=witness,witness_factory=witness_factory,seal=seal,
                        frame=frame,core=core,reader=reader)
            finally:
                if pipe._gate.locked():pipe._gate.release()
                for stream in streams:
                    if not stream.closed:stream.close()

    def assert_finalized_once(self,fixture):
        fixture.seal.assert_called_once_with()
        self.assertTrue(fixture.pipe._sealed)
        self.assertTrue(all(stream.closed for stream in fixture.streams))
        self.assertTrue(fixture.handle.closed)
        self.assertEqual(fixture.handle.close_count,1)
        self.assertEqual(fixture.witness.wait_for_exit.call_args_list,[call(60000),call(0)])
        self.assertEqual(fixture.witness_factory.call_args_list,
            [call(fixture.process),call(fixture.process)])

    def test_normal_execute_delivery_has_one_finalizer_seal(self):
        with self.delivery() as fixture:
            self.assertEqual(entrypoint.run_native_parent(fixture.launch),fixture.frame)
            fixture.core.assert_called_once_with();fixture.reader.assert_not_called()
            self.assert_finalized_once(fixture)
            self.assertNotIn('success',fixture.frame['result'])
            self.assertNotIn('receipt_digest',fixture.frame['result'])

    def test_negative_inspect_delivery_retains_no_go_schema_after_one_seal(self):
        with self.delivery(inspection=True) as fixture:
            result=entrypoint.run_native_parent(fixture.launch)
            self.assertEqual(result,fixture.frame)
            self.assertIs(result['result']['success'],False)
            self.assertIsNone(result['result']['receipt_digest'])
            fixture.reader.assert_called_once_with();fixture.core.assert_not_called()
            self.assert_finalized_once(fixture)

    def test_first_strict_seal_error_is_not_recast_as_delivery_success(self):
        with self.delivery(seal_failure=True) as fixture:
            with self.assertRaisesRegex(PhaseError,'ntfs.pipe_seal_unknown'):
                entrypoint.run_native_parent(fixture.launch)
            self.assert_finalized_once(fixture)

    def test_delivery_primary_survives_secondary_first_seal_error(self):
        primary=PhaseError('synthetic.delivery.primary')
        with self.delivery(receive_error=primary,seal_failure=True) as fixture:
            with self.assertRaises(PhaseError) as caught:entrypoint.run_native_parent(fixture.launch)
            self.assertIs(caught.exception,primary)
            self.assertIn('Native Core delivery finalization: PhaseError',primary.__notes__)
            self.assert_finalized_once(fixture)

    def test_staged_read_loss_requires_positive_same_process_finalization(self):
        for seal_failure in (False, True):
            primary = PhaseError('ntfs.pipe_frame_unknown', details={'direction':'receive'})
            primary.__cause__ = PhaseError('ntfs.pipe_eof')
            signal = PhaseError if seal_failure else entrypoint._ClosedStagedFileInspectionLoss
            with (
                self.subTest(seal_failure=seal_failure),
                self.delivery(inspection=True, receive_error=primary, seal_failure=seal_failure,
                              closed_reader=True) as fixture,
                patch.object(input_stage,'_active_input_deadline_ns',return_value=time.perf_counter_ns()+10_000_000_000),
                self.assertRaises(signal) as caught,
            ):
                entrypoint.run_native_parent(fixture.launch,_report_closed_staged_inspection_loss=True)
            if seal_failure:
                self.assertIs(caught.exception,primary)
            else:
                self.assertIs(caught.exception.__cause__,primary)
                self.assertIs(caught.exception.launch,fixture.launch)
            self.assertEqual(fixture.witness.wait_for_exit.call_count,2)
            self.assertEqual(fixture.witness.wait_for_exit.call_args.args,(0,))
            fixture.seal.assert_called_once_with()
            self.assertTrue(all(stream.closed for stream in fixture.streams))
            self.assertTrue(fixture.handle.closed)
            self.assertEqual(fixture.handle.close_count,1)

    def test_repeat_finalization_refuses_before_any_second_owner_action(self):
        with self.delivery() as fixture:
            entrypoint.run_native_parent(fixture.launch)
            with self.assertRaisesRegex(PhaseError,'ntfs.process_finalization_consumed'):
                fixture.launch._finalize_exited(fixture.process,fixture.pipe)
            self.assert_finalized_once(fixture)


class NativeLinuxContourComparisonTests(unittest.TestCase):
    def config(self):
        image='sha256:'+'e'*64
        def contour(identity,readonly):
            return {'id':identity,'image':image,'user':'10001:10001','readonly_rootfs':True,
                'cap_drop':['ALL'],'security_options':['no-new-privileges'],'network_mode':'none',
                'mounts':[{'Type':'volume','Name':'synthetic-one','Source':'/synthetic/one',
                    'Destination':'/qualification/one','Driver':'local','Mode':'ro' if readonly else 'rw',
                    'RW':not readonly,'Propagation':''},
                    {'Type':'bind','Source':'/synthetic/artifacts','Destination':'/artifacts',
                    'Mode':'ro','RW':False,'Propagation':'rprivate'}],
                'pids_limit':128,'memory':2*1024**3,'nano_cpus':2*10**9,'running':True}
        return {'core_container_id':'c'*64,'reader_container_id':'d'*64,'image_digest':image,
            'docker_executable':'synthetic-never-executed-docker',
            'expected_linux_contours':{'core':contour('c'*64,False),'original':contour('d'*64,True)}}

    @contextmanager
    def comparison(self, *, declared=None, actual=None):
        config=self.config() if declared is None else declared
        observations=deepcopy(config['expected_linux_contours']) if actual is None else actual
        launch=object.__new__(_NativeAcceptedLaunch)
        launch._config_bytes=canonical_bytes(config);launch._linux_contours_checked=False
        def inspect(args,**kwargs):
            role='core' if args[-1]==config['core_container_id'] else 'original'
            return SimpleNamespace(stdout=canonical_bytes(observations[role]))
        with (patch.object(bootstrap.subprocess,'CREATE_NO_WINDOW',0,create=True),
                patch.object(bootstrap.subprocess,'run',side_effect=inspect) as inspect_call):
            yield launch,inspect_call

    def test_active_input_checks_two_exact_contours_in_one_bounded_call(self):
        config = self.config()
        rows = tuple(config['expected_linux_contours'].values())
        arguments = [config['core_container_id'], config['reader_container_id']]
        deadline = 4_000_000_000

        def model(observations, *, expected_error=None, finish_late=False):
            launch = object.__new__(_NativeAcceptedLaunch)
            launch._config_bytes = canonical_bytes(config)
            launch._linux_contours_checked = False
            raw = b''.join(canonical_bytes(row) + b'\n' for row in observations)
            clock = Mock(return_value=1_000_000_000)

            def inspect(*args, **kwargs):
                if finish_late:
                    clock.return_value = deadline
                return SimpleNamespace(stdout=raw)

            with (patch.object(bootstrap, '_active_input_deadline_ns', return_value=deadline),
                  patch.object(bootstrap.time, 'perf_counter_ns', clock),
                  patch.object(bootstrap.time, 'monotonic_ns', clock),
                  patch.object(bootstrap.subprocess, 'CREATE_NO_WINDOW', 0, create=True),
                  patch.object(bootstrap.subprocess, 'run', side_effect=inspect) as inspect_call):
                if expected_error is None:
                    launch._check_linux_contours()
                    launch._check_linux_contours()
                else:
                    with self.assertRaisesRegex(PhaseError, expected_error):
                        launch._check_linux_contours()
            inspect_call.assert_called_once()
            self.assertEqual(inspect_call.call_args.args[0][4:], arguments)
            self.assertEqual(inspect_call.call_args.kwargs['timeout'], 3.0)
            return launch._linux_contours_checked

        self.assertTrue(model(tuple(reversed(rows))))
        self.assertFalse(model(rows[:1], expected_error='ntfs.accepted_linux_contour_required'))
        self.assertFalse(model((rows[0], rows[0]), expected_error='ntfs.accepted_linux_contour_mismatch'))
        self.assertFalse(model((rows[0], dict(rows[1], id='f'*64)), expected_error='ntfs.accepted_linux_contour_mismatch'))
        self.assertFalse(model(rows, expected_error='input_stage.deadline', finish_late=True))

    def test_reordered_full_mount_maps_match_and_completed_check_is_cached(self):
        config=self.config();actual=deepcopy(config['expected_linux_contours'])
        for row in actual.values():row['mounts'].reverse()
        with self.comparison(declared=config,actual=actual) as (launch,inspect_call):
            launch._check_linux_contours();launch._check_linux_contours()
            self.assertTrue(launch._linux_contours_checked);self.assertEqual(inspect_call.call_count,2)

    def test_every_mount_field_including_unknown_extension_remains_compared(self):
        config=self.config()
        for field,value in {'Type':'bind','Name':'different','Source':'/different','Destination':'/different',
                'Driver':'other','Mode':'ro','RW':False,'Propagation':'rshared','Extra':'must-not-be-dropped'}.items():
            with self.subTest(field=field):
                actual=deepcopy(config['expected_linux_contours']);actual['core']['mounts'][0][field]=value
                with self.comparison(declared=config,actual=actual) as (launch,inspect_call):
                    with self.assertRaisesRegex(PhaseError,'ntfs.accepted_linux_contour_mismatch'):
                        launch._check_linux_contours()
                    self.assertFalse(launch._linux_contours_checked);self.assertEqual(inspect_call.call_count,1)

    def test_nonmount_fields_still_require_exact_match(self):
        config=self.config()
        for field,value in {'id':'f'*64,'image':'sha256:'+'f'*64,'user':'0:0','readonly_rootfs':False,
                'cap_drop':[],'security_options':[],'network_mode':'host','pids_limit':129,
                'memory':1,'nano_cpus':1,'running':False}.items():
            with self.subTest(field=field):
                actual=deepcopy(config['expected_linux_contours']);actual['core'][field]=value
                with self.comparison(declared=config,actual=actual) as (launch,_):
                    with self.assertRaisesRegex(PhaseError,'ntfs.accepted_linux_contour_mismatch'):
                        launch._check_linux_contours()
                    self.assertFalse(launch._linux_contours_checked)

    def test_duplicate_or_malformed_actual_mounts_refuse_before_success(self):
        config=self.config();valid=config['expected_linux_contours']['core']['mounts'][0]
        for mounts in ([valid,deepcopy(valid)],{},[None],[{}],[dict(valid,Destination=1)],
                [dict(valid,Destination='relative')],[dict(valid,RW=1)]):
            with self.subTest(mounts=mounts):
                actual=deepcopy(config['expected_linux_contours']);actual['core']['mounts']=mounts
                with self.comparison(declared=config,actual=actual) as (launch,_):
                    with self.assertRaisesRegex(PhaseError,'ntfs.accepted_linux_contour_required'):
                        launch._check_linux_contours()
                    self.assertFalse(launch._linux_contours_checked)

    def test_ambiguous_declaration_and_writable_reader_are_rejected(self):
        for kind in ('duplicate','reader-rw'):
            with self.subTest(kind=kind):
                config=self.config()
                if kind=='duplicate':config['expected_linux_contours']['core']['mounts']*=2
                else:config['expected_linux_contours']['original']['mounts'][0]['RW']=True
                with self.comparison(declared=config) as (launch,inspect_call):
                    code=('ntfs.accepted_linux_contour_required' if kind=='duplicate'
                        else 'ntfs.original_readonly_contour_required')
                    with self.assertRaisesRegex(PhaseError,code):launch._check_linux_contours()
                    self.assertFalse(launch._linux_contours_checked)
                    self.assertEqual(inspect_call.call_count,0 if kind=='duplicate' else 1)
