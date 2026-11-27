"""Job API failure tests. Synthetic handles are never passed to Windows."""
from contextlib import contextmanager
import ctypes
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import worker_job as module


class Function:
    def __init__(self, call): self.call = call
    def __call__(self, *arguments): return self.call(*arguments)


class Kernel:
    def __init__(self, failure=None):
        self.failure, self.calls = failure, []
        self.flags, self.limit, self.inherit, self.member, self.pid = 0x2008, 1, 0, 1, 731
        for name in ('CreateJobObjectW', 'SetInformationJobObject', 'QueryInformationJobObject',
            'AssignProcessToJobObject', 'IsProcessInJob', 'GetHandleInformation', 'CloseHandle'):
            setattr(self, name, Function(lambda *args, name=name: self.invoke(name, args)))

    def invoke(self, name, arguments):
        self.calls.append(name)
        if name == self.failure: return 0
        if name == 'CreateJobObjectW':
            assert arguments == (None, None)  # Unnamed and non-inheritable.
            return 91
        if name == 'SetInformationJobObject':
            assert arguments[1] == 9
            data = arguments[2]._obj.BasicLimitInformation
            assert data.LimitFlags == 0x2008 and data.ActiveProcessLimit == 1
        if name == 'GetHandleInformation': arguments[1]._obj.value = self.inherit
        if name == 'IsProcessInJob': arguments[2]._obj.value = self.member
        if name == 'QueryInformationJobObject':
            if arguments[1] == 9:
                data = arguments[2]._obj.BasicLimitInformation
                data.LimitFlags, data.ActiveProcessLimit = self.flags, self.limit
            else:
                assert arguments[1] == 3
                data = arguments[2]._obj
                data.NumberOfAssignedProcesses = data.NumberOfProcessIdsInList = 1
                data.ProcessIdList[0] = self.pid
        return 1


class Witness:
    def __init__(self, process):
        self._popen, self.handle = True, 41
        self.process, self.exited, self.waits = process, True, []
    def _owned(self): pass
    def wait_for_exit(self, timeout):
        self.waits.append(timeout)
        return {'worker_exit_established': self.exited}


@contextmanager
def boundary(kernel=None):
    kernel = Kernel() if kernel is None else kernel
    with patch.object(module, 'WindowsProcessWitness', Witness), \
        patch.object(module.C, 'WinDLL', return_value=kernel, create=True), \
        patch.object(module.C, 'set_last_error', return_value=None, create=True), \
        patch.object(module.C, 'get_last_error', return_value=5, create=True):
        yield kernel


class WorkerJobTests(unittest.TestCase):
    def test_assigns_only_existing_process_then_checks_limits_and_membership(self):
        process = SimpleNamespace(pid=731)
        with boundary() as kernel:
            job = module.WindowsWorkerJob(process)
            self.assertEqual(job._state, 'bound')
            self.assertLess(kernel.calls.index('SetInformationJobObject'), kernel.calls.index('AssignProcessToJobObject'))
            self.assertLess(kernel.calls.index('AssignProcessToJobObject'), kernel.calls.index('IsProcessInJob'))
            self.assertNotIn('CloseHandle', kernel.calls)
            job.close_after_exit(process)
            self.assertEqual(job._witness.waits, [0])
            self.assertEqual(job._state, 'closed')
            self.assertEqual(kernel.calls.count('CloseHandle'), 1)
            with self.assertRaisesRegex(PhaseError, 'ntfs.worker_job_unavailable'):
                job.close_after_exit(process)
            self.assertEqual(kernel.calls.count('CloseHandle'), 1)

    def test_every_setup_api_failure_prohibits_binding_and_never_claims_exit(self):
        for failure in ('CreateJobObjectW', 'SetInformationJobObject', 'GetHandleInformation',
            'QueryInformationJobObject', 'AssignProcessToJobObject', 'IsProcessInJob'):
            with self.subTest(failure=failure), boundary(Kernel(failure)) as kernel:
                job = module.WindowsWorkerJob.__new__(module.WindowsWorkerJob)
                with self.assertRaisesRegex(PhaseError, 'ntfs.worker_job_api_failed'):
                    job.__init__(SimpleNamespace(pid=731))
                self.assertEqual(job._witness.waits, [])
                self.assertNotIn('CloseHandle', kernel.calls)
                with self.assertRaisesRegex(PhaseError, 'ntfs.worker_job_initialization_consumed'):
                    job.__init__(job._process)

    def test_unknown_worker_exit_retains_job_and_creation_handle(self):
        process = SimpleNamespace(pid=731)
        with boundary() as kernel:
            job = module.WindowsWorkerJob(process)
            job._witness.exited = False
            with self.assertRaisesRegex(PhaseError, 'ntfs.worker_exit_not_established'):
                job.close_after_exit(process)
            self.assertEqual(job._state, 'bound')
            self.assertNotIn('CloseHandle', kernel.calls)

    def test_close_failure_is_sticky_and_never_retried(self):
        process = SimpleNamespace(pid=731)
        with boundary(Kernel('CloseHandle')) as kernel:
            job = module.WindowsWorkerJob(process)
            with self.assertRaisesRegex(PhaseError, 'ntfs.worker_job_api_failed'):
                job.close_after_exit(process)
            self.assertEqual(job._state, 'unknown')
            with self.assertRaisesRegex(PhaseError, 'ntfs.worker_job_unavailable'):
                job.close_after_exit(process)
            self.assertEqual(kernel.calls.count('CloseHandle'), 1)

    def test_inheritance_breakaway_limit_or_membership_drift_refuses(self):
        process = SimpleNamespace(pid=731)
        for field, value in (('inherit', 1), ('flags', 0x2808), ('limit', 2), ('member', 0), ('pid', 732)):
            with self.subTest(field=field), boundary() as kernel:
                setattr(kernel, field, value)
                with self.assertRaises(PhaseError): module.WindowsWorkerJob(process)
                self.assertNotIn('CloseHandle', kernel.calls)

    def test_wrong_owner_and_non_popen_refuse_before_job_native_access(self):
        process = SimpleNamespace(pid=731)
        with boundary() as kernel:
            job = module.WindowsWorkerJob(process)
            calls = list(kernel.calls)
            with self.assertRaisesRegex(PhaseError, 'ntfs.worker_job_owner_changed'):
                job.check_bound(SimpleNamespace(pid=731))
            job._owner = (-1, -1)
            with self.assertRaisesRegex(PhaseError, 'ntfs.worker_job_owner_changed'):
                job.close_after_exit(process)
            self.assertEqual(kernel.calls, calls)
        with boundary() as kernel, patch.object(module, 'WindowsProcessWitness', return_value=SimpleNamespace(_popen=False)):
            with self.assertRaisesRegex(PhaseError, 'ntfs.owned_popen_handle_required'):
                module.WindowsWorkerJob(process)
            self.assertEqual(kernel.calls, [])


    def test_bootstrap_setup_fails_inside_parent_owned_worker_finalization(self):
        from pathlib import Path
        from phase_tool.canonical import canonical_bytes, parse_json_bytes
        from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch
        from phase_tool.mutation.ntfs import parent
        from tests.test_native_version1_transfer import original, grant
        from unittest.mock import Mock
        for fail in (False, True):
            with self.subTest(fail=fail):
                parsed = original()
                ctx = parse_json_bytes(parsed.context_bytes)
                launch = object.__new__(_NativeAcceptedLaunch)
                launch._inspection_only = False
                launch._spawn_attempted = False
                launch._worker_job = None
                launch._config_bytes = canonical_bytes({'windows_launcher': str(Path(__file__).absolute())})
                process, events = SimpleNamespace(pid=731), []
                class Job:
                    def __init__(self, actual):
                        self_test.assertIs(launch._worker, process)
                        self_test.assertIs(launch._worker_job, self)
                        self_test.assertIs(actual, process)
                        events.append('job_setup')
                        if fail: raise PhaseError('synthetic.assignment_failed')
                self_test = self
                with patch.object(launch, '_spawn', return_value=process) as spawn, \
                    patch.object(launch, '_pipe', side_effect=PhaseError('synthetic.stop_before_original')) as pipe, \
                    patch.object(module, 'WindowsWorkerJob', Job):
                    # Actual Popen owner returns before setup; parent can retain
                    # its witness before worker_pipe attempts any assignment.
                    self.assertIs(launch.spawn_worker(), process)
                    self.assertEqual(events, [])
                    owner = object.__new__(parent._NativeWindowsParent)
                    owner._launch = SimpleNamespace(read_original=Mock(return_value=parsed),
                        run_id=ctx['run_id'], operation_nonce=ctx['operation_nonce'],
                        installation_digest=ctx['installation_digest'], root_grant=grant(),
                        spawn_worker=Mock(return_value=process), worker_pipe=launch.worker_pipe,
                        send_worker_original=Mock(), finalize_worker=Mock(), check_runtime=Mock())
                    owner._version1=True;owner._version2=False;owner._file2=False;owner._bundle=False
                    owner._inspection_only=False;owner._consumed=True;owner._spawn_attempted=False
                    owner._go_attempted=False;owner._worker=None;owner._worker_count=0
                    owner._worker_finalized=False;owner._partial_bytes=None
                    owner._ready_wire=owner._completion_wire=None
                    fact={'worker_exit_established':True,'wait_result':0,'exit_code':50}
                    witness=SimpleNamespace(wait_for_exit=Mock(return_value=fact))
                    with patch.object(parent,'WindowsProcessWitness',return_value=witness):
                        with self.assertRaisesRegex(PhaseError,'ntfs.parent_execution_unresolved') as caught:
                            owner._execute(ctx['intent_digest'])
                    witness.wait_for_exit.assert_called_once_with(60000)
                    owner._launch.finalize_worker.assert_called_once_with(process,None)
                    owner._launch.send_worker_original.assert_not_called()
                    self.assertFalse(owner._go_attempted)
                    self.assertIs(caught.exception.details['possible_dispatch'],False)
                    self.assertEqual(events,['job_setup'])
                    self.assertEqual(pipe.call_count,0 if fail else 1)
                    with self.assertRaisesRegex(PhaseError,'ntfs.parent_execution_consumed'):
                        launch.spawn_worker()
                    spawn.assert_called_once()

    def test_failed_assignment_job_closes_only_after_actual_worker_exit(self):
        process=SimpleNamespace(pid=731)
        with boundary(Kernel('AssignProcessToJobObject')) as kernel:
            job=module.WindowsWorkerJob.__new__(module.WindowsWorkerJob)
            with self.assertRaises(PhaseError):job.__init__(process)
            self.assertEqual(job._state,'open')
            self.assertNotIn('CloseHandle',kernel.calls)
            job.close_after_exit(process)
            self.assertEqual(job._state,'closed')
            self.assertEqual(job._witness.waits,[0])
            self.assertEqual(kernel.calls.count('CloseHandle'),1)



if __name__ == '__main__': unittest.main()
