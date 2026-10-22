"""Unexecuted pure witness controls: synthetic process owners and Win32 API.

No child, real HANDLE, installed parent, Core admission or exit proof is run.
"""
import ctypes
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import process_witness as witness


class SyntheticHandle(int):
    closed = False


class SyntheticPopen:
    def __init__(self):
        self.pid = 731
        self._child_created = True
        self._handle = SyntheticHandle(41)


class SyntheticSpawn:
    pid = 731
    sentinel = 41


class Call:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


class SyntheticKernel:
    def __init__(self, *, wait=0, code=0):
        self.calls = []
        self.pid, self.birth, self.wait, self.code = 731, 123456, wait, code
        self.exit_ok = 1
        for name in ('GetProcessId', 'GetProcessTimes', 'WaitForSingleObject', 'GetExitCodeProcess'):
            setattr(self, name, Call(lambda *args, name=name: self.call(name, args)))

    def call(self, name, args):
        self.calls.append((name, args[0]))
        if name == 'GetProcessId':
            return self.pid
        if name == 'GetProcessTimes':
            args[1]._obj.low = self.birth & 0xffffffff
            args[1]._obj.high = self.birth >> 32
            return 1
        if name == 'WaitForSingleObject':
            return self.wait
        if name == 'GetExitCodeProcess':
            args[1]._obj.value = self.code
            return self.exit_ok
        raise AssertionError(name)


@contextmanager
def boundary(kernel=None):
    kernel = SyntheticKernel() if kernel is None else kernel
    with ExitStack() as stack:
        stack.enter_context(patch.object(witness, 'os', SimpleNamespace(name='nt', getpid=lambda: 901)))
        stack.enter_context(patch.object(witness, 'sys', SimpleNamespace(platform='win32',
            implementation=SimpleNamespace(name='cpython'), version_info=(3, 12, 10))))
        stack.enter_context(patch.object(witness, 'subprocess', SimpleNamespace(Popen=SyntheticPopen, Handle=SyntheticHandle)))
        stack.enter_context(patch.object(witness, 'SpawnProcess', SyntheticSpawn))
        stack.enter_context(patch.object(witness.C, 'WinDLL', return_value=kernel, create=True))
        stack.enter_context(patch.object(witness.C, 'set_last_error', return_value=None, create=True))
        stack.enter_context(patch.object(witness.C, 'get_last_error', return_value=5, create=True))
        yield kernel


class NativePopenWitnessTests(unittest.TestCase):
    def test_exact_popen_positive_wait_zero_and_259(self):
        for code in (0, 259):
            with self.subTest(code=code), boundary(SyntheticKernel(code=code)) as kernel:
                owner = SyntheticPopen()
                item = witness.WindowsProcessWitness(owner)
                seen = item.wait_for_exit(50)
                self.assertIs(item.process, owner)
                self.assertIs(item._handle_object, owner._handle)
                self.assertIs(seen['worker_exit_established'], True)
                self.assertEqual(seen['wait_result'], 0)
                self.assertEqual(seen['exit_code'], code)
                self.assertEqual(seen['creation_filetime'], 123456)
                self.assertEqual([name for name, _ in kernel.calls].count('GetExitCodeProcess'), 1)
                self.assertTrue(all(handle == 41 for _, handle in kernel.calls))
                self.assertIs(owner._handle.closed, False)

    def test_spawn_path_keeps_sentinel_and_no_popen_handle(self):
        with boundary():
            owner = SyntheticSpawn()
            item = witness.WindowsProcessWitness(owner)
            self.assertIs(item.process, owner)
            self.assertIsNone(item._handle_object)
            self.assertFalse(item._popen)
            self.assertTrue(item.wait_for_exit(0)['worker_exit_established'])

    def test_timeout_never_queries_exit_or_proves_quiescence(self):
        with boundary(SyntheticKernel(wait=0x102, code=259)) as kernel:
            item = witness.WindowsProcessWitness(SyntheticPopen())
            seen = item.wait_for_exit(25)
            self.assertIs(seen['worker_exit_established'], False)
            self.assertIsNone(seen['exit_code'])
            self.assertNotIn('GetExitCodeProcess', [name for name, _ in kernel.calls])

    def test_same_number_replacement_handle_rejected_before_api(self):
        with boundary() as kernel:
            owner = SyntheticPopen()
            item = witness.WindowsProcessWitness(owner)
            owner._handle = SyntheticHandle(41)
            count = len(kernel.calls)
            with self.assertRaises(PhaseError) as caught:
                item.wait_for_exit(0)
            self.assertEqual(caught.exception.code, 'ntfs.worker_creation_handle_changed')
            self.assertEqual(len(kernel.calls), count)

    def test_closed_child_or_pid_changes_rejected_before_api(self):
        for field in ('closed', 'child', 'pid'):
            with self.subTest(field=field), boundary() as kernel:
                owner = SyntheticPopen()
                item = witness.WindowsProcessWitness(owner)
                if field == 'closed': owner._handle.closed = True
                elif field == 'child': owner._child_created = False
                else: owner.pid = 732
                count = len(kernel.calls)
                with self.assertRaises(PhaseError): item.wait_for_exit(0)
                self.assertEqual(len(kernel.calls), count)

    def test_bad_creation_handle_or_child_rejected_before_api(self):
        for field in ('plain_int', 'closed', 'child', 'zero', 'negative_pid'):
            with self.subTest(field=field), boundary() as kernel:
                owner = SyntheticPopen()
                if field == 'plain_int': owner._handle = 41
                elif field == 'closed': owner._handle.closed = True
                elif field == 'child': owner._child_created = False
                elif field == 'zero': owner._handle = SyntheticHandle(0)
                else: owner.pid = -1
                with self.assertRaises(PhaseError): witness.WindowsProcessWitness(owner)
                self.assertEqual(kernel.calls, [])

    def test_subclasses_and_arbitrary_process_denied(self):
        class PopenSubclass(SyntheticPopen): pass
        class SpawnSubclass(SyntheticSpawn): pass
        for owner in (PopenSubclass(), SpawnSubclass(), SimpleNamespace(pid=731, sentinel=41)):
            with self.subTest(owner=type(owner).__name__), boundary() as kernel:
                with self.assertRaises(PhaseError): witness.WindowsProcessWitness(owner)
                self.assertEqual(kernel.calls, [])

    def test_unpinned_platform_version_implementation_denied(self):
        for field, value in (('platform', 'linux'), ('version_info', (3, 12, 11)),
                             ('implementation', SimpleNamespace(name='pypy'))):
            with self.subTest(field=field), boundary() as kernel:
                setattr(witness.sys, field, value)
                with self.assertRaises(PhaseError): witness.WindowsProcessWitness(SyntheticPopen())
                self.assertEqual(kernel.calls, [])

    def test_initialization_is_consumed(self):
        with boundary() as kernel:
            owner = SyntheticPopen()
            item = witness.WindowsProcessWitness(owner)
            count = len(kernel.calls)
            with self.assertRaises(PhaseError): item.__init__(owner)
            self.assertEqual(len(kernel.calls), count)

    def test_identity_pid_and_creation_time_mismatch(self):
        for field, value in (('pid', 732), ('birth', 123457)):
            with self.subTest(field=field), boundary() as kernel:
                item = witness.WindowsProcessWitness(SyntheticPopen())
                setattr(kernel, field, value)
                with self.assertRaises(PhaseError) as caught: item.wait_for_exit(0)
                self.assertEqual(caught.exception.code, 'ntfs.worker_process_identity_mismatch')
                self.assertEqual(kernel.calls[-1][0], 'GetProcessId' if field == 'pid' else 'GetProcessTimes')
                self.assertNotIn('WaitForSingleObject', [name for name, _ in kernel.calls])

    def test_wait_and_exit_code_api_failures_never_prove_exit(self):
        for field, value in (('wait', 0xffffffff), ('exit_ok', 0)):
            with self.subTest(field=field), boundary() as kernel:
                item = witness.WindowsProcessWitness(SyntheticPopen())
                setattr(kernel, field, value)
                with self.assertRaises(PhaseError) as caught: item.wait_for_exit(0)
                expected = ('ntfs.worker_process_wait_unknown', 'WaitForSingleObject') if field == 'wait' else ('ntfs.worker_exit_code_unavailable', 'GetExitCodeProcess')
                self.assertEqual(caught.exception.code, expected[0])
                self.assertEqual(kernel.calls[-1][0], expected[1])
                self.assertFalse(item._entered)
                self.assertIs(item._handle_object.closed, False)

    def test_wait_bounds_owner_and_reentrancy(self):
        for variant in ('bool', 'negative', 'too_large', 'owner', 'reentrant'):
            with self.subTest(variant=variant), boundary() as kernel:
                item = witness.WindowsProcessWitness(SyntheticPopen())
                arg = {'bool': True, 'negative': -1, 'too_large': 60001}.get(variant, 0)
                if variant == 'owner': item._owner = (-1, -1)
                if variant == 'reentrant': item._entered = True
                count = len(kernel.calls)
                with self.assertRaises(PhaseError): item.wait_for_exit(arg)
                self.assertEqual(len(kernel.calls), count)


if __name__ == '__main__':
    unittest.main()
