"""Pure gate/fault simulation. No Windows API or filesystem effect executes."""
import dis
import os
import sys
import threading
import unittest
from unittest.mock import patch

from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import mutating as mutation
from phase_tool.mutation.ntfs.native import NativeHandle, NativeIO, NativeIdentity


class Session(mutation.NativeMutationIO):
    def __init__(self):
        # Real production gate initialization; omit all native initialization.
        self._init_mutation_session()
        self._writable, self._created = {object()}, {object()}
        self.events, self._handles = [], {}

    @mutation._mutation_call
    def step(self, callback=None, result=None):
        self.events.append({'simulated_body_entered': True})
        if callback is not None:
            callback()
        return result


class SealTests(unittest.TestCase):
    def assert_sealed(self, io):
        self.assertEqual(io.mutation_state, 'sealed')
        self.assertFalse(io._mutation_active)
        self.assertFalse(io._writable or io._created)
        with self.assertRaisesRegex(PhaseError, 'ntfs.mutation_session_sealed'):
            io.step()

    def test_owned_failure_preserves_exact_primary_and_raw_event(self):
        for primary in (PhaseError('synthetic.post_commit_error'), OSError('synthetic I/O'), KeyboardInterrupt()):
            with self.subTest(type=type(primary).__name__):
                io = Session()
                event = {'synthetic_native_outcome': 'committed_but_unverified'}
                def fault():
                    io.events.append(event)
                    raise primary
                with self.assertRaises(BaseException) as raised:
                    io.step(fault)
                self.assertIs(raised.exception, primary)
                self.assertIs(io.events[-1], event)
                self.assertEqual(io.mutation_seal_reason, 'error:step')
                io.seal_mutations()
                self.assertEqual(io.mutation_seal_reason, 'error:step')
                self.assert_sealed(io)

    def test_active_seal_preserves_accepted_result_and_does_not_close(self):
        io = Session()
        # Synthetic handle number, never sent to an OS API.
        result = NativeHandle(io, 17, directory=False)
        io._handles[17] = result
        observed = []
        def signal_seal():
            observed.append(io.seal_mutations())
            # A future entry is rejected even while the accepted call is active.
            with self.assertRaisesRegex(PhaseError, 'ntfs.mutation_session_sealed'):
                io.flush_namespace(None, None)
        self.assertIs(io.step(signal_seal, result), result)
        self.assertEqual(observed, ['sealed_active'])
        self.assertEqual(result.finalization_state, 'open')
        self.assertIs(io._handles[17], result)
        self.assert_sealed(io)

    def test_reentrant_mutation_revokes_outer_session(self):
        io = Session()
        with self.assertRaisesRegex(PhaseError, 'ntfs.reentrant_mutation_forbidden'):
            io.step(io.step)
        self.assertEqual(len(io.events), 1)
        self.assertEqual(io.mutation_seal_reason, 'reentrant:step')
        self.assert_sealed(io)

    def test_session_cannot_be_reinitialized_to_reopen_a_seal(self):
        io = Session()
        owner = io._mutation_owner
        io.events.append({'preserved': True})
        io.seal_mutations()
        for _ in range(2):
            with self.assertRaisesRegex(PhaseError, 'ntfs.mutation_session_already_initialized'):
                io._init_mutation_session()
        self.assertEqual(io._mutation_owner, owner)
        self.assertEqual(io.events, [{'preserved': True}])
        self.assertEqual(io.mutation_seal_reason, 'owner_finalization')
        self.assert_sealed(io)

    def test_all_mutation_ingress_stops_before_native_access(self):
        io = Session()
        self.assertEqual(io.seal_mutations(), 'sealed')
        calls = [
            lambda: io.create_exclusive(None, 'new', directory=False, expected_parent=None),
            lambda: io.open_writable(None, 'old', expected_parent=None, expected=None),
            lambda: io.write_chunk(None, b'x', offset=0, expected=None),
            lambda: io.truncate(None, length=0, expected=None),
            lambda: io.flush_file(None, None),
            lambda: io.flush_namespace(None, None),
            lambda: io.rename(None, None, 'new', expected_source=None, expected_parent=None),
            lambda: io.rename_noreplace(None, None, 'new', expected_source=None, expected_parent=None),
            lambda: io.hardlink_noreplace(None, None, 'new', expected_source=None, expected_parent=None),
            lambda: io.delete_created_link_and_close(None, None),
            lambda: io._open('old', parent=None, directory=False, rename_source=True),
            lambda: io._open('parent', parent=None, directory=True, namespace_flush=True),
        ]
        for ordinal, call in enumerate(calls):
            with self.subTest(ordinal=ordinal), self.assertRaisesRegex(PhaseError, 'ntfs.mutation_session_sealed'):
                call()
        self.assertEqual(io.events, [])

    def test_private_effect_helpers_require_owned_active_gate(self):
        io = Session()
        with self.assertRaisesRegex(PhaseError, 'ntfs.mutation_gate_required'):
            io._open_disposition(None, 'new', directory=False, expected_parent=None, exclusive=True)
        with self.assertRaisesRegex(PhaseError, 'ntfs.mutation_gate_required'):
            io._name_effect(None, None, 'new', expected_source=None, expected_parent=None,
                            hardlink=False, replace=False)
        self.assertEqual(io.events, [])

    def test_namespace_flush_failure_seals_before_later_flush(self):
        io = Session()
        expected = NativeIdentity(42, 'ab'*16)
        event = {'accepted': False, 'return_status': 'synthetic_failure'}
        with patch.object(NativeIO, 'flush_namespace', return_value=event) as simulated:
            with self.assertRaisesRegex(PhaseError, 'ntfs.namespace_flush_failed'):
                io.flush_namespace(None, expected)
            self.assertIs(io.events[-1], event)
            with self.assertRaisesRegex(PhaseError, 'ntfs.mutation_session_sealed'):
                io.flush_namespace(None, expected)
            self.assertEqual(simulated.call_count, 1)
        self.assert_sealed(io)

    def test_mutable_open_failure_also_seals(self):
        io = Session()
        primary = PhaseError('synthetic.open_postcheck_failure')
        with patch.object(NativeIO, '_open', side_effect=primary) as simulated:
            with self.assertRaises(PhaseError) as raised:
                io._open('old', parent=None, directory=False, rename_source=True)
            self.assertIs(raised.exception, primary)
            self.assertEqual(simulated.call_count, 1)
        self.assert_sealed(io)

    def test_read_only_open_and_one_close_remain_after_seal(self):
        io = Session()
        io.seal_mutations()
        with patch.object(NativeIO, '_open', return_value='synthetic_read_handle') as simulated:
            self.assertEqual(io._open('old', parent=None, directory=False), 'synthetic_read_handle')
            self.assertEqual(simulated.call_count, 1)
        closed = []
        io.kernel = type('SimulatedKernel', (), {'CloseHandle': staticmethod(lambda value: closed.append(value) or 1)})()
        handle = NativeHandle(io, 19, directory=False)
        io._handles[19] = handle
        handle.close()
        self.assertEqual(closed, [19])
        with self.assertRaisesRegex(PhaseError, 'ntfs.invalid_or_closed_handle'):
            handle.close()
        self.assertEqual(closed, [19])
        self.assertEqual(io.events, [])

    def test_wrong_thread_and_process_cannot_mutate_or_seal(self):
        io, errors = Session(), []
        def foreign():
            for call in (io.step, io.seal_mutations):
                try:
                    call()
                except PhaseError as error:
                    errors.append(error.code)
        worker = threading.Thread(target=foreign)
        worker.start()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, ['ntfs.mutation_wrong_thread_or_process'] * 2)
        pid = os.getpid()
        with patch.object(mutation.os, 'getpid', return_value=pid + 1):
            with self.assertRaisesRegex(PhaseError, 'ntfs.mutation_wrong_thread_or_process'):
                io.step()
        self.assertEqual(io.mutation_state, 'open')
        self.assertEqual(io.events, [])

    def test_reentrant_seal_at_each_reached_wrapper_line_is_never_pending(self):
        # Deterministic Python signal-style boundaries, not real Windows races.
        # Discover reached lines without pinning line numbers, then inject seal
        # once at each. This includes activation and finally/return boundaries.
        code = Session.step.__code__
        possible = {line for _, line in dis.findlinestarts(code)}
        reached = set()
        def discover(frame, event, argument):
            if event == 'line' and frame.f_code is code:
                reached.add(frame.f_lineno)
            return discover
        old_trace = sys.gettrace()
        try:
            sys.settrace(discover)
            Session().step()
        finally:
            sys.settrace(old_trace)
        self.assertTrue(reached <= possible)
        self.assertGreaterEqual(len(reached), 10)
        for line in sorted(reached):
            with self.subTest(line=line):
                io, chronology, injected = Session(), [], []
                def trace(frame, event, argument):
                    if event == 'line' and frame.f_code is code and frame.f_lineno == line and not injected:
                        injected.append(True)
                        chronology.append(('seal', io.seal_mutations()))
                    return trace
                try:
                    sys.settrace(trace)
                    try:
                        io.step(lambda: chronology.append(('body', 'entered')))
                    except PhaseError as error:
                        self.assertEqual(error.code, 'ntfs.mutation_session_sealed')
                finally:
                    sys.settrace(old_trace)
                self.assertEqual(injected, [True])
                self.assert_sealed(io)
                seal_index = next(i for i,item in enumerate(chronology) if item[0]=='seal')
                for index,item in enumerate(chronology):
                    if item[0]=='body' and index > seal_index:
                        self.assertEqual(chronology[seal_index][1], 'sealed_active')


if __name__ == '__main__':
    unittest.main()
