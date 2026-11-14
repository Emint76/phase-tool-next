"""Models for bounded native-input diagnostics. They dispatch no native operation."""

from contextlib import nullcontext
from copy import deepcopy
import os
from pathlib import Path
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bootstrap, parent, windows_pipe
from phase_tool.mutation.ntfs.input_stage import _InputOperationDeadline, _input_operation_scope


RESOURCES = Path(__file__).absolute().parents[1] / 'src/phase_tool/data/native'
BOUNDARY = windows_pipe._InputExecutePipeBoundary


def template(name):
    path = RESOURCES / name
    scope = {'__name__': '_phase_template_diagnostic_model', '__file__': str(path)}
    exec(compile(path.read_bytes(), str(path), 'exec'), scope)
    return scope


def diagnostic(reason=None, error_class='timeout', phase='execute'):
    result = {'error_class': error_class, 'phase': phase}
    if reason is not None:
        result['reason'] = reason
    return canonical_bytes(result) + b'\n'


def frame_error(direction, wire_bytes, code='ntfs.pipe_deadline_expired'):
    pipe = object.__new__(windows_pipe.WindowsPipeFrames)
    pipe._gate = threading.Lock()
    pipe._identity = lambda _: 1
    pipe._time = lambda _: 1
    pipe._usable = lambda: None

    def fail(_, deadline, progress):
        progress['wire_bytes'] = wire_bytes
        progress['prefix_hex'] = '70726976617465'
        raise PhaseError(code, 'private frame error')

    pipe._read = fail
    pipe._write = fail
    try:
        if direction == 'receive':
            pipe.receive_frame(100)
        else:
            pipe.send_frame(b'private outbound frame', 100)
    except PhaseError as error:
        assert pipe._failed is True
        assert error.code == 'ntfs.pipe_frame_unknown'
        assert error.__cause__.code == code
        return error
    raise AssertionError('frame unexpectedly succeeded')


class NativeInputPipeAttributionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.launcher = template('native_phase_candidate_launcher_v1.py.in')
        cls.cli = template('native_phase_cli_v1.py.in')

    def render(self, error, phase='execute'):
        calls = []
        with patch.dict(self.launcher, os=SimpleNamespace(write=lambda fd, raw: calls.append((fd, raw)))):
            self.launcher['_input_failure_diagnostic'](phase, error)
        self.assertEqual(len(calls), 1)
        fd, raw = calls[0]
        self.assertEqual(fd, 2)
        self.assertLessEqual(len(raw), 64)
        self.assertNotIn(b'private', raw)
        return raw

    def run_parent(self, failure, *, fail_at, active=True, inspection=False, reject_observation=False):
        events = []
        value = dict.fromkeys(parent._COMMON, 'unused')
        value['kind'] = 'observe_file'

        def receive(deadline):
            ordinal = events.count('receive')
            events.append('receive')
            if fail_at == ('first' if ordinal == 0 else 'later'):
                raise failure
            return canonical_bytes(value), {}

        def send(raw, deadline):
            events.append('send')
            if fail_at == 'observation':
                raise failure

        def observe(raw):
            events.append('observe')
            if reject_observation:
                raise PhaseError('modeled.observation_refused')
            return {}, {}

        owner = object.__new__(parent._NativeWindowsParent)
        owner._owner = (os.getpid(), threading.get_ident())
        owner._launch = SimpleNamespace(check_runtime=lambda: None)
        owner._pipe = SimpleNamespace(receive_frame=receive, send_frame=send)
        owner._request = observe
        owner._inspection_only = inspection
        owner._file2 = owner._bundle = owner._failed = owner._finished = False
        token = object.__new__(_InputOperationDeadline)
        token.owner = owner._owner
        token.deadline_ns = time.perf_counter_ns() + 10_000_000_000
        token.entered = token.finished = False
        with patch.object(bootstrap, '_is_bundle_recovery_launch', return_value=False):
            with _input_operation_scope(token) if active else nullcontext():
                with self.assertRaises(PhaseError) as caught:
                    owner.serve()
        self.assertIs(caught.exception, failure)
        self.assertTrue(owner._failed)
        self.assertFalse(owner._finished)
        if active:
            self.assertTrue(token.finished)
        expected = {'first': ['receive'], 'later': ['receive', 'observe', 'send', 'receive'],
            'observation': ['receive', 'observe', 'send']}
        self.assertEqual(events, expected[fail_at])

    def test_exact_owned_parent_boundaries_and_terminal_frame(self):
        vectors = (('first', 'receive', 0, 'rx_first'), ('first', 'receive', 7, 'rx_fdata'),
            ('later', 'receive', 0, 'rx_next'), ('later', 'receive', 7, 'rx_ndata'),
            ('observation', 'send', 0, 'tx_obs'), ('observation', 'send', 7, 'tx_obs'))
        for boundary, direction, count, reason in vectors:
            with self.subTest(boundary=boundary, count=count):
                error = frame_error(direction, count)
                original_details = deepcopy(error.details)
                self.run_parent(error, fail_at=boundary)
                self.assertEqual(error.details, original_details)
                self.assertEqual(self.render(error), diagnostic(reason))
                self.assertEqual(self.cli['input_failure_line'](diagnostic(reason)), diagnostic(reason))

    def test_attribution_requires_active_execute_and_validated_observation(self):
        for active, inspection in ((False, False), (True, True)):
            with self.subTest(active=active, inspection=inspection):
                error = frame_error('receive', 0)
                self.run_parent(error, fail_at='first', active=active, inspection=inspection)
                self.assertFalse(hasattr(error, '_input_execute_pipe_boundary'))
                self.assertEqual(self.render(error), diagnostic('rx_empty'))
        error = frame_error('send', 7)
        self.run_parent(error, fail_at='observation', reject_observation=True)
        self.assertFalse(hasattr(error, '_input_execute_pipe_boundary'))
        self.assertEqual(self.render(error), diagnostic('tx'))

    def test_malformed_wrapper_details_never_add_attribution(self):
        vectors = ({'direction': 'private wrong direction'}, {'direction': ['receive']},
            {'effect_success_established': True}, {'peer_exit_established': 0},
            {'primary': {'type': 'PhaseError', 'code': 'private wrong primary'}},
            {'progress': None}, {'progress': {'wire_bytes': True}},
            {'progress': {'wire_bytes': -1}}, {'progress': {'wire_bytes': windows_pipe.MAX_FRAME + 11}},
            {'direction': 'send', 'progress': {'wire_bytes': 12, 'expected_wire_bytes': 11}},
            {'direction': 'send', 'progress': {'wire_bytes': 1}}, {'extra': 'private extra'})
        for change in vectors:
            with self.subTest(change=change):
                error = frame_error('receive', 0)
                error.details.update(change)
                self.assertEqual(self.render(error), diagnostic('deadline'))
        for marker in ('rx_first', BOUNDARY.OBSERVATION_REPLY):
            error = frame_error('receive', 1)
            error._input_execute_pipe_boundary = marker
            self.assertEqual(self.render(error), diagnostic('rx_bytes'))
        error = frame_error('receive', windows_pipe.MAX_FRAME + 10)
        self.assertEqual(self.render(error), diagnostic('rx_bytes'))
        self.assertEqual(self.render(error, phase='inspect'), diagnostic(None, 'error', 'inspect'))

    def test_old_packet_and_non_deadline_meanings(self):
        old = PhaseError('ntfs.pipe_frame_unknown')
        old.__cause__ = PhaseError('ntfs.pipe_deadline_expired')
        self.assertEqual(self.render(old), diagnostic('deadline'))
        self.assertEqual(self.render(frame_error('receive', 0, 'ntfs.pipe_eof')), diagnostic('eof', 'error'))
        self.assertEqual(self.render(frame_error('receive', 0, 'ntfs.pipe_invalid_header')), diagnostic(None, 'error'))
        self.assertEqual(self.render(TimeoutError('private outer')), diagnostic(None))

    def test_outer_allowlist_and_exact_64_byte_limit(self):
        read = self.cli['input_failure_line']
        reasons = ('deadline', 'rx_empty', 'rx_bytes', 'rx_first', 'rx_fdata', 'rx_next', 'rx_ndata', 'tx', 'tx_obs')
        self.assertEqual(max(len(diagnostic(reason)) for reason in reasons), 64)
        for reason in reasons:
            with self.subTest(reason=reason):
                self.assertEqual(read(diagnostic(reason)), diagnostic(reason))
        self.assertEqual(read(diagnostic('eof', 'error')), diagnostic('eof', 'error'))
        self.assertEqual(read(diagnostic(None, 'error', 'stage')), diagnostic(None, 'error', 'stage'))
        self.assertEqual(len(diagnostic('rx_emptyx')), 65)
        foreign = (diagnostic('rx_emptyx'), diagnostic('rx_emptx'), diagnostic('rx_empty', 'error'),
            diagnostic('rx_first', phase='inspect'), diagnostic('eof'), diagnostic(['rx_empty']),
            diagnostic('é'), diagnostic('rx_empty').replace(b'rx_empty', b'RX_EMPTY'),
            b'{"error_class":"timeout","phase":"execute","reason":"tx","x":0}\n',
            b'{"error_class":"timeout","phase":"execute","reason":"tx"}\n\n',
            b'{"phase":"execute","phase":"execute","reason":"tx"}\n')
        for raw in foreign:
            with self.subTest(raw=raw):
                self.assertEqual(read(raw), diagnostic(None, 'error', 'delivery'))
                self.assertEqual(read(raw, timeout=True), diagnostic(None, 'timeout', 'delivery'))


if __name__ == '__main__':
    unittest.main()
