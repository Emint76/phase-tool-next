"""Models of the genuine File2 channel and endpoints with in-memory pipes only."""

from collections import deque
import os
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.canonical import canonical_bytes, parse_json_bytes
from phase_tool.mutation.ntfs import channel_v4, entrypoint, file2_execution, file2_stream as wire, parent
from phase_tool.mutation.ntfs.channel import NativeChannelError
from phase_tool.mutation.ntfs.experimental_file2 import _FILE2_CONTRACT
from phase_tool.mutation.ntfs.handoff import _OriginalControlProjection
from phase_tool.mutation.ntfs.owner_semantic_contracts import semantic_owner_contract

from .test_native_file2_binary_chunks import (CHANNEL, CHUNK, CONTEXT, MemorySnapshot, digest, frames, header, token)


def projection(data):
    context = CONTEXT | {'worker_protocol': 'phase.native.file-worker', 'worker_version': '1.2',
        'effect_plan_digest': 'sha256:' + '7' * 64, 'native_binding_digest': 'sha256:' + '8' * 64,
        'implementation_artifact_digest': 'sha256:' + '9' * 64}
    grant = {'root_binding': 'phase_result_root', 'device': r'\Device\HarddiskVolume7',
        'volume_guid': '\\\\?\\volume{fedcba98-7654-3210-fedc-ba9876543210}\\',
        'volume_serial32': 7, 'components': ['test-output'],
        'native_identity': {'volume_serial': 7, 'file_id': '1' * 32}}
    effect = {'effect_id': 'native-file2-create', 'kind': 'exclusive_create',
        'target': {'root_binding': 'phase_result_root', 'relative_locator': 'data.bin'}, 'input_binding': 'payload',
        'content_source': {'kind': 'frozen_input', 'binding_id': 'payload', 'source_digest': digest(data)},
        'content_digest': digest(data), 'content_length': len(data), 'preconditions': {'existence': 'absent',
        'expected_digest': None, 'expected_head': None, 'concurrency_token': None}, 'lock_scope': None,
        'durability_policy_id': 'file_data_synced', 'on_failure': 'stop_and_classify'}
    return _OriginalControlProjection(canonical_bytes(context), canonical_bytes(grant), canonical_bytes(effect),
        '2026-11-11T00:00:00Z', 'payload', digest(data), len(data))


def fake_channel_base(channel, channel_id, *, _inspection_only=False):
    channel.channel_id = channel_id
    channel._inspection_only = _inspection_only
    channel._gate = threading.Lock()
    channel._possible_dispatch = False
    channel._finish_attempted = False
    channel._sequence = 0


class PipeModel:
    def __init__(self, deadline, frames=()):
        self.deadline = deadline
        self.queue = deque(frames)

    def receive_frame(self, deadline, *, maximum_bytes):
        assert deadline == self.deadline
        raw = self.queue.popleft()
        assert type(raw) is bytes and len(raw) <= maximum_bytes
        return raw, None


class InstalledBinaryExchangeModels(unittest.TestCase):
    def test_exact_contract_mode_is_closed_and_core_channel_selects_before_sending(self):
        current = semantic_owner_contract('File2')
        self.assertTrue(wire._file2_binary_chunks_for_contract(current))
        for foreign in (_FILE2_CONTRACT, semantic_owner_contract('Bundle2'), current | {'extra': True},
                current | {'package_digest': 'sha256:' + '0' * 64}):
            self.assertFalse(wire._file2_binary_chunks_for_contract(foreign))
        data = b'file2 channel bytes'
        original = projection(data)
        memory = MemorySnapshot(data)
        api = SimpleNamespace(fstat=memory.fstat, read=memory.read, lseek=memory.lseek,
            SEEK_SET=wire.os.SEEK_SET, SEEK_CUR=wire.os.SEEK_CUR)
        with patch.object(channel_v4.LinuxNativeChannelV2, '__init__', fake_channel_base), patch.object(wire, 'os', api):
            channel = channel_v4.LinuxNativeChannelV4(CHANNEL, _binary_chunks=True)
            source = wire._File2SnapshotSource(9, header(data))
            self.assertIsNone(source._binary_header)
            ready = {'file2_stage': 'ready', 'worker_ready': file2_execution._file2_ready_value(original, CHANNEL, 77)}
            send_deadlines = []
            sent = []

            def record(raw, deadline):
                self.assertIsNotNone(source._binary_header)
                sent.append(raw)
                send_deadlines.append(deadline)

            terminal = {'model': 'closed'}
            with patch.object(channel, '_usable'), patch.object(channel, '_send_frame', side_effect=record), \
                    patch.object(channel, '_receive_bound', side_effect=[ready, terminal]):
                result = channel.execute_file2(run_id=CONTEXT['run_id'], intent_digest=CONTEXT['intent_digest'],
                    projection=original, source=source)
            self.assertEqual(result, terminal)
            self.assertEqual(len(set(send_deadlines)), 1)
            self.assertEqual(sent[1:], [*frames(data, 1, binary_chunks=True), token(header(data), 'rewound'),
                                       *frames(data, 2, binary_chunks=True)])
            self.assertEqual(memory.rewinds, 1)

            memory.position = 0
            legacy = channel_v4.LinuxNativeChannelV4(CHANNEL)
            binary = wire._File2SnapshotSource(9, header(data), _binary_chunks=True)
            with patch.object(legacy, '_usable'), patch.object(legacy, '_send_frame') as send:
                with self.assertRaises(NativeChannelError) as error:
                    legacy.execute_file2(run_id=CONTEXT['run_id'], intent_digest=CONTEXT['intent_digest'],
                        projection=original, source=binary)
                self.assertFalse(error.exception.possible_dispatch)
                self.assertEqual(error.exception.details['primary']['code'], 'ntfs.file2_chunk_mode_required')
                send.assert_not_called()

    def test_parent_and_worker_check_both_passes_and_identical_stream_facts(self):
        data = b'X' * CHUNK + b'last frame'
        summaries = []
        for binary in (False, True):
            with self.subTest(binary=binary):
                original = projection(data)
                deadline = time.perf_counter_ns() + 25_000_000_000
                first = list(frames(data, 1, binary_chunks=binary))
                replay = list(frames(data, 2, binary_chunks=binary))
                core = PipeModel(deadline, [*first, token(header(data), 'rewound'), *replay])
                worker_input = PipeModel(deadline)
                core_replies = []
                go_records = []
                core.send_frame = lambda raw, when: core_replies.append((raw, when))
                accepted = semantic_owner_contract('File2') if binary else _FILE2_CONTRACT
                actual_parent = object.__new__(parent._NativeWindowsParent)
                actual_parent._launch = SimpleNamespace(manifest={'contract': accepted}, channel_id=CHANNEL)
                actual_parent._worker = SimpleNamespace(pid=77)
                actual_parent._pipe = core
                actual_parent._go_attempted = False
                with patch.object(file2_execution, 'WindowsPipeFrames', PipeModel), \
                        patch.object(file2_execution, 'os', SimpleNamespace(name='nt', getpid=os.getpid)):
                    worker = file2_execution._File2WorkerInput(worker_input, original, CHANNEL, deadline,
                        _binary_chunks=wire._file2_binary_chunks_for_contract(accepted))

                    def to_worker(raw, when):
                        self.assertEqual(when, deadline)
                        if raw.startswith(b'{"command":"execute_file2",'):
                            self.assertFalse(worker_input.queue)
                            go_records.append(raw)
                            worker.accept_go(raw)
                        else:
                            worker_input.queue.append(raw)

                    def from_worker(when, *, maximum_bytes):
                        self.assertEqual(when, deadline)
                        self.assertEqual(list(worker_input.queue), first)
                        ready_token = worker.first_pass()
                        ready = file2_execution._file2_ready_value(original, CHANNEL, 77)
                        self.assertEqual(ready_token, canonical_bytes(ready['ready_token']))
                        raw = canonical_bytes(ready)
                        self.assertLess(len(raw), maximum_bytes)
                        return raw, None

                    modeled_worker = SimpleNamespace(send_frame=to_worker, receive_frame=from_worker)
                    actual_parent._transfer_file2(modeled_worker, original, deadline, {'modeled': True})
                    self.assertEqual(len(go_records), 1)
                    self.assertEqual(list(worker_input.queue), replay)
                    self.assertEqual(len(core_replies), 1)
                    self.assertEqual(core_replies[0][1], deadline)
                    self.assertTrue(actual_parent._go_attempted)
                    self.assertEqual(worker.next_chunk() + worker.next_chunk(), data)
                    self.assertIsNone(worker.next_chunk())
                    self.assertTrue(worker.complete)
                    summaries.append(worker.stream_facts())
        self.assertEqual(summaries[0], summaries[1])

    def test_worker_entrypoint_derives_mode_from_bound_manifest_not_original_fields(self):
        original = projection(b'worker selection')
        value = file2_execution._file2_projection_value(original)
        request = {'native_worker_original_version': '2.0', 'channel_id': CHANNEL, 'projection': value}
        for binary, contract in ((False, _FILE2_CONTRACT), (True, semantic_owner_contract('File2'))):
            with self.subTest(binary=binary):
                runtime_checks = []
                launch = SimpleNamespace(run_id=CONTEXT['run_id'], operation_nonce=CONTEXT['operation_nonce'],
                    installation_digest=CONTEXT['installation_digest'], channel_id=CHANNEL, root_grant=value['grant'],
                    manifest={'contract': contract}, check_runtime=lambda: runtime_checks.append(True))
                deadline = time.perf_counter_ns() + 25_000_000_000
                pipe = object()
                with patch.object(file2_execution, 'run_file2_worker') as start, \
                        patch.object(entrypoint, '_close_worker_stdio') as finalize:
                    self.assertEqual(entrypoint._run_file2_worker_transfer(launch, request, pipe, deadline), 0)
                    start.assert_called_once_with(pipe, original, CHANNEL, _transfer_deadline_ns=deadline,
                                                  _binary_chunks=binary)
                    finalize.assert_called_once_with(None)
                self.assertEqual(len(runtime_checks), 2)


if __name__ == '__main__':
    unittest.main()
