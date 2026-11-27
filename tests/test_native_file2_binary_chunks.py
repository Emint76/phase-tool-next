"""Portable File2 codec checks, with no native process, disk or accepted launch."""

import base64
from hashlib import sha256
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import file2_stream as wire


CHUNK = 256 * 1024
LIMIT = 2 * 1024**3
CHANNEL = '4' * 32
CONTEXT = {'run_id': 'file2-binary-model', 'intent_digest': 'sha256:' + '1' * 64,
           'installation_digest': 'sha256:' + '2' * 64, 'operation_nonce': '3' * 32}
PROTOCOL = {'protocol': 'phase.native.file2.bytes', 'version': '1.0'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(raw):
    return 'sha256:' + sha256(raw).hexdigest()


def arguments(data):
    return dict(context_bytes=canonical(CONTEXT), channel_id=CHANNEL,
                content_digest=digest(data), content_length=len(data))


def header(data):
    return canonical(PROTOCOL | {'kind': 'header', 'channel_id': CHANNEL, 'context': CONTEXT,
        'content_digest': digest(data), 'content_length': len(data), 'chunk_bytes': CHUNK,
        'chunk_count': (len(data) + CHUNK - 1) // CHUNK})


def token(header_raw, kind):
    return canonical(PROTOCOL | {'kind': kind, 'header_digest': digest(header_raw)})


def binary(header_raw, phase, ordinal, offset, chunk):
    return (b'PHF2\x01' + sha256(header_raw).digest() + bytes([phase]) + ordinal.to_bytes(4, 'big')
        + offset.to_bytes(8, 'big') + len(chunk).to_bytes(4, 'big') + chunk)


def frames(data, phase, *, binary_chunks):
    header_raw = header(data)
    if phase == 1:
        yield header_raw
    common = PROTOCOL | {'header_digest': digest(header_raw), 'pass': phase}
    for ordinal, offset in enumerate(range(0, len(data), CHUNK)):
        chunk = data[offset:offset + CHUNK]
        if binary_chunks:
            yield binary(header_raw, phase, ordinal, offset, chunk)
        else:
            yield canonical(common | {'kind': 'chunk', 'index': ordinal, 'offset': offset,
                'content_base64': base64.b64encode(chunk).decode('ascii')})
    yield canonical(common | {'kind': 'end', 'content_digest': digest(data), 'content_length': len(data),
        'chunk_count': (len(data) + CHUNK - 1) // CHUNK})


class MemorySnapshot:
    """Model only the existing borrowed fd with real source state transitions."""

    def __init__(self, data):
        self.data = data
        self.position = 0
        self.rewinds = 0
        self.snapshot = SimpleNamespace(st_dev=1, st_ino=2, st_size=len(data), st_mtime_ns=3, st_ctime_ns=4)

    def fstat(self, fd):
        assert fd == 9
        return self.snapshot

    def read(self, fd, count):
        assert fd == 9
        result = self.data[self.position:self.position + min(32768, count)]
        self.position += len(result)
        return result

    def lseek(self, fd, offset, origin):
        assert fd == 9 and offset == 0
        if origin == wire.os.SEEK_SET:
            self.rewinds += 1
            self.position = 0
        else:
            assert origin == wire.os.SEEK_CUR
        return self.position


class BinaryChunkModels(unittest.TestCase):
    def receiver(self, data, *, binary_chunks=True):
        return wire._File2TwoPassReceiver(**arguments(data), _binary_chunks=binary_chunks)

    def expect_poisoned(self, receiver):
        self.assertEqual(receiver._state, 'failed')
        with self.assertRaises(PhaseError):
            receiver.feed(b'{}')
        with self.assertRaises(PhaseError):
            receiver.finish()

    def advance_to_replay(self, receiver, data):
        for raw in frames(data, 1, binary_chunks=True):
            self.assertIsNone(receiver.feed(raw))
        self.assertEqual(receiver.ready_frame(), token(header(data), 'ready'))
        receiver.accept_rewound(token(header(data), 'rewound'))
        receiver.accept_go(token(header(data), 'go'))

    def test_source_and_receiver_match_independent_binary_and_legacy_oracles(self):
        for length in (0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK + 17):
            data = (bytes(range(256)) * ((length + 255) // 256))[:length]
            for use_binary in (False, True):
                with self.subTest(length=length, binary=use_binary):
                    receiver = self.receiver(data, binary_chunks=use_binary)
                    memory = MemorySnapshot(data)
                    api = SimpleNamespace(fstat=memory.fstat, read=memory.read, lseek=memory.lseek,
                                          SEEK_SET=wire.os.SEEK_SET, SEEK_CUR=wire.os.SEEK_CUR)
                    with patch.object(wire, 'os', api):
                        source = wire._File2SnapshotSource(9, header(data), _binary_chunks=use_binary)
                        first = tuple(source.first_frames())
                        self.assertEqual(first, tuple(frames(data, 1, binary_chunks=use_binary)))
                        for raw in first:
                            self.assertIsNone(receiver.feed(raw))
                        ready = receiver.ready_frame()
                        self.assertEqual(ready, token(header(data), 'ready'))
                        rewound = source.rewind_after_ready(ready)
                        self.assertEqual(rewound, token(header(data), 'rewound'))
                        receiver.accept_rewound(rewound)
                        receiver.accept_go(token(header(data), 'go'))
                        replay = tuple(source.replay_frames())
                        self.assertEqual(replay, tuple(frames(data, 2, binary_chunks=use_binary)))
                        pieces = [receiver.feed(raw) for raw in replay]
                        self.assertIsNone(pieces.pop())
                        self.assertEqual(b''.join(pieces), data)
                        self.assertEqual(memory.rewinds, 1)
                        self.assertEqual(receiver.finish(), {'accepted_content_digest': digest(data),
                            'accepted_content_length': length, 'accepted_chunks': (length + CHUNK - 1) // CHUNK})

    def test_each_field_mismatch_and_payload_size_poison_first_pass(self):
        data = b'abcd' * 20
        header_raw, first, _ = frames(data, 1, binary_chunks=True)
        for name, raw in {'magic': b'X' + first[1:], 'version': first[:4] + b'\x02' + first[5:],
                'header_digest': first[:5] + b'\0' * 32 + first[37:], 'pass': first[:37] + b'\x02' + first[38:],
                'ordinal': first[:38] + b'\0\0\0\x01' + first[42:],
                'offset': first[:42] + b'\0' * 7 + b'\x01' + first[50:],
                'length': first[:50] + b'\0' * 4 + first[54:], 'truncated': first[:-1],
                'extra': first + b'x', 'wrong_type': bytearray(first),
                'over_bound': first + b'\0' * CHUNK}.items():
            with self.subTest(name=name):
                receiver = self.receiver(data)
                receiver.feed(header_raw)
                with self.assertRaises(PhaseError):
                    receiver.feed(raw)
                self.assertEqual((receiver._index, receiver._offset, receiver._hashes), (0, 0, []))
                self.expect_poisoned(receiver)

    def test_corruption_of_either_pass_cannot_be_completed_or_released(self):
        data = b'payload abc'
        header_raw, first, end = frames(data, 1, binary_chunks=True)
        receiver = self.receiver(data)
        receiver.feed(header_raw)
        receiver.feed(first[:-1] + b'x')
        with self.assertRaisesRegex(PhaseError, 'ntfs.file2_end_mismatch'):
            receiver.feed(end)
        self.expect_poisoned(receiver)

        receiver = self.receiver(data)
        self.advance_to_replay(receiver, data)
        replay, _ = frames(data, 2, binary_chunks=True)
        with self.assertRaisesRegex(PhaseError, 'ntfs.file2_replay_mismatch'):
            receiver.feed(replay[:-1] + b'x')
        self.assertEqual((receiver._index, receiver._offset, receiver._hash.hexdigest()), (0, 0, sha256(b'').hexdigest()))
        self.expect_poisoned(receiver)

    def test_early_end_and_missing_go_never_release_bytes(self):
        data = b'one byte'
        header_raw, first, end = frames(data, 1, binary_chunks=True)
        replay, _ = frames(data, 2, binary_chunks=True)
        for operation in ('early_end', 'no_ready', 'no_rewind', 'no_go', 'bad_go', 'extra_chunk'):
            with self.subTest(operation=operation):
                receiver = self.receiver(data)
                receiver.feed(header_raw)
                if operation == 'early_end':
                    with self.assertRaises(PhaseError):
                        receiver.feed(end)
                elif operation == 'no_ready':
                    with self.assertRaises(PhaseError):
                        receiver.ready_frame()
                else:
                    receiver.feed(first)
                    receiver.feed(end)
                    receiver.ready_frame()
                    if operation == 'no_rewind':
                        with self.assertRaises(PhaseError):
                            receiver.accept_go(token(header_raw, 'go'))
                    else:
                        receiver.accept_rewound(token(header_raw, 'rewound'))
                        if operation == 'no_go':
                            with self.assertRaises(PhaseError):
                                receiver.feed(replay)
                        elif operation == 'bad_go':
                            with self.assertRaises(PhaseError):
                                receiver.accept_go(token(header_raw, 'ready'))
                        else:
                            receiver.accept_go(token(header_raw, 'go'))
                            self.assertEqual(receiver.feed(replay), data)
                            with self.assertRaises(PhaseError):
                                receiver.feed(replay)
                self.expect_poisoned(receiver)

    def test_modes_are_explicit_and_never_fall_back(self):
        data = b'x' * 64
        for receiver_mode, sender_mode in ((False, True), (True, False)):
            receiver = self.receiver(data, binary_chunks=receiver_mode)
            header_raw, chunk, _ = frames(data, 1, binary_chunks=sender_mode)
            receiver.feed(header_raw)
            with self.assertRaises(PhaseError):
                receiver.feed(chunk)
            self.expect_poisoned(receiver)
        for invalid in (0, 1, None, 'binary'):
            with self.assertRaisesRegex(PhaseError, 'ntfs.file2_chunk_mode_required'):
                self.receiver(data, binary_chunks=invalid)

    def test_last_2_gib_ordinal_and_offset_without_large_fixture(self):
        header_digest = b'd' * 32
        data = b'X' * CHUNK
        ordinal = LIMIT // CHUNK - 1
        offset = LIMIT - CHUNK
        frame = wire._binary_chunk_frame(header_digest, 2, ordinal, offset, data)
        self.assertEqual(frame[:54], b'PHF2\x01' + header_digest + b'\x02' + ordinal.to_bytes(4, 'big')
                         + offset.to_bytes(8, 'big') + CHUNK.to_bytes(4, 'big'))
        self.assertEqual(wire._binary_chunk_payload(frame, header_digest, 2, ordinal, offset, CHUNK), data)
        self.assertLessEqual(len(frame), wire._MAX_FRAME)
        with self.assertRaisesRegex(PhaseError, 'ntfs.file2_chunk_order'):
            wire._binary_chunk_frame(header_digest, 2, ordinal + 1, offset + CHUNK, data)


if __name__ == '__main__':
    unittest.main()
