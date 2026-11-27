"""Unselected Linux data-role controls; no NativeIO or native qualification."""
from __future__ import annotations

import base64
from contextlib import contextmanager
import errno
import hashlib
import json
import os
import sys
import tracemalloc

import pytest

from phase_tool.errors import PhaseError
from phase_tool.installation import qualify_host_authority_roots
from phase_tool.mutation.ntfs import file2_stream as wire


pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
    reason="actual qualified Linux anonymous snapshot required")
CHUNK = 256 * 1024
LIMIT = 2 * 1024**3
CONTEXT = {"run_id": "file2-leaf", "intent_digest": "sha256:" + "1" * 64,
    "installation_digest": "sha256:" + "2" * 64, "operation_nonce": "3" * 32}
CHANNEL = "4" * 32


def _json(value):
    # Independent literal wire oracle, not the product header/token builder.
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _arguments(data):
    return dict(context_bytes=_json(CONTEXT), channel_id=CHANNEL,
        content_digest=_digest(data), content_length=len(data))


def _expected_header(data):
    return _json({"protocol": "phase.native.file2.bytes", "version": "1.0",
        "kind": "header", "channel_id": CHANNEL, "context": CONTEXT,
        "content_digest": _digest(data), "content_length": len(data),
        "chunk_bytes": CHUNK, "chunk_count": (len(data) + CHUNK - 1) // CHUNK})


def _token(data, kind):
    return _json({"protocol": "phase.native.file2.bytes", "version": "1.0",
        "kind": kind, "header_digest": _digest(_expected_header(data))})


def _oracle(data, phase):
    if phase == 1:
        yield _expected_header(data)
    common = {"protocol": "phase.native.file2.bytes", "version": "1.0",
        "header_digest": _digest(_expected_header(data)), "pass": phase}
    for index, offset in enumerate(range(0, len(data), CHUNK)):
        yield _json(common | {"kind": "chunk", "index": index, "offset": offset,
            "content_base64": base64.b64encode(data[offset:offset + CHUNK]).decode()})
    yield _json(common | {"kind": "end", "content_digest": _digest(data),
        "content_length": len(data), "chunk_count": (len(data) + CHUNK - 1) // CHUNK})


def _payload(length):
    return (bytes(range(256)) * ((length + 255) // 256))[:length]


@pytest.fixture(autouse=True)
def _qualified(tmp_path):
    qualify_host_authority_roots({"file2_leaf": tmp_path})


def _blob(tmp_path, data):
    blob = tmp_path / "frozen-input"
    blob.write_bytes(data)
    return blob


def _first(receiver, data):
    for raw in _oracle(data, 1):
        assert receiver.feed(raw) is None
    ready = receiver.ready_frame()
    assert ready == _token(data, "ready")
    return ready


def _replay_receiver(data):
    receiver = wire._File2TwoPassReceiver(**_arguments(data))
    _first(receiver, data)
    receiver.accept_rewound(_token(data, "rewound"))
    receiver.accept_go(_token(data, "go"))
    return receiver


def _poisoned(receiver):
    with pytest.raises(PhaseError):
        receiver.finish()
    with pytest.raises(PhaseError):
        receiver.feed(b"{}")


@pytest.mark.parametrize("length", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK + 17])
def test_literal_wire_roundtrip_same_anonymous_fd_and_retirement(tmp_path, length):
    data = _payload(length)
    blob = _blob(tmp_path, data)
    receiver = wire._File2TwoPassReceiver(**_arguments(data))
    source = None
    with wire._file2_verified_source(blob, **_arguments(data)) as source:
        fd = source._fd
        opened = os.fstat(fd)
        assert opened.st_nlink == 0 and opened.st_size == length
        assert (opened.st_dev, opened.st_ino) != (blob.stat().st_dev, blob.stat().st_ino)
        frames = list(source.first_frames())
        assert frames == list(_oracle(data, 1))
        assert all(receiver.feed(raw) is None for raw in frames)
        assert os.lseek(fd, 0, os.SEEK_CUR) == length
        ready = receiver.ready_frame()
        assert ready == _token(data, "ready")
        rewound = source.rewind_after_ready(ready)
        assert rewound == _token(data, "rewound")
        assert source._fd == fd and os.lseek(fd, 0, os.SEEK_CUR) == 0
        receiver.accept_rewound(rewound)
        receiver.accept_go(_token(data, "go"))
        replay = list(source.replay_frames())
        assert replay == list(_oracle(data, 2))
        accepted = [receiver.feed(raw) for raw in replay]
        assert b"".join(x for x in accepted if x is not None) == data
        assert receiver.finish() == {"accepted_content_digest": _digest(data),
            "accepted_content_length": length, "accepted_chunks": (length + CHUNK - 1) // CHUNK}
    assert source._fd is None and source._state == "retired"
    with pytest.raises(OSError) as caught:
        os.fstat(fd)
    assert caught.value.errno == errno.EBADF
    with pytest.raises(PhaseError):
        source.replay_frames()
    _poisoned(receiver)


def test_blob_path_replacement_cannot_replace_snapshot_bytes(tmp_path):
    data = _payload(CHUNK + 9)
    blob = _blob(tmp_path, data)
    with wire._file2_verified_source(blob, **_arguments(data)) as source:
        fd = source._fd
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"different path content")
        replacement.replace(blob)
        assert list(source.first_frames()) == list(_oracle(data, 1))
        source.rewind_after_ready(_token(data, "ready"))
        assert source._fd == fd
        assert list(source.replay_frames()) == list(_oracle(data, 2))
    assert blob.read_bytes() == b"different path content"


def test_two_gib_geometry_is_not_a_two_gib_transfer_claim():
    args = _arguments(b"") | {"content_length": LIMIT}
    metadata = json.loads(wire._header(**args))
    assert metadata["content_length"] == LIMIT and metadata["chunk_count"] == 8192
    assert metadata["chunk_bytes"] == CHUNK
    receiver = wire._File2TwoPassReceiver(**args)
    assert receiver._chunks == 8192 and receiver._hashes == []
    assert not hasattr(receiver, "receipt")


@pytest.mark.parametrize("change", [
    {"content_length": LIMIT + 1}, {"content_length": -1}, {"content_length": True},
    {"content_digest": "sha256:" + "A" * 64}, {"channel_id": "0" * 31},
    {"context_bytes": b"{}"}, {"context_bytes": _json(CONTEXT) + b"\n"},
    {"context_bytes": _json(CONTEXT | {"extra": 1})},
    {"context_bytes": _json(CONTEXT | {"operation_nonce": "0" * 31})},
    {"context_bytes": _json(CONTEXT | {"run_id": "../outside"})},
    {"context_bytes": _json(CONTEXT | {"intent_digest": "bad"})},
])
def test_invalid_binding_refuses_before_any_snapshot(tmp_path, monkeypatch, change):
    def forbidden(*args, **kwargs):
        raise AssertionError("snapshot entered before metadata rejection")
    monkeypatch.setattr(wire, "_verified_blob_snapshot", forbidden)
    with pytest.raises(PhaseError):
        with wire._file2_verified_source(tmp_path / "absent", **(_arguments(b"") | change)):
            pytest.fail("invalid metadata was accepted")


@pytest.mark.parametrize("field,value", [
    ("channel_id", "5" * 32), ("content_length", 2),
    ("content_digest", "sha256:" + "f" * 64), ("chunk_bytes", CHUNK // 2),
    ("version", "2.0"), ("unexpected", True),
    ("context", CONTEXT | {"run_id": "other-run"}),
    ("context", CONTEXT | {"intent_digest": "sha256:" + "e" * 64}),
])
def test_different_header_binding_poisoned(field, value):
    data = b"x"
    receiver = wire._File2TwoPassReceiver(**_arguments(data))
    raw = _json(json.loads(_expected_header(data)) | {field: value})
    with pytest.raises(PhaseError):
        receiver.feed(raw)
    _poisoned(receiver)


@pytest.mark.parametrize("fault", ["pass", "index", "offset", "boolean-index", "header",
    "payload", "base64", "length", "extra", "noncanonical", "frame-cap"])
def test_first_pass_bad_chunk_never_releases_data_or_ready(fault):
    data = _payload(CHUNK + 7)
    receiver = wire._File2TwoPassReceiver(**_arguments(data))
    assert receiver.feed(_expected_header(data)) is None
    raw = next(iter(_oracle(data, 2)))
    chunk = json.loads(raw) | {"pass": 1}
    changes = {"pass": {"pass": 2}, "index": {"index": 1}, "offset": {"offset": 1},
        "boolean-index": {"index": False}, "header": {"header_digest": "sha256:" + "0" * 64},
        "base64": {"content_base64": "!" * len(chunk["content_base64"])},
        "length": {"content_base64": base64.b64encode(data[:CHUNK - 1]).decode()},
        "extra": {"extra": 1}}
    chunk.update(changes.get(fault, {}))
    if fault == "payload":
        chunk["content_base64"] = base64.b64encode(b"!" + data[1:CHUNK]).decode()
    raw = _json(chunk)
    if fault == "noncanonical":
        raw += b"\n"
    if fault == "frame-cap":
        raw = b"x" * (2 * CHUNK + 1)
    if fault == "payload":
        # A well-shaped corrupt first chunk is not knowable until full SHA.
        assert receiver.feed(raw) is None
        remaining = list(_oracle(data, 1))[2:]
        with pytest.raises(PhaseError, match="end_mismatch"):
            for frame in remaining:
                assert receiver.feed(frame) is None
    else:
        with pytest.raises((PhaseError, ValueError)):
            receiver.feed(raw)
    with pytest.raises(PhaseError):
        receiver.ready_frame()
    _poisoned(receiver)


@pytest.mark.parametrize("fault", ["truncated", "digest", "count", "length", "boolean-count", "extra"])
def test_first_pass_end_is_checked_before_ready(fault):
    data = b"some bytes"
    receiver = wire._File2TwoPassReceiver(**_arguments(data))
    frames = list(_oracle(data, 1))
    for raw in frames[:-1]:
        assert receiver.feed(raw) is None
    if fault == "truncated":
        with pytest.raises(PhaseError):
            receiver.ready_frame()
    else:
        changes = {"digest": {"content_digest": "sha256:" + "f" * 64},
            "count": {"chunk_count": 0}, "length": {"content_length": len(data) + 1},
            "boolean-count": {"chunk_count": True}, "extra": {"extra": 1}}
        with pytest.raises(PhaseError):
            receiver.feed(_json(json.loads(frames[-1]) | changes[fault]))
    _poisoned(receiver)


@pytest.mark.parametrize("fault", ["early-ready", "early-go", "duplicate-ready", "stale-rewound",
    "duplicate-rewound", "pre-go-data", "duplicate-go", "stale-go"])
def test_one_shot_tokens_and_go_order(fault):
    data = b"ordered data"
    receiver = wire._File2TwoPassReceiver(**_arguments(data))
    if fault != "early-ready":
        for raw in _oracle(data, 1):
            receiver.feed(raw)
    with pytest.raises(PhaseError):
        if fault == "early-ready":
            receiver.ready_frame()
        elif fault == "early-go":
            receiver.accept_go(_token(data, "go"))
        else:
            receiver.ready_frame()
            if fault == "duplicate-ready":
                receiver.ready_frame()
            elif fault == "stale-rewound":
                receiver.accept_rewound(_token(b"stale", "rewound"))
            else:
                receiver.accept_rewound(_token(data, "rewound"))
                if fault == "duplicate-rewound":
                    receiver.accept_rewound(_token(data, "rewound"))
                elif fault == "pre-go-data":
                    receiver.feed(next(_oracle(data, 2)))
                elif fault == "stale-go":
                    receiver.accept_go(_token(b"stale", "go"))
                else:
                    receiver.accept_go(_token(data, "go"))
                    receiver.accept_go(_token(data, "go"))
    _poisoned(receiver)


@pytest.mark.parametrize("index", [0, 1, 2])
def test_replay_corruption_refuses_that_chunk_before_returning_it(index):
    data = _payload(2 * CHUNK + 17)
    receiver = _replay_receiver(data)
    accepted = bytearray()
    frames = list(_oracle(data, 2))
    for raw in frames[:index]:
        accepted.extend(receiver.feed(raw))
    chunk = json.loads(frames[index])
    bad = bytearray(base64.b64decode(chunk["content_base64"]))
    bad[-1] ^= 1
    chunk["content_base64"] = base64.b64encode(bad).decode()
    with pytest.raises(PhaseError, match="replay_mismatch"):
        receiver.feed(_json(chunk))
    assert accepted == data[:index * CHUNK]
    # A valid returned prefix is DATA ONLY, never a no-effect/rollback claim.
    _poisoned(receiver)


@pytest.mark.parametrize("fault", ["truncated", "bad-end", "extra"])
def test_replay_exact_end_required_for_finish(fault):
    data = b"fully returned bytes are still not a receipt"
    receiver = _replay_receiver(data)
    frames = list(_oracle(data, 2))
    assert receiver.feed(frames[0]) == data
    with pytest.raises(PhaseError):
        if fault == "truncated":
            receiver.finish()
        elif fault == "bad-end":
            receiver.feed(_json(json.loads(frames[-1]) | {"content_length": 0}))
        else:
            receiver.feed(frames[-1])
            receiver.feed(frames[-1])
    _poisoned(receiver)


def _until_end(generator):
    while True:
        raw = next(generator)
        if json.loads(raw)["kind"] == "end":
            return


@pytest.mark.parametrize("phase", [1, 2])
def test_paused_end_generator_cannot_revive_poison(tmp_path, phase):
    data = b"paused at the suspension point"
    with wire._file2_verified_source(_blob(tmp_path, data), **_arguments(data)) as source:
        if phase == 2:
            list(source.first_frames())
            source.rewind_after_ready(_token(data, "ready"))
        generator = source.first_frames() if phase == 1 else source.replay_frames()
        _until_end(generator)
        with pytest.raises(PhaseError):
            source.rewind_after_ready(_token(data, "ready"))
        assert source._state == "failed"
        with pytest.raises(PhaseError, match="source_unavailable"):
            next(generator)
        assert source._state == "failed"
        with pytest.raises(PhaseError):
            source.rewind_after_ready(_token(data, "ready"))
        with pytest.raises(PhaseError):
            source.replay_frames()


@pytest.mark.parametrize("phase", [1, 2])
def test_generator_suspended_at_end_stays_retired_on_context_exit(tmp_path, phase):
    data = b"no borrower beyond lifetime"
    with wire._file2_verified_source(_blob(tmp_path, data), **_arguments(data)) as source:
        fd = source._fd
        if phase == 2:
            list(source.first_frames())
            source.rewind_after_ready(_token(data, "ready"))
        generator = source.first_frames() if phase == 1 else source.replay_frames()
        _until_end(generator)
    assert source._state == "retired" and source._fd is None
    with pytest.raises(PhaseError):
        next(generator)
    assert source._state == "retired" and source._fd is None
    with pytest.raises(OSError):
        os.fstat(fd)


@pytest.mark.parametrize("fault", ["raise", "wrong-position", "wrong-token"])
def test_same_fd_rewind_failure_is_one_attempt(tmp_path, monkeypatch, fault):
    data = b"real rewind"
    with wire._file2_verified_source(_blob(tmp_path, data), **_arguments(data)) as source:
        fd = source._fd
        list(source.first_frames())
        original, calls = os.lseek, []
        def attempted(descriptor, offset, whence):
            assert descriptor == fd and offset == 0 and whence == os.SEEK_SET
            calls.append((descriptor, offset, whence))
            if fault == "raise":
                raise OSError("synthetic rewind failure")
            return 1
        with monkeypatch.context() as patcher:
            patcher.setattr(wire.os, "lseek", attempted)
            token = _token(b"stale", "ready") if fault == "wrong-token" else _token(data, "ready")
            with pytest.raises((PhaseError, OSError)):
                source.rewind_after_ready(token)
            with pytest.raises(PhaseError):
                source.rewind_after_ready(_token(data, "ready"))
            with pytest.raises(PhaseError):
                source.replay_frames()
        assert len(calls) == (0 if fault == "wrong-token" else 1)
        assert original(fd, 0, os.SEEK_CUR) == len(data)


def test_short_reads_are_accumulated_without_reopening_blob(tmp_path, monkeypatch):
    data = _payload(CHUNK + 3)
    with wire._file2_verified_source(_blob(tmp_path, data), **_arguments(data)) as source:
        fd, read, calls = source._fd, os.read, []
        def short(descriptor, maximum):
            assert descriptor == fd
            calls.append(maximum)
            return read(descriptor, min(maximum, 17001))
        with monkeypatch.context() as patcher:
            patcher.setattr(wire.os, "read", short)
            assert list(source.first_frames()) == list(_oracle(data, 1))
            source.rewind_after_ready(_token(data, "ready"))
            assert list(source.replay_frames()) == list(_oracle(data, 2))
        assert len(calls) > 20 and max(calls) <= CHUNK


@pytest.mark.parametrize("mismatch", ["digest", "length"])
def test_actual_private_copy_binding_is_required(tmp_path, mismatch):
    data = b"actual frozen bytes"
    args = _arguments(data)
    args.update({"content_digest": _digest(b"other")} if mismatch == "digest"
        else {"content_length": len(data) + 1})
    with pytest.raises(PhaseError, match="mechanism.content_binding_mismatch"):
        with wire._file2_verified_source(_blob(tmp_path, data), **args):
            pytest.fail("mismatched private copy was yielded")


@pytest.mark.parametrize("pause", ["before-start", "after-header", "after-chunk"])
def test_duplicate_first_call_poison_survives_old_generator(tmp_path, pause):
    data = _payload(CHUNK + 1)
    with wire._file2_verified_source(_blob(tmp_path, data), **_arguments(data)) as source:
        generator = source.first_frames()
        if pause != "before-start":
            next(generator)
        if pause == "after-chunk":
            next(generator)
        with pytest.raises(PhaseError):
            source.first_frames()
        with pytest.raises(PhaseError):
            next(generator)
        assert source._state == "failed"
        with pytest.raises(PhaseError):
            source.rewind_after_ready(_token(data, "ready"))


def test_consumer_primary_error_preserved_and_real_fd_closed(tmp_path):
    data = b"real closure after consumer error"
    primary = PhaseError("test.consumer_primary")
    with pytest.raises(PhaseError) as caught:
        with wire._file2_verified_source(_blob(tmp_path, data), **_arguments(data)) as source:
            fd = source._fd
            raise primary
    assert caught.value is primary and source._fd is None
    with pytest.raises(OSError) as closed:
        os.fstat(fd)
    assert closed.value.errno == errno.EBADF


@pytest.mark.parametrize("change", ["grow", "shrink", "overwrite"])
def test_snapshot_drift_refuses_and_keeps_source_failed(tmp_path, change):
    data = _payload(CHUNK + 7)
    with wire._file2_verified_source(_blob(tmp_path, data), **_arguments(data)) as source:
        generator = source.first_frames()
        assert next(generator) == _expected_header(data)
        if change == "grow":
            os.pwrite(source._fd, b"extra", len(data))
        elif change == "shrink":
            os.ftruncate(source._fd, 1)
        else:
            before = os.fstat(source._fd)
            os.pwrite(source._fd, b"different", 0)
            # Do not assume an overwrite advances the filesystem clock tick.
            os.utime(source._fd, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
            assert os.fstat(source._fd).st_mtime_ns != before.st_mtime_ns
        with pytest.raises(PhaseError, match="snapshot_changed"):
            next(generator)
        assert source._state == "failed"
        with pytest.raises(PhaseError):
            source.rewind_after_ready(_token(data, "ready"))


@pytest.mark.parametrize("primary", [False, True])
def test_snapshot_close_failure_never_becomes_success(tmp_path, monkeypatch, primary):
    data = b"closing is not worker finalization"
    original = wire._verified_blob_snapshot
    held = []
    @contextmanager
    def fail_after_actual_close(*args, **kwargs):
        with original(*args, **kwargs) as fd:
            held.append(fd)
            yield fd
        raise OSError("synthetic secondary close observation")
    monkeypatch.setattr(wire, "_verified_blob_snapshot", fail_after_actual_close)
    initial = PhaseError("test.primary")
    expected = PhaseError if primary else OSError
    with pytest.raises(expected) as caught:
        with wire._file2_verified_source(_blob(tmp_path, data), **_arguments(data)) as source:
            list(source.first_frames())
            if primary:
                raise initial
    if primary:
        assert caught.value.code == "ntfs.file2_source_finalization_unavailable"
        assert caught.value.__cause__ is initial
        assert caught.value.details == {"primary": {"type": "PhaseError", "code": "test.primary"},
            "finalization": {"type": "OSError", "code": None}}
    assert source._fd is None and source._state == "retired"
    with pytest.raises(OSError) as closed:
        os.fstat(held[0])
    assert closed.value.errno == errno.EBADF


def _measured_transfer(tmp_path, size):
    blob = tmp_path / ("large-" + str(size))
    hasher = hashlib.sha256()
    block = bytes(range(256)) * 4096
    with blob.open("wb") as output:
        for _ in range(size // len(block)):
            output.write(block)
            hasher.update(block)
    arguments = _arguments(b"") | {"content_length": size,
        "content_digest": "sha256:" + hasher.hexdigest()}
    del block
    tracemalloc.start()
    try:
        receiver = wire._File2TwoPassReceiver(**arguments)
        accepted, count = hashlib.sha256(), 0
        with wire._file2_verified_source(blob, **arguments) as source:
            for raw in source.first_frames():
                assert receiver.feed(raw) is None
            assert len(receiver._hashes) == size // CHUNK
            assert all(type(h) is bytes and len(h) == 32 for h in receiver._hashes)
            receiver.accept_rewound(source.rewind_after_ready(receiver.ready_frame()))
            receiver.accept_go(_json({"protocol": "phase.native.file2.bytes", "version": "1.0",
                "kind": "go", "header_digest": json.loads(raw)["header_digest"]}))
            for raw in source.replay_frames():
                chunk = receiver.feed(raw)
                if chunk is not None:
                    accepted.update(chunk)
                    count += len(chunk)
            assert receiver.finish()["accepted_content_length"] == size
        assert count == size and "sha256:" + accepted.hexdigest() == arguments["content_digest"]
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def test_real_four_to_thirty_two_mib_has_bounded_traced_python_growth(tmp_path):
    # Real bytes through both passes, bounded hash-only sink; no list(payloads).
    # This is neither whole-process RSS nor native2GiB/backpressure qualification.
    small = _measured_transfer(tmp_path, 4 * 1024**2)
    large = _measured_transfer(tmp_path, 32 * 1024**2)
    assert large - small < 4 * 1024**2, (small, large)
