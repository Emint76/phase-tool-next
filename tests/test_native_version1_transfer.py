"""Pure transfer/owner components with explicit synthetic prerequisites.

No admission, actual Windows pipe/process/HANDLE, NativeIO, target filesystem,
Core lifecycle or qualification claim. Empty-read and owner-exit facts are
separate; a Docker CLI witness is not proof that Linux exec has stopped.
"""
from dataclasses import replace
import errno
import os
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import parent,windows_pipe,version1_observation
from phase_tool.mutation.ntfs.handoff import ParsedNativeVersion1
from phase_tool.mutation.ntfs.original_transfer import original_version1_frames,_Version1OriginalDecoder
from phase_tool.mutation.ntfs.windows_pipe import WindowsPipeFrames
from .test_native_version1_parent import fixture,grant


CHANNEL='a'*32


def original(content=None):
    ctx,effect,payload,_=fixture()
    if content is not None:
        payload=content;effect=effect|{'content_digest':digest_bytes(payload),'content_length':len(payload)}
    return ParsedNativeVersion1(canonical_bytes(ctx),canonical_bytes(grant()),canonical_bytes(effect),
        payload,'2026-01-01T00:00:00Z')


def decoder(parsed,*,leg='worker'):
    context=parse_json_bytes(parsed.context_bytes)
    expected={name:context[name] for name in ('run_id','operation_nonce','installation_digest')}
    if leg=='reader':expected['intent_digest']=context['intent_digest']
    return _Version1OriginalDecoder(channel_id=CHANNEL,leg=leg,
        query_digest=None if leg=='worker' else 'sha256:'+'b'*64,
        expected_context=expected,expected_grant=parsed.grant_bytes)


def ready(parsed,pid=123):
    return canonical_bytes({'worker_ready_version':'1.1','context':parse_json_bytes(parsed.context_bytes),
        'pid':pid,'grant_digest':digest_bytes(parsed.grant_bytes),'effect_digest':digest_bytes(parsed.effect_bytes),
        'content_digest':digest_bytes(parsed.content_bytes),'content_length':len(parsed.content_bytes),
        'timestamp':parsed.timestamp})


class Version1FiniteTransferTests(unittest.TestCase):
    def test_zero_small_and_full16m_tail_roundtrip_both_fixed_legs_without_materialized_frame_list(self):
        for size in (0,1,1024**2+1,16*1024**2):
            payload=b'' if not size else b'x'*(size-1)+b'\xff'
            for leg in ('reader','worker'):
                with self.subTest(size=size,leg=leg):
                    parsed=original(payload);consumer=decoder(parsed,leg=leg);count=0
                    frames=original_version1_frames(parsed,channel_id=CHANNEL,leg=leg,
                        query_digest=None if leg=='worker' else 'sha256:'+'b'*64)
                    self.assertEqual(iter(frames),frames)
                    for raw in frames:
                        count+=1;self.assertLess(len(raw),2*1024**2);consumer.feed(raw)
                    self.assertEqual(count,2+(size+256*1024-1)//(256*1024))
                    self.assertTrue(consumer.ended);self.assertEqual(consumer.finish(),parsed)
                    with self.assertRaises(PhaseError):consumer.finish()

    def test_existing16m_plus_one_refuses_before_any_frame(self):
        parsed=original(b'x'*(16*1024**2+1))
        frames=original_version1_frames(parsed,channel_id=CHANNEL,leg='worker',query_digest=None)
        with self.assertRaises(PhaseError):next(frames)

    def test_end_token_truncation_reordering_duplicate_and_trailing_frames_are_terminal(self):
        parsed=original(b'x'*(256*1024+1))
        frames=list(original_version1_frames(parsed,channel_id=CHANNEL,leg='worker',query_digest=None))
        sequences=[frames[:-1],[frames[0],frames[2],frames[1],frames[3]],
            [frames[0],frames[1],frames[1],frames[2],frames[3]],frames+[frames[-1]]]
        for sequence in sequences:
            with self.subTest(count=len(sequence)):
                consumer=decoder(parsed)
                with self.assertRaises(PhaseError):
                    for raw in sequence:consumer.feed(raw)
                    consumer.finish()
                with self.assertRaises(PhaseError):consumer.finish()

    def test_changed_timestamp_can_be_consistently_transferred_but_parent_sends_no_go(self):
        expected=original();changed=replace(expected,timestamp='2027-01-01T00:00:00Z')
        consumer=decoder(expected)
        # Recompute every header/chunk/end hash using the real generator. This
        # reaches READY correlation, rather than failing on stale transfer SHA.
        for raw in original_version1_frames(changed,channel_id=CHANNEL,leg='worker',query_digest=None):
            consumer.feed(raw)
        transferred=consumer.finish();self.assertEqual(transferred.timestamp,changed.timestamp)
        self.assertNotEqual(transferred.timestamp,expected.timestamp)
        ctx=parse_json_bytes(expected.context_bytes)
        process=SimpleNamespace(pid=123)
        pipe=SimpleNamespace(receive_frame=Mock(return_value=(ready(transferred),{})),send_frame=Mock())
        launch=SimpleNamespace(read_original=Mock(return_value=expected),run_id=ctx['run_id'],
            operation_nonce=ctx['operation_nonce'],installation_digest=ctx['installation_digest'],root_grant=grant(),
            spawn_worker=Mock(return_value=process),worker_pipe=Mock(return_value=pipe),
            send_worker_original=Mock(),finalize_worker=Mock(),check_runtime=Mock())
        owner=object.__new__(parent._NativeWindowsParent)
        owner._launch=launch;owner._version1=True;owner._inspection_only=False;owner._consumed=True
        owner._spawn_attempted=False;owner._go_attempted=False;owner._worker=None;owner._worker_count=0
        owner._worker_finalized=False;owner._partial_bytes=None;owner._ready_wire=None;owner._completion_wire=None
        fact={'process_witness_version':'1.0','pid':123,'wait_result':0,'exit_code':0,'worker_exit_established':True}
        witness=SimpleNamespace(wait_for_exit=Mock(return_value=fact))
        # Parent orchestration is real; only creation/HANDLE/pipe/physical-owner
        # boundaries are explicit models. No profile or admission is exercised.
        with patch.object(parent,'WindowsProcessWitness',return_value=witness):
            with self.assertRaises(PhaseError) as caught:owner._execute(ctx['intent_digest'])
        self.assertEqual(caught.exception.code,'ntfs.parent_execution_unresolved')
        self.assertIs(caught.exception.details['possible_dispatch'],False)
        self.assertFalse(owner._go_attempted);pipe.send_frame.assert_not_called()
        self.assertEqual(pipe.receive_frame.call_count,1);self.assertEqual(launch.spawn_worker.call_count,1)
        self.assertEqual(launch.finalize_worker.call_count,1)
        self.assertIsNone(parse_json_bytes(owner._partial_bytes)['completion'])


    def test_exact_full_original_ready_reaches_one_go_and_separate_pair_observation(self):
        parsed=original();ctx,effect,_,expected=fixture()
        process=SimpleNamespace(pid=123)
        pipe=SimpleNamespace(receive_frame=Mock(side_effect=[(ready(parsed),{}),
            (canonical_bytes(expected['completion']),{})]),send_frame=Mock())
        launch=SimpleNamespace(read_original=Mock(return_value=parsed),run_id=ctx['run_id'],
            operation_nonce=ctx['operation_nonce'],installation_digest=ctx['installation_digest'],root_grant=grant(),
            spawn_worker=Mock(return_value=process),worker_pipe=Mock(return_value=pipe),
            send_worker_original=Mock(),finalize_worker=Mock(),check_runtime=Mock())
        owner=object.__new__(parent._NativeWindowsParent)
        owner._launch=launch;owner._version1=True;owner._inspection_only=False;owner._consumed=True
        owner._spawn_attempted=False;owner._go_attempted=False;owner._worker=None;owner._worker_count=0
        owner._worker_finalized=False;owner._partial_bytes=None;owner._ready_wire=None;owner._completion_wire=None
        witness=SimpleNamespace(wait_for_exit=Mock(return_value=expected['process_witness']))
        pair=expected['post_observation']
        with patch.object(parent,'WindowsProcessWitness',return_value=witness), \
             patch.object(version1_observation,'observe_version1_file',side_effect=[pair['current'],pair['archive']]) as observe:
            result=owner._execute(ctx['intent_digest'])
        self.assertEqual(result,expected);self.assertTrue(owner._go_attempted)
        self.assertEqual(launch.spawn_worker.call_count,1);self.assertEqual(launch.finalize_worker.call_count,1)
        pipe.send_frame.assert_called_once()
        go,deadline=pipe.send_frame.call_args.args
        self.assertEqual(parse_json_bytes(go),{'command':'execute_version1','context':ctx})
        self.assertEqual(launch.send_worker_original.call_args.kwargs,{'_handshake_deadline_ns':deadline})
        self.assertEqual(pipe.receive_frame.call_args_list[0].args[0],deadline)
        self.assertEqual(observe.call_count,2);witness.wait_for_exit.assert_called_once_with(60000)


class ReaderEOFComponentTests(unittest.TestCase):
    def shell(self):
        # Constructor/native metadata prerequisites are deliberately unexercised.
        # Test the retained method's checks with no OS descriptor being opened.
        pipe=object.__new__(WindowsPipeFrames)
        pipe._owner=(os.getpid(),threading.get_ident());pipe._gate=threading.Lock()
        pipe._failed=False;pipe._sealed=False;pipe._eof_attempted=False
        pipe._identity=Mock(side_effect=lambda side:7+side)
        return pipe

    def call(self,pipe,read):
        api=SimpleNamespace(getpid=os.getpid,read=read)
        with patch.object(windows_pipe,'os',api):
            return pipe._expect_eof(time.perf_counter_ns()+1_000_000_000)

    def test_actual_empty_read_requires_all_six_identity_checks_and_claims_no_peer_exit(self):
        pipe=self.shell();read=Mock(return_value=b'')
        self.assertEqual(self.call(pipe,read),{'eof_observed':True,'peer_exit_established':False,
            'effect_success_established':False})
        self.assertEqual([call.args for call in pipe._identity.call_args_list],[(0,),(1,)]*3)
        read.assert_called_once_with(7,1)
        with self.assertRaises(PhaseError):self.call(pipe,read)
        self.assertEqual(read.call_count,1)

    def test_postread_or_postrelease_identity_fault_never_returns_positive_eof(self):
        for stage in ('postread','postrelease'):
            with self.subTest(stage=stage):
                pipe=self.shell();facts={'postread':False,'postrelease':False}
                class Gate:
                    def __init__(self):self.lock=threading.Lock()
                    def acquire(self,*,blocking):return self.lock.acquire(blocking=blocking)
                    def release(self):
                        self.lock.release();facts['postrelease']=True
                def identity(side):
                    if facts[stage]:raise PhaseError('synthetic.'+stage)
                    return 7+side
                def read_one(fd,count):
                    self.assertEqual((fd,count),(7,1));facts['postread']=True
                    return b''
                pipe._gate=Gate();pipe._identity=Mock(side_effect=identity);read=Mock(side_effect=read_one)
                with self.assertRaises(PhaseError) as caught:self.call(pipe,read)
                self.assertEqual(caught.exception.code,'ntfs.pipe_eof_unverified')
                self.assertEqual(caught.exception.details['primary']['code'],'synthetic.'+stage)
                self.assertTrue(pipe._failed);self.assertIs(caught.exception.details['peer_exit_established'],False)
                self.assertEqual(read.call_count,1)

    def test_trailing_byte_and_read_error_are_not_eof(self):
        for read in (Mock(return_value=b'X'),Mock(side_effect=OSError(errno.EBADF,'synthetic.badfd'))):
            with self.subTest(read=read):
                pipe=self.shell()
                with self.assertRaises(PhaseError) as caught:self.call(pipe,read)
                self.assertEqual(caught.exception.code,'ntfs.pipe_eof_unverified')
                self.assertTrue(pipe._failed)

    def test_would_block_does_not_create_eof_or_reset_the_supplied_deadline(self):
        pipe=self.shell();pipe._pause=Mock()
        deadline=time.perf_counter_ns()+1_000_000_000
        read=Mock(side_effect=[BlockingIOError(errno.EAGAIN,'synthetic.empty'),b''])
        with patch.object(windows_pipe,'os',SimpleNamespace(getpid=os.getpid,read=read)):
            result=pipe._expect_eof(deadline)
        self.assertTrue(result['eof_observed']);pipe._pause.assert_called_once_with(deadline)
        self.assertEqual(read.call_count,2)
