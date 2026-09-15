"""C2: real process lock-finalization failures retain known effect progress."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from .test_rc01_correction import crash_prepared_bundle

pytestmark = pytest.mark.skipif(os.name != 'posix', reason='qualified Linux mutation')


CHILD = r'''
import errno, fcntl, json, os, sys
from pathlib import Path
from phase_tool.application import PhaseApplication
from phase_tool.mutation import bundle_create
from phase_tool.errors import PhaseError
from phase_tool.mutation.posix.authority import PosixTargetAuthority
q = json.loads(sys.argv[1])
for key in ('evidence_root', 'target_root'): q[key] = Path(q[key])
fault, point, mode = sys.argv[2:5]
real_flock, real_close = fcntl.flock, os.close
lock_fd = None
counts = {'unlock': 0, 'close': 0, 'rename': 0}
at_commit = False

commit = bundle_create.commit_prepared_bundle
def committing(*args, **kwargs):
    global at_commit
    at_commit = True
    try: return commit(*args, **kwargs)
    finally: at_commit = False
bundle_create.commit_prepared_bundle = committing

namespace = PosixTargetAuthority.assert_namespace_binding
def namespace_check(self):
    if at_commit and point == 'precheck':
        raise PhaseError('test.before_effect')
    return namespace(self)
PosixTargetAuthority.assert_namespace_binding = namespace_check

fsync_parent = PosixTargetAuthority.fsync_parent
def sync_parent(self):
    if at_commit and point == 'committed_unverified':
        raise PhaseError('test.after_commit')
    return fsync_parent(self)
PosixTargetAuthority.fsync_parent = sync_parent

if point == 'broker_precheck':
    from phase_tool.mutation import EffectBroker
    def refuse(*args, **kwargs): raise PhaseError('test.broker_precheck')
    EffectBroker._locked_plan_from_evidence = refuse

# Intercept the actual native-call boundary, not the mechanism entry/prechecks.
real_library = bundle_create.ctypes.CDLL
class SyscallFailure:
    def __call__(self, *args):
        raise OSError(errno.EIO, 'injected rename syscall uncertainty')
class Library:
    renameat2 = SyscallFailure()
def library(*args, **kwargs):
    if at_commit and point in ('unknown', 'unavailable'):
        value = Library()
        if point == 'unavailable': value.renameat2 = None
        return value
    return real_library(*args, **kwargs)
bundle_create.ctypes.CDLL = library

if point == 'return':
    from phase_tool import continuation
    continued = continuation.continue_locked
    def failed_return(*args, **kwargs):
        continued(*args, **kwargs)
        raise OSError(errno.EIO, 'injected broker return failure')
    continuation.continue_locked = failed_return

def flock(fd, operation):
    global lock_fd
    if operation & fcntl.LOCK_EX:
        # Only the descriptor actually locked for this exact target root.
        if os.readlink('/proc/self/fd/' + str(fd)) == str(q['target_root']):
            lock_fd = fd
    if fd == lock_fd and operation == fcntl.LOCK_UN:
        counts['unlock'] += 1
        if fault in ('unlock', 'both'):
            raise OSError(errno.EIO, 'injected root unlock failure')
    return real_flock(fd, operation)

def close(fd):
    global lock_fd
    if fd == lock_fd:
        counts['close'] += 1
        # Model an ambiguous close: fd may still be open. Never retry it.
        if fault in ('close', 'both'):
            raise OSError(errno.EIO, 'injected root close failure')
        lock_fd = None
    return real_close(fd)

rename = bundle_create._rename_noreplace
def counted(*args, **kwargs):
    counts['rename'] += 1
    return rename(*args, **kwargs)
bundle_create._rename_noreplace = counted
fcntl.flock, os.close = flock, close
r = PhaseApplication().recover_publication(**q, mode=mode)
open_after = False
if lock_fd is not None:
    try: os.fstat(lock_fd); open_after = True
    except OSError: pass
print(json.dumps({'result': r.payload, 'counts': counts, 'open_after': open_after}))
sys.exit(r.exit_code)
'''


def recover_child(query, fault='none', point='committed', mode='commit_prepared'):
    child = subprocess.run(
        [sys.executable, '-c', CHILD, json.dumps(query, default=str), fault, point, mode],
        capture_output=True, text=True, timeout=25,
    )
    assert child.stdout, child.stderr
    output = json.loads(child.stdout)
    from jsonschema import Draft202012Validator
    from phase_tool.application import PhaseApplication
    schema = PhaseApplication().registry.schema_document('https://phase-tool.local/schemas/recovery-result-1.1.schema.json')
    Draft202012Validator(schema).validate(output['result'])
    return child.returncode, output


def assert_observation(result):
    path = result['observation_path']
    assert path, result
    saved = json.loads(Path(path).read_text())
    from jsonschema import Draft202012Validator
    from phase_tool.application import PhaseApplication
    schema = PhaseApplication().registry.schema_document('https://phase-tool.local/schemas/recovery-result-1.1.schema.json')
    Draft202012Validator(schema).validate(saved)
    assert saved == {k: v for k, v in result.items() if k not in {'observation_path', 'observation_digest'}}


@pytest.mark.parametrize('fault', ['unlock', 'close', 'both'])
def test_c2_committed_progress_survives_lock_finalization(tmp_path, fault):
    args, run, query = crash_prepared_bundle(tmp_path, version='2.0')
    stage = next(args['target_root'].glob('phase-stage-*'))
    identity = stage.stat().st_ino
    original_intent = (run/'intent.json').read_bytes()
    code, output = recover_child(query, fault)
    result = output['result']
    target = args['target_root']/args['target_locator']
    assert code == 40 and not result['success'], output
    assert target.stat().st_ino == identity and not stage.exists()
    assert result['recovery_mutation_attempted'] is True, result
    assert result['recovery_effect_state'] == 'committed', result
    assert result['target_verified'] is True, result
    assert result['inspection_required'] is True
    assert result['error'] == 'recovery.lock_finalization_failed'
    assert result['lock_finalization'] == {
        'unlock': 'failed' if fault in ('unlock', 'both') else 'succeeded',
        'close': 'unknown' if fault in ('close', 'both') else 'succeeded',
    }
    phases = ['lock_unlock', 'lock_close'] if fault == 'both' else ['lock_' + fault]
    assert [e['phase'] for e in result['error_details']] == phases
    assert output['counts'] == {'unlock': 1, 'close': 1, 'rename': 1}
    assert output['open_after'] == (fault in ('close', 'both'))
    receipt = json.loads((run/'recovery/commit-receipt.json').read_text())
    assert receipt['target_verified'] is True
    assert_observation(result)
    # First process is gone (including any uncertain descriptor). A fresh child
    # must recognize the exact same target without invoking publication again.
    retry_code, retry = recover_child(query)
    assert retry_code == 0 and retry['result']['success'], retry
    assert not retry['result']['recovery_mutation_attempted']
    assert retry['counts']['rename'] == 0
    assert target.stat().st_ino == identity
    assert (run/'intent.json').read_bytes() == original_intent


@pytest.mark.parametrize('fault', ['unlock', 'close', 'both'])
@pytest.mark.parametrize('point,attempted,state,verified,error', [
    ('broker_precheck', False, 'not_attempted', False, 'test.broker_precheck'),
    ('precheck', False, 'not_attempted', False, 'test.before_effect'),
    ('unavailable', False, 'not_attempted', False, 'bundle.atomic_commit_unavailable'),
    ('unknown', True, 'unknown', False, 'recovery.commit_failed'),
    ('committed_unverified', True, 'committed', False, 'test.after_commit'),
    ('return', True, 'committed', True, 'recovery.commit_failed'),
])
def test_c2_primary_and_cleanup_failures_preserve_exact_progress(
        tmp_path, fault, point, attempted, state, verified, error):
    args, run, query = crash_prepared_bundle(tmp_path, version='2.0')
    stage = next(args['target_root'].glob('phase-stage-*'))
    identity = stage.stat().st_ino
    target = args['target_root']/args['target_locator']
    code, output = recover_child(query, fault, point)
    result = output['result']
    assert code == 40 and result['success'] is False, output
    assert result['error'] == error, result
    assert result['recovery_mutation_attempted'] is attempted, result
    assert result['recovery_effect_state'] == state, result
    assert result['target_verified'] is verified, result
    assert result['inspection_required'] is True
    assert target.exists() == (state == 'committed')
    assert stage.exists() != target.exists()
    assert output['counts']['unlock'] == output['counts']['close'] == 1
    assert output['open_after'] == (fault in ('close', 'both'))
    phases = ['continuation'] + (['lock_unlock', 'lock_close'] if fault == 'both' else ['lock_' + fault])
    assert [e['phase'] for e in result['error_details']] == phases, result
    assert result['error_details'][0]['code'] == (error if error != 'recovery.commit_failed' else 'recovery.failure')
    assert (run/'recovery/commit-intent.json').exists() == (point != 'broker_precheck')
    assert (run/'recovery/commit-receipt.json').exists() == verified
    assert_observation(result)
    retry_code, retry = recover_child(query)
    assert retry_code == 0 and retry['result']['success'], retry
    assert retry['result']['recovery_mutation_attempted'] == (state != 'committed')
    assert retry['counts']['rename'] == (0 if state == 'committed' else 1)
    assert target.stat().st_ino == identity


@pytest.mark.parametrize('fault', ['unlock', 'close'])
def test_c2_observe_does_not_persist_success_before_lock_finalization(tmp_path, fault):
    from phase_tool.application import PhaseApplication
    from .test_publish_bundle import bundle_arguments
    args = bundle_arguments(tmp_path)
    original = PhaseApplication().publish_bundle(**args, publication_version='2.0').payload
    assert original['success'], original
    run = args['evidence_root']/'.phase/runs'/args['run_id']
    old_receipt = (run/'receipt.json').read_bytes()
    query = {k: args[k] for k in ('evidence_root', 'run_id', 'target_root', 'request_id')}
    query['expected_intent_digest'] = original['intent_digest']
    code, output = recover_child(query, fault, mode='observe')
    result = output['result']
    assert code == 40 and not result['success'], result
    assert not result['recovery_mutation_attempted']
    assert result['recovery_effect_state'] == 'committed'
    assert result['target_verified'] is True
    assert result['error'] == 'recovery.lock_finalization_failed'
    assert output['counts'] == {'unlock': 1, 'close': 1, 'rename': 0}
    assert_observation(result)
    observations = [json.loads(p.read_text()) for p in (run/'recovery').glob('*.json')]
    assert observations and all(not value['success'] for value in observations)
    retry_code, retry = recover_child(query, mode='observe')
    assert retry_code == 0 and retry['result']['success'], retry
    assert retry['counts']['rename'] == 0
    assert (run/'receipt.json').read_bytes() == old_receipt
