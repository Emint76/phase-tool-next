"""Private passive C05 observer for one exact experimental File1 width-eight round."""
from __future__ import annotations

import errno
import os
from pathlib import Path
import stat
import threading
import time


_CASE = '51c05d17-7e2b-4c45-9273-15aa66bdab75'
_LAUNCHER_DIGEST = 'sha256:7e80db61c3b70788635f7ac24ae053627e60b76590385c3d750e354b2be67901'
_SPECS = {
    'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p0':'sha256:4a9cda3af363bfd566f3d7cb6a178f10b365b38fc43df1b3cbd1ef647b9f9ad8',
    'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p1':'sha256:d798b97811562b7a5c5f0174ca0e7aa149dd7a2ac72d06939bdb22f5b3381fae',
    'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p2':'sha256:eb220d7611374b87db771e561bcf10d45ca5d6907a8662094e6f6ebd254eadd5',
    'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p3':'sha256:a7ab795cebd7a87130d415b43ad2102694f085b07a62c8c3ef4dd2957e6dbb67',
    'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p4':'sha256:cdd7e566b6906d09e6de40f5a1c78a809f067386b935092e19cd57203564454d',
    'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p5':'sha256:3ae651133743b63f5a111621190e663a9af2ee1088748a281e56c4e6fa7c7010',
    'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p6':'sha256:47876af8f47bd2cc2aa6d9692a137320920331097dbe0ca35fc70c4cbd932dfa',
    'od3-51c05d17-7e2b-4c45-9273-15aa66bdab75-c05-file1-r000-p7':'sha256:0243d61a052238a600d6e54bb9c1ebe09e4a53f03e471e23b9c4fb8025f0c166',
}
_INPUT_SCOPE = 'owner3-input-'+_CASE+'-file1'
_TARGET = 'c05-r000.bin'
_CAP = 4096
_ATTEMPT_LIMIT = 256
_CONTENDED = {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}


def _need(condition):
    if not condition:
        raise ValueError('ntfs.c05_passive_lock_observation')


def _identity(pair):
    return (type(pair) is tuple and len(pair)==2 and type(pair[0]) is type(pair[1]) is int
            and 0<=pair[0]<2**64 and 0<pair[1]<2**64)


class _PassiveC05FlockObservation:
    """No path writes, socket IO, sleeps, control messages or lock calls here."""

    def __init__(self, lock_path, *, manifest_digest, run, now=time.monotonic_ns):
        self._owner = (os.getpid(),threading.get_ident())
        self._lock_path = lock_path
        self._manifest_digest = manifest_digest
        self._run = run
        self._now = now
        self.selected = self.taken = self.invalid = False
        self.fd = self.parent_identity = self.identity = None
        self.pending = self.acq_enter = self.acq_return = self.checked = self.history = None
        self.unlock = self.closed = self.guard = self.deadline_ns = self.timeout = None
        self.attempts = self.contended = self.interrupted = self.other_errors = 0
        self.unlock_failed = self.close_failed = False

    def consume(self,binding,run_id):
        if self.invalid:
            return False
        try:
            from ...installation import _NativeFileCreateReadBinding
            _need(self._owner==(os.getpid(),threading.get_ident()) and self.selected and not self.taken
                  and type(binding)is _NativeFileCreateReadBinding and binding.manifest_digest==self._manifest_digest
                  and run_id==self._run)
            self.taken = True
            return True
        except Exception:
            self.invalid = True
            return False

    def bind_lock(self,path,descriptor,parent_identity,identity,deadline):
        if self.invalid:
            return
        try:
            _need(self._owner==(os.getpid(),threading.get_ident()) and self.taken and self.fd is None
                  and path==self._lock_path and type(descriptor)is int and 0<=descriptor<2**31
                  and _identity(parent_identity) and _identity(identity) and identity[0]==parent_identity[0]
                  and type(deadline)is float)
            self.fd, self.parent_identity, self.identity = descriptor, parent_identity, identity
            self.deadline_ns = int(deadline*1_000_000_000)
            _need(0<self.deadline_ns<2**63)
        except Exception:
            self.invalid = True

    def _observe(self, stage, descriptor, succeeded=None, error_number=None):
        if self.invalid:
            return
        try:
            _need(self._owner==(os.getpid(),threading.get_ident()) and self.taken
                  and self.fd is not None and descriptor==self.fd)
            now = self._now()
            _need(type(now)is int and 0<now<2**63)
            if stage=='enter':
                _need(self.pending is None and self.acq_enter is None and self.timeout is None
                      and self.attempts<_ATTEMPT_LIMIT)
                self.attempts += 1
                self.pending = now
            elif stage=='acquire':
                _need(type(succeeded)is bool and self.pending is not None and self.pending<=now and self.acq_enter is None)
                if succeeded:
                    _need(error_number is None)
                    self.acq_enter,self.acq_return = self.pending,now
                elif error_number in _CONTENDED:
                    self.contended += 1
                elif error_number==errno.EINTR:
                    self.interrupted += 1
                else:
                    self.other_errors += 1
                self.pending = None
            elif stage=='checked':
                _need(self.acq_return is not None and self.acq_return<=now and self.checked is None)
                self.checked = now
            elif stage=='history':
                _need(self.checked is not None and self.checked<=now and self.history is None)
                self.history = now
            elif stage=='timeout':
                _need(self.acq_return is None and self.pending is None and self.timeout is None
                      and self.attempts>0 and now>=self.deadline_ns)
                self.timeout = now
            elif stage=='unlock':
                _need(type(succeeded)is bool and self.unlock is None and not self.unlock_failed)
                self.unlock_failed = not succeeded
                if succeeded:
                    self.unlock = now
            elif stage=='close':
                _need(type(succeeded)is bool and self.closed is None and not self.close_failed
                      and (self.unlock is not None or self.unlock_failed))
                self.close_failed = not succeeded
                if succeeded:
                    self.closed = now
            elif stage=='guard':
                _need(self.history is not None and self.closed is not None and self.closed<=now and self.guard is None)
                self.guard = now
        except Exception:
            self.invalid = True

    def acquire_entry(self,descriptor):
        self._observe('enter',descriptor)

    def acquire_return(self,descriptor,succeeded,error_number):
        self._observe('acquire',descriptor,succeeded,error_number)

    def acquired(self,descriptor):
        self._observe('checked',descriptor)

    def before_history(self,descriptor):
        self._observe('history',descriptor)

    def observed_acquire_timeout(self,descriptor,deadline):
        try:
            _need(type(deadline)is float and self.deadline_ns==int(deadline*1_000_000_000))
            self._observe('timeout',descriptor)
        except Exception:
            self.invalid = True

    def unlock_return(self,descriptor,succeeded,error_number):
        self._observe('unlock',descriptor,succeeded)

    def close_return(self,descriptor,succeeded,error_number):
        self._observe('close',descriptor,succeeded)

    def guard_return(self):
        self._observe('guard',self.fd)

    def capture_eligible(self):
        # Do not perform file IO when this passive observer cannot
        # establish the common lock was never opened or is released.
        return (self.taken and not self.invalid and self.pending is None
                and (self.fd is None or self.unlock is not None and self.closed is not None
                     and not self.unlock_failed and not self.close_failed))

    def snapshot(self):
        return {'instrumentation_invalid':self.invalid,'actual_descriptor':self.fd,
                'lock_parent_device_inode':self.parent_identity,'lock_device_inode':self.identity,
                'acquire_enter_ns':self.acq_enter,'acquire_return_ns':self.acq_return,
                'namespace_checked_ns':self.checked,'history_enter_ns':self.history,
                'unlock_return_ns':self.unlock,'close_return_ns':self.closed,'guard_return_ns':self.guard,
                'lock_deadline_ns':self.deadline_ns,'timeout_ns':self.timeout,
                'attempts':self.attempts,'contended_attempts':self.contended,'interrupted_attempts':self.interrupted,
                'other_errors':self.other_errors,'unlock_failed':self.unlock_failed,'close_failed':self.close_failed}


def _linux_owner():
    pid = os.getpid()
    with open('/proc/self/stat','rb') as stream:
        raw = stream.read(4097)
    _need(len(raw)<=4096 and int(raw.split(b' ',1)[0])==pid)
    start_ticks = int(raw.rsplit(b') ',1)[1].split()[19])
    clocks = os.stat('/proc/self/ns/time')
    pids = os.stat('/proc/self/ns/pid')
    _need(start_ticks>0 and clocks.st_ino>0 and pids.st_ino>0)
    return {'pid':pid,'start_ticks':start_ticks,'pid_namespace':[pids.st_dev,pids.st_ino],
            'time_namespace':[clocks.st_dev,clocks.st_ino]}


def _bindings(launch):
    from .bootstrap import _NativeAcceptedLaunch
    from .input_stage import _require_staged_publication_request
    from .owner_directory_fixture import _kinds, fixture_document
    from .owner_semantic_contracts import semantic_owner_contract
    from ...canonical import canonical_bytes,digest_bytes,parse_json_bytes
    from ...evidence import _read_qualification_catalog_chunk
    _need(type(launch)is _NativeAcceptedLaunch and os.sys.platform.startswith('linux') and not launch._inspection_only)
    config,manifest,invocation = launch._config,launch.manifest,launch.invocation
    admission = launch._experimental_admission_context
    _need(type(admission)is _kinds()['File1'] and config['native_launch_version']=='3.0'
          and config['artifact_graph']['launcher_digest']==_LAUNCHER_DIGEST
          and manifest['contract']==semantic_owner_contract('File1'))
    fixture = fixture_document(admission.raw)
    _need(fixture['fixture_uuid']==_CASE and fixture['experimental_admission_version']=='3.0'
          and 'c02_current_root_alias' not in fixture)
    run = invocation['run_id']
    request = _require_staged_publication_request(invocation['request'],role='File1')
    _need(run in _SPECS and request['request_id']==run and request['input_scope']==_INPUT_SCOPE
          and request['target_locator']==_TARGET and request['source_length']==65536
          and request['source_digest']==_SPECS[run])
    evidence,prep = Path(manifest['evidence_root']),Path(manifest['preparation_root'])
    _need(evidence==Path('/qualification/evidence') and prep==Path('/qualification/preparation'))
    policy_path = Path(config['linux_launcher']).parent/'c05-flock-observer.json'
    _need(policy_path==Path('/opt/experiment/file1/linux/c05-flock-observer.json'))
    policy_raw = _read_qualification_catalog_chunk(policy_path,4096)
    policy_digest = digest_bytes(policy_raw)
    _need(policy_digest==config['dependency_file_digests'].get(str(policy_path))
          ==config['artifact_graph']['linux']['dependency_file_digests'].get(str(policy_path)))
    policy = parse_json_bytes(policy_raw,maximum_bytes=4096)
    _need(type(policy)is dict and canonical_bytes(policy)==policy_raw
          and set(policy)=={'schema','case','parent_device_inode','observations_device_inode'}
          and policy['schema']=='phase.c05.passive-flock-capture/1' and policy['case']==_CASE)
    identities = tuple(tuple(policy[field]) for field in ('parent_device_inode','observations_device_inode'))
    _need(all(_identity(identity) for identity in identities))
    common = evidence/'.phase'/'locks'/(digest_bytes(b'phase.native-original-intents.v1')[7:]+'.lock')
    claims = {'run_id':run,'manifest_digest':launch.installation_digest,'launcher_digest':_LAUNCHER_DIGEST,
              'fixture_digest':digest_bytes(admission.raw),'operation_nonce':invocation['operation_nonce'],
              'capture_policy_digest':policy_digest,
              'staged_request_sha256':digest_bytes(canonical_bytes(request)),
              'stage_header_digest':request['stage_header_digest']}
    root = manifest['preparation_identity']
    return common,prep,((root['device'],root['inode']),*identities),claims


def _capture(preparation,identities,run,raw,deadline):
    from ...evidence import _opened_owned_private_directory, _write_bytes_exclusive_atomic
    from ...installation import _linux_filesystem_type, _require_native_no_descendant_mounts
    _need(run in _SPECS and 0<len(raw)<=_CAP and time.monotonic()<deadline)
    _need(_linux_filesystem_type(preparation)=='ext4')
    _require_native_no_descendant_mounts(preparation)
    current = preparation
    pinned = []
    for leaf,expected in zip((None,'qualification-c05','observations'),identities,strict=True):
        if leaf is not None:
            current = current/leaf
        info = current.lstat()
        _need(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
              and info.st_uid==os.geteuid() and not info.st_mode&0o077)
        identity = (info.st_dev,info.st_ino)
        _need(identity==expected and identity[0]==identities[0][0])
        pinned.append((current,identity))
    _need(time.monotonic()<deadline)
    with _opened_owned_private_directory(current,pinned[-1][1]) as descriptor:
        _need(time.monotonic()<deadline)
        _write_bytes_exclusive_atomic(current/(run+'.json'),raw,'C05 qualification RAW observation',_parent_descriptor=descriptor)
        for path,identity in pinned:
            info = path.lstat()
            _need((info.st_dev,info.st_ino)==identity and stat.S_ISDIR(info.st_mode)
                  and info.st_uid==os.geteuid() and not info.st_mode&0o077)


def _run_first_c05_observed_core(launch,initial_deadline):
    from .common_flock_test import _C05_PASSIVE_SELECTED,_SELECTED
    from .entrypoint import run_native_core
    from ...canonical import canonical_bytes
    common,prep,identities,claims = _bindings(launch)
    _need(type(initial_deadline)is float and 0<initial_deadline-time.monotonic()<=30
          and _C05_PASSIVE_SELECTED.get() is None and _SELECTED.get() is None)
    observation = _PassiveC05FlockObservation(common,manifest_digest=claims['manifest_digest'],run=claims['run_id'])
    try:
        owner = _linux_owner()
    except Exception:
        owner = None
        observation.invalid = True
    if owner is not None:
        try:
            from .c05_pidfd_endpoint import producer
            producer(launch,claims,owner,initial_deadline)
        except Exception:
            # The independent observer remains incomplete. Preserve V2's own lock trace.
            pass
    observation.selected = True
    token = _C05_PASSIVE_SELECTED.set(observation)
    try:
        return run_native_core(launch)
    finally:
        _C05_PASSIVE_SELECTED.reset(token)
        # No telemetry failure promotes, blocks, retries, or changes the
        # existing Core outcome. A late/missing member is external UNKNOWN.
        try:
            if (observation.capture_eligible() and owner is not None and _linux_owner()==owner
                    and time.monotonic()<initial_deadline):
                raw = canonical_bytes({'schema':'phase.c05.passive-flock/1','case':_CASE,'owner':owner,
                    'binding':claims,'clock':'LINUX_MONOTONIC','observation':observation.snapshot(),
                    'acceptance':None,'retry_authorized':False})
                _capture(prep,identities,claims['run_id'],raw,initial_deadline)
        except Exception:
            pass
