"""Internal native physical primitives, not an admitted storage route.

Only a code-owned contract executor may use these methods. There is no entry
point or caller-supplied filesystem dispatcher. All locators are single leaves
relative to handles obtained by the native authority. Raw events survive post
observation errors; callers must classify those effects and never blindly retry.
"""
from __future__ import annotations

import ctypes as C
from functools import wraps
import os
import threading
import time

from .native import (NativeHandle, NativeIdentity, NativeIO, _ObjectAttributes,
                     _UnicodeString, _IoStatus, _RenameInfo, _leaf, _require, _error_record)
from ...errors import PhaseError


def _mutation_call(method):
    """Gate one owner-thread method, including all its checks and native call.

    Sealing revokes future ingress, not an already accepted syscall or result.
    There is no automatic retry, result close, deletion or outcome rewriting.
    """
    @wraps(method)
    def controlled(self, *arguments, **keywords):
        self._assert_mutation_owner()
        with self._mutation_guard:
            _require(not self._mutation_sealed, 'ntfs.mutation_session_sealed')
            if self._mutation_active:
                self._seal_locked('reentrant:' + method.__name__)
                raise PhaseError('ntfs.reentrant_mutation_forbidden')
            try:
                self._mutation_active = True
                # A reentrant seal between the ingress check and activation
                # must not start the method after a quiescent seal returned.
                _require(not self._mutation_sealed, 'ntfs.mutation_session_sealed')
                return method(self, *arguments, **keywords)
            except BaseException:
                # Preserve the original exception and every native event. An
                # error does not prove that the accepted call had no effect.
                self._seal_locked('error:' + method.__name__)
                raise
            finally:
                self._mutation_active = False
                if self._mutation_sealed:
                    self._writable.clear()
                    self._created.clear()
    return controlled


class _RenameInfoEx(C.Structure):
    _fields_ = [('Flags', C.c_uint32), ('RootDirectory', C.c_void_p),
                ('FileNameLength', C.c_uint32), ('FileName', C.c_wchar * 1)]


class NativeMutationIO(NativeIO):
    """Native API adapter. Admission, contract leases and root scope live above."""

    def __init__(self):
        self._init_mutation_session()
        super().__init__()
        _require(_RenameInfoEx.RootDirectory.offset == 8 and _RenameInfoEx.FileName.offset == 20
                 and C.sizeof(_RenameInfoEx) == 24, 'ntfs.abi_mismatch')
        self.events: list[dict] = []
        self._writable: set[NativeHandle] = set()
        self._created: set[NativeHandle] = set()
        self.nt.NtCreateFile.argtypes = [C.POINTER(C.c_void_p), C.c_uint32,
            C.POINTER(_ObjectAttributes), C.POINTER(_IoStatus), C.c_void_p,
            C.c_uint32, C.c_uint32, C.c_uint32, C.c_uint32, C.c_void_p, C.c_uint32]
        self.nt.NtCreateFile.restype = C.c_int32
        self.kernel.WriteFile.argtypes = [C.c_void_p, C.c_void_p, C.c_uint32,
                                          C.POINTER(C.c_uint32), C.c_void_p]
        self.kernel.WriteFile.restype = C.c_int32
        self.kernel.SetEndOfFile.argtypes = [C.c_void_p]
        self.kernel.SetEndOfFile.restype = C.c_int32

    def _init_mutation_session(self) -> None:
        _require(not hasattr(self, '_mutation_owner'), 'ntfs.mutation_session_already_initialized')
        self._mutation_owner = (os.getpid(), threading.get_native_id())
        self._mutation_guard = threading.RLock()
        self._mutation_active = self._mutation_sealed = False
        self._mutation_seal_metadata: dict[str, str] = {}

    @property
    def mutation_state(self) -> str:
        if self._mutation_sealed:
            return 'sealed_active' if self._mutation_active else 'sealed'
        return 'active' if self._mutation_active else 'open'

    @property
    def mutation_seal_reason(self) -> str | None:
        return self._mutation_seal_metadata.get('reason')

    def _assert_mutation_owner(self) -> None:
        _require(self._mutation_owner == (os.getpid(), threading.get_native_id()),
                 'ntfs.mutation_wrong_thread_or_process')

    def _seal_locked(self, reason: str) -> None:
        # This flag is the irreversible ingress revocation. Diagnostic reason
        # uses one builtin setdefault, so reentrant seal cannot overwrite it.
        self._mutation_sealed = True
        self._mutation_seal_metadata.setdefault('reason', reason)
        if not self._mutation_active:
            self._writable.clear()
            self._created.clear()

    def seal_mutations(self) -> str:
        """Revoke future methods without cancelling an accepted call.

        A signal handler may ONLY call this method. It must not read/hash/close
        handles, because those operations can change a shared file pointer or
        finalize a handle still in use. This trusted-executor restriction is
        not enforced against arbitrary Python callbacks by this primitive.

        'sealed_active' is not quiescence. The accepted method may still change
        storage and return its real result (including a handle owned by caller).
        The executor must await its completion, stop subsequent mutations and
        classify actual events/independent observations before saving evidence.
        Read-only observation and one-attempt close remain available afterwards.
        """
        self._assert_mutation_owner()
        with self._mutation_guard:
            self._seal_locked('owner_finalization')
            return self.mutation_state

    def _require_active_mutation(self) -> None:
        self._assert_mutation_owner()
        _require(self._mutation_active and not self._mutation_sealed,
                 'ntfs.mutation_gate_required')

    def _live(self, handle: NativeHandle) -> None:
        self._assert_mutation_owner()
        super()._live(handle)

    def _open(self, name: str, *, parent: NativeHandle | None, directory: bool,
              rename_source: bool = False, namespace_flush: bool = False,
              sharing: int = 3) -> NativeHandle:
        self._assert_mutation_owner()
        if rename_source or namespace_flush:
            return self._open_mutable(name, parent=parent, directory=directory,
                rename_source=rename_source, namespace_flush=namespace_flush, sharing=sharing)
        # Observation remains available after a seal; it grants no DELETE or
        # namespace-flush access and never truncates or creates.
        return super()._open(name, parent=parent, directory=directory,
            rename_source=rename_source, namespace_flush=namespace_flush, sharing=sharing)

    @_mutation_call
    def _open_mutable(self, name: str, **mode) -> NativeHandle:
        return super()._open(name, **mode)

    def _checked_writable(self, handle: NativeHandle, expected: NativeIdentity) -> None:
        self.assert_object(handle, directory=False, expected=expected)
        _require(handle in self._writable, 'ntfs.write_lease_required')

    def _post(self, event: dict, *checks) -> None:
        errors = []
        for handle, directory, expected in checks:
            try:
                self.assert_object(handle, directory=directory, expected=expected)
            except BaseException as error:
                errors.append(_error_record(error))
        if errors:
            event['post_observation_errors'] = errors
            raise PhaseError('ntfs.post_observation_failed', details={'event': event})

    def _open_disposition(self, parent: NativeHandle, name: str, *, directory: bool,
                          expected_parent: NativeIdentity, exclusive: bool,
                          delete_access: bool = False) -> NativeHandle:
        self._require_active_mutation()
        _leaf(name)
        _require(type(directory) is bool and type(exclusive) is bool and type(delete_access) is bool,
                 'ntfs.invalid_open_mode')
        self.assert_object(parent, directory=True, expected=expected_parent)
        encoded = name.encode('utf-16-le')
        text_buffer = C.create_unicode_buffer(name)
        text = _UnicodeString(len(encoded),len(encoded)+2,C.cast(text_buffer,C.c_void_p))
        attrs = _ObjectAttributes(C.sizeof(_ObjectAttributes),parent.value,C.pointer(text),0x1040,None,None)
        value, ios = C.c_void_p(), _IoStatus()
        disposition = 2 if exclusive else 1  # FILE_CREATE / FILE_OPEN. Never OVERWRITE.
        sharing = 3 if directory else 1
        access = 0x100000|0x80|1|2|(0x20 if directory else 0)|(0x10000 if delete_access else 0)
        started = time.monotonic_ns()
        status = self.nt.NtCreateFile(C.byref(value),access,C.byref(attrs),C.byref(ios),
            None,0x80,sharing,disposition,0x20|0x200000|(1 if directory else 0x40),None,0)
        event = {'api':'NtCreateFile','disposition':disposition,'directory':directory,'leaf':name,
                 'return_status':f'0x{status & 0xffffffff:08x}',
                 'io_status':f'0x{ios.Result.Status & 0xffffffff:08x}',
                 'information':ios.Information,'output_handle_present':bool(value.value),
                 'started_ns':started,'returned_ns':time.monotonic_ns(),
                 'effect_state':'created' if status==0 and ios.Result.Status==0 and exclusive
                     and ios.Information==2 else 'opened' if status==0 and ios.Result.Status==0
                     and not exclusive and ios.Information==1 else 'not_committed_by_this_call'
                     if not value.value and status & 0xffffffff in {0xc0000035,0xc0000022,0xc0000034,0xc000050b} else 'unknown'}
        self.events.append(event)
        result = None
        if value.value:
            result = self._adopt(value.value,directory=directory,rename_source=delete_access,
                                 namespace_flush=directory)
        try:
            if not (status==0 and ios.Result.Status==0 and result is not None
                    and ios.Information==(2 if exclusive else 1)):
                raise PhaseError(('ntfs.create_outcome_unknown' if exclusive else 'ntfs.open_outcome_unknown')
                                 if result is not None else
                                 ('ntfs.create_failed' if exclusive else 'ntfs.open_failed'),
                                 details={'event':event})
            identity = self.identity(result)
            event['object_identity'] = identity.as_dict()
            self._post(event,(parent,True,expected_parent),(result,directory,identity))
            if not directory: self._writable.add(result)
            if exclusive: self._created.add(result)
            return result
        except BaseException as primary:
            if result is not None:
                try: result.close()
                except BaseException as close_error:
                    event['close_error'] = _error_record(close_error)
                    raise PhaseError('ntfs.create_finalization_failed',details={
                        'primary_error':_error_record(primary),'event':event}) from primary
            raise

    @_mutation_call
    def create_exclusive(self, parent: NativeHandle, name: str, *, directory: bool,
                         expected_parent: NativeIdentity, delete_access: bool = False) -> NativeHandle:
        return self._open_disposition(parent,name,directory=directory,expected_parent=expected_parent,
                                      exclusive=True,delete_access=delete_access)

    @_mutation_call
    def open_writable(self, parent: NativeHandle, name: str, *, expected_parent: NativeIdentity,
                      expected: NativeIdentity) -> NativeHandle:
        result = self._open_disposition(parent,name,directory=False,expected_parent=expected_parent,exclusive=False)
        try:
            self.assert_object(result,directory=False,expected=expected)
            return result
        except BaseException as primary:
            try: result.close()
            except BaseException as error:
                raise PhaseError('ntfs.open_finalization_failed',details={
                    'primary_error':_error_record(primary),'close_error':_error_record(error)}) from primary
            raise

    @_mutation_call
    def write_chunk(self, file: NativeHandle, data: bytes, *, offset: int,
                    expected: NativeIdentity) -> int:
        self._checked_writable(file,expected)
        _require(type(data) is bytes and 0 < len(data) <= 1024**2 and type(offset) is int
                 and 0 <= offset <= 2*1024**3-len(data),'ntfs.invalid_write_range')
        position = C.c_int64()
        if not self.kernel.SetFilePointerEx(file.value,offset,C.byref(position),0):
            raise PhaseError('ntfs.seek_failed',details={'winerror':C.get_last_error()})
        _require(position.value == offset,'ntfs.seek_failed')
        buffer, written = C.create_string_buffer(data), C.c_uint32()
        started = time.monotonic_ns()
        result = self.kernel.WriteFile(file.value,buffer,len(data),C.byref(written),None)
        code = C.get_last_error() if not result else None
        event = {'api':'WriteFile','offset':offset,'requested':len(data),'succeeded':bool(result),
                 'reported_written':written.value,'winerror':code,'started_ns':started,
                 'returned_ns':time.monotonic_ns(),'object_identity':expected.as_dict()}
        self.events.append(event)
        self._post(event,(file,False,expected))
        if not result or not 0 < written.value <= len(data):
            raise PhaseError('ntfs.write_failed',details={'event':event})
        return written.value

    @_mutation_call
    def truncate(self, file: NativeHandle, *, length: int, expected: NativeIdentity) -> None:
        self._checked_writable(file,expected)
        _require(type(length) is int and 0 <= length <= 2*1024**3,'ntfs.invalid_truncate_range')
        position = C.c_int64()
        if not self.kernel.SetFilePointerEx(file.value,length,C.byref(position),0):
            raise PhaseError('ntfs.seek_failed',details={'winerror':C.get_last_error()})
        _require(position.value==length,'ntfs.seek_failed')
        started = time.monotonic_ns()
        result = self.kernel.SetEndOfFile(file.value)
        code = C.get_last_error() if not result else None
        event = {'api':'SetEndOfFile','length':length,'succeeded':bool(result),'winerror':code,
                 'started_ns':started,'returned_ns':time.monotonic_ns(),'object_identity':expected.as_dict()}
        self.events.append(event)
        self._post(event,(file,False,expected))
        if not result: raise PhaseError('ntfs.truncate_failed',details={'event':event})

    @_mutation_call
    def flush_file(self, file: NativeHandle, expected: NativeIdentity) -> dict:
        self._checked_writable(file,expected)
        ios, started = _IoStatus(), time.monotonic_ns()
        status = self.nt.NtFlushBuffersFileEx(file.value,0,None,0,C.byref(ios))
        event = {'api':'NtFlushBuffersFileEx','flags':0,'kind':'file',
                 'return_status':f'0x{status & 0xffffffff:08x}',
                 'io_status':f'0x{ios.Result.Status & 0xffffffff:08x}',
                 'accepted':status==0 and ios.Result.Status==0,'started_ns':started,
                 'returned_ns':time.monotonic_ns(),'object_identity':expected.as_dict()}
        self.events.append(event)
        self._post(event,(file,False,expected))
        if not event['accepted']: raise PhaseError('ntfs.flush_failed',details={'event':event})
        return event

    @_mutation_call
    def flush_namespace(self, parent: NativeHandle, expected: NativeIdentity) -> dict:
        event = super().flush_namespace(parent,expected)
        event['kind'] = 'directory'
        event['object_identity'] = expected.as_dict()
        self.events.append(event)
        if not event['accepted'] or 'post_observation_error' in event:
            raise PhaseError('ntfs.namespace_flush_failed',details={'event':event})
        return event

    def _name_effect(self, source: NativeHandle, parent: NativeHandle, name: str, *,
                     expected_source: NativeIdentity, expected_parent: NativeIdentity,
                     hardlink: bool, replace: bool) -> dict:
        self._require_active_mutation()
        _leaf(name)
        _require(type(hardlink) is bool and type(replace) is bool and not (hardlink and replace),
                 'ntfs.invalid_name_effect')
        self.assert_object(source,expected=expected_source)
        self.assert_object(parent,directory=True,expected=expected_parent)
        _require(expected_source.volume_serial == expected_parent.volume_serial,'ntfs.cross_volume_forbidden')
        _require(not (source.directory and (hardlink or replace)),'ntfs.directory_effect_forbidden')
        _require(hardlink or source.rename_source,'ntfs.source_lease_required')
        encoded = name.encode('utf-16-le')
        structure = _RenameInfoEx if replace else _RenameInfo
        buffer = C.create_string_buffer(C.sizeof(structure)+len(encoded))
        data = structure.from_buffer(buffer)
        if replace:
            # FileRenameInformationEx: preserve existing readers on the old
            # object while future opens resolve the replacement. No fallback
            # to legacy class 10, copy/delete, or bypass-access-check classes.
            data.Flags = 0x1 | 0x2  # REPLACE_IF_EXISTS | POSIX_SEMANTICS.
        else:
            data.ReplaceIfExists = 0
        data.RootDirectory,data.FileNameLength = parent.value,len(encoded)
        C.memmove(C.addressof(buffer)+structure.FileName.offset,encoded,len(encoded))
        ios, started = _IoStatus(), time.monotonic_ns()
        info_class = 11 if hardlink else 65 if replace else 10
        if not hardlink:
            # The original link may be the committed destination even when the
            # response is unknown. Never let a finally block delete it as a
            # temporary after any rename attempt.
            self._created.discard(source)
        status = self.nt.NtSetInformationFile(source.value,C.byref(ios),buffer,len(buffer),info_class)
        event = {'api':'NtSetInformationFile','class':info_class,'replace_if_exists':replace,'leaf':name,
                 'rename_flags':3 if replace else 0,
                 'source_identity':expected_source.as_dict(),'parent_identity':expected_parent.as_dict(),
                 'return_status':f'0x{status & 0xffffffff:08x}',
                 'io_status':f'0x{ios.Result.Status & 0xffffffff:08x}',
                 'started_ns':started,'returned_ns':time.monotonic_ns(),
                 'effect_state':'committed' if status==0 and ios.Result.Status==0
                     else 'not_committed_by_this_call' if status & 0xffffffff in {0xc0000035,0xc0000022}
                     else 'unknown'}
        self.events.append(event)
        self._post(event,(source,source.directory,expected_source),(parent,True,expected_parent))
        if event['effect_state']!='committed': raise PhaseError('ntfs.name_effect_failed',details={'event':event})
        return event

    @_mutation_call
    def rename(self, source: NativeHandle, parent: NativeHandle, name: str, *,
               expected_source: NativeIdentity, expected_parent: NativeIdentity, replace: bool = False) -> dict:
        return self._name_effect(source,parent,name,expected_source=expected_source,
                                 expected_parent=expected_parent,hardlink=False,replace=replace)

    def rename_noreplace(self, source: NativeHandle, parent: NativeHandle, destination: str, *,
                         expected_source: NativeIdentity, expected_parent: NativeIdentity) -> dict:
        # Close the inherited mutating entry point: every rename must revoke
        # temporary cleanup and retain its native event.
        return self.rename(source,parent,destination,expected_source=expected_source,
                           expected_parent=expected_parent,replace=False)

    @_mutation_call
    def hardlink_noreplace(self, source: NativeHandle, parent: NativeHandle, name: str, *,
                          expected_source: NativeIdentity, expected_parent: NativeIdentity) -> dict:
        return self._name_effect(source,parent,name,expected_source=expected_source,
                                 expected_parent=expected_parent,hardlink=True,replace=False)

    @_mutation_call
    def delete_created_link_and_close(self, source: NativeHandle, expected: NativeIdentity) -> dict:
        """Consume an original created handle, set disposition, then only close.

        Caller must remove this consumed handle from its cleanup stack. Unknown
        syscall/finalization outcome is never retried. No post-info is allowed.
        """
        self.assert_object(source,directory=False,expected=expected)
        _require(source in self._created and source.rename_source,'ntfs.created_delete_lease_required')
        delete, ios, started = C.c_uint8(1), _IoStatus(), time.monotonic_ns()
        event = {'api':'NtSetInformationFile','class':13,'delete':True,'object_identity':expected.as_dict(),
                 'started_ns':started,'effect_state':'unknown','finalization':'pending'}
        self.events.append(event)
        # Mark unusable BEFORE the syscall, also covering unknown responses.
        # NativeIO._live rejects this state for every inherited I/O entry point.
        source.finalization_state = 'closing'
        self._created.discard(source)
        self._writable.discard(source)
        primary = None
        try:
            status = self.nt.NtSetInformationFile(source.value,C.byref(ios),C.byref(delete),1,13)
            event.update(return_status=f'0x{status & 0xffffffff:08x}',
                         io_status=f'0x{ios.Result.Status & 0xffffffff:08x}',
                         returned_ns=time.monotonic_ns(),accepted=status==0 and ios.Result.Status==0)
            if not event['accepted']:
                raise PhaseError('ntfs.delete_disposition_failed',details={'event':event.copy()})
        except BaseException as error:
            primary = error
            event['primary_error'] = _error_record(error)
        try:
            closed = self.kernel.CloseHandle(source.value)
            error = C.get_last_error() if not closed else None
        except BaseException as close_error:
            closed, error = False, _error_record(close_error)
        if closed:
            self._handles.pop(source.value)
            source.value, source.finalization_state = None, 'closed'
            event['finalization'] = 'closed'
        else:
            source.finalization_state = 'unknown'
            event.update(finalization='unknown',close_error=error)
            raise PhaseError('ntfs.delete_finalization_failed',details={'event':event}) from primary
        if primary is not None:
            raise PhaseError('ntfs.delete_failed',details={'event':event}) from primary
        return event
