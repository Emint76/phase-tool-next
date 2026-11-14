"""Internal Windows physical operations for a bounded Phase composition.

No command-line entry point, path dispatcher, create/write/delete operation,
network listener or fallback. Only an installation-owned publisher may select
roots; operation locators are relative to handles already pinned by that owner.
"""
from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
import hashlib
import os
import re
import struct
import threading
import time
from typing import Iterator

from ...errors import PhaseError
from ...paths import safe_relative_locator


def _require(value: bool, code: str) -> None:
    if not value:
        raise PhaseError(code)


def _error_record(error: BaseException) -> dict:
    return {'type': type(error).__name__, 'message': str(error),
            'code': getattr(error, 'code', None), 'details': getattr(error, 'details', {})}


def _finalization_failure(code, primary, finalization):
    # Lazy import keeps native <-> uncertainty initialization acyclic.
    # Reuse the existing bounded serializer after the close attempt has ended.
    from .uncertainty import _diagnostic
    error = PhaseError(code,details={'primary_error':_diagnostic(primary),
        'close_error':_diagnostic(finalization)})
    error.primary_error = primary
    error.finalization_error = finalization
    return error


def _leaf(value: str) -> str:
    _require(type(value) is str and '/' not in value, 'ntfs.invalid_leaf')
    return safe_relative_locator(value)


class _UnicodeString(C.Structure):
    _fields_ = [('Length', C.c_uint16), ('MaximumLength', C.c_uint16), ('Buffer', C.c_void_p)]


class _ObjectAttributes(C.Structure):
    _fields_ = [('Length', C.c_uint32), ('RootDirectory', C.c_void_p),
                ('ObjectName', C.POINTER(_UnicodeString)), ('Attributes', C.c_uint32),
                ('SecurityDescriptor', C.c_void_p), ('SecurityQoS', C.c_void_p)]


class _StatusUnion(C.Union):
    _fields_ = [('Status', C.c_int32), ('Pointer', C.c_void_p)]


class _IoStatus(C.Structure):
    _fields_ = [('Result', _StatusUnion), ('Information', C.c_size_t)]


class _RenameInfo(C.Structure):
    _fields_ = [('ReplaceIfExists', C.c_uint8), ('RootDirectory', C.c_void_p),
                ('FileNameLength', C.c_uint32), ('FileName', C.c_wchar * 1)]


class _IdentityInfo(C.Structure):
    _fields_ = [('VolumeSerialNumber', C.c_uint64), ('FileId', C.c_ubyte * 16)]


class _BasicInfo(C.Structure):
    _fields_ = [(name, C.c_uint32) for name in (
        'Attributes', 'CreationLow', 'CreationHigh', 'AccessLow', 'AccessHigh',
        'WriteLow', 'WriteHigh', 'VolumeSerial', 'SizeHigh', 'SizeLow',
        'Links', 'IndexHigh', 'IndexLow')]


@dataclass(frozen=True)
class NativeIdentity:
    volume_serial: int
    file_id: str

    def as_dict(self) -> dict:
        return {'volume_serial': self.volume_serial, 'file_id': self.file_id}

    @classmethod
    def parse(cls, value: object) -> 'NativeIdentity':
        _require(type(value) is dict and set(value) == {'volume_serial', 'file_id'}, 'ntfs.invalid_identity')
        _require(type(value['volume_serial']) is int and 0 <= value['volume_serial'] < 2**64,
                 'ntfs.invalid_identity')
        _require(type(value['file_id']) is str and re.fullmatch('[0-9a-f]{32}', value['file_id']) is not None,
                 'ntfs.invalid_identity')
        return cls(value['volume_serial'], value['file_id'])


class NativeHandle:
    def __init__(self, api: 'NativeIO', value: int, *, directory: bool, rename_source: bool = False,
                 namespace_flush: bool = False):
        self.api, self.value = api, value
        self.directory, self.rename_source, self.namespace_flush = directory, rename_source, namespace_flush
        self.finalization_state = 'open'

    def close(self) -> None:
        self.api._live(self)
        self.finalization_state = 'closing'
        try:
            closed = self.api.kernel.CloseHandle(self.value)
            error = C.get_last_error() if not closed else None
        except BaseException:
            self.finalization_state = 'unknown'
            raise
        if not closed:
            self.finalization_state = 'unknown'
            raise PhaseError('ntfs.close_failed', details={'winerror': error, 'finalization': 'unknown'})
        self.api._handles.pop(self.value)
        self.value, self.finalization_state = None, 'closed'

    def __enter__(self):
        return self

    def __exit__(self, kind, value, tb):
        try:
            self.close()
        except BaseException as error:
            if value is not None:
                raise _finalization_failure('ntfs.finalization_failed',value,error) from value
            raise


class NativeIO:
    """Handle-relative NT operations. The sole mutation is no-replace rename."""

    def __init__(self):
        _require(os.name == 'nt' and C.sizeof(C.c_void_p) == 8 and C.sizeof(C.c_wchar) == 2,
                 'ntfs.windows_amd64_required')
        shell = C.WinDLL('shell32')
        shell.IsUserAnAdmin.restype = C.c_int
        _require(not shell.IsUserAnAdmin(), 'ntfs.elevated_token_forbidden')
        self._handles: dict[int, NativeHandle] = {}
        self.nt = C.WinDLL('ntdll')
        self.kernel = C.WinDLL('kernel32', use_last_error=True)
        self.nt.NtOpenFile.argtypes = [C.POINTER(C.c_void_p), C.c_uint32, C.POINTER(_ObjectAttributes),
                                       C.POINTER(_IoStatus), C.c_uint32, C.c_uint32]
        self.nt.NtOpenFile.restype = C.c_int32
        self.nt.NtSetInformationFile.argtypes = [C.c_void_p, C.POINTER(_IoStatus), C.c_void_p,
                                                 C.c_uint32, C.c_int32]
        self.nt.NtSetInformationFile.restype = C.c_int32
        self.kernel.GetFileInformationByHandle.argtypes = [C.c_void_p, C.POINTER(_BasicInfo)]
        self.kernel.GetFileInformationByHandle.restype = C.c_int32
        self.kernel.GetFileInformationByHandleEx.argtypes = [C.c_void_p, C.c_int, C.c_void_p, C.c_uint32]
        self.kernel.GetFileInformationByHandleEx.restype = C.c_int32
        self.kernel.CloseHandle.argtypes = [C.c_void_p]
        self.kernel.CloseHandle.restype = C.c_int32
        self.kernel.GetCurrentProcess.argtypes = []
        self.kernel.GetCurrentProcess.restype = C.c_void_p
        self.kernel.IsWow64Process2.argtypes = [C.c_void_p, C.POINTER(C.c_uint16), C.POINTER(C.c_uint16)]
        self.kernel.IsWow64Process2.restype = C.c_int32
        self.kernel.ReadFile.argtypes = [C.c_void_p, C.c_void_p, C.c_uint32, C.POINTER(C.c_uint32), C.c_void_p]
        self.kernel.ReadFile.restype = C.c_int32
        self.kernel.SetFilePointerEx.argtypes = [C.c_void_p, C.c_int64, C.POINTER(C.c_int64), C.c_uint32]
        self.kernel.SetFilePointerEx.restype = C.c_int32
        self.nt.NtFlushBuffersFileEx.argtypes = [C.c_void_p, C.c_uint32, C.c_void_p, C.c_uint32,
                                                C.POINTER(_IoStatus)]
        self.nt.NtFlushBuffersFileEx.restype = C.c_int32
        self.kernel.QueryDosDeviceW.argtypes = [C.c_wchar_p, C.c_wchar_p, C.c_uint32]
        self.kernel.QueryDosDeviceW.restype = C.c_uint32
        self.kernel.GetVolumeNameForVolumeMountPointW.argtypes = [C.c_wchar_p, C.c_wchar_p, C.c_uint32]
        self.kernel.GetVolumeNameForVolumeMountPointW.restype = C.c_int32
        self.kernel.GetVolumeInformationW.argtypes = [C.c_wchar_p, C.c_wchar_p, C.c_uint32,
            C.POINTER(C.c_uint32), C.POINTER(C.c_uint32), C.POINTER(C.c_uint32), C.c_wchar_p, C.c_uint32]
        self.kernel.GetVolumeInformationW.restype = C.c_int32
        _require(C.sizeof(_ObjectAttributes) == 48 and C.sizeof(_IoStatus) == 16
                 and C.sizeof(_IdentityInfo) == 24 and _RenameInfo.RootDirectory.offset == 8
                 and _RenameInfo.FileName.offset == 20, 'ntfs.abi_mismatch')
        self.process_environment = self._process_environment()

    def _process_environment(self) -> dict:
        process = self.kernel.GetCurrentProcess()
        process_machine, native_machine = C.c_uint16(), C.c_uint16()
        if not self.kernel.IsWow64Process2(process, C.byref(process_machine), C.byref(native_machine)):
            raise PhaseError('ntfs.architecture_query_failed', details={'winerror': C.get_last_error()})
        _require(native_machine.value == 0x8664 and process_machine.value == 0,
                 'ntfs.native_amd64_required')
        security = C.WinDLL('advapi32', use_last_error=True)
        security.OpenProcessToken.argtypes = [C.c_void_p, C.c_uint32, C.POINTER(C.c_void_p)]
        security.OpenProcessToken.restype = C.c_int32
        security.GetTokenInformation.argtypes = [C.c_void_p, C.c_int, C.c_void_p, C.c_uint32,
                                                 C.POINTER(C.c_uint32)]
        security.GetTokenInformation.restype = C.c_int32
        token = C.c_void_p()
        if not security.OpenProcessToken(process, 8, C.byref(token)):  # TOKEN_QUERY only.
            raise PhaseError('ntfs.elevation_query_failed', details={'winerror': C.get_last_error()})
        primary = None
        try:
            elevated, length = C.c_uint32(), C.c_uint32()
            if not security.GetTokenInformation(token.value, 20, C.byref(elevated), C.sizeof(elevated), C.byref(length)):
                raise PhaseError('ntfs.elevation_query_failed', details={'winerror': C.get_last_error()})
            _require(length.value == C.sizeof(elevated) and elevated.value == 0,
                     'ntfs.elevated_token_forbidden')
        except BaseException as error:
            primary = error
            raise
        finally:
            if not self.kernel.CloseHandle(token.value):
                raise PhaseError('ntfs.elevation_handle_finalization_failed', details={
                    'winerror': C.get_last_error(), 'finalization': 'unknown',
                    'primary_error': _error_record(primary) if primary else None}) from primary
        # No token, SID or credentials are retained; only admission flags.
        return {'architecture': 'AMD64', 'elevated': False}

    def _live(self, handle: NativeHandle) -> None:
        _require(type(handle) is NativeHandle and handle.api is self
                 and handle.finalization_state == 'open' and type(handle.value) is int
                 and self._handles.get(handle.value) is handle, 'ntfs.invalid_or_closed_handle')

    def _adopt(self, value: int, **flags) -> NativeHandle:
        _require(type(value) is int and value not in self._handles and value > 0,
                 'ntfs.handle_ownership_conflict')
        result = NativeHandle(self, value, **flags)
        self._handles[value] = result
        return result

    def volume(self) -> dict:
        device = C.create_unicode_buffer(32768)
        guid = C.create_unicode_buffer(128)
        filesystem = C.create_unicode_buffer(128)
        serial, maximum, flags = C.c_uint32(), C.c_uint32(), C.c_uint32()
        if not self.kernel.QueryDosDeviceW('S:', device, len(device)):
            raise PhaseError('ntfs.device_query_failed', details={'winerror': C.get_last_error()})
        _require(re.fullmatch(r'\\Device\\HarddiskVolume[0-9]+', device.value) is not None,
                 'ntfs.local_fixed_volume_required')
        if not self.kernel.GetVolumeNameForVolumeMountPointW('S:\\', guid, len(guid)):
            raise PhaseError('ntfs.volume_query_failed', details={'winerror': C.get_last_error()})
        if not self.kernel.GetVolumeInformationW('S:\\', None, 0, C.byref(serial), C.byref(maximum),
                                                 C.byref(flags), filesystem, len(filesystem)):
            raise PhaseError('ntfs.volume_query_failed', details={'winerror': C.get_last_error()})
        _require(filesystem.value == 'NTFS', 'ntfs.filesystem_unsupported')
        return {'device': device.value, 'volume_guid': guid.value.lower(), 'volume_serial32': serial.value,
                'filesystem': filesystem.value, 'flags': flags.value}

    def input_volume(self,drive):
        _require(type(drive)is str and re.fullmatch('[A-Z]:',drive)is not None,'input_stage.local_drive_required')
        device=C.create_unicode_buffer(32768);guid=C.create_unicode_buffer(128);filesystem=C.create_unicode_buffer(128)
        serial,maximum,flags=C.c_uint32(),C.c_uint32(),C.c_uint32()
        if not self.kernel.QueryDosDeviceW(drive,device,len(device)):
            raise PhaseError('ntfs.device_query_failed',details={'winerror':C.get_last_error()})
        _require(re.fullmatch(r'\\Device\\HarddiskVolume[0-9]+',device.value)is not None,'ntfs.local_fixed_volume_required')
        if not self.kernel.GetVolumeNameForVolumeMountPointW(drive+'\\',guid,len(guid)):
            raise PhaseError('ntfs.volume_query_failed',details={'winerror':C.get_last_error()})
        if not self.kernel.GetVolumeInformationW(drive+'\\',None,0,C.byref(serial),C.byref(maximum),C.byref(flags),filesystem,len(filesystem)):
            raise PhaseError('ntfs.volume_query_failed',details={'winerror':C.get_last_error()})
        _require(filesystem.value=='NTFS','ntfs.filesystem_unsupported')
        return {'device':device.value,'volume_guid':guid.value.lower(),'volume_serial32':serial.value,'filesystem':filesystem.value,'flags':flags.value}

    def input_state(self,handle):
        self.assert_object(handle)
        basic=_InputBasicInfo()
        _require(C.sizeof(_InputBasicInfo)==40,'input_stage.basic_info_abi')
        if not self.kernel.GetFileInformationByHandleEx(handle.value,0,C.byref(basic),C.sizeof(basic)):
            raise PhaseError('ntfs.file_query_failed',details={'winerror':C.get_last_error()})
        info=self.info(handle)
        return {'native_identity':self.identity(handle).as_dict(),'length':info['length'],
            'attributes':info['attributes'],'links':info['links'],
            'creation_time':basic.creation,'write_time':basic.write,'change_time':basic.change}

    def input_snapshot(self,scope,source_locator,members,deadline_ns,*,_publication_root=None):
        return _NativeInputSnapshot(self,scope,source_locator,members,deadline_ns,
            _publication_root=_publication_root)


    def _open(self, name: str, *, parent: NativeHandle | None, directory: bool,
              rename_source: bool = False, namespace_flush: bool = False,
              sharing: int = 3, _input_name: bool = False) -> NativeHandle:
        if parent is not None:
            self.assert_object(parent, directory=True)
            _input_leaf(name)if _input_name else _leaf(name)
        _require(type(_input_name)is bool and (not _input_name or(parent is not None and sharing==1
            and not rename_source and not namespace_flush)),'input_stage.readonly_name_mode_required')
        _require(type(directory) is bool and type(rename_source) is bool and type(namespace_flush) is bool,
                 'ntfs.invalid_open_mode')
        _require(type(sharing)is int and sharing in {1, 3, 7} and (sharing == 3 or not (rename_source or namespace_flush)),
                 'ntfs.invalid_sharing_mode')
        encoded = name.encode('utf-16-le')
        _require(len(encoded) <= 65532 and '\0' not in name, 'ntfs.name_too_large')
        buffer = C.create_unicode_buffer(name)
        text = _UnicodeString(len(encoded), len(encoded) + 2, C.cast(buffer, C.c_void_p))
        attrs = _ObjectAttributes(C.sizeof(_ObjectAttributes), parent.value if parent else None,
                                  C.pointer(text), 0x40 | 0x1000, None, None)
        value, ios = C.c_void_p(), _IoStatus()
        access = (0x100000 | 0x80 | 1 | (0x20 if directory else 0)
                  | (0x10000 if rename_source else 0) | (2 if namespace_flush else 0))
        # Read-only data/list access, traversal and optional source DELETE.
        # Other processes cannot rename/delete this open object. No writes.
        status = self.nt.NtOpenFile(C.byref(value), access, C.byref(attrs), C.byref(ios), sharing,
                                    0x20 | 0x200000 | (1 if directory else 0x40))
        if status != 0:
            if value.value:
                # Only the initialized-NULL output of this own syscall is adopted;
                # never used for I/O, with one bounded finalization attempt.
                unexpected = self._adopt(value.value, directory=directory)
                detail = {'ntstatus': f'0x{status & 0xffffffff:08x}', 'output_handle': 'unexpected'}
                try:
                    unexpected.close()
                    detail['finalization'] = 'closed'
                except BaseException as close_error:
                    detail.update(finalization='unknown', close_error=_error_record(close_error))
                raise PhaseError('ntfs.open_outcome_unknown', details=detail)
            raise PhaseError('ntfs.open_failed', details={'ntstatus': f'0x{status & 0xffffffff:08x}'})
        result = self._adopt(value.value, directory=directory, rename_source=rename_source,
                             namespace_flush=namespace_flush)
        try:
            self.assert_object(result, directory=directory)
            return result
        except BaseException as primary:
            try:
                result.close()
            except BaseException as close_error:
                raise PhaseError('ntfs.open_finalization_failed', details={
                    'primary_error': _error_record(primary), 'close_error': _error_record(close_error)}) from primary
            raise

    def open_device_root(self, volume: dict) -> NativeHandle:
        _require(volume == self.volume(), 'ntfs.volume_mapping_changed')
        return self._open(volume['device'] + '\\', parent=None, directory=True)

    def child(self, parent: NativeHandle, name: str, *, directory: bool,
              rename_source: bool = False, namespace_flush: bool = False) -> NativeHandle:
        return self._open(name, parent=parent, directory=directory, rename_source=rename_source,
                           namespace_flush=namespace_flush)

    def identity(self, handle: NativeHandle) -> NativeIdentity:
        self._live(handle)
        data = _IdentityInfo()
        if not self.kernel.GetFileInformationByHandleEx(handle.value, 18, C.byref(data), C.sizeof(data)):
            raise PhaseError('ntfs.identity_query_failed', details={'winerror': C.get_last_error()})
        return NativeIdentity(data.VolumeSerialNumber, bytes(data.FileId).hex())

    def directory_stat_identity(self, handle: NativeHandle, expected: NativeIdentity) -> dict:
        """Actual bundle owner1.0 stat, never a fabricated POSIX root identity.

        Duplicate the SAME pinned directory HANDLE, transfer only that duplicate
        to CPython's CRT, and compare its real fstat with full native FileIdInfo.
        The original lease remains pinned. Unknown transfer/close is retained in
        the existing handle table and forbids a successful worker finalization.
        """
        import msvcrt
        import stat
        import sys
        _require(os.name == 'nt' and sys.implementation.name == 'cpython'
                 and sys.version_info[:3] == (3,12,10), 'ntfs.bundle_stat_runtime_required')
        _require(not getattr(self,'_bundle_stat_ownership_unknown',False),'ntfs.bundle_stat_ownership_unknown')
        self.assert_object(handle,directory=True,expected=expected)
        duplicate = C.c_void_p()
        kernel = self.kernel
        kernel.DuplicateHandle.argtypes = [C.c_void_p,C.c_void_p,C.c_void_p,
            C.POINTER(C.c_void_p),C.c_uint32,C.c_int32,C.c_uint32]
        kernel.DuplicateHandle.restype = C.c_int32
        process = kernel.GetCurrentProcess()
        success = kernel.DuplicateHandle(process,handle.value,process,C.byref(duplicate),0,False,2)
        error = C.get_last_error() if not success else None
        if not success or not duplicate.value:
            if duplicate.value:self._bundle_stat_ownership_unknown = True
            raise PhaseError('ntfs.bundle_stat_duplicate_failed',details={
                'winerror':error,'output_handle_present':bool(duplicate.value),
                'ownership':'unproven'})
        try:
            borrowed = self._adopt(duplicate.value,directory=True)
        except BaseException:
            # A registration conflict or interrupted adoption never licenses
            # closing a value that might belong to an already registered owner.
            self._bundle_stat_ownership_unknown = True
            raise
        pre_crt_primary = None
        try:
            self.assert_object(borrowed,directory=True,expected=expected)
            # Consume BEFORE calling the transfer API: an exception never licenses
            # closing or re-transferring a possibly already CRT-owned HANDLE.
            borrowed.finalization_state = 'crt_transfer_pending'
            try:
                descriptor = msvcrt.open_osfhandle(borrowed.value,os.O_RDONLY|os.O_BINARY)
            except BaseException:
                borrowed.finalization_state = 'unknown'
                self._bundle_stat_ownership_unknown = True
                raise
            borrowed.finalization_state = 'crt_owned'
            primary = None
            try:
                info = os.fstat(descriptor)
                _require(stat.S_ISDIR(info.st_mode)
                    and type(info.st_dev) is int and type(info.st_ino) is int
                    and info.st_dev == expected.volume_serial
                    and info.st_ino == int.from_bytes(bytes.fromhex(expected.file_id),'little')
                    and info.st_ino > 0, 'ntfs.bundle_stat_identity_mismatch')
            except BaseException as caught:
                primary = caught
                raise
            finally:
                borrowed.finalization_state = 'closing'
                try:
                    os.close(descriptor)  # Exactly one CRT close, never CloseHandle afterwards.
                except BaseException as close_error:
                    borrowed.finalization_state = 'unknown'
                    self._bundle_stat_ownership_unknown = True
                    if primary is not None:
                        raise _finalization_failure('ntfs.bundle_stat_finalization_failed',primary,close_error) from primary
                    raise
                self._handles.pop(borrowed.value)
                borrowed.value,borrowed.finalization_state = None,'closed'
            self.assert_object(handle,directory=True,expected=expected)
            return {'device':info.st_dev,'inode':info.st_ino}
        except BaseException as caught:
            pre_crt_primary = caught
            raise
        finally:
            # Only a duplicate NEVER transferred to CRT can use native close.
            # Unknown transfer/close stays registered; do not retry either API.
            if borrowed.finalization_state == 'open':
                try:borrowed.close()
                except BaseException as close_error:
                    self._bundle_stat_ownership_unknown = True
                    if pre_crt_primary is not None:
                        raise _finalization_failure('ntfs.bundle_stat_finalization_failed',
                            pre_crt_primary,close_error) from pre_crt_primary
                    raise

    def info(self, handle: NativeHandle) -> dict:
        self._live(handle)
        data = _BasicInfo()
        if not self.kernel.GetFileInformationByHandle(handle.value, C.byref(data)):
            raise PhaseError('ntfs.file_query_failed', details={'winerror': C.get_last_error()})
        return {'attributes': data.Attributes, 'length': data.SizeHigh << 32 | data.SizeLow,
                'links': data.Links}

    def assert_object(self, handle: NativeHandle, *, directory: bool | None = None,
                      expected: NativeIdentity | None = None) -> dict:
        self._live(handle)
        info = self.info(handle)
        wanted = handle.directory if directory is None else directory
        _require(type(wanted) is bool and bool(info['attributes'] & 0x10) == wanted,
                 'ntfs.object_type_mismatch')
        _require(not info['attributes'] & 0x400, 'ntfs.reparse_forbidden')
        if expected is not None:
            _require(type(expected) is NativeIdentity and self.identity(handle) == expected,
                     'ntfs.object_identity_mismatch')
        return info

    def read_chunks(self, handle: NativeHandle, maximum: int) -> Iterator[bytes]:
        _require(type(maximum) is int and 0 <= maximum <= 2 * 1024**3, 'ntfs.invalid_read_bound')
        self.assert_object(handle, directory=False)
        position = C.c_int64()
        if not self.kernel.SetFilePointerEx(handle.value, 0, C.byref(position), 0):
            raise PhaseError('ntfs.seek_failed', details={'winerror': C.get_last_error()})
        _require(position.value == 0, 'ntfs.seek_failed')
        total = 0
        buffer = C.create_string_buffer(1024**2)
        while True:
            self.assert_object(handle, directory=False)
            count = C.c_uint32()
            size = min(len(buffer), max(1, maximum - total + 1))
            if not self.kernel.ReadFile(handle.value, buffer, size, C.byref(count), None):
                raise PhaseError('ntfs.read_failed', details={'winerror': C.get_last_error()})
            self.assert_object(handle, directory=False)
            if count.value == 0:
                return
            total += count.value
            _require(total <= maximum, 'ntfs.read_limit')
            yield buffer.raw[:count.value]

    def hash_file(self, handle: NativeHandle, length: int) -> tuple[str, int]:
        _require(type(length) is int and 0 <= length <= 2 * 1024**3, 'ntfs.invalid_read_bound')
        self.assert_object(handle, directory=False)
        _require(self.info(handle)['length'] == length, 'ntfs.length_mismatch')
        before = self.identity(handle)
        digest, observed = hashlib.sha256(), 0
        for chunk in self.read_chunks(handle, length):
            digest.update(chunk)
            observed += len(chunk)
        _require(observed == length and self.identity(handle) == before
                 and self.info(handle)['length'] == length, 'ntfs.file_changed')
        self.assert_object(handle, directory=False, expected=before)
        return 'sha256:' + digest.hexdigest(), observed

    def entries(self, handle: NativeHandle, maximum_entries: int) -> dict[str, dict]:
        _require(type(maximum_entries) is int and 1 <= maximum_entries <= 1026, 'ntfs.invalid_listing_bound')
        expected = self.identity(handle)
        entries: dict[str, dict] = {}
        first = True
        while True:
            self.assert_object(handle, directory=True, expected=expected)
            buffer = C.create_string_buffer(64 * 1024)
            C.set_last_error(0)
            result = self.kernel.GetFileInformationByHandleEx(handle.value, 20 if first else 19,
                                                               buffer, len(buffer))
            code = C.get_last_error() if not result else None
            try:
                self.assert_object(handle, directory=True, expected=expected)
            except BaseException as error:
                raise PhaseError('ntfs.directory_post_observation_failed', details={
                    'query_succeeded': bool(result), 'query_winerror': code,
                    'post_observation_error': _error_record(error)}) from error
            first = False
            if not result:
                if code == 18:  # ERROR_NO_MORE_FILES
                    return entries
                raise PhaseError('ntfs.directory_query_failed', details={'winerror': code})
            data, offset = buffer.raw, 0
            while True:
                _require(offset + 88 <= len(data), 'ntfs.invalid_directory_record')
                following = struct.unpack_from('<I', data, offset)[0]
                attributes, name_length = struct.unpack_from('<II', data, offset + 56)
                _require(name_length % 2 == 0 and offset + 88 + name_length <= len(data),
                         'ntfs.invalid_directory_record')
                name = data[offset + 88: offset + 88 + name_length].decode('utf-16-le')
                if name not in {'.', '..'}:
                    _leaf(name)
                    _require(name not in entries and len(entries) < maximum_entries, 'ntfs.directory_entry_limit')
                    _require(not attributes & 0x400, 'ntfs.reparse_forbidden')
                    entries[name] = {'directory': bool(attributes & 0x10),
                        'file_id': data[offset + 72: offset + 88].hex()}
                if not following:
                    break
                _require(following % 8 == 0 and following >= 88 + name_length
                         and offset + following < len(data), 'ntfs.invalid_directory_record')
                offset += following

    def rename_noreplace(self, source: NativeHandle, parent: NativeHandle, destination: str, *,
                         expected_source: NativeIdentity, expected_parent: NativeIdentity) -> dict:
        _leaf(destination)
        self.assert_object(source, directory=True, expected=expected_source)
        self.assert_object(parent, directory=True, expected=expected_parent)
        _require(source.rename_source, 'ntfs.source_lease_required')
        _require(expected_source.volume_serial == expected_parent.volume_serial,
                 'ntfs.cross_volume_forbidden')
        encoded = destination.encode('utf-16-le')
        buffer = C.create_string_buffer(C.sizeof(_RenameInfo) + len(encoded))
        data = _RenameInfo.from_buffer(buffer)
        data.ReplaceIfExists, data.RootDirectory, data.FileNameLength = 0, parent.value, len(encoded)
        C.memmove(C.addressof(buffer) + _RenameInfo.FileName.offset, encoded, len(encoded))
        ios = _IoStatus()
        before = time.monotonic_ns()
        status = self.nt.NtSetInformationFile(source.value, C.byref(ios), buffer, len(buffer), 10)
        return {'api': 'NtSetInformationFile', 'class': 10, 'replace_if_exists': False,
                'return_status': f'0x{status & 0xffffffff:08x}',
                'io_status': f'0x{ios.Result.Status & 0xffffffff:08x}',
                'effect_state': 'committed' if status == 0 and ios.Result.Status == 0 else
                    'not_committed_by_this_call' if status & 0xffffffff in {0xc0000035, 0xc0000022} else 'unknown',
                'observation_required': True,
                'started_ns': before, 'returned_ns': time.monotonic_ns()}

    def observe_committed_name(self, parent: NativeHandle, source: NativeHandle, destination: str, *,
                               expected_source: NativeIdentity, expected_parent: NativeIdentity) -> NativeHandle:
        """Read-only name observation while the original DELETE handle pins source.

        The observing handle must share DELETE with the already-open source;
        the original handle still denies every other DELETE open.
        """
        self.assert_object(parent, directory=True, expected=expected_parent)
        self.assert_object(source, directory=True, expected=expected_source)
        _require(source.rename_source, 'ntfs.source_lease_required')
        result = self._open(destination, parent=parent, directory=True, sharing=7)
        try:
            self.assert_object(result, directory=True, expected=expected_source)
        except BaseException as primary:
            try:
                result.close()
            except BaseException as close_error:
                raise PhaseError('ntfs.observation_finalization_failed', details={
                    'primary_error': _error_record(primary), 'close_error': _error_record(close_error)}) from primary
            raise
        return result

    def flush_namespace(self, parent: NativeHandle, expected: NativeIdentity) -> dict:
        """Actual normal NTFS flush request. G06 equivalence needs qualification."""
        self.assert_object(parent, directory=True, expected=expected)
        _require(parent.namespace_flush, 'ntfs.flush_access_required')
        ios = _IoStatus()
        started = time.monotonic_ns()
        status = self.nt.NtFlushBuffersFileEx(parent.value, 0, None, 0, C.byref(ios))
        event = {'api': 'NtFlushBuffersFileEx', 'flags': 0, 'parameters_size': 0,
                 'return_status': f'0x{status & 0xffffffff:08x}',
                 'io_status': f'0x{ios.Result.Status & 0xffffffff:08x}',
                 'accepted': status == 0 and ios.Result.Status == 0,
                 'started_ns': started, 'returned_ns': time.monotonic_ns()}
        try:
            self.assert_object(parent, directory=True, expected=expected)
        except BaseException as error:
            event['post_observation_error'] = _error_record(error)
        return event


def _input_leaf(value):
    """Readonly source spelling only; target/member _leaf stays unchanged."""
    _require(type(value)is str and value not in{'','.','..'}and not value.endswith(('.', ' '))
        and not any(ord(c)<32 or c in '<>:"/\\|?*'for c in value),'input_stage.invalid_source_leaf')
    try:encoded=value.encode('utf-16-le',errors='strict')
    except UnicodeError as error:raise PhaseError('input_stage.invalid_source_unicode')from error
    _require(0<len(encoded)<=510,'input_stage.source_leaf_utf16_bound')
    # Win32 DOS aliases remain forbidden, including superscript device digits
    # and spaces before an extension. No DOS/device/ADS normalization occurs.
    stem=value.split('.',1)[0].rstrip(' ').casefold()
    _require(stem not in{'con','prn','aux','nul','conin$','conout$','clock$'}and re.fullmatch(r'(?:com|lpt)[1-9\u00b9\u00b2\u00b3]',stem)is None,
        'input_stage.source_device_name')
    return value


class _InputBasicInfo(C.Structure):
    _fields_=[('creation',C.c_int64),('access',C.c_int64),('write',C.c_int64),('change',C.c_int64),('attributes',C.c_uint32)]


class _InputPublicationRootOverlap(Exception):
    """Raised only for overlapping pinned roots; caller must confirm closure."""


class _NativeInputSnapshot:
    """Readonly retained source handles; only existing NativeIO performs APIs.

    Ordinary input-directory admission is installation-owned. Selected file
    handles deny write/delete sharing. Directory observations are freshly
    rechecked; this does not assert global or adversarial lifetime immutability.
    """
    def __init__(self,api,scope,source_locator,members,deadline_ns,*,_publication_root=None):
        from pathlib import PureWindowsPath
        from ...bundle import validate_members
        self.api=api;self.scope=scope;self.deadline=deadline_ns
        self.owner=(os.getpid(),threading.get_ident());self.handles=[]
        self.files=[];self.directories={};self.anchors=[];self.records=[];self.close_attempted=False
        root=PureWindowsPath(scope['windows_root']);self.drive=root.drive
        primary=None
        try:
            self._time()
            _require(api.input_volume(self.drive)==scope['volume'],'input_stage.volume_mapping_changed')
            device=self._adopt(api._open(scope['volume']['device']+'\\',parent=None,directory=True))
            self.anchors.append((device,api.identity(device)))
            parent=device
            for component in root.parts[1:]:
                parent=self._adopt(api._open(component,parent=parent,directory=True,sharing=1,_input_name=True))
                self.anchors.append((parent,api.identity(parent)))
            api.assert_object(parent,directory=True,expected=NativeIdentity.parse(scope['root_identity']))
            self.root=parent
            if _publication_root is not None:
                self._check_publication_root(*_publication_root)
            from .input_stage import _safe_input_locator
            source_locator=_safe_input_locator(source_locator)
            components=source_locator.split('/')
            source=parent
            for ordinal,component in enumerate(components):
                directory=members is not None or ordinal<len(components)-1
                # Scope/locator ancestors are pinned, not fully enumerated.
                # A directory-once grant has no 1024-file global census cap.
                _input_leaf(component)
                source=self._adopt(api._open(component,parent=source,directory=directory,sharing=1,_input_name=True))
                api.assert_object(source,directory=directory)
                _require(api.identity(source).volume_serial==NativeIdentity.parse(scope['root_identity']).volume_serial,
                    'input_stage.foreign_source_volume')
                if directory:self.anchors.append((source,api.identity(source)))
            if members is None:
                self._file(source,'payload')
            else:
                for member in validate_members(members):
                    current=source;parts=member.split('/')
                    for ordinal,component in enumerate(parts):
                        self._directory(current)
                        directory=ordinal<len(parts)-1
                        key=(current.value,component.casefold(),directory)
                        if not hasattr(self,'selected'):self.selected={}
                        if key not in self.selected:self.selected[key]=self._selected(current,component,directory)
                        current=self.selected[key]
                    self._file(current,member)
            self.verify_complete()
        except BaseException as error:primary=error
        if primary is not None:
            try:self.close()
            except BaseException as close_error:
                raise BaseExceptionGroup('input source acquisition and close failed',[primary,close_error])
            raise primary

    def _check_publication_root(self,grant,locator):
        from .scoped import NativeScopedTarget

        self.verify_complete()
        source_volume=self.scope['volume']
        same_device=source_volume['device']==grant.device
        same_guid=source_volume['volume_guid']==grant.volume_guid
        _require(same_device==same_guid and (not same_guid or source_volume['volume_serial32']==grant.volume_serial32),
            'input_stage.publication_volume_identity_mismatch')
        # The leaf is never opened. A single-component locator pins the grant
        # itself and excludes every caller-selected descendant from this check.
        with NativeScopedTarget(self.api,grant,locator.rsplit('/',1)[-1]) as target:
            self._time()
            target_ancestry=target._pinned_root_ancestry()
            source_ancestry=tuple(identity for _,identity in self.anchors)
            self.verify_complete()
            _require(not same_guid or (source_ancestry[0]==target_ancestry[0]
                and source_ancestry[-1].volume_serial==target_ancestry[-1].volume_serial),
                'input_stage.publication_volume_identity_mismatch')
            overlap=same_guid and (source_ancestry[-1] in target_ancestry or target_ancestry[-1] in source_ancestry)
        self._time()
        if overlap:
            raise _InputPublicationRootOverlap()

    def _time(self):
        _require(self.owner==(os.getpid(),threading.get_ident())and not self.close_attempted,
            'input_stage.source_owner_consumed')
        _require(type(self.deadline)is int and time.perf_counter_ns()<self.deadline,'input_stage.deadline')

    def _adopt(self,handle):
        # Append actual owned handle before any later query can fail.
        self.handles.append(handle);self._time();return handle

    def _directory(self,handle):
        if handle.value in self.directories:return
        self._time();self.api.assert_object(handle,directory=True)
        self.directories[handle.value]=(handle,self.api.identity(handle))

    def _selected(self,parent,name,directory):
        self._time();_input_leaf(name)
        child=self._adopt(self.api._open(name,parent=parent,directory=directory,sharing=1,_input_name=True))
        expected=self.api.identity(child)
        self.api.assert_object(child,directory=directory,expected=expected)
        _require(expected.volume_serial==NativeIdentity.parse(self.scope['root_identity']).volume_serial,'input_stage.foreign_source_volume')
        return child

    def _file(self,handle,path):
        self._time();state=self.api.input_state(handle)
        _require(not handle.directory and state['links']==1,'input_stage.source_hardlink')
        _require(all(old['native_identity']!=state['native_identity']for _,old in self.files),
            'input_stage.source_physical_alias')
        self.files.append((handle,state))
        self.records.append({'path':path,'length':state['length'],'native_identity':state['native_identity'],'state':state})

    def chunks(self,index):
        self._time();_require(type(index)is int and 0<=index<len(self.files),'input_stage.member_index')
        handle,state=self.files[index];length=state['length'];seen=0
        _require(self.api.input_state(handle)==state,'input_stage.source_changed')
        buffered=bytearray()
        for large in self.api.read_chunks(handle,length):
            self._time();buffered.extend(large)
            while len(buffered)>=256*1024:
                piece=bytes(buffered[:256*1024]);del buffered[:256*1024]
                self._time();seen+=len(piece)
                _require(seen<=length and self.api.input_state(handle)==state,'input_stage.source_changed')
                yield piece
        if buffered:
            self._time();seen+=len(buffered)
            _require(seen<=length and self.api.input_state(handle)==state,'input_stage.source_changed')
            yield bytes(buffered)
        _require(seen==length and self.api.input_state(handle)==state,'input_stage.source_changed')

    def verify_complete(self):
        self._time()
        _require(self.api.input_volume(self.drive)==self.scope['volume'],'input_stage.volume_mapping_changed')
        for handle,identity in self.anchors:
            self._time();self.api.assert_object(handle,directory=True,expected=identity)
        for handle,identity in self.directories.values():
            self._time();self.api.assert_object(handle,directory=True,expected=identity)
        for handle,state in self.files:
            self._time();_require(self.api.input_state(handle)==state,'input_stage.source_changed')

    def close(self):
        _require(self.owner==(os.getpid(),threading.get_ident())and not self.close_attempted,
            'input_stage.source_close_consumed')
        self.close_attempted=True;errors=[]
        for handle in reversed(self.handles):
            try:handle.close()
            except BaseException as error:errors.append(error)
        if errors:raise BaseExceptionGroup('input source handle finalization failed',errors)
