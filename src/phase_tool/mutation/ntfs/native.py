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
                raise PhaseError('ntfs.finalization_failed', details={
                    'primary_error': _error_record(value), 'close_error': _error_record(error)}) from value
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

    def _open(self, name: str, *, parent: NativeHandle | None, directory: bool,
              rename_source: bool = False, namespace_flush: bool = False,
              sharing: int = 3) -> NativeHandle:
        if parent is not None:
            self.assert_object(parent, directory=True)
            _leaf(name)
        _require(type(directory) is bool and type(rename_source) is bool and type(namespace_flush) is bool,
                 'ntfs.invalid_open_mode')
        _require(sharing in {3, 7} and (sharing == 3 or not (rename_source or namespace_flush)),
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
