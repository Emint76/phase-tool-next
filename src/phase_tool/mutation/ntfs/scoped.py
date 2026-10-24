"""Internal native namespace pins; no installed provider or storage admission.

The grant is immutable data supplied by a future trusted composition. It is not
itself authorization or a qualification certificate. This module has no path
dispatcher, grant discovery, or fallback to host path IO. The closed archive
parent mode borrows an already active NativeMutationIO after GO; it is not
a filesystem admission, process owner or public request capability.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from ...errors import PhaseError
from ...paths import safe_relative_locator
from .native import NativeHandle, NativeIdentity, NativeIO, _error_record, _leaf, _require
from .mutating import NativeMutationIO


@dataclass(frozen=True)
class NativeRootGrant:
    binding: str
    device: str
    volume_guid: str
    volume_serial32: int
    components: tuple[str, ...]
    root_identity: NativeIdentity

    def __post_init__(self):
        _require(type(self.binding) is str and re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}',self.binding) is not None,
                 'ntfs.invalid_root_grant')
        _require(type(self.device) is str and re.fullmatch(r'\\Device\\HarddiskVolume[0-9]+',self.device) is not None,
                 'ntfs.invalid_root_grant')
        _require(type(self.volume_guid) is str and re.fullmatch(
            r'\\\\\?\\volume\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}\\',
            self.volume_guid) is not None, 'ntfs.invalid_root_grant')
        _require(type(self.volume_serial32) is int and 0 <= self.volume_serial32 < 2**32,
                 'ntfs.invalid_root_grant')
        _require(type(self.components) is tuple and bool(self.components),'ntfs.invalid_root_grant')
        for component in self.components:
            _leaf(component)
        _require(type(self.root_identity) is NativeIdentity,'ntfs.invalid_root_grant')
        NativeIdentity.parse(self.root_identity.as_dict())

    def as_dict(self) -> dict:
        return {'root_binding':self.binding,'device':self.device,'volume_guid':self.volume_guid,
                'volume_serial32':self.volume_serial32,'components':list(self.components),
                'native_identity':self.root_identity.as_dict()}


class NativeScopedTarget:
    """Pin all existing ancestors of one safe relative locator.

    Default and read-only modes never create parents. A private archive-only
    worker mode may provision relative parents under an existing grant.
    Construct only after the caller has authenticated its
    grant/intent. Does not implement the POSIX int-fd AuthorityProvider protocol.
    Existing root components currently obey the same ASCII policy as locators;
    this is an explicit candidate boundary, not universal Windows path support.
    """

    def __init__(self, io: NativeIO, grant: NativeRootGrant, locator: str, *, namespace_flush: bool = False,
                 _allow_missing_ancestors: bool = False, _create_ancestors: bool = False):
        _require(type(io) in (NativeIO,NativeMutationIO) and type(grant) is NativeRootGrant,
                 'ntfs.invalid_scope_owner')
        _require(type(namespace_flush) is bool and type(_allow_missing_ancestors) is bool
                 and type(_create_ancestors) is bool,
                 'ntfs.invalid_scope_mode')
        # A partial prefix is strictly a read-only absence observation.
        # It must never become a parent for NativeMutationIO.
        _require(not _allow_missing_ancestors or (type(io) is NativeIO and not namespace_flush),
                 'ntfs.partial_scope_read_only_required')
        _require(not _create_ancestors or (type(io) is NativeMutationIO and namespace_flush
                 and not _allow_missing_ancestors),'ntfs.archive_parent_mutation_owner_required')
        if _create_ancestors:
            io._assert_mutation_owner()
            _require(io.mutation_state == 'open','ntfs.archive_parent_session_unavailable')
        self._missing_ancestors: tuple[str, ...] = ()
        self._existing_relative: tuple[str, ...] = ()
        self.io,self.grant = io,grant
        self.locator = safe_relative_locator(locator)
        self.name = self.locator.split('/')[-1]
        self._handles: list[NativeHandle] = []
        self._relations: list[tuple[NativeHandle,str,NativeHandle,NativeIdentity]] = []
        self._state = 'opening'
        self.parent: NativeHandle | None = None
        self.parent_identity: NativeIdentity | None = None
        try:
            facts = self._volume()
            root = io.open_device_root(facts)
            self._handles.append(root)
            _require(io.identity(root).volume_serial == grant.root_identity.volume_serial,
                     'ntfs.scope_volume_identity_mismatch')
            components = (*grant.components,*self.locator.split('/')[:-1])
            for ordinal,component in enumerate(components):
                parent = root
                created = False
                observed_identity = None
                try:
                    if _create_ancestors and ordinal >= len(grant.components):
                        # A missing mutable-open would seal the attempt before
                        # create. Probe read-only first; retain its actual pin
                        # through a separately gated flush-capable open.
                        observed = io.child(parent,component,directory=True)
                        self._handles.append(observed)
                        observed_identity = io.identity(observed)
                        root = io.child(parent,component,directory=True,namespace_flush=True)
                    else:
                        root = io.child(parent,component,directory=True,
                                        namespace_flush=namespace_flush and (ordinal==len(components)-1
                                            or (_create_ancestors and ordinal==len(grant.components)-1)))
                except PhaseError as error:
                    # Grant components MUST all exist and match before
                    # any missing relative ancestor can mean absence.
                    if (_allow_missing_ancestors and ordinal >= len(grant.components)
                            and error.code == 'ntfs.open_failed'
                            and error.details == {'ntstatus':'0xc0000034'}):
                        relative_index = ordinal-len(grant.components)
                        self._existing_relative = tuple(self.locator.split('/')[:relative_index])
                        self._missing_ancestors = tuple(self.locator.split('/')[relative_index:])
                        root = parent
                        break
                    if (_create_ancestors and observed_identity is None and ordinal >= len(grant.components)
                            and error.code == 'ntfs.open_failed'
                            and error.details == {'ntstatus':'0xc0000034'}):
                        root = io.create_exclusive(parent,component,directory=True,
                            expected_parent=io.identity(parent))
                        created = True
                    else:
                        raise
                self._handles.append(root)
                identity = io.identity(root)
                if observed_identity is not None:
                    io.assert_object(root,directory=True,expected=observed_identity)
                self._relations.append((parent,component,root,identity))
                if created:
                    # Adopt/register before a possible flush error. The
                    # caller collects existing bounded mutation diagnostics
                    # after return OR error; no retry/reset after collision.
                    io.flush_namespace(parent,io.identity(parent))
                if ordinal == len(grant.components)-1:
                    _require(identity == grant.root_identity,'ntfs.granted_root_identity_mismatch')
            self.parent,self.parent_identity = root,io.identity(root)
            self._state = 'open'
            self.assert_bound()
        except BaseException as primary:
            try:
                self.close()
            except BaseException as close_error:
                raise PhaseError('ntfs.scope_initialization_finalization_failed',details={
                    'primary_error':_error_record(primary),'close_error':_error_record(close_error)}) from primary
            raise

    def _volume(self) -> dict:
        facts = self.io.volume()
        _require(facts['device']==self.grant.device and facts['volume_guid']==self.grant.volume_guid
                 and facts['volume_serial32']==self.grant.volume_serial32 and facts['filesystem']=='NTFS',
                 'ntfs.granted_volume_mapping_changed')
        return facts

    def assert_bound(self) -> None:
        _require(self._state=='open','ntfs.scope_closed_or_unknown')
        self._volume()
        for parent,name,opened,identity in self._relations:
            self.io.assert_object(parent,directory=True)
            self.io.assert_object(opened,directory=True,expected=identity)
            # Reopen every name with the same native no-reparse barrier; text
            # equality and a still-live old handle are not a binding check.
            with self.io.child(parent,name,directory=True) as fresh:
                self.io.assert_object(fresh,directory=True,expected=identity)
            self.io.assert_object(opened,directory=True,expected=identity)
        self.io.assert_object(self.parent,directory=True,expected=self.parent_identity)

    def ancestor_absence(self) -> dict | None:
        """Recheck ONLY a missing relative directory under a pinned prefix.

        No identity for the absent suffix is fabricated. This sampled
        read is not a reservation, atomic pair snapshot or mutation
        capability; callers must independently establish worker state.
        """
        self.assert_bound()
        if not self._missing_ancestors:
            return None
        try:
            handle = self.io.child(self.parent,self._missing_ancestors[0],directory=True)
        except PhaseError as error:
            if error.code != 'ntfs.open_failed' or error.details != {'ntstatus':'0xc0000034'}:
                raise
        else:
            with handle:
                self.io.assert_object(handle,directory=True)
            raise PhaseError('ntfs.missing_ancestor_appeared')
        self.assert_bound()
        return {'existing_relative_components':list(self._existing_relative),
                'missing_relative_components':list(self._missing_ancestors),
                'existing_parent_identity':self.parent_identity.as_dict()}

    def open_file(self, *, expected: NativeIdentity | None = None) -> NativeHandle:
        _require(not self._missing_ancestors,'ntfs.partial_scope_has_no_leaf_parent')
        self.assert_bound()
        result = self.io.child(self.parent,self.name,directory=False)
        try:
            self.io.assert_object(result,directory=False,expected=expected)
            self.assert_bound()
            return result
        except BaseException as primary:
            try:
                result.close()
            except BaseException as close_error:
                raise PhaseError('ntfs.scope_open_finalization_failed',details={
                    'primary_error':_error_record(primary),'close_error':_error_record(close_error)}) from primary
            raise

    def assert_file_name(self, handle: NativeHandle, expected: NativeIdentity) -> None:
        _require(not self._missing_ancestors,'ntfs.partial_scope_has_no_leaf_parent')
        self.assert_bound()
        self.io.assert_object(handle,directory=False,expected=expected)
        # Share=7 is required only for a source that already owns DELETE access.
        # It is an observation, not an independent NoDelete pin.
        with self.io._open(self.name,parent=self.parent,directory=False,sharing=7) as fresh:
            self.io.assert_object(fresh,directory=False,expected=expected)
        self.assert_bound()
        self.io.assert_object(handle,directory=False,expected=expected)

    def close(self) -> None:
        _require(self._state in ('open','opening'),'ntfs.scope_closed_or_unknown')
        self._state = 'closing'
        errors = []
        for handle in reversed(self._handles):
            try:
                handle.close()
            except BaseException as error:
                errors.append(_error_record(error))
        self._state = 'unknown' if errors else 'closed'
        if errors:
            raise PhaseError('ntfs.scope_finalization_failed',details={'errors':errors,'finalization':'unknown'})
        self._handles.clear()
        self._relations.clear()
        self.parent,self.parent_identity = None,None

    def __enter__(self):
        _require(self._state=='open','ntfs.scope_closed_or_unknown')
        return self

    def __exit__(self, kind, value, tb):
        try:
            self.close()
        except BaseException as error:
            if value is not None:
                raise PhaseError('ntfs.scope_finalization_failed',details={
                    'primary_error':_error_record(value),'close_error':_error_record(error)}) from value
            raise
