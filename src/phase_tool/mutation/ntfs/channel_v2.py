"""DRAFT closed protocol 1.1, reusing the existing owned byte transport.

Not selected, imported, executed or qualified. The 1.0 implementation retains
its default wire generation and behavior. Only a fixed trusted installation
may select this distinct class; no request/environment version parameter.
"""
from __future__ import annotations

import re

from .channel import LinuxNativeChannel, _DIGEST, _RUN
from .native import _require


class LinuxNativeChannelV2(LinuxNativeChannel):
    _PROTOCOL_VERSION = '1.1'

    def __init__(self, channel_id: str, *, _inspection_only: bool = False):
        # Base consumes its initialization attempt before any fallible pipe
        # check. A repeat fails before this subclass resets its terminal flag.
        super().__init__(channel_id)
        _require(type(_inspection_only) is bool, 'ntfs.fixed_role_required')
        self._inspection_only = _inspection_only
        self._finish_attempted = False

    def _request(self, kind, run_id, intent_digest, payload):
        # Executed under the same inherited owner/thread and nonreentrant gate.
        # Any rejection poisons the channel in the existing _exchange handler.
        _require(not self._inspection_only or kind == 'observe_file',
            'ntfs.inspection_only_operation_forbidden')
        _require(not self._finish_attempted, 'ntfs.channel_terminal_consumed')
        if kind != 'finish_without_execution':
            return super()._request(kind, run_id, intent_digest, payload)
        self._finish_attempted = True
        _require(not self._possible_dispatch, 'ntfs.channel_finish_after_possible_dispatch')
        _require(type(run_id) is str and _RUN.fullmatch(run_id) is not None, 'evidence.invalid_run_id')
        _require(intent_digest is None or (type(intent_digest) is str
            and _DIGEST.fullmatch(intent_digest) is not None), 'ntfs.invalid_intent_reference')
        _require(type(payload) is dict and set(payload) == {'operation_nonce', 'installation_digest'}
            and type(payload['operation_nonce']) is str
            and re.fullmatch(r'[0-9a-f]{32}', payload['operation_nonce']) is not None
            and type(payload['installation_digest']) is str
            and _DIGEST.fullmatch(payload['installation_digest']) is not None,
            'ntfs.channel_finish_binding_required')
        return payload

    def finish_without_execution(self, *, run_id: str, intent_digest: str | None,
                                 operation_nonce: str, installation_digest: str):
        """Ask the SAME trusted parent to consume its never-used execution slot.

        This does not authenticate that parent or infer no-worker from client
        state. The actual owner/installation and exact typed reply must be
        verified separately. A lost reply cannot resync, clear possible_dispatch,
        upgrade an outcome or authorize a second worker. It is not recovery.
        """
        return self._exchange('finish_without_execution', run_id, intent_digest,
            {'operation_nonce': operation_nonce, 'installation_digest': installation_digest})
