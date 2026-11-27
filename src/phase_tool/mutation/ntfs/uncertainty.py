"""Transient native uncertainty; never a receipt, retry gate or new journal.
DRAFT source only: not imported, installed, executed or qualified.
"""
from __future__ import annotations

import re

from ...canonical import canonical_bytes, digest_bytes, parse_json_bytes
from ...errors import PhaseError
from .native import _error_record


# Construction must keep its type even if diagnostic formatting itself fails.
# nulls describe unknown facts, never absence or a no-dispatch assertion.
_FALLBACK = b'{"common_guard_finalized":null,"effect_plan_digest":null,"intent_digest":null,"native_unresolved_version":"1.0","original_intent_recording_started":null,"possible_dispatch":null,"primary":null,"proof_publication_attempted":null,"receipt_publication_attempted":null,"reporting_error":true,"retry_authorized":false,"run_id":null,"secondary":[]}'
_REPORTING_ERROR = {'type': 'unavailable', 'code': None,
    'message': 'Diagnostic formatting failed; operation remains unresolved',
    'details': {'reporting_error': True}}


def _diagnostic(error):
    try:
        record = _error_record(error)
        raw = canonical_bytes(record)
        if len(raw) <= 16*1024:
            return parse_json_bytes(raw, maximum_bytes=16*1024)
        return {'type': 'oversized', 'code': None,
            'message': 'Oversized diagnostic omitted; operation remains unresolved',
            'details': {'omitted': True, 'sha256': digest_bytes(raw), 'length': len(raw)}}
    except BaseException:
        # No recursive attempt to stringify or canonicalize the reporting error.
        return dict(_REPORTING_ERROR)


def _nullable_digest(value):
    return value if type(value) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', value) else None


def _nullable_bool(value):
    return value if type(value) is bool else None


class _NativeLifecycleUnresolved(PhaseError):
    """Known failure with an immutable best-effort context snapshot.

    None receipt_digest is unconfirmed, NOT absent: a failed directory fsync
    may follow a visible receipt link. Reporting failures remain this exact
    uncertainty type, including failure while reading/formatting the context.
    """

    def __init_subclass__(cls, **kwargs):
        raise TypeError('native uncertainty is a closed internal type')

    def __init__(self, *, request, context, authority, primary, secondary=()):
        if getattr(self, '_initialization_attempted', False):
            raise self
        self._initialization_attempted = True
        self._state_bytes = _FALLBACK
        try:
            state = parse_json_bytes(_FALLBACK)
            state['reporting_error'] = False
            # Independently preserve each known fact. A broken prepared getter
            # must not erase an already known possible GO or receipt attempt.
            try:
                run_id = request.run_id
                if type(run_id) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', run_id):
                    state['run_id'] = run_id
            except BaseException:
                state['reporting_error'] = True
            for output, owner, attribute in (
                ('original_intent_recording_started', context, 'intent_recording_started'),
                ('proof_publication_attempted', context, 'proof_publication_attempted'),
                ('receipt_publication_attempted', context, 'publication_attempted'),
                ('common_guard_finalized', context, 'common_guard_finalized')):
                try:
                    state[output] = _nullable_bool(getattr(owner, attribute))
                except BaseException:
                    state['reporting_error'] = True
            try:
                state['possible_dispatch'] = _nullable_bool(authority.channel.possible_dispatch)
            except BaseException:
                state['reporting_error'] = True
            try:
                state['intent_digest'] = _nullable_digest(context.original_intent_digest)
            except BaseException:
                state['reporting_error'] = True
            try:
                prepared = context.prepared
                state['effect_plan_digest'] = _nullable_digest(
                    None if prepared is None else prepared.effect_plan_digest)
            except BaseException:
                state['reporting_error'] = True
            state['primary'] = _diagnostic(primary)
            try:
                state['secondary'] = [_diagnostic(error) for error in secondary[:16]]
                state['secondary_omitted_count'] = max(0, len(secondary)-16)
            except BaseException:
                state['reporting_error'] = True
            try:
                notes = getattr(primary, '__notes__', ())
                state['primary_notes'] = [note[:512] if type(note) is str else
                    'Non-text diagnostic note omitted' for note in notes[:16]]
                state['primary_notes_omitted_count'] = max(0, len(notes)-16)
            except BaseException:
                state['reporting_error'] = True
            raw = canonical_bytes(state)
            if len(raw) <= 320*1024:
                self._state_bytes = raw
        except BaseException:
            # Last-resort literal unknown snapshot; never ordinary rejection.
            pass
        super().__init__('ntfs.native_lifecycle_unresolved')

    @property
    def diagnostic(self):
        return parse_json_bytes(self._state_bytes, maximum_bytes=320*1024)

    def command_result(self, command):
        # Trusted application supplies one of the schema's three commands.
        # Invalid delivery callers must fail at the fixed serializer; they never
        # become ordinary rejection responses or canonical receipts.
        state = self.diagnostic
        return {'stage3_command_result_version': '1.2', 'command': command,
            'success': False, 'run_id': state['run_id'],
            'terminal_status': None, 'execution_disposition': None,
            'mutation_attempted': None, 'receipt_digest': None,
            'effect_plan_digest': state['effect_plan_digest'],
            'intent_digest': state['intent_digest'], 'target_verified': None,
            'blockers': ['ntfs.native_lifecycle_unresolved'],
            'error': 'ntfs.native_lifecycle_unresolved', 'exit_code': 40,
            'inspection_required': True, 'retry_authorized': False,
            'possible_dispatch': state['possible_dispatch'],
            'receipt_publication_attempted': state['receipt_publication_attempted'],
            'diagnostic_digest': digest_bytes(self._state_bytes)}
