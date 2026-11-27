"""Version2 roles over the existing pinned native file observer.

Three sequential samples are not an atomic snapshot. No execution permission,
retry, evidence owner or version store is introduced by these functions.
"""
from ...canonical import canonical_bytes
from ...contracts.publish_new_version_v2 import object_locator
from ...paths import safe_relative_locator
from .native import NativeIdentity, _require
from .version1_observation import _observe_native_bounded_file, validate_version1_observation


_LIMIT = 512*1024
_NAMES = ('current', 'old_object', 'new_object')


def _version2_grants(value):
    """Pure exact two-root role checks; actual handles verify identities later."""
    from .worker import _grant
    _require(type(value) is list and len(value) == 2, 'ntfs.version2_root_grants')
    current, objects = [_grant(row) for row in value]
    _require([current.binding, objects.binding] == ['current_root', 'objects_root'],
        'ntfs.version2_root_grants')
    _require(current.volume_guid == objects.volume_guid
        and current.volume_serial32 == objects.volume_serial32
        and current.root_identity.volume_serial == objects.root_identity.volume_serial
        and current.root_identity != objects.root_identity, 'ntfs.version2_roots_not_separate')
    a, b = (tuple(part.casefold() for part in grant.components) for grant in (current, objects))
    _require(a[:len(b)] != b and b[:len(a)] != a, 'ntfs.version2_roots_not_separate')
    return {current.binding: current, objects.binding: objects}


def _version2_targets(effect):
    _require(type(effect) is dict and effect.get('kind') == 'publish_new_version'
        and type(effect.get('target')) is dict
        and set(effect['target']) == {'root_binding', 'relative_locator'}
        and effect['target']['root_binding'] == 'current_root', 'ntfs.version2_effect_binding')
    current = safe_relative_locator(effect['target']['relative_locator'])
    old = object_locator(effect['archive_digest'])
    new = object_locator(effect['content_digest'])
    _require(effect.get('archive_target') == {'root_binding': 'objects_root', 'relative_locator': old}
        and effect.get('content_object_target') == {'root_binding': 'objects_root', 'relative_locator': new},
        'ntfs.version2_effect_binding')
    return {'current': ('current_root', current), 'old_object': ('objects_root', old),
        'new_object': ('objects_root', new)}


def validate_version2_observation(raw, grant, locator):
    observed = validate_version1_observation(raw, grant, locator)
    _require(not observed['state']['exists'] or observed['state']['length'] <= _LIMIT,
        'ntfs.version2_file_too_large')
    return observed


def observe_version2_file(grant, locator, *, expected=None):
    return validate_version2_observation(_observe_native_bounded_file(grant, locator,
        expected=expected, _maximum_bytes=_LIMIT),
        grant.as_dict(), locator)


def validate_version2_triple(raw, grants, effect, *, expected_targets=None):
    accepted = _version2_grants(grants)
    targets = _version2_targets(effect)
    _require(type(raw) is dict and set(raw) == set(_NAMES), 'ntfs.version2_triple_shape')
    if expected_targets is not None:
        _require(type(expected_targets) is dict and set(expected_targets) == set(_NAMES),
            'ntfs.version2_observer_identity_mismatch')
        for identity in expected_targets.values():
            NativeIdentity.parse(identity)
    result = {}
    for name, (binding, locator) in targets.items():
        observed = validate_version2_observation(raw[name], accepted[binding].as_dict(), locator)
        if expected_targets is not None:
            _require(observed['native']['exists'] is True
                and canonical_bytes(observed['native']['native_identity']) == canonical_bytes(expected_targets[name]),
                'ntfs.version2_observer_identity_mismatch')
        result[name] = observed
    identities = {name: row['native']['native_identity'] for name, row in result.items()}
    for name in ('old_object', 'new_object'):
        _require(identities['current'] is None or identities[name] is None
            or identities['current'] != identities[name], 'ntfs.version2_current_object_alias')
    if identities['old_object'] is not None and identities['new_object'] is not None:
        _require((identities['old_object'] == identities['new_object']) ==
            (targets['old_object'] == targets['new_object']), 'ntfs.version2_object_identity_mismatch')
    return result


def observe_version2_triple(grants, effect, *, expected_targets=None):
    accepted = _version2_grants(grants)
    if expected_targets is not None:
        _require(type(expected_targets) is dict and set(expected_targets) == set(_NAMES),
            'ntfs.version2_observer_identity_mismatch')
        for identity in expected_targets.values():
            NativeIdentity.parse(identity)
    observed = {name: observe_version2_file(accepted[binding], locator,
        expected=None if expected_targets is None else NativeIdentity.parse(expected_targets[name]))
        for name, (binding, locator) in _version2_targets(effect).items()}
    return validate_version2_triple(observed, grants, effect, expected_targets=expected_targets)
