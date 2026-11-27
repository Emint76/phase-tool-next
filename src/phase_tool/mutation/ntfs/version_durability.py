"""Pure correlation for new version-kernel durability facts.

No target IO, authority, receipt owner or reinterpretation of legacy records.
Marker-free historical evidence remains under its historical verifier branch.
"""
from .native import NativeIdentity,_require


def durability_binding(identity,parent_identity):
    """Kernel calls only after actual file+namespace flushes returned success."""
    _require(type(identity)is NativeIdentity and type(parent_identity)is NativeIdentity,
        'ntfs.version_durability_identity')
    return {'object_identity':identity.as_dict(),'parent_identity':parent_identity.as_dict(),
        'file_data_flushed':True,'parent_namespace_flushed':True}


def verify_version_durability(physical,role,observations):
    from .version_failure_completion import _closed_synchronous_trace,_mutex_closed
    from .root_lock import root_mutex_name
    from .worker import _grant
    from .version2_observation import _version2_grants
    names={'current','archive'}if role=='Version1'else{'current','old_object','new_object'}if role=='Version2'else set()
    if role=='Version1':
        _require(type(observations)is dict and set(observations)=={'observation_pair_version','current','archive'}
            and observations['observation_pair_version']=='1.0','ntfs.version_durability_unproven')
        observations={name:observations[name]for name in names}
    _require(bool(names)and physical.get('native_version_durability_version')=='1.1'
        and type(physical.get('durability_bindings'))is dict
        and set(physical['durability_bindings'])==set(observations)==names,
        'ntfs.version_durability_unproven')
    records=_closed_synchronous_trace(physical)
    if role=='Version1':
        events=[physical['mutex_events']];_mutex_closed(events[0],root_mutex_name(_grant(physical['grant'])))
        _require(all(physical.get(name)is True for name in('current_data_flushed','archive_data_flushed',
            'current_namespace_flushed','archive_namespace_flushed')),'ntfs.version_durability_unproven')
    else:
        grants=_version2_grants(physical['grants']);expected=sorted(root_mutex_name(grant)for grant in grants.values())
        mutexes=physical['mutexes']
        _require([row.get('name')for row in mutexes]==expected,'ntfs.version_durability_unproven')
        for row in mutexes:_mutex_closed(row['events'],row['name'])
        events=[row['events']for row in mutexes]
        _require(set(physical['namespace_flushed'])==names,'ntfs.version_durability_unproven')
    _require(all(max(row[1]['returned_ns']for row in events)<=call['started_ns']<=call['returned_ns']
        <=min(row[2]['started_ns']for row in events)for call in records),'ntfs.version_durability_unproven')
    for name in names:
        binding=physical['durability_bindings'][name];observed=observations[name]['native']
        _require(type(binding)is dict and set(binding)=={'object_identity','parent_identity','file_data_flushed','parent_namespace_flushed'}
            and binding['file_data_flushed']is True and binding['parent_namespace_flushed']is True
            and observed['exists']is True and binding['object_identity']==observed['native_identity'],
            'ntfs.version_durability_unproven')
        for field,kind in(('object_identity','file'),('parent_identity','directory')):
            identity=NativeIdentity.parse(binding[field]).as_dict()
            matches=[call for call in records if call.get('api')=='NtFlushBuffersFileEx'
                and call.get('kind')==kind and call.get('object_identity')==identity
                and call.get('accepted')is True and call.get('flags')==0
                and call.get('return_status')==call.get('io_status')=='0x00000000']
            _require(bool(matches),'ntfs.version_durability_unproven')
    return True
