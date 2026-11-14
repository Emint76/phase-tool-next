"""Real descriptor getters and actual closed role metadata; no accepted launch."""
from copy import deepcopy
from phase_tool.canonical import canonical_bytes,parse_json_bytes
from phase_tool.mutation.ntfs.bootstrap import _NativeAcceptedLaunch
from tests.test_owner_semantic_source_closure_v2 import current_readers,ROLES

def test_actual_bundle_descriptor_is_one_callable_property_and_all_roles_match():
 descriptor=_NativeAcceptedLaunch.__dict__['_bundle']
 assert type(descriptor)is property and callable(descriptor.fget)
 for version in('2.0','3.0'):
  readers,_=current_readers(version)
  for role,reader in zip(ROLES,readers,strict=True):
   obj=object.__new__(_NativeAcceptedLaunch);obj._manifest_bytes=reader.manifest_bytes
   assert type(obj._bundle)is bool and obj._bundle==(role in{'Bundle1','Bundle2'})
   assert type(obj._file2)is bool and obj._file2==(role=='File2')
   assert type(obj._version1)is bool and obj._version1==(role=='Version1')
   assert type(obj._version2)is bool and obj._version2==(role=='Version2')
   altered=parse_json_bytes(reader.manifest_bytes);altered['contract']['package_digest']='sha256:'+'f'*64
   obj._manifest_bytes=canonical_bytes(altered)
   assert obj._bundle is False
