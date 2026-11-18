"""Literal unpublished owner3 registry factories; no request-selected source."""

def _native_owner_semantic_file1_registry():
 from ...installation import _load_native_file_create_registry
 from .owner_semantic_contracts import require_semantic_owner_contract
 registry=_load_native_file_create_registry('registries/native-owner3-semantic-file1-candidate-v1.json','sha256:d638312b48804848157c1530b8fcd7bef78d1a677c03acc27f078dbb9d92fec7','sha256:75d6086ad78a84946c140ae6aa138b09be02a9fa70934a9cd421f3d6f707415a')
 require_semantic_owner_contract('File1',registry.contract_bindings().get('file_create.v1@1.0.1'))
 return registry


def _native_owner_semantic_file2_registry():
 from ...installation import _load_native_file_create_registry
 from .owner_semantic_contracts import require_semantic_owner_contract
 registry=_load_native_file_create_registry('registries/native-owner3-semantic-file2-candidate-v1.json','sha256:c5da71cf5c4a65009848c07ae683331b468293bebb3f1bb95267f20c5b383c7c','sha256:75d6086ad78a84946c140ae6aa138b09be02a9fa70934a9cd421f3d6f707415a')
 require_semantic_owner_contract('File2',registry.contract_bindings().get('file_create.v2@1.0.1'))
 return registry


def _native_owner_semantic_version1_registry():
 from ...installation import _load_native_file_create_registry
 from .owner_semantic_contracts import require_semantic_owner_contract
 registry=_load_native_file_create_registry('registries/native-owner3-semantic-version1-candidate-v1.json','sha256:eec3ba03d1a1b640c2005a492487b3295866f53162fc66ff2d87c3b44b4551a5','sha256:75d6086ad78a84946c140ae6aa138b09be02a9fa70934a9cd421f3d6f707415a')
 require_semantic_owner_contract('Version1',registry.contract_bindings().get('publish_new_version.v1@1.0.1'))
 return registry


def _native_owner_semantic_version2_registry():
 from ...installation import _load_native_file_create_registry
 from .owner_semantic_contracts import require_semantic_owner_contract
 registry=_load_native_file_create_registry('registries/native-owner3-semantic-version2-candidate-v1.json','sha256:8b2539f694d37cb373ecf9d6738962ecd123a51afc9bba086a788c9a68d92f4a','sha256:75d6086ad78a84946c140ae6aa138b09be02a9fa70934a9cd421f3d6f707415a')
 require_semantic_owner_contract('Version2',registry.contract_bindings().get('publish_new_version.v2@1.0.1'))
 return registry


def _native_owner_semantic_bundle1_registry():
 from ...installation import _load_native_file_create_registry
 from .owner_semantic_contracts import require_semantic_owner_contract
 registry=_load_native_file_create_registry('registries/native-owner3-semantic-bundle1-candidate-v1.json','sha256:a25edff1d3c490f9ec32f7f8f7b94ba002ec6f0a0beae4078c170ccdf220a1f3','sha256:75d6086ad78a84946c140ae6aa138b09be02a9fa70934a9cd421f3d6f707415a')
 require_semantic_owner_contract('Bundle1',registry.contract_bindings().get('bundle_create.v1@1.1.1'))
 return registry


def _native_owner_semantic_bundle2_registry():
 from ...installation import _load_native_file_create_registry
 from .owner_semantic_contracts import require_semantic_owner_contract
 registry=_load_native_file_create_registry('registries/native-owner3-semantic-bundle2-candidate-v1.json','sha256:ce05e4e71f948b4c0062d19c87fe516e6203422c62fdc5829b025281e61d40f4','sha256:75d6086ad78a84946c140ae6aa138b09be02a9fa70934a9cd421f3d6f707415a')
 require_semantic_owner_contract('Bundle2',registry.contract_bindings().get('bundle_create.v2@1.2.2'))
 return registry
