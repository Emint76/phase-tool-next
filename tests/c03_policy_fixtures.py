"""Disposable C03 contract fixtures; never bundled/installed registry changes.

Windows keeps the real unsupported Host preparation boundary. Linux
execution tests use the real Host provider/profile on those disposable roots.
This does not qualify NTFS, admit a native authority or alter production gates.
"""
from copy import deepcopy
import hashlib
from pathlib import Path
import sys

from phase_tool import __version__
from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes
from phase_tool.core import PhaseRequest
from phase_tool.installation import Installation
from phase_tool.mutation.guarantees import registered_profile_binding
from phase_tool.mutation.platform import HostAuthorityProvider
from phase_tool.registry import BundledRegistry, RegistrySnapshot


def policy_registry(policy, *, original=None, binding=None, active=True):
    original = original or BundledRegistry.load()
    binding = binding or original.contract_bindings()['bundle_create.v1@1.0.0']
    document = original.to_document()
    resources = BundledRegistry.resources()
    old = next(row for row in document['entries'] if row.get('kind') == 'contract'
               and all(row[key] == binding[key] for key in ('id', 'version', 'package_digest')))
    entry = deepcopy(old)
    contract = parse_json_bytes(resources[RegistrySnapshot._entry_resource(old)])
    contract['idempotency']['request_digest_policy_id'] = policy
    raw = canonical_bytes(contract)
    location = 'test-fixtures/c03/request-policy-' + hashlib.sha256(raw).hexdigest() + '.json'
    resources[location] = raw
    entry['archive_resource'] = location
    entry['artifact_digest'] = digest_bytes(raw)
    for item in entry['package_artifacts']:
        if item['resource'] == old['artifact'] or item.get('archive_resource') == RegistrySnapshot._entry_resource(old):
            item['archive_resource'] = location
            item['digest'] = digest_bytes(raw)
    entry['package_digest'] = canonical_digest({
        'profile': 'phase_contract_package_v1',
        'artifacts': [{'resource': item['resource'], 'digest': item['digest']}
                      for item in entry['package_artifacts']],
    })
    entry['current'] = active
    if active:
        for row in document['entries']:
            if row.get('kind') == 'contract' and row.get('current') is True and all(
                    row[key] == binding[key] for key in ('id', 'version')):
                row['current'] = False
    document['entries'].append(entry)
    registry = RegistrySnapshot.from_document(document, resources)
    exact = {key: entry[key] for key in ('id', 'version', 'package_digest')}
    resolved = registry.resolve_contract(exact['id'], exact['version'], exact['package_digest'],
                                         core_version=__version__)
    assert resolved.document['idempotency']['request_digest_policy_id'] == policy
    # Exact legacy package remains available independently of current selection.
    legacy = registry.resolve_contract(binding['id'], binding['version'], binding['package_digest'],
                                       core_version=__version__)
    assert legacy.document == original.resolve_contract(
        binding['id'], binding['version'], binding['package_digest'], core_version=__version__).document
    return registry, exact


class ComponentInstallation(Installation):
    def qualify_authority_roots(self, root_bindings):
        # Explicit disposable component fixture, not a production admission.
        for path in root_bindings.values():
            path = Path(path)
            assert path.is_dir() and not path.is_symlink()
            assert path.absolute() == path.resolve(strict=True)


def component_installation():
    return ComponentInstallation(
        authority_provider=HostAuthorityProvider(),
        authority_profile_binding=(registered_profile_binding('phase.posix.authority.v1@1.0.0')
                                   if sys.platform.startswith('linux') else None),
    )


def bundle_case(tmp_path, registry):
    source, target, evidence = (tmp_path / name for name in ('source', 'target', 'evidence'))
    source.mkdir()
    target.mkdir()
    (source / 'member.bin').write_bytes(b'C03 real Core captured input\n')
    candidate = tmp_path / 'bundle-candidate.json'
    candidate.write_bytes(canonical_bytes({
        'operation_id': 'c03-bundle', 'idempotency_key': 'c03-same-key',
        'input_binding': 'payload', 'target_locator': 'published',
        'members': ['member.bin'],
    }))
    binding = registry.contract_bindings()['bundle_create.v1@1.0.0']
    def request(run):
        return PhaseRequest(
            contract_id=binding['id'], contract_version=binding['version'],
            contract_digest=binding['package_digest'], candidate_path=candidate,
            evidence_root=evidence, run_id=run, input_paths={'payload': source},
            root_bindings={'phase_result_root': target},
        )
    return request, source, target, evidence


def file_case(tmp_path, registry):
    source, target, evidence = (tmp_path / name for name in ('source', 'target', 'evidence'))
    source.mkdir()
    target.mkdir()
    payload = source / 'input.bin'
    payload.write_bytes(b'C03 real Linux Host effect\n')
    candidate = tmp_path / 'file-candidate.json'
    candidate.write_bytes(canonical_bytes({
        'operation_id': 'c03-file', 'idempotency_key': 'c03-same-key',
        'input_binding': 'payload', 'target_locator': 'published.bin',
    }))
    binding = registry.contract_bindings()['file_create.v1@1.0.0']
    def request(run):
        return PhaseRequest(
            contract_id=binding['id'], contract_version=binding['version'],
            contract_digest=binding['package_digest'], candidate_path=candidate,
            evidence_root=evidence, run_id=run, input_paths={'payload': payload},
            root_bindings={'phase_result_root': target},
        )
    return request, payload, target, evidence
