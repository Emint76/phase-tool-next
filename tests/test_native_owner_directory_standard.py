"""Ordinary all-six SOURCE component tests, not qualified native execution.

Real registry/contract/parser/class metadata is exercised; synthetic production
descriptors are in-memory fixtures only. No accepted launch/worker/NativeIO.
"""
import base64
from copy import deepcopy
from dataclasses import replace
import json
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from phase_tool import inspection, installation
from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes, profile_digest
from phase_tool.errors import PhaseError
from phase_tool.registry import BundledRegistry
from phase_tool.mutation.ntfs import owner_directory as m
from phase_tool.mutation.ntfs import owner_directory_installation as factory
from tests.owner_directory_test_data import synthetic_catalog, owner_document, mutate_manifest, altered_profile_catalog
from .test_native_intent_v12 import fixture as intent_fixture


class OrdinaryOwnerDirectoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = synthetic_catalog().check()
        cls.doc = owner_document(cls.catalog)
        cls.raw = canonical_bytes(cls.doc)
        row = cls.doc['manifests'][0]
        cls.active, cls.history = factory._owner_directory_bindings_with_catalog(
            configuration_bytes=cls.raw, expected_configuration_digest=digest_bytes(cls.raw),
            manifest_bytes=base64.b64decode(row['manifest_base64']), expected_manifest_digest=row['manifest_digest'],
            _catalog=cls.catalog)

    def reject_document(self, doc):
        raw = canonical_bytes(doc)
        with self.assertRaises(PhaseError):
            m.owner_directory_configuration(raw, digest_bytes(raw))

    def test_six_genuine_contracts_bindings_no_experimental_admission(self):
        self.assertEqual(len(self.history), 6)
        self.assertEqual(tuple(row._owner_directory_context.role for row in self.history), m.ROLES)
        for role, row in zip(m.ROLES, self.history):
            self.assertIs(type(row), installation._NativeFileCreateReadBinding)
            self.assertIsNone(row.experimental_admission)
            self.assertIs(row.registry, self.catalog.registry)
            self.assertEqual(m.require_owner_directory_binding(row, role)[0], role)

    def test_stable_owner_configuration_has_no_per_file_or_run_fields(self):
        names = set(self.doc)
        self.assertFalse(names & {'run_id', 'request_id', 'candidate_digest', 'payload_digest',
            'target_locator', 'experimental_admission_version', 'authorization_digest', 'request_limits'})
        for role, row in zip(m.ROLES, self.history):
            manifest = parse_json_bytes(row.manifest_bytes)
            self.assertEqual(manifest['installation_id'], m.owner_directory_installation_id(self.doc['owner_scope_id'], role))
        for key in ('target_locator', 'request_id', 'allow_unqualified', 'experimental_admission_version'):
            self.reject_document({**self.doc, key: 'not permitted'})

    def test_all_six_fixed_factories_refuse_without_qualified_catalog_before_authority(self):
        self.assertIsNone(factory._NATIVE_OWNER_DIRECTORY_CATALOG_DIGEST)
        for row in self.history:
            with self.subTest(role=row._owner_directory_context.role), self.assertRaises(PhaseError) as error:
                factory._native_owner_directory_installation(configuration_bytes=self.raw,
                    expected_configuration_digest=digest_bytes(self.raw), manifest_bytes=row.manifest_bytes,
                    expected_manifest_digest=row.manifest_digest, run_id='ordinary-source-only',
                    operation_nonce='1'*32, channel_id='2'*32)
            self.assertEqual(error.exception.code, 'ntfs.native_profile_not_qualified')

    def test_windows_metadata_import_does_not_import_linux_authorities(self):
        if sys.platform.startswith('linux'):
            self.skipTest('Windows import boundary; genuine Linux constructors covered separately')
        self.assertNotIn('phase_tool.mutation.ntfs.owner_directory_authorities', sys.modules)

    def test_unknown_version_extra_missing_role_or_order_refused(self):
        for kind in ('version', 'missing', 'duplicate', 'foreign', 'order'):
            doc = deepcopy(self.doc)
            if kind == 'version': doc['owner_directory_configuration_version'] = '3.0'
            elif kind == 'missing': doc['manifests'].pop()
            elif kind == 'duplicate': doc['manifests'][-1] = deepcopy(doc['manifests'][0])
            elif kind == 'foreign': doc['manifests'][0]['role'] = 'file1'
            else: doc['manifests'].reverse()
            with self.subTest(kind=kind): self.reject_document(doc)

    def test_hash_canonical_base64_and_whole_configuration_bound(self):
        with self.assertRaises(PhaseError): m.owner_directory_configuration(self.raw, 'sha256:'+'0'*64)
        with self.assertRaises(PhaseError): m.owner_directory_configuration(self.raw+b'\n', digest_bytes(self.raw+b'\n'))
        oversized = b' '*(m.MAX_CONFIGURATION_BYTES+1)
        with self.assertRaises(PhaseError): m.owner_directory_configuration(oversized, digest_bytes(oversized))
        doc = deepcopy(self.doc); doc['manifests'][0]['manifest_base64'] = '!!'
        self.reject_document(doc)
        doc = deepcopy(self.doc); doc['manifests'][0]['manifest_digest'] = 'sha256:'+'0'*64
        self.reject_document(doc)

    def test_no_extra_grant_alias_foreign_identity_or_nested_objects(self):
        for kind in ('same-id', 'nested', 'case-alias', 'foreign-volume', 'extra'):
            doc = deepcopy(self.doc)
            if kind == 'same-id': doc['root_grants'][1]['native_identity'] = deepcopy(doc['root_grants'][0]['native_identity'])
            elif kind in ('nested', 'case-alias'):
                doc['root_grants'][1]['components'] = deepcopy(doc['root_grants'][0]['components'])
                if kind == 'nested': doc['root_grants'][1]['components'].append('nested')
                else: doc['root_grants'][1]['components'][-1] = doc['root_grants'][1]['components'][-1].upper()
            elif kind == 'foreign-volume': doc['root_grants'][1]['volume_guid'] = '\\\\?\\volume{00000000-0000-0000-0000-000000000000}\\'
            else: doc['root_grants'].append(deepcopy(doc['root_grants'][0]))
            with self.subTest(kind=kind): self.reject_document(doc)

    def test_supported_owner_directory_is_not_forced_to_experiment_uuid_or_results_leaf(self):
        doc = deepcopy(self.doc)
        for index, leaf in enumerate(('owner-published', 'owner-objects')):
            doc['root_grants'][index]['components'] = ['OwnerApproved', 'Phase', leaf]
            doc['windows_roots'][('current_root', 'objects_root')[index]] = 'S:\\OwnerApproved\\Phase\\' + leaf
        for row in doc['manifests']:
            role, raw, digest, manifest = m._manifest_row(row)
            grants = deepcopy(doc['root_grants']) if role == 'Version2' else [deepcopy(doc['root_grants'][0])]
            if role != 'Version2': grants[0]['root_binding'] = m.ROOT_BINDINGS[role]
            manifest['root_grants'] = grants
            body = canonical_bytes(manifest)
            row.update(manifest_base64=base64.b64encode(body).decode(), manifest_digest=digest_bytes(body))
        raw = canonical_bytes(doc)
        self.assertEqual(m.owner_directory_configuration(raw, digest_bytes(raw))['windows_roots'], doc['windows_roots'])

    def test_unsupported_drive_unc_relative_and_projection_overlap_refused(self):
        for path in ('C:\\other', '\\\\server\\share\\other', 'relative', 'S:\\x\\..\\other'):
            doc = deepcopy(self.doc); doc['windows_roots']['current_root'] = path
            self.reject_document(doc)
        doc = deepcopy(self.doc); doc['preparation_root'] = doc['evidence_root']+'/nested'
        self.reject_document(doc)

    def test_every_role_contract_and_native_grant_are_exact(self):
        for role in m.ROLES:
            for key in ('contract', 'grant', 'installation'):
                def damage(manifest):
                    if key == 'contract': manifest['contract']['package_digest'] = 'sha256:'+'0'*64
                    elif key == 'grant': manifest['root_grants'][0]['native_identity']['file_id'] = '0'*32
                    else: manifest['installation_id'] = 'foreign.installation'
                with self.subTest(role=role, key=key): self.reject_document(mutate_manifest(self.doc, role, damage))

    def test_per_role_graphs_differ_but_each_exact_map_entry_is_bound(self):
        self.assertEqual(len({c['artifact_graph_digest'] for c in self.doc['compositions'].values()}), 6)
        doc = deepcopy(self.doc)
        doc['compositions']['File1'], doc['compositions']['File2'] = doc['compositions']['File2'], doc['compositions']['File1']
        self.reject_document(doc)

    def test_scope_graph_manifest_owner_config_assembly_is_acyclic(self):
        doc = deepcopy(self.doc)
        domain = m.owner_directory_scope_digest(doc)
        for role in m.ROLES:
            scope = {'native_input_scope_version': '2.0', 'owner_scope_id': doc['owner_scope_id'],
                     'owner_directory_scope_digest': domain, 'role': role}
            scope_raw = canonical_bytes(scope)
            graph = {'scope_digest': digest_bytes(scope_raw), 'wheel_digest': doc['phase_wheel_digest'], 'role': role}
            graph_digest = canonical_digest(graph)
            doc = mutate_manifest(doc, role, lambda manifest: manifest['composition'].update(artifact_graph_digest=graph_digest))
            doc['compositions'][role]['artifact_graph_digest'] = graph_digest
        raw = canonical_bytes(doc)
        m.owner_directory_configuration(raw, digest_bytes(raw))
        self.assertEqual(m.owner_directory_scope_digest(doc), domain)
        # Full config/outer Base64 envelope uses the EXISTING 2MiB bound.
        config = canonical_bytes({'native_launch_version': '4.0', 'owner_directory_configuration_base64': base64.b64encode(raw).decode(),
                                  'owner_directory_configuration_digest': digest_bytes(raw)})
        outer = canonical_bytes({'config_base64': base64.b64encode(config).decode(), 'config_digest': digest_bytes(config)})
        self.assertLess(len(config), 2*1024**2); self.assertLess(len(outer), 2*1024**2)
        changed = deepcopy(doc); changed['root_grants'][0]['native_identity']['file_id'] = '0'*32
        self.assertNotEqual(m.owner_directory_scope_digest(changed), domain)
        changed = deepcopy(doc); changed['phase_wheel_digest'] = 'sha256:'+'4'*64
        self.assertEqual(m.owner_directory_scope_digest(changed), domain)

    def test_complete_history_and_original_tuple_never_filter_foreign_reader(self):
        for role, row in zip(m.ROLES, self.history):
            manifest = parse_json_bytes(row.manifest_bytes)
            selected = installation._native_history_binding_for_original(self.history, run_id='ordinary-historical',
                contract=manifest['contract'], core=manifest['core'],
                installation={'id': manifest['installation_id'], 'descriptor_digest': row.manifest_digest},
                registry_snapshot_digest=manifest['registry_snapshot_digest'])
            self.assertIs(selected, row)
            with self.assertRaises(PhaseError):
                installation._native_history_binding_for_original(self.history, run_id='ordinary-historical',
                    contract=manifest['contract'], core=manifest['core'], installation={'id': 'foreign', 'descriptor_digest': row.manifest_digest},
                    registry_snapshot_digest=manifest['registry_snapshot_digest'])
        with self.assertRaises(PhaseError): installation._validate_native_history_bindings(self.active, self.history[:-1])
        foreign = replace(self.history[1], _owner_directory_context=object())
        with self.assertRaises(PhaseError): installation._validate_native_history_bindings(self.active, (self.history[0], foreign, *self.history[2:]))

    def test_context_exact_type_rechecks_selected_profile_and_mutable_snapshot(self):
        for row in self.history:
            with self.assertRaises(PhaseError): m.require_owner_directory_binding(replace(row, _owner_directory_context=object()))
            with self.assertRaises(PhaseError): m.require_owner_directory_binding(row, 'Unknown')
        with patch.object(self.catalog.registry, 'digest', 'sha256:'+'0'*64):
            with self.assertRaises(PhaseError): m.require_owner_directory_binding(self.active)

    def test_explicit_predecessor_full_tuple_supported_without_per_attempt_manifest(self):
        doc = deepcopy(self.doc)
        prior = deepcopy(doc['manifests'][0])
        manifest = parse_json_bytes(base64.b64decode(prior['manifest_base64']))
        manifest['composition']['artifact_graph_digest'] = 'sha256:'+'e'*64
        raw_prior = canonical_bytes(manifest)
        prior.update(manifest_base64=base64.b64encode(raw_prior).decode(), manifest_digest=digest_bytes(raw_prior))
        doc['predecessors'] = [prior]
        raw = canonical_bytes(doc); selected = doc['manifests'][1]
        active, history = factory._owner_directory_bindings_with_catalog(configuration_bytes=raw,
            expected_configuration_digest=digest_bytes(raw), manifest_bytes=base64.b64decode(selected['manifest_base64']),
            expected_manifest_digest=selected['manifest_digest'], _catalog=self.catalog)
        self.assertEqual(len(history), 7)
        self.assertIs(installation._native_history_binding_for_original(history, run_id='prior-ordinary-run',
            contract=manifest['contract'], core=manifest['core'], installation={'id': manifest['installation_id'],
            'descriptor_digest': prior['manifest_digest']}, registry_snapshot_digest=manifest['registry_snapshot_digest']), history[-1])
        self.assertNotEqual(history[-1].manifest_digest, history[0].manifest_digest)
        duplicate = deepcopy(doc); duplicate['predecessors'].append(deepcopy(prior)); self.reject_document(duplicate)
        too_many = deepcopy(doc); too_many['predecessors'] = [deepcopy(prior) for _ in range(33)]; self.reject_document(too_many)

    def test_inspect_selects_receipt_bound_configured_issuer_only(self):
        for role in m.ROLES:
            with self.subTest(role=role):
                self.assert_inspect_issuer(m.ROLES.index(role), role)

    def assert_inspect_issuer(self, index, expected_role):
        def with_predecessor(digit):
            doc = deepcopy(self.doc)
            row = deepcopy(doc['manifests'][index])
            manifest = parse_json_bytes(base64.b64decode(row['manifest_base64']))
            manifest['composition']['artifact_graph_digest'] = 'sha256:' + digit * 64
            manifest_bytes = canonical_bytes(manifest)
            row.update(manifest_base64=base64.b64encode(manifest_bytes).decode(),
                       manifest_digest=digest_bytes(manifest_bytes))
            doc['predecessors'] = [row]
            raw = canonical_bytes(doc)
            active_row = doc['manifests'][index]
            return factory._owner_directory_bindings_with_catalog(
                configuration_bytes=raw, expected_configuration_digest=digest_bytes(raw),
                manifest_bytes=base64.b64decode(active_row['manifest_base64']),
                expected_manifest_digest=active_row['manifest_digest'], _catalog=self.catalog,
            )

        active, history = with_predecessor('e')
        foreign_active, foreign_history = with_predecessor('f')
        issuer = history[-1]
        _, manifest = m.require_owner_directory_binding(issuer, expected_role)
        intent = intent_fixture(BundledRegistry.load())
        intent.update(contract=manifest['contract'], core=manifest['core'], registry_snapshot_digest=self.catalog.registry.digest)
        intent['operation']['mechanism'] = manifest['mechanism']
        intent['implementation_binding']['mechanism'] = manifest['mechanism']
        intent['native_binding'].update(
            installation={'id':manifest['installation_id'], 'descriptor_digest':issuer.manifest_digest},
            evidence_identity=manifest['evidence_identity'], composition=manifest['composition'],
        )
        receipt = {
            'run_id':intent['run_id'], 'contract':intent['contract'], 'core':intent['core'],
            'terminal_status':'succeeded_verified', 'execution_disposition':'executed',
            'evidence':{'intent_digest':profile_digest('intent', intent)},
        }
        bound = object.__new__(installation._NativeFileCreateInstallation)
        run_root = Path('unused-modeled-original')
        # Only the platform-specific authority shell and evidence read are modeled.
        # The selector, fixed history validation and complete intent schema are real.
        with (
            patch.object(inspection, 'is_owner_directory_authority',
                         side_effect=lambda authority, role: role == expected_role) as role_check,
            patch('phase_tool.mutation.ntfs.proof._canonical', return_value=(intent, canonical_bytes(intent))) as read,
        ):
            bound.authority = Mock(read_binding=active, _inspection_only=True)
            bound.read_binding, bound.history_bindings = active, history
            self.assertIs(inspection._owner_directory_inspect_original(bound, bound.authority, run_root, receipt), issuer)
            self.assertEqual(role_check.call_args.args, (bound.authority, expected_role))
            read.assert_called_once_with(run_root / 'intent.json')
            bad_receipt = dict(receipt, evidence={'intent_digest':'sha256:'+'1'*64})
            with self.assertRaisesRegex(PhaseError, 'ntfs.original_intent_mismatch'):
                inspection._owner_directory_inspect_original(bound, bound.authority, run_root, bad_receipt)
            bound.authority = Mock(read_binding=foreign_active, _inspection_only=True)
            bound.read_binding, bound.history_bindings = foreign_active, foreign_history
            with self.assertRaisesRegex(PhaseError, 'ntfs.original_history_binding_mismatch'):
                inspection._owner_directory_inspect_original(bound, bound.authority, run_root, receipt)
            bound.history_bindings = history
            with self.assertRaisesRegex(PhaseError, 'ntfs.original_history_binding_mismatch'):
                inspection._owner_directory_inspect_original(bound, bound.authority, run_root, receipt)
            bound.authority._inspection_only = False
            read.reset_mock()
            self.assertIs(inspection._owner_directory_inspect_original(bound, bound.authority, run_root, receipt), foreign_active)
            read.assert_not_called()

    def test_fresh_context_identity_is_metadata_not_registry_object_equality(self):
        context = self.active._owner_directory_context
        identity = m.owner_directory_context_identity(context)
        self.assertEqual(identity[:3], (self.raw, digest_bytes(self.raw), 'File1'))
        self.assertIsNot(identity, context)
        with self.assertRaises(PhaseError): m.owner_directory_context_identity(object())

    def test_all_six_candidate_descriptors_cannot_masquerade_as_qualified(self):
        for role in m.ROLES:
            catalog = altered_profile_catalog(self.catalog, role, lambda descriptor:
                descriptor.update(classification='qualification_candidate', provided_guarantees=[], conformance=[]))
            with self.subTest(role=role), self.assertRaises(PhaseError) as error:
                catalog.profile(role)
            self.assertEqual(error.exception.code, 'ntfs.native_profile_not_qualified')

    def test_all_six_self_consistent_production_profiles_still_require_actual_coverage(self):
        for role in m.ROLES:
            def omit(descriptor):
                missing = descriptor['provided_guarantees'].pop(0)
                descriptor['conformance'] = [r for r in descriptor['conformance'] if r['guarantee'] != missing]
            catalog = altered_profile_catalog(self.catalog, role, omit)
            with self.subTest(role=role), self.assertRaises(PhaseError): catalog.profile(role)

    def test_provider_role_and_actual_physical_implementation_hash_rechecked(self):
        for key in ('id', 'artifact_digest'):
            def damage(descriptor):
                descriptor['implementation'][key] = ('phase.foreign.authority' if key == 'id' else 'sha256:'+'0'*64)
            catalog = altered_profile_catalog(self.catalog, 'File1', damage)
            with self.subTest(key=key), self.assertRaises(PhaseError): catalog.profile('File1')

    @unittest.skipUnless(sys.platform.startswith('linux'), 'actual Linux authority class/IPC imports required')
    def test_six_real_constructors_share_installation_history_and_unchanged_physical_methods(self):
        # Genuine channels require two distinct nonblocking FIFO descriptors.
        # Pytest capture is not that transport. A finite metadata-only child
        # supplies real pipes; no channel/authority constructor is mocked.
        program = r"""
import json,os,stat,subprocess,sys
from unittest.mock import patch
sys.path[:0]=sys.argv[1:3]
os.set_blocking(0,False);os.set_blocking(1,False)
from tests.test_native_owner_directory_standard import OrdinaryOwnerDirectoryTests
from phase_tool import installation
from phase_tool.mutation.ntfs import owner_directory as m,owner_directory_installation as factory
from phase_tool.mutation.ntfs.native import NativeIO
from phase_tool.mutation.ntfs.owner_directory_authorities import _ordinary_authority_types
from phase_tool.mutation.ntfs.authority import _NativeFileCreateAuthority
from phase_tool.mutation.ntfs.experimental_version2_authority_v2 import _ExperimentalVersion2AuthorityV2
from phase_tool.mutation.ntfs.experimental_bundle1_authority import _ExperimentalBundle1Authority
from phase_tool.mutation.ntfs.experimental_bundle2_authority_v3 import _ExperimentalBundle2AuthorityV3
before=[os.fstat(fd)for fd in(0,1)]
assert all(stat.S_ISFIFO(info.st_mode)for info in before)
assert (before[0].st_dev,before[0].st_ino)!=(before[1].st_dev,before[1].st_ino)
physical=(_NativeFileCreateAuthority,_NativeFileCreateAuthority,_NativeFileCreateAuthority,
 _ExperimentalVersion2AuthorityV2,_ExperimentalBundle1Authority,_ExperimentalBundle2AuthorityV3)
OrdinaryOwnerDirectoryTests.setUpClass();history=OrdinaryOwnerDirectoryTests.history
rows=[]
# These constructors must not reach any NativeIO or subprocess creation. The
# actual six Linux channel/authority constructors and all static guards run.
with (patch.object(NativeIO,'__init__',side_effect=AssertionError('NativeIO forbidden'))as native,
      patch.object(subprocess,'Popen',side_effect=AssertionError('spawn forbidden'))as spawn):
 for row,kind,base in zip(history,_ordinary_authority_types(),physical):
  registry,installed=factory._installation_from_owner_directory_bindings(row,history,
   run_id='ordinary-constructor-only',operation_nonce='1'*32,channel_id='2'*32)
  assert type(installed)is installation._NativeFileCreateInstallation and type(installed.authority)is kind
  assert installed.history_bindings is history and kind.execute is base.execute
  assert installed.read_binding.experimental_admission is None
  assert installed.authority.channel.possible_dispatch is False
  rows.append({'role':row._owner_directory_context.role,'authority':kind.__name__,
   'channel':type(installed.authority.channel).__name__,'history_identity_preserved':True,
   'physical_execute_identity_preserved':True,'possible_dispatch':False})
 native.assert_not_called();spawn.assert_not_called()
after=[os.fstat(fd)for fd in(0,1)]
assert [(i.st_dev,i.st_ino,i.st_mode)for i in before]==[(i.st_dev,i.st_ino,i.st_mode)for i in after]
print(json.dumps({'scope':'REAL_LINUX_CONSTRUCTOR_FIFO_COMPONENT_ONLY','rows':rows,
 'history':[row.manifest_digest for row in history],'distinct_FIFO':True,'NativeIO_calls':0,'spawn_calls':0}))
"""
        process=subprocess.Popen([sys.executable,'-I','-B','-c',program,
            str(Path(installation.__file__).resolve().parent.parent),str(Path(__file__).resolve().parent.parent)],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            try:stdout,stderr=process.communicate(b'',timeout=180)
            except subprocess.TimeoutExpired:
                # This is solely the disposable metadata test child. Its source
                # forbids NativeIO/spawn and invokes no Core operation.
                process.kill();stdout,stderr=process.communicate(timeout=5)
                self.fail('constructor metadata child timeout: '+repr((stdout,stderr)))
            self.assertEqual(process.returncode,0,(stdout,stderr));self.assertEqual(stderr,b'')
            self.assertLessEqual(len(stdout),65536)
            result=json.loads(stdout);self.assertEqual(result['scope'],'REAL_LINUX_CONSTRUCTOR_FIFO_COMPONENT_ONLY')
            self.assertTrue(result['distinct_FIFO']);self.assertEqual(result['NativeIO_calls'],0);self.assertEqual(result['spawn_calls'],0)
            self.assertEqual(result['history'],[row.manifest_digest for row in self.history])
            self.assertEqual([row['role']for row in result['rows']],list(m.ROLES))
            self.assertTrue(all(row['history_identity_preserved']and row['physical_execute_identity_preserved']
                and row['possible_dispatch']is False for row in result['rows']))
        finally:
            for stream in(process.stdin,process.stdout,process.stderr):
                if not stream.closed:stream.close()

    @unittest.skipUnless(sys.platform.startswith('linux'), 'actual ext4/flock history guard required')
    def test_foreign_unresolved_original_blocks_all_six_under_existing_core_flock(self):
        from phase_tool import core
        with tempfile.TemporaryDirectory(prefix='ordinary-six-') as name:
            directory = Path(name)
            if installation._linux_filesystem_type(directory) != 'ext4': self.skipTest('real ext4 required')
            doc = owner_document(self.catalog, directory=directory)
            evidence = Path(doc['evidence_root']); runs = evidence/'.phase/runs'; locks = evidence/'.phase/locks'
            runs.mkdir(parents=True, mode=0o700); locks.mkdir(mode=0o700)
            (runs/'foreign-unresolved').mkdir(mode=0o700)
            raw = canonical_bytes(doc); first = doc['manifests'][0]
            _, rows = factory._owner_directory_bindings_with_catalog(configuration_bytes=raw,expected_configuration_digest=digest_bytes(raw),
                manifest_bytes=base64.b64decode(first['manifest_base64']),expected_manifest_digest=first['manifest_digest'],_catalog=self.catalog)
            identity = None
            for row in rows:
                with self.assertRaisesRegex(PhaseError, 'ntfs.original_history_unresolved'):
                    with core._guard_native_original_intents(row, history_bindings=rows): self.fail('foreign Original filtered')
                info = next(locks.iterdir()).stat(); current = info.st_dev, info.st_ino
                if identity is None: identity = current
                self.assertEqual(current, identity)


if __name__ == '__main__':
    unittest.main()
