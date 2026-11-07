"""Pure static consistency/refusal components; NOT native qualification.

No native effects, admission mocks, profile replacement, startup authentication
or target authority. Synthetic claims never establish G01 or deployment trust.
"""
import base64
from copy import deepcopy
from dataclasses import FrozenInstanceError
import unittest
from unittest.mock import patch
from jsonschema.exceptions import ValidationError
from phase_tool.canonical import canonical_bytes,digest_bytes,parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool import installation
from phase_tool.installation import _resolve_native_history_bindings,_validate_native_history_bindings
from phase_tool.mutation.ntfs.bootstrap import _native_history_manifest_buffers,_accepted_launch_history
from phase_tool.mutation.ntfs.channel_v3 import LinuxNativeChannelV3
from phase_tool.evidence import EvidenceStore
from ._native_history_fixture import manifests,set_bytes,binding


class NativeHistoryBindingsTests(unittest.TestCase):
    def setUp(self):
        self.registry,self.leaves=manifests();self.raw=set_bytes(self.leaves)
        self.active=binding(self.registry,self.leaves[0])

    def resolve(self,leaves=None,active=None):
        raw=self.raw if leaves is None else set_bytes(leaves)
        return _resolve_native_history_bindings(active or self.active,raw,digest_bytes(raw))

    def test_exact_two_immutable_roles_and_both_active_orderings(self):
        for index in (0,1):
            active=binding(self.registry,self.leaves[index]);rows=self.resolve(active=active)
            self.assertIs(type(rows),tuple);self.assertEqual(len(rows),2)
            self.assertEqual([r.manifest_bytes for r in rows],[canonical_bytes(m) for m in self.leaves])
            self.assertTrue(all(r.registry is self.registry for r in rows))
            with self.assertRaises(FrozenInstanceError):rows[0].manifest_bytes=b'{}'
            self.assertIs(_validate_native_history_bindings(active,rows),rows)

    def test_external_expected_hash_and_active_exact_member_required(self):
        with self.assertRaisesRegex(PhaseError,'ntfs.accepted_history_binding_mismatch'):
            _resolve_native_history_bindings(self.active,self.raw,'sha256:'+'f'*64)
        other=deepcopy(self.leaves[0]);other['installation_id']='synthetic.other'
        with self.assertRaisesRegex(PhaseError,'ntfs.accepted_history_binding_mismatch'):
            self.resolve(active=binding(self.registry,other))
        for raw,digest in ((None,digest_bytes(self.raw)),(self.raw,None)):
            with self.assertRaises(PhaseError):_resolve_native_history_bindings(self.active,raw,digest)
        self.assertIsNone(_resolve_native_history_bindings(self.active,None,None))

    def test_closed_canonical_set_shape_order_duplicate_and_version(self):
        doc=parse_json_bytes(self.raw)
        changes=[lambda v:v.update(extra=True),lambda v:v.update(history_manifest_set_version='2.0'),
            lambda v:v['manifests'].reverse(),lambda v:v['manifests'].append(deepcopy(v['manifests'][0])),
            lambda v:v['manifests'].__setitem__(1,deepcopy(v['manifests'][0])),
            lambda v:v['manifests'][1].update(extra=True),lambda v:v['manifests'][1].update(manifest_base64='not base64!')]
        for change in changes:
            with self.subTest(change=change):
                value=deepcopy(doc);change(value);raw=canonical_bytes(value)
                with self.assertRaises((PhaseError,ValueError)):
                    _native_history_manifest_buffers(raw,digest_bytes(raw),active_bytes=self.active.manifest_bytes,active_digest=self.active.manifest_digest)
        raw=self.raw+b'\n'
        with self.assertRaises(PhaseError):_resolve_native_history_bindings(self.active,raw,digest_bytes(raw))

    def test_each_leaf_hash_canonical_bytes_and_generation_are_bound(self):
        for change in ('digest','noncanonical','v11'):
            value=parse_json_bytes(self.raw);row=value['manifests'][1]
            if change=='digest':row['manifest_digest']='sha256:'+'f'*64
            else:
                leaf=deepcopy(self.leaves[1])
                if change=='v11':leaf['native_read_installation_version']='1.1'
                raw=canonical_bytes(leaf)+(b' ' if change=='noncanonical' else b'')
                row.update(manifest_base64=base64.b64encode(raw).decode('ascii'),manifest_digest=digest_bytes(raw))
            raw=canonical_bytes(value)
            with self.subTest(change=change),self.assertRaises(PhaseError):
                _resolve_native_history_bindings(self.active,raw,digest_bytes(raw))

    def test_every_shared_domain_field_and_full_physical_id_must_match(self):
        changes=[lambda m:m['core'].update(package_digest='sha256:'+'e'*64),
            lambda m:m['authority']['provider'].update(artifact_digest='sha256:'+'e'*64),
            lambda m:m['composition'].update(artifact_graph_digest='sha256:'+'e'*64),
            lambda m:m.update(evidence_root='/synthetic/other/evidence'),
            lambda m:m['evidence_identity'].update(stable_id='synthetic.other.evidence'),
            lambda m:m['evidence_identity'].update(inode=991),
            lambda m:m.update(preparation_root='/synthetic/other/preparation'),
            lambda m:m['preparation_identity'].update(stable_id='synthetic.other.preparation'),
            lambda m:m['preparation_identity'].update(inode=992),
            lambda m:m['root_grants'][0].update(device=r'\Device\HarddiskVolume18'),
            lambda m:m['root_grants'][0].update(volume_serial32=18),
            lambda m:m['root_grants'][0].update(components=['Other']),
            lambda m:m['root_grants'][0]['native_identity'].update(volume_serial=(1<<48)+18),
            lambda m:m['root_grants'][0]['native_identity'].update(file_id='a'*32),
            lambda m:m['root_projections'].update(fixture_result_root='/synthetic/other/opaque-result')]
        for index,change in enumerate(changes):
            leaves=deepcopy(self.leaves);change(leaves[1])
            with self.subTest(field=index),self.assertRaisesRegex(PhaseError,'ntfs.original_history_domain_mismatch'):
                self.resolve(leaves)

    def test_unknown_registry_contract_alias_and_mutable_collection_refuse(self):
        for change in (lambda m:m.update(registry_snapshot_digest='sha256:'+'e'*64),
                lambda m:m['contract'].update(package_digest='sha256:'+'e'*64),
                lambda m:m['root_grants'][0].update(root_binding='phase_result_root')):
            leaves=deepcopy(self.leaves);change(leaves[1])
            with self.assertRaises((PhaseError,ValidationError)):self.resolve(leaves)
        rows=self.resolve()
        with self.assertRaises(PhaseError):_validate_native_history_bindings(self.active,list(rows))
        with self.assertRaises(PhaseError):_validate_native_history_bindings(self.active,rows[::-1])

    def test_config10_unchanged_and11_closed_no_request_flag_or_extra(self):
        old={key:None for key in ('phase_wheel','phase_wheel_digest','dependency_file_digests',
            'windows_launcher','linux_launcher','docker_executable','core_container_id','reader_container_id',
            'image_digest','linux_python','expected_linux_contours','artifact_graph')}
        old['native_launch_version']='1.0'
        self.assertEqual(_accepted_launch_history(old,self.active.manifest_bytes,self.active.manifest_digest),(None,None))
        new=old|{'native_launch_version':'1.1','history_manifest_set_base64':base64.b64encode(self.raw).decode('ascii'),
            'history_manifest_set_digest':digest_bytes(self.raw)}
        self.assertEqual(_accepted_launch_history(new,self.active.manifest_bytes,self.active.manifest_digest),(self.raw,digest_bytes(self.raw)))
        for value in (old|{'history_manifest_set_digest':digest_bytes(self.raw)},new|{'qualified':True},
                new|{'native_launch_version':'1.2'},{k:v for k,v in new.items() if k!='history_manifest_set_digest'}):
            with self.assertRaises(PhaseError):_accepted_launch_history(value,self.active.manifest_bytes,self.active.manifest_digest)

    def test_real_unqualified_factory_refuses_before_channel_evidence_and_set_resolver(self):
        for index in (0,1):
            active=binding(self.registry,self.leaves[index])
            with (patch.object(LinuxNativeChannelV3,'__init__',side_effect=AssertionError('channel reached')) as channel,
                    patch.object(EvidenceStore,'__init__',side_effect=AssertionError('store reached')) as store,
                    patch.object(installation,'_resolve_native_history_bindings',side_effect=AssertionError('history reached before guard')) as history):
                with self.assertRaisesRegex(PhaseError,'ntfs.native_profile_not_qualified'):
                    installation._native_installation_for_manifest(manifest_bytes=active.manifest_bytes,
                        expected_manifest_digest=active.manifest_digest,run_id='synthetic-unqualified-history',
                        operation_nonce='a'*32,channel_id='b'*32,history_manifest_set_bytes=self.raw,
                        history_manifest_set_digest=digest_bytes(self.raw))
                channel.assert_not_called();store.assert_not_called();history.assert_not_called()
