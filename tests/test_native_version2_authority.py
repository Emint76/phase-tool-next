"""Constructor refusal tests with explicit uninitialized data-only stand-ins.

No pipe, native authority admission, worker, filesystem effect or qualification.
These exercise early negative gates only; the real canary must admit its own
actual two-root installation without any of these stand-ins.
"""
from copy import deepcopy
import sys
import unittest

if sys.platform.startswith('linux'):
    from phase_tool.canonical import canonical_bytes,digest_bytes
    from phase_tool.errors import PhaseError
    from phase_tool.installation import _NativeFileCreateReadBinding,_native_experimental_version2_registry
    from phase_tool.mutation.guarantees import GuaranteeProfileBinding
    from phase_tool.mutation.ntfs.channel_v3 import LinuxNativeChannelV3,LinuxNativeChannelV5
    from phase_tool.mutation.ntfs.experimental_version2_authority_v2 import _ExperimentalVersion2AuthorityV2
    from phase_tool.registry import BundledRegistry
    from .test_native_intent_v12 import fixture as native_claims


@unittest.skipUnless(sys.platform.startswith('linux'),'Authority constructor is a Linux role')
class Version2AuthorityRefusalTests(unittest.TestCase):
    def setUp(self):
        registry=_native_experimental_version2_registry()
        exact=registry.guarantee_profile_bindings()['phase.native.ntfs.experiment.version2.authority.v3@1.0.0']
        descriptor=registry.resolve_guarantee_profile(exact);implementation=descriptor['implementation']
        self.profile=GuaranteeProfileBinding(exact['id'],exact['version'],exact['descriptor_digest'],
            implementation['id'],implementation['version'],implementation['artifact_digest'])
        grant=deepcopy(native_claims(BundledRegistry.load())['idempotency']['root_identities'][0])
        grants=[]
        for name,leaf,identifier in [('current_root','current','a'),('objects_root','objects','b')]:
            row=deepcopy(grant);row['root_binding']=name;row['components']+=[leaf]
            row['native_identity']['file_id']=identifier*32;grants.append(row)
        self.registry=registry
        self.manifest={'native_read_installation_version':'1.5','contract':{'id':'publish_new_version.v2'},
            'root_grants':grants}
        self.projections=canonical_bytes({'current_root':'/current','objects_root':'/objects'})

    def binding(self,manifest):
        raw=canonical_bytes(manifest)
        return _NativeFileCreateReadBinding(raw,digest_bytes(raw),self.registry)

    def channel(self,kind=None):
        # No __init__/pipe check is invoked. The authority must reject the
        # invalid setup before profile admission or any transport method.
        if kind is None:kind=LinuxNativeChannelV5
        channel=object.__new__(kind);channel._inspection_only=False
        return channel

    def construct(self,manifest=None,channel=None,authority=None):
        value=object.__new__(_ExperimentalVersion2AuthorityV2) if authority is None else authority
        value.__init__(self.binding(self.manifest if manifest is None else manifest),self.profile,self.projections,
            self.channel() if channel is None else channel,run_id='version2-negative',operation_nonce='a'*32)

    def test_wrong_generation_and_channel_refuse_without_profile_or_pipe_use(self):
        for generation in ('1.1','1.2','1.3','1.4'):
            with self.subTest(generation=generation):
                manifest=deepcopy(self.manifest);manifest['native_read_installation_version']=generation
                with self.assertRaisesRegex(PhaseError,'ntfs.fixed_role_mismatch'):self.construct(manifest)
        with self.assertRaisesRegex(PhaseError,'ntfs.closed_native_installation_required'):
            self.construct(channel=self.channel(LinuxNativeChannelV3))

    def test_missing_reordered_and_duplicate_grants_refuse_before_admission(self):
        cases=[self.manifest['root_grants'][:1],list(reversed(self.manifest['root_grants'])),
            [self.manifest['root_grants'][0],self.manifest['root_grants'][0]]]
        for grants in cases:
            with self.subTest(grants=grants):
                manifest=deepcopy(self.manifest);manifest['root_grants']=grants
                with self.assertRaises(PhaseError):self.construct(manifest)

    def test_failed_initialization_consumes_object_before_a_second_attempt(self):
        authority=object.__new__(_ExperimentalVersion2AuthorityV2)
        with self.assertRaises(PhaseError):self.construct(channel=self.channel(LinuxNativeChannelV3),authority=authority)
        with self.assertRaisesRegex(PhaseError,'ntfs.native_role_initialization_consumed'):
            self.construct(authority=authority)


if __name__=='__main__':unittest.main()
