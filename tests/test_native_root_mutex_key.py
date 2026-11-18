"""Pure lock-key boundaries, separate from actual Windows lock qualification."""
from dataclasses import replace
import unittest

from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.native import NativeIdentity
from phase_tool.mutation.ntfs.root_lock import NativeRootMutex, root_mutex_name
from phase_tool.mutation.ntfs.scoped import NativeRootGrant


class NativeRootMutexKeyTests(unittest.TestCase):
    def grant(self):
        return NativeRootGrant('phase_result_root', r'\Device\HarddiskVolume6',
            '\\\\?\\volume{00000000-0000-0000-0000-000000000001}\\', 42,
            ('qualification', 'synthetic'), NativeIdentity(0x7c0000000000002a, '01'*16))

    def test_alias_and_binding_do_not_partition_one_physical_root(self):
        grant = self.grant()
        alias = replace(grant, binding='another_contract_root', device=r'\Device\HarddiskVolume9',
                        components=('another', 'name'), volume_serial32=43)
        self.assertEqual(root_mutex_name(grant), root_mutex_name(alias))

    def test_distinct_physical_identity_or_volume_has_distinct_key(self):
        grant = self.grant()
        variants = [replace(grant, root_identity=NativeIdentity(43, '01'*16)),
                    replace(grant, root_identity=NativeIdentity(grant.root_identity.volume_serial, '02'*16)),
                    replace(grant, volume_guid='\\\\?\\volume{00000000-0000-0000-0000-000000000002}\\')]
        keys = {root_mutex_name(grant), *(root_mutex_name(item) for item in variants)}
        self.assertEqual(len(keys), 4)
        for key in keys:
            self.assertRegex(key, r'^Global\\Phase\.NTFS\.RootLock\.v1\.[0-9a-f]{64}$')

    def test_untyped_grants_rejected_without_io(self):
        for value in (None, {}, self.grant().as_dict(), object()):
            with self.subTest(value=type(value)), self.assertRaisesRegex(PhaseError, 'ntfs.invalid_root_grant'):
                root_mutex_name(value)

    def test_arbitrary_backend_rejected_before_native_open(self):
        with self.assertRaisesRegex(PhaseError, 'ntfs.invalid_root_lock_owner'):
            NativeRootMutex(object(), self.grant())


if __name__ == '__main__':
    unittest.main()
