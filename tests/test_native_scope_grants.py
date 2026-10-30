"""Pure grant boundary checks; real Windows namespace gates remain separate."""
from dataclasses import FrozenInstanceError, replace
import unittest
from unittest.mock import Mock

from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.native import NativeIdentity
from phase_tool.mutation.ntfs.scoped import NativeRootGrant, NativeScopedTarget


class NativeScopeGrantTests(unittest.TestCase):
    def grant(self):
        return NativeRootGrant('phase_result_root',r'\Device\HarddiskVolume6',
            '\\\\?\\volume{00000000-0000-0000-0000-000000000001}\\',42,
            ('qualification','synthetic'),NativeIdentity(0x7c0000000000002a,'01'*16))

    def test_existing_binding_name_and_distinct_serial_domains(self):
        grant = self.grant()
        self.assertEqual(grant.binding,'phase_result_root')
        self.assertNotEqual(grant.volume_serial32,grant.root_identity.volume_serial)
        self.assertEqual(grant.as_dict()['native_identity']['file_id'],'01'*16)

    def test_rejects_aliases_mutable_components_and_invalid_native_identity(self):
        grant = self.grant()
        invalid = (
            {'binding':''}, {'binding':'root:stream'},
            {'device':'S:'}, {'device':r'\Device\Mup\server'},
            {'volume_guid':'S:\\'}, {'volume_guid':grant.volume_guid.upper()},
            {'volume_serial32':True}, {'volume_serial32':2**32},
            {'components':[]}, {'components':()}, {'components':('..',)},
            {'components':('safe','x/y')}, {'components':('x\\y',)},
            {'components':('CON',)}, {'components':('space dir',)},
            {'root_identity':NativeIdentity(True,'01'*16)},
            {'root_identity':NativeIdentity(42,'01'*15)},
        )
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(PhaseError):
                replace(grant,**changes)

    def test_serialized_grant_cannot_modify_original(self):
        grant = self.grant()
        serialized = grant.as_dict()
        serialized['components'][0] = 'elsewhere'
        serialized['native_identity']['file_id'] = '02'*16
        self.assertEqual(grant.components,('qualification','synthetic'))
        self.assertEqual(grant.root_identity.file_id,'01'*16)
        with self.assertRaises(FrozenInstanceError):
            grant.binding = 'elsewhere'

    def test_arbitrary_adapter_rejected_before_native_io(self):
        with self.assertRaisesRegex(PhaseError,'ntfs.invalid_scope_owner'):
            NativeScopedTarget(object(),self.grant(),'result.bin')

    def test_replacement_reader_shares_delete_without_changing_default_reader(self):
        # Exercise the real scoped opening/identity/finalization method with a
        # modeled IO boundary; this does not establish a native rename result.
        scope=object.__new__(NativeScopedTarget)
        scope._missing_ancestors=[];scope.parent=object();scope.name='synthetic.txt'
        scope.assert_bound=Mock();scope.io=Mock(spec=['child','_open','assert_object'])
        expected=NativeIdentity(42,'01'*16)
        ordinary=scope.open_file(expected=expected)
        scope.io.child.assert_called_once_with(scope.parent,scope.name,directory=False)
        scope.io._open.assert_not_called()
        replacement=scope.open_file(expected=expected,_replacement_read=True)
        scope.io._open.assert_called_once_with(scope.name,parent=scope.parent,directory=False,sharing=7)
        self.assertIs(ordinary,scope.io.child.return_value)
        self.assertIs(replacement,scope.io._open.return_value)
        scope.io.assert_object.assert_any_call(ordinary,directory=False,expected=expected)
        scope.io.assert_object.assert_any_call(replacement,directory=False,expected=expected)
        with self.assertRaisesRegex(PhaseError,'ntfs.invalid_replacement_read'):
            scope.open_file(expected=expected,_replacement_read=1)

    def test_replacement_reader_identity_failure_closes_once_without_fallback(self):
        scope=object.__new__(NativeScopedTarget)
        scope._missing_ancestors=[];scope.parent=object();scope.name='synthetic.txt'
        scope.assert_bound=Mock();scope.io=Mock(spec=['child','_open','assert_object'])
        scope.io.assert_object.side_effect=PhaseError('synthetic.identity_mismatch')
        with self.assertRaisesRegex(PhaseError,'synthetic.identity_mismatch'):
            scope.open_file(expected=NativeIdentity(42,'01'*16),_replacement_read=True)
        scope.io._open.return_value.close.assert_called_once_with()
        scope.io.child.assert_not_called()


if __name__ == '__main__':
    unittest.main()
