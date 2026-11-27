"""Fault oracles for bundle HANDLE ownership, not native qualification.

Only ctypes/CRT calls are instrumented. These tests never create a Windows
file, alter privileges, or substitute this model for a real Core bundle run.
"""
import ctypes
from contextlib import ExitStack
import os
import stat
import sys
from types import SimpleNamespace, ModuleType
import unittest
from unittest.mock import Mock, patch

from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.native import NativeIO,NativeHandle,NativeIdentity
from phase_tool.mutation.ntfs.bundle_observation import _BundleHandlePins


class BundleIdentityOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.identity=NativeIdentity(0x7c2a123456789022,(0xa7654321fedcba0989abcdef01234567).to_bytes(16,'little').hex())
        self.io=object.__new__(NativeIO);self.io._handles={}
        self.original=self.io._adopt(11,directory=True,rename_source=True)
        def duplicate(*args):args[3]._obj.value=22;return 1
        self.io.kernel=SimpleNamespace(DuplicateHandle=Mock(side_effect=duplicate),
            GetCurrentProcess=Mock(return_value=999),CloseHandle=Mock(return_value=1))
        self.io.assert_object=Mock(return_value={'attributes':16,'links':1,'length':0})
        self.crt=ModuleType('msvcrt');self.crt.open_osfhandle=Mock(return_value=77)
        self.info=SimpleNamespace(st_mode=stat.S_IFDIR,st_dev=self.identity.volume_serial,
            st_ino=int.from_bytes(bytes.fromhex(self.identity.file_id),'little'))
        self.patches=ExitStack();self.addCleanup(self.patches.close)
        self.patches.enter_context(patch.dict(sys.modules,{'msvcrt':self.crt}))
        self.patches.enter_context(patch('os.name','nt'))
        self.patches.enter_context(patch.object(os,'O_BINARY',getattr(os,'O_BINARY',0),create=True))
        self.patches.enter_context(patch.object(sys,'version_info',(3,12,10)))
        self.patches.enter_context(patch.object(ctypes,'get_last_error',return_value=123,create=True))
        self.fstat=self.patches.enter_context(patch('os.fstat',return_value=self.info))
        self.close=self.patches.enter_context(patch('os.close'))

    def call(self):return self.io.directory_stat_identity(self.original,self.identity)

    def test_full_128bit_actual_stat_only_duplicate_is_transferred_and_closed(self):
        self.assertEqual(self.call(),{'device':self.info.st_dev,'inode':self.info.st_ino})
        self.assertGreater(self.info.st_ino,2**64)
        self.crt.open_osfhandle.assert_called_once_with(22,os.O_RDONLY|os.O_BINARY)
        self.fstat.assert_called_once_with(77);self.close.assert_called_once_with(77)
        self.io.kernel.CloseHandle.assert_not_called()
        self.assertEqual(self.io._handles,{11:self.original});self.assertEqual(self.original.value,11)
        self.assertIs(self.io.assert_object.call_args_list[-1].args[0],self.original)

    def test_false_duplicate_with_nonzero_output_never_adopts_or_closes(self):
        def failed(*args):args[3]._obj.value=22;return 0
        self.io.kernel.DuplicateHandle.side_effect=failed
        with self.assertRaises(PhaseError)as error:self.call()
        self.assertEqual(error.exception.code,'ntfs.bundle_stat_duplicate_failed')
        self.assertEqual(error.exception.details['winerror'],123)
        self.assertTrue(error.exception.details['output_handle_present'])
        self.assertTrue(self.io._bundle_stat_ownership_unknown)
        with self.assertRaisesRegex(PhaseError,'ntfs.bundle_stat_ownership_unknown'):self.call()
        self.io.kernel.DuplicateHandle.assert_called_once()
        self.assertEqual(self.io._handles,{11:self.original})
        self.io.kernel.CloseHandle.assert_not_called();self.crt.open_osfhandle.assert_not_called()
        self.fstat.assert_not_called();self.close.assert_not_called()

    def test_adoption_conflict_never_blind_closes_registered_owner(self):
        self.io._adopt=Mock(side_effect=PhaseError('ntfs.handle_ownership_conflict'))
        with self.assertRaisesRegex(PhaseError,'ntfs.handle_ownership_conflict'):self.call()
        self.assertTrue(self.io._bundle_stat_ownership_unknown)
        self.io.kernel.CloseHandle.assert_not_called();self.crt.open_osfhandle.assert_not_called()
        self.assertEqual(self.original.value,11)

    def test_unknown_crt_transfer_retains_duplicate_and_never_closes_twice(self):
        self.crt.open_osfhandle.side_effect=OSError('transfer outcome unavailable')
        with self.assertRaises(OSError):self.call()
        self.assertTrue(self.io._bundle_stat_ownership_unknown)
        self.assertEqual(self.io._handles[22].finalization_state,'unknown')
        self.io.kernel.CloseHandle.assert_not_called();self.close.assert_not_called()
        self.assertEqual(self.original.value,11)

    def test_crt_close_failure_keeps_unknown_native_duplicate_without_closehandle(self):
        self.close.side_effect=OSError('CRT close unavailable')
        with self.assertRaises(OSError):self.call()
        self.close.assert_called_once_with(77);self.io.kernel.CloseHandle.assert_not_called()
        self.assertEqual(self.io._handles[22].finalization_state,'unknown')
        self.assertEqual(self.original.value,11)

    def test_lower_64bit_only_identity_is_rejected_and_crt_closed_once(self):
        self.info.st_ino &=2**64-1
        with self.assertRaisesRegex(PhaseError,'ntfs.bundle_stat_identity_mismatch'):self.call()
        self.close.assert_called_once_with(77);self.io.kernel.CloseHandle.assert_not_called()
        self.assertEqual(self.io._handles,{11:self.original})

    def test_primary_fstat_and_crt_close_failures_are_both_preserved(self):
        self.fstat.side_effect=OSError('fstat failed');self.close.side_effect=OSError('CRT close failed')
        with self.assertRaises(PhaseError)as caught:self.call()
        self.assertEqual(caught.exception.code,'ntfs.bundle_stat_finalization_failed')
        self.assertIn('fstat failed',caught.exception.details['primary_error']['message'])
        self.assertIn('CRT close failed',caught.exception.details['close_error']['message'])
        self.close.assert_called_once_with(77);self.io.kernel.CloseHandle.assert_not_called()

    def test_pre_crt_primary_and_native_close_failures_are_both_preserved(self):
        def check(handle,**kw):
            if handle.value==22:raise PhaseError('ntfs.object_identity_mismatch')
        self.io.assert_object.side_effect=check;self.io.kernel.CloseHandle.return_value=0
        with self.assertRaises(PhaseError)as caught:self.call()
        self.assertEqual(caught.exception.code,'ntfs.bundle_stat_finalization_failed')
        self.assertEqual(caught.exception.details['primary_error']['code'],'ntfs.object_identity_mismatch')
        self.assertEqual(caught.exception.details['close_error']['code'],'ntfs.close_failed')
        self.io.kernel.CloseHandle.assert_called_once_with(22)
        self.crt.open_osfhandle.assert_not_called();self.close.assert_not_called()
        self.assertEqual(self.original.value,11)


class BundlePinsFinalizationTests(unittest.TestCase):
    def test_body_and_all_close_failures_retained_and_each_close_attempted_once(self):
        first=object.__new__(NativeHandle);first.finalization_state='open'
        first.close=Mock(side_effect=OSError('first close'))
        second=object.__new__(NativeHandle);second.finalization_state='open'
        second.close=Mock(side_effect=OSError('second close'))
        primary=PhaseError('test.original_failure')
        with self.assertRaises(PhaseError)as caught:
            with _BundleHandlePins()as pins:
                pins.hold(first);pins.hold(second);raise primary
        self.assertIs(caught.exception.primary_error,primary)
        self.assertEqual(len(caught.exception.close_errors),2)
        self.assertEqual(caught.exception.details['primary_error']['code'],'test.original_failure')
        self.assertEqual([e['message']for e in caught.exception.details['close_errors']],['second close','first close'])
        first.close.assert_called_once();second.close.assert_called_once()
        self.assertEqual(pins._state,'unknown')
        with self.assertRaisesRegex(PhaseError,'ntfs.bundle_pins_closed'):pins.__exit__(None,None,None)
        first.close.assert_called_once();second.close.assert_called_once()


if __name__=='__main__':unittest.main()
