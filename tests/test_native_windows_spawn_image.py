"""Direct-interpreter checks are synthetic API tests, not G01 qualification."""
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import bootstrap, process_witness as module


class Function:
    def __init__(self, callback):self.callback=callback
    def __call__(self,*arguments):return self.callback(*arguments)


@contextmanager
def boundary(*,same=True,length=None,terminated=True,absolute=True):
    image=str(Path(__file__).absolute())if absolute else 'relative-python.exe'
    record=[]
    def module_name(handle,buffer,capacity):
        record.append((handle,capacity))
        assert handle is None and capacity==32768
        buffer.value=image
        result=len(image)if length is None else length
        if not terminated and 0<result<capacity:buffer[result]='X'
        return result
    kernel=SimpleNamespace(GetModuleFileNameW=Function(module_name))
    with patch.object(module,'os',SimpleNamespace(name='nt')), \
        patch.object(module,'sys',SimpleNamespace(platform='win32',implementation=SimpleNamespace(name='cpython'),
            version_info=(3,12,10),executable=str(Path(__file__).absolute()))), \
        patch.object(module.C,'WinDLL',return_value=kernel,create=True)as library, \
        patch.object(module.C,'set_last_error',return_value=None,create=True), \
        patch.object(module.C,'get_last_error',return_value=122,create=True), \
        patch.object(Path,'samefile',return_value=same)as samefile:
        yield SimpleNamespace(calls=record,library=library,samefile=samefile)


class DirectWindowsInterpreterTests(unittest.TestCase):
    def test_current_executable_image_must_be_same_physical_file(self):
        with boundary()as seen:
            module._require_direct_windows_interpreter()
            self.assertEqual(seen.calls,[(None,32768)])
            seen.samefile.assert_called_once()
        with boundary(same=False)as seen:
            with self.assertRaisesRegex(PhaseError,'ntfs.worker_interpreter_redirector_forbidden'):
                module._require_direct_windows_interpreter()
            seen.samefile.assert_called_once()

    def test_zero_truncation_unterminated_and_relative_image_fail_closed(self):
        for options in ({'length':0},{'length':32768},{'length':32769},
            {'terminated':False},{'absolute':False}):
            with self.subTest(options=options),boundary(**options)as seen:
                with self.assertRaisesRegex(PhaseError,'ntfs.worker_interpreter_image_unavailable'):
                    module._require_direct_windows_interpreter()
                seen.samefile.assert_not_called()

    def test_image_stat_or_dll_load_oserror_is_typed_without_fallback(self):
        for target in ('library','samefile'):
            with self.subTest(target=target),boundary()as seen:
                getattr(seen,target).side_effect=OSError(5,'synthetic inaccessible image')
                with self.assertRaisesRegex(PhaseError,'ntfs.worker_interpreter_image_unavailable'):
                    module._require_direct_windows_interpreter()

    def test_nonexact_runtime_fails_before_windows_api(self):
        variants=(('platform','linux'),('version_info',(3,12,11)),
            ('implementation',SimpleNamespace(name='pypy')))
        for attribute,value in variants:
            with self.subTest(attribute=attribute),boundary()as seen:
                setattr(module.sys,attribute,value)
                with self.assertRaises(PhaseError):module._require_direct_windows_interpreter()
                seen.library.assert_not_called()

    def test_redirector_refuses_before_any_contour_or_process_spawn(self):
        launch=object.__new__(bootstrap._NativeAcceptedLaunch)
        with boundary(same=False), \
            patch.object(bootstrap,'os',SimpleNamespace(name='nt')), \
            patch.object(launch,'check_runtime')as checked, \
            patch.object(launch,'_check_linux_contours')as contours, \
            patch.object(bootstrap.subprocess,'Popen')as spawn:
            with self.assertRaisesRegex(PhaseError,'ntfs.worker_interpreter_redirector_forbidden'):
                launch._spawn(['synthetic-never-run'])
            checked.assert_called_once();contours.assert_not_called();spawn.assert_not_called()


if __name__=='__main__':unittest.main()
