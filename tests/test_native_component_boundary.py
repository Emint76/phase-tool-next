"""Candidate identity and a fail-closed boundary for unadmitted native code."""
import os
from importlib import metadata

import pytest
from packaging.version import Version

from phase_tool import __distribution_version__, __version__
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs.native import NativeIO
from phase_tool.mutation.ntfs.mutating import NativeMutationIO


def test_candidate_core_and_distribution_versions_are_exact_equivalents():
    assert __version__ == "1.2.0-rc.1"
    assert metadata.version("phase-tool") == __distribution_version__ == "1.2.0rc1"
    assert str(Version(__version__)) == __distribution_version__


@pytest.mark.skipif(os.name == "nt", reason="Linux rejection boundary; real Windows gates are separate")
@pytest.mark.parametrize("adapter", [NativeIO, NativeMutationIO])
def test_native_adapter_rejects_linux_before_loading_windows_libraries(adapter):
    with pytest.raises(PhaseError, match="ntfs.windows_amd64_required"):
        adapter()
