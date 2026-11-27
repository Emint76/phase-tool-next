"""Closed synthetic B2 experiment; no ordinary startup or qualification grant."""
from dataclasses import dataclass
from typing import ClassVar
from .experimental_bundle1 import _ExperimentalBundle1Admission
from .bundle_execution import _BUNDLE2_CONTRACT_V2 as _BUNDLE2_CONTRACT


@dataclass(frozen=True)
class _ExperimentalBundle2AdmissionV3(_ExperimentalBundle1Admission):
    _contract: ClassVar[dict]=_BUNDLE2_CONTRACT
    _profile: ClassVar[str]='phase.native.ntfs.experiment.bundle2.authority.v1@1.0.2'
    _manifest_version: ClassVar[str]='1.9'
    _installation_prefix: ClassVar[str]='phase.experiment.bundle2.'
    _authority_artifact: ClassVar[str]='phase_tool/mutation/ntfs/experimental_bundle2_authority_v3.py'
