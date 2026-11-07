"""B2 PREPARED/ACK within the existing bundle exchange, owner/gate and deadline.

No second command, GO, worker, queue or persistent owner. Only the closed B2
installation can bind an existing Core checkpoint before dispatch.
"""
from ...canonical import canonical_bytes
from .bundle_prepared import _CoreBundleCheckpoint, validate_prepared_message
from .channel_v4 import LinuxNativeBundleChannel
from .native import _require


class LinuxNativeBundle2Channel(LinuxNativeBundleChannel):
    _PROTOCOL_VERSION='1.6'

    def __init__(self,channel_id,*,_inspection_only=False):
        super().__init__(channel_id,_inspection_only=_inspection_only)
        self._checkpoint=None

    def bind_checkpoint(self,checkpoint):
        self._usable()
        _require(not self._inspection_only and not self._possible_dispatch
            and self._checkpoint is None and type(checkpoint) is _CoreBundleCheckpoint,
            'ntfs.original_closed_checkpoint_required')
        self._checkpoint=checkpoint

    def _prepare_bundle_exchange(self,projection):
        _require(type(self._checkpoint) is _CoreBundleCheckpoint,
            'ntfs.original_closed_checkpoint_required')
        self._checkpoint.bind_projection(projection)

    def _bundle_terminal(self,common,deadline,*,projection,expected_pid):
        value=self._receive_bound(common,deadline)
        if 'parent_execution_version' in value:
            # Existing-target or early negative completion may have no stage.
            # The unchanged final receipt/physical checks still own its outcome.
            return value
        _require(set(value)=={'bundle_stage','prepared'} and value['bundle_stage']=='prepared',
            'ntfs.bundle_prepared_binding_mismatch')
        message=validate_prepared_message(value['prepared'],projection=projection,
            channel_id=self.channel_id,expected_pid=expected_pid)
        ack=self._checkpoint.persist(projection,message,channel_id=self.channel_id,expected_pid=expected_pid)
        self._send_frame(canonical_bytes(ack),deadline)
        return self._receive_bound(common,deadline)
