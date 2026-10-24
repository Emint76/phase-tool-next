"""Fixed public mutation exports deferred with ordinary relative imports.

The native physical role does not import Linux Broker or jsonschema merely to
load its package. No dynamic loader, plugin, provider or qualifier is added.
"""
__all__ = ["AppendRecordFaults", "BrokerFaults", "ContentAddressedCopyFaults", "EffectBroker", "ExclusiveCreateFaults", "ObjectStorePublishFaults"]


def __getattr__(name):
    if name == "AppendRecordFaults":
        from .expected_head_append import AppendRecordFaults
        return AppendRecordFaults
    if name == "BrokerFaults":
        from .broker import BrokerFaults
        return BrokerFaults
    if name == "ContentAddressedCopyFaults":
        from .content_addressed_copy import ContentAddressedCopyFaults
        return ContentAddressedCopyFaults
    if name == "EffectBroker":
        from .broker import EffectBroker
        return EffectBroker
    if name == "ExclusiveCreateFaults":
        from .exclusive_create import ExclusiveCreateFaults
        return ExclusiveCreateFaults
    if name == "ObjectStorePublishFaults":
        from .object_store_publish import ObjectStorePublishFaults
        return ObjectStorePublishFaults
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | set(__all__))
