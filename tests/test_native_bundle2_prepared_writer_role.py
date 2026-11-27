"""Role admission at the existing anchored PREPARED Evidence writer."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import stat
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from phase_tool import evidence, installation, recovery
from phase_tool.canonical import canonical_bytes, digest_bytes
from phase_tool.continuation import prepared_record, save_prepared_record
from phase_tool.errors import PhaseError
from tests.native_staged_original14_records import made_data, record_for


@pytest.fixture(scope="module")
def originals():
    return {version: record_for("Bundle2", made_data(version)[1]) for version in ("3.0", "2.0")}


def checkpoint(original, binding=None, *, mutate=None):
    binding = binding or original["binding"]
    intent, effect = original["intent"], original["plan"]["effects"][0]
    root = Path(original["manifest"]["evidence_root"])
    run = root / ".phase" / "runs" / intent["run_id"]
    store = object.__new__(evidence.EvidenceStore)
    store.evidence_root = root
    store.run_root = run
    # The model only substitutes physical filesystem calls. Actual bindings,
    # native writer, exact record construction and all admission code run.
    dev, inode = (original["manifest"]["evidence_identity"][key] for key in ("device", "inode"))
    store._owned_run_identity = (dev, inode + 3)
    prepared = prepared_record(intent, effect, "synthetic-stage", device=31, inode=32)
    if mutate is not None:
        mutate(prepared)
    opened, closed, saved, read_back = [], [], {}, []
    names = (root, ".phase", "runs", intent["run_id"], "attachments")

    def opened_descriptor(name, flags, *, dir_fd):
        offset = len(opened)
        assert offset < len(names) and name == names[offset]
        assert flags == 7 and dir_fd == (None if offset == 0 else offset - 1)
        opened.append(name)
        return offset

    def info(offset):
        return SimpleNamespace(st_dev=dev, st_ino=inode + offset, st_uid=10001, st_mode=stat.S_IFDIR | 0o700)

    def named_info(name, *, dir_fd, follow_symlinks):
        offset = names.index(name)
        assert follow_symlinks is False and dir_fd == (None if offset == 0 else offset - 1)
        return info(offset)

    def write(path, data, label, *, _parent_descriptor):
        assert path not in saved and path == run / label
        assert _parent_descriptor == (4 if path.parent.name == "attachments" else 3)
        saved[path] = data

    def read(path):
        from phase_tool.canonical import parse_json_bytes
        read_back.append(path)
        return parse_json_bytes(saved[path])

    fake_os = SimpleNamespace(O_RDONLY=0, O_DIRECTORY=1, O_NOFOLLOW=2, O_CLOEXEC=4,
        open=opened_descriptor, fstat=info, stat=named_info, getpid=lambda: 101,
        geteuid=lambda: 10001, close=closed.append)
    with patch.object(installation._NativeFileCreateReadBinding, "check_evidence_root", autospec=True,
                      return_value=root), patch.object(evidence, "os", fake_os), \
         patch.object(evidence, "_write_bytes_exclusive_atomic", side_effect=write), \
         patch.object(recovery, "read_record", side_effect=read):
        try:
            result = save_prepared_record(intent, effect, prepared, run,
                _native_store=store, _native_binding=binding)
        except PhaseError:
            assert opened == closed == read_back == [] and not saved
            raise
    assert opened == list(names) and closed == [4, 3, 2, 1, 0]
    assert list(saved) == read_back == [run / "attachments/prepared-stage.json", run / "preparation-binding.json"]
    from phase_tool.prepared_binding import binding_value
    assert result == digest_bytes(saved[read_back[0]]) == digest_bytes(canonical_bytes(prepared))
    assert saved[read_back[1]] == canonical_bytes(binding_value(intent, effect, prepared))


@pytest.mark.parametrize("version", ["3.0", "2.0"])
def test_prepared_writer_admits_exact_bundle2_role_and_writes_pair(originals, version):
    checkpoint(originals[version])


@pytest.mark.parametrize("version", ["3.0", "2.0"])
def test_prepared_writer_refuses_different_record_contract_before_io(originals, version):
    with pytest.raises(PhaseError, match="recovery.preparation_mismatch"):
        checkpoint(originals[version], mutate=lambda row: row["contract"].update(version="9.9.9"))


def test_prepared_writer_does_not_treat_semantic_tuple_as_admission(originals):
    original = originals["3.0"]
    foreign = replace(original["binding"], experimental_admission=None)
    with pytest.raises(PhaseError, match="ntfs.semantic_owner_admission_required"):
        checkpoint(original, foreign)


def test_prepared_writer_refuses_semantic_tuple_at_legacy_generation(originals):
    original = originals["3.0"]
    manifest = deepcopy(original["manifest"])
    manifest["native_read_installation_version"] = "1.8"
    raw = canonical_bytes(manifest)
    wrong_generation = replace(original["binding"], manifest_bytes=raw, manifest_digest=digest_bytes(raw))
    with pytest.raises(PhaseError, match="ntfs.original_closed_checkpoint_required"):
        checkpoint(original, wrong_generation)


def test_prepared_writer_requires_fixture_provider_binding(originals):
    original = originals["3.0"]
    manifest = deepcopy(original["manifest"])
    manifest["authority"]["provider"]["artifact_digest"] = "sha256:" + "e" * 64
    raw = canonical_bytes(manifest)
    wrong_provider = replace(original["binding"], manifest_bytes=raw, manifest_digest=digest_bytes(raw))
    with pytest.raises(PhaseError, match="ntfs.owner_fixture_binding_mismatch"):
        checkpoint(original, wrong_provider)


@pytest.fixture(scope="module")
def ordinary_original(originals):
    """Real ordinary context validation against existing in-memory test data."""
    from base64 import b64decode
    from phase_tool.canonical import parse_json_bytes
    from phase_tool.mutation.ntfs.owner_directory import require_owner_directory_binding
    from phase_tool.mutation.ntfs.owner_directory_installation import _owner_directory_bindings_with_catalog
    from tests.native_staged_original14_records import rehash
    from tests.owner_directory_test_data import owner_document, synthetic_catalog

    catalog = synthetic_catalog()
    doc = owner_document(catalog)
    raw = canonical_bytes(doc)
    row = next(item for item in doc["manifests"] if item["role"] == "Bundle2")
    binding, history = _owner_directory_bindings_with_catalog(configuration_bytes=raw,
        expected_configuration_digest=digest_bytes(raw), manifest_bytes=b64decode(row["manifest_base64"]),
        expected_manifest_digest=row["manifest_digest"], _catalog=catalog)
    assert len(history) == 6 and binding.experimental_admission is None
    assert require_owner_directory_binding(binding, "Bundle2")[0] == "Bundle2"
    manifest = parse_json_bytes(binding.manifest_bytes)
    original = dict(originals["3.0"], manifest=manifest, binding=binding,
                    intent=deepcopy(originals["3.0"]["intent"]), plan=deepcopy(originals["3.0"]["plan"]))
    intent = original["intent"]
    intent.update(core=manifest["core"], registry_snapshot_digest=binding.registry.digest)
    intent["implementation_binding"]["authority"] = manifest["authority"]
    intent["native_binding"].update(installation={"id":manifest["installation_id"], "descriptor_digest":binding.manifest_digest},
        composition=manifest["composition"], evidence_identity=manifest["evidence_identity"])
    return rehash(original)


def test_prepared_writer_accepts_existing_exact_ordinary_context_model(ordinary_original):
    checkpoint(ordinary_original)


@pytest.mark.parametrize(("alteration", "code"), [
    ("missing", "ntfs.semantic_owner_admission_required"),
    ("catalogue", "ntfs.owner_directory_catalog_mismatch"),
    ("graph", "ntfs.owner_directory_context_mismatch"),
])
def test_prepared_writer_requires_same_ordinary_catalogue_and_manifest(ordinary_original, alteration, code):
    binding = ordinary_original["binding"]
    context = binding._owner_directory_context
    if alteration == "missing":
        binding = replace(binding, _owner_directory_context=None)
    elif alteration == "catalogue":
        bad_catalog = replace(context.catalog, expected_digest="sha256:" + "e" * 64)
        binding = replace(binding, _owner_directory_context=replace(context, catalog=bad_catalog))
    else:
        manifest = deepcopy(ordinary_original["manifest"])
        manifest["composition"]["artifact_graph_digest"] = "sha256:" + "e" * 64
        raw = canonical_bytes(manifest)
        binding = replace(binding, manifest_bytes=raw, manifest_digest=digest_bytes(raw))
    with pytest.raises(PhaseError, match=code):
        checkpoint(ordinary_original, binding)
