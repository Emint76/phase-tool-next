"""Schema/profile data checks only; no native installation or qualification."""
from copy import deepcopy
from importlib import resources as package_resources
import unittest

from phase_tool.canonical import canonical_bytes, canonical_digest, digest_bytes, parse_json_bytes
from phase_tool.errors import PhaseError
from phase_tool.registry import BundledRegistry, RegistrySnapshot


_SCHEMA = "schemas/mutation-guarantee-profile-1.1.schema.json"
_URI = "https://phase-tool.local/" + _SCHEMA
_RESOURCE = "descriptors/guarantee/test.native.candidate.authority.v1.json"
_ID = "phase.test.native.candidate.authority.v1"


def _fixture():
    bundled = BundledRegistry.load()
    document, resources = bundled.to_document(), dict(BundledRegistry.resources())
    original = next(e for e in document["entries"] if e.get("kind") == "guarantee_profile")
    descriptor = parse_json_bytes(resources[original["artifact"]])
    descriptor.update(descriptor_version="1.1", id=_ID, classification="qualification_candidate",
        provided_guarantees=[], conformance=[])
    # This leaf artifact hash only validates this profile field; it is not the
    # trusted runtime graph, an admitted installation or a conformance report.
    leaf = "phase_tool/mutation/ntfs/file_create.py"
    leaf_bytes = package_resources.files("phase_tool").joinpath("mutation/ntfs/file_create.py").read_bytes()
    descriptor["implementation"] = {"id": "phase.test.native.authority", "version": "1.0.0",
        "artifact": leaf, "artifact_digest": digest_bytes(leaf_bytes)}
    descriptor["storage_scope"] = {"filesystem": "Unqualified synthetic NTFS profile data only",
        "mount_boundary": "No admission", "cooperating_processes_only": True}
    descriptor["limitations"] = ["NOT_VERIFIED: no native execution, G01/A05, MIX or qualification."]
    schema_entry = deepcopy(next(e for e in document["entries"]
        if e.get("schema_ref") == "https://phase-tool.local/schemas/mutation-guarantee-profile.schema.json"))
    schema_sha = digest_bytes(resources[_SCHEMA])
    schema_entry.update(id="schema.mutation_guarantee_profile_1_1", version="1.1.0", artifact=_SCHEMA,
        schema_ref=_URI, artifact_digest=schema_sha, package_digest=schema_sha)
    entry = deepcopy(original)
    entry.update(id=_ID, artifact=_RESOURCE)
    entry["package_artifacts"] = [a for a in entry["package_artifacts"] if a["resource"] != original["artifact"]
        and a["resource"] != "schemas/mutation-guarantee-profile.schema.json"]
    entry["package_artifacts"] += [{"resource": _SCHEMA, "digest": schema_sha}]
    document["entries"] += [schema_entry, entry]
    return document, resources, descriptor, entry


def _snapshot(document, resources, descriptor, entry):
    raw = canonical_bytes(descriptor)
    resources[_RESOURCE] = raw
    entry["artifact_digest"] = digest_bytes(raw)
    dependencies = [a for a in entry["package_artifacts"] if a["resource"] != _RESOURCE]
    entry["package_artifacts"] = [{"resource": _RESOURCE, "digest": entry["artifact_digest"]}] + dependencies
    entry["package_digest"] = canonical_digest({"profile": "phase_contract_package_v1",
        "artifacts": entry["package_artifacts"]})
    binding = {"id": _ID, "version": "1.0.0", "descriptor_digest": entry["artifact_digest"]}
    return RegistrySnapshot.from_document(document, resources), binding


class NativeProfileSchemaTests(unittest.TestCase):
    def rejected(self, fixture, code):
        registry, binding = _snapshot(*fixture)
        with self.assertRaises(PhaseError) as failure:
            registry.resolve_guarantee_profile(binding)
        self.assertEqual(failure.exception.code, code)

    def test_old_posix_profile_keeps_exact_binding_and_schema(self):
        registry = BundledRegistry.load()
        binding = registry.guarantee_profile_bindings()["phase.posix.authority.v1@1.0.0"]
        self.assertEqual(binding["descriptor_digest"],
            "sha256:0e721cd573a90813de73a8ee1e2b5574d7e67438bbcf03430de355d065bee42f")
        profile = registry.resolve_guarantee_profile(binding)
        self.assertEqual(profile["descriptor_version"], "1.0")
        self.assertEqual(profile["classification"], "production")
        self.assertEqual(len(profile["provided_guarantees"]), 6)

    def test_candidate_has_empty_claims_and_distinct_binding(self):
        fixture = _fixture()
        before = deepcopy(BundledRegistry.load().to_document())
        registry, binding = _snapshot(*fixture)
        profile = registry.resolve_guarantee_profile(binding)
        self.assertEqual(profile["classification"], "qualification_candidate")
        self.assertEqual(profile["provided_guarantees"], [])
        self.assertEqual(profile["conformance"], [])
        self.assertEqual(registry.to_document()["entries"][:len(before["entries"])], before["entries"])
        self.assertEqual(set(registry.guarantee_profile_bindings()),
            {"phase.posix.authority.v1@1.0.0", _ID + "@1.0.0"})

    def test_candidate_cannot_claim_a_provided_guarantee(self):
        f = _fixture(); f[2]["provided_guarantees"] = ["exclusive_create"]
        self.rejected(f, "guarantee_profile.schema_invalid")

    def test_candidate_cannot_claim_conformance(self):
        f = _fixture(); f[2]["conformance"] = [{"guarantee": "exclusive_create", "test_id": "synthetic"}]
        self.rejected(f, "guarantee_profile.schema_invalid")

    def test_unknown_descriptor_version_is_rejected(self):
        for version in ("1.2", ["1.1"], {"version": "1.1"}, True, None):
            with self.subTest(version=version):
                f = _fixture(); f[2]["descriptor_version"] = version
                self.rejected(f, "guarantee_profile.schema_unsupported")

    def test_missing_exact_schema_package_binding_is_rejected(self):
        f = _fixture(); f[3]["package_artifacts"] = [a for a in f[3]["package_artifacts"] if a["resource"] != _SCHEMA]
        self.rejected(f, "guarantee_profile.schema_unbound")

    def test_absent_null_or_malformed_package_binding_has_closed_error(self):
        for bad in (None, "absent", {}, True, [None], [{"resource": []}], [{"resource": _SCHEMA, "digest": None}]):
            with self.subTest(bad=bad):
                fixture = _fixture()
                registry, binding = _snapshot(*fixture)
                document = registry.to_document()
                entry = next(e for e in document["entries"] if e.get("id") == _ID)
                if bad == "absent":
                    del entry["package_artifacts"]
                else:
                    entry["package_artifacts"] = bad
                altered = RegistrySnapshot.from_document(document, fixture[1])
                with self.assertRaises(PhaseError) as failure:
                    altered.resolve_guarantee_profile(binding)
                self.assertEqual(failure.exception.code, "guarantee_profile.schema_unbound")

    def test_duplicate_exact_schema_package_binding_is_rejected(self):
        f = _fixture(); f[3]["package_artifacts"].append(deepcopy(next(a for a in f[3]["package_artifacts"] if a["resource"] == _SCHEMA)))
        self.rejected(f, "guarantee_profile.schema_unbound")

    def test_profile_uses_package_bound_schema_even_with_another_current(self):
        f = _fixture()
        schema = parse_json_bytes(f[1][_SCHEMA]); schema["properties"]["classification"] = {"const": "never"}
        other_raw = canonical_bytes(schema); other_sha = digest_bytes(other_raw)
        other = deepcopy(f[0]["entries"][-2]); other.update(id="schema.synthetic.other", artifact="schemas/synthetic-other.json",
            artifact_digest=other_sha, package_digest=other_sha, current=True)
        f[1][other["artifact"]] = other_raw; f[0]["entries"].append(other)
        registry, binding = _snapshot(*f)
        self.assertEqual(registry.resolve_guarantee_profile(binding)["classification"], "qualification_candidate")

    def test_descriptor_cannot_select_a_schema_uri(self):
        f = _fixture(); f[2]["$schema"] = "https://example.invalid/untrusted"
        self.rejected(f, "guarantee_profile.schema_invalid")

    def test_changed_schema_bytes_are_rejected_before_validation(self):
        f = _fixture(); f[1][_SCHEMA] += b" "
        self.rejected(f, "registry.digest_mismatch")

    def test_native_profile_cannot_relabel_posix_implementation(self):
        f = _fixture(); f[2]["implementation"]["artifact"] = "phase_tool/mutation/posix/authority.py"
        self.rejected(f, "guarantee_profile.schema_invalid")

    def test_wrong_leaf_digest_is_rejected_without_executing_leaf(self):
        f = _fixture(); f[2]["implementation"]["artifact_digest"] = "sha256:" + "0" * 64
        self.rejected(f, "guarantee_profile.implementation_digest_mismatch")

    def test_production_cannot_have_an_empty_provided_set(self):
        f = _fixture(); f[2]["classification"] = "production"
        self.rejected(f, "guarantee_profile.schema_invalid")

    def test_production_conformance_must_match_known_guarantees(self):
        f = _fixture(); f[2].update(classification="production", provided_guarantees=["exclusive_create"],
            conformance=[{"guarantee": "readback_verification", "test_id": "synthetic_not_qualification"}])
        self.rejected(f, "guarantee_profile.conformance_incomplete")
