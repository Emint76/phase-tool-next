"""Exact private C01 fixture binding with no publication or process start."""
import ast
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
import unittest

from phase_tool.canonical import canonical_bytes
from phase_tool.errors import PhaseError
from phase_tool.mutation.ntfs import common_flock_test as observer, owner_directory_fixture as owner
from phase_tool.mutation.ntfs.owner_semantic_contracts import semantic_owner_contract

from .native_staged_original14_data import fixture


def binding(case,launcher):
    doc = fixture("3.0")
    before = doc["fixture_uuid"]
    doc.update(fixture_uuid=case,owner_scope_id="phase.qualification.owner."+case)
    doc["windows_roots"] = {role:root.replace(before,case) for role,root in doc["windows_roots"].items()}
    for grant in doc["root_grants"]:
        grant["components"][1] = case
    doc["request_limits"]["run_prefix"] = "od3-"+case+"-"
    raw = canonical_bytes(doc)
    parsed = owner.fixture_document(raw)
    admission = owner._kinds()["File2"](raw)
    config = {"native_launch_version":"3.0","artifact_graph":{"launcher_digest":launcher}}
    manifest = {"contract":semantic_owner_contract("File2")}
    return parsed,admission,config,manifest


def frontend(run,scope):
    return {"run_id":run,"request":{"operation":"publish_file","input_scope":scope,
        "source_locator":"file2.bin","target_locator":"c01-timeout-file2.bin",
        "request_id":"c01.file2.timeout.component.v1","publication_version":"2.0",
        "expected_digest":observer._TIMEOUT_DIGEST,"root_binding":"phase_result_root"}}


def core(run,scope):
    header = "sha256:"+"f"*64
    return {"run_id":run,"channel_id":"a"*32,"operation_nonce":"b"*32,"request":{
        "operation":"execute","native_staged_publication_request_version":"1.0","input_scope":scope,
        "stage_header_digest":header,"source_locator":"phase-native-input-"+header[7:39]+"/payload/payload",
        "source_digest":observer._TIMEOUT_DIGEST,"source_length":65536,"request_id":"c01.file2.timeout.component.v1",
        "target_locator":"c01-timeout-file2.bin","members":None,"expected_current_digest":None,"content_utf8":None}}


class ClosedC01TimeoutBinding(unittest.TestCase):
    def test_actual_fixture_parser_and_both_immutable_launcher_pairs(self):
        for case,run,scope,launcher in (
            (observer._TIMEOUT_CASE,observer._TIMEOUT_RUN,observer._TIMEOUT_SCOPE,observer._TIMEOUT_LAUNCHER),
            (observer._TIMEOUT_FRESH_CASE,observer._TIMEOUT_FRESH_RUN,
             observer._TIMEOUT_FRESH_SCOPE,observer._TIMEOUT_FRESH_LAUNCHER),
        ):
            with self.subTest(case=case):
                parsed,admission,config,manifest = binding(case,launcher)
                self.assertEqual(observer._require_timeout_startup(config,manifest,admission),(run,scope))
                launch = SimpleNamespace(_config=config,manifest=manifest,_experimental_admission_context=admission,run_id=run)
                self.assertEqual(observer._closed_timeout_launcher(launch,parsed),launcher)
                launch.run_id += "-foreign"
                with self.assertRaises(PhaseError):
                    observer._closed_timeout_launcher(launch,parsed)

    def test_foreign_or_cross_paired_context_cannot_bind(self):
        for case,launcher in (
            (observer._TIMEOUT_CASE,observer._TIMEOUT_FRESH_LAUNCHER),
            (observer._TIMEOUT_FRESH_CASE,observer._TIMEOUT_LAUNCHER),
            ("bc5542d1-7c1e-4561-a6e2-0aee40392b89",observer._TIMEOUT_FRESH_LAUNCHER),
        ):
            with self.subTest(case=case):
                _,admission,config,manifest = binding(case,launcher)
                with self.assertRaises(PhaseError):
                    observer._require_timeout_startup(config,manifest,admission)
        _,admission,config,manifest = binding(observer._TIMEOUT_FRESH_CASE,observer._TIMEOUT_FRESH_LAUNCHER)
        with self.assertRaises(PhaseError):
            observer._require_timeout_startup(config,manifest,owner._kinds()["File1"](admission.raw))
        with self.assertRaises(PhaseError):
            observer._require_timeout_startup(config,{"contract":semantic_owner_contract("File1")},admission)

    def test_frontend_and_core_require_same_startup_pair(self):
        old = (observer._TIMEOUT_RUN,observer._TIMEOUT_SCOPE)
        new = (observer._TIMEOUT_FRESH_RUN,observer._TIMEOUT_FRESH_SCOPE)
        for make,check in ((frontend,observer._require_timeout_frontend),(core,observer._require_timeout_core)):
            check(make(*old))
            check(make(*new),_startup=new)
            for body,startup in ((make(*new),old),(make(*old),new),(make(*new),list(new)),
                                 (make(new[0],old[1]),new),(make(*new)|{"_startup":new},new)):
                with self.subTest(check=check.__name__,startup=startup):
                    with self.assertRaises(PhaseError):
                        check(body,_startup=startup)

    def test_staging_header_uses_same_resolved_admission_scope(self):
        _,admission,config,manifest = binding(observer._TIMEOUT_FRESH_CASE,observer._TIMEOUT_FRESH_LAUNCHER)
        run,scope = observer._TIMEOUT_FRESH_RUN,observer._TIMEOUT_FRESH_SCOPE
        launch = SimpleNamespace(_config=config,manifest=manifest,_experimental_admission_context=admission,run_id=run)
        header = {"run_id":run,"input_scope":scope,"role":"File2","source_locator":"file2.bin",
            "payload_kind":"file","member_count":1,"total_length":65536,"members":[{"path":"payload","length":65536}]}
        observer._require_timeout_stage(launch,{"scope_id":scope},"File2",header)
        for mutation in ({"run_id":observer._TIMEOUT_RUN},{"input_scope":observer._TIMEOUT_SCOPE},
                         {"member_count":True},{"total_length":65535}):
            with self.subTest(mutation=mutation):
                with self.assertRaises(PhaseError):
                    observer._require_timeout_stage(launch,{"scope_id":scope},"File2",header|mutation)

    def test_fixture_hash_and_private_role_call_sites(self):
        path = Path(__file__).parent/"fixtures/native/qualification_fixed_native_c01_timeout_v3.py.in"
        raw = path.read_bytes()
        self.assertEqual("sha256:"+sha256(raw).hexdigest(),observer._TIMEOUT_FRESH_LAUNCHER)
        tree = ast.parse(raw)
        main = next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="main")
        src = ast.get_source_segment(raw.decode(),main)
        self.assertIn("({'publish-input'} if os.name=='nt' else {'prepare-input','core'})",src)
        self.assertLess(src.index("bound=_require_timeout_startup"),src.index("receive_initial()"))
        self.assertEqual(src.count("_startup=bound"),2)
        self.assertIn("_c01_timeout_stage=True",src)
        self.assertIn("_CommonCoreFlockTest(launch,_initial_deadline=initial_deadline_ns)",src)


if __name__=="__main__":
    unittest.main(verbosity=2)
