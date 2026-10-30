"""Pure RSS-selection regressions, not new measured resource workloads."""
import importlib.util
import io
import json
from contextlib import redirect_stdout
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
import sys
import unittest


@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux resource harness module required')
class ResourceRssGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source=Path(__file__).resolve().parents[1]/'scripts'/'rc01_resources.py'
        spec=importlib.util.spec_from_file_location('phase_resource_gate_test',source)
        cls.module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def growth(self,*peaks):
        return self.module.maximum_peak_rss_growth([{'input_bytes':size,'peak_rss_bytes':peak}
            for size,peak in zip((64*1024**2,1024**3,2*1024**3),peaks)])

    def test_only_two_gib_regression_exceeds_the_existing_limit(self):
        baseline=40*1024**2;limit=128*1024**2
        # The former records[1]-records[0] formula would return zero and pass.
        growth=self.growth(baseline,baseline,baseline+limit+1)
        self.assertEqual(growth,limit+1)
        self.assertGreater(growth,limit)

    def test_one_gib_peak_still_counts_when_two_gib_is_lower(self):
        baseline=40*1024**2;limit=128*1024**2
        growth=self.growth(baseline,baseline+limit+1,baseline)
        self.assertEqual(growth,limit+1)
        self.assertGreater(growth,limit)

    def test_exact_existing_threshold_remains_accepted(self):
        baseline=40*1024**2;limit=128*1024**2
        growth=self.growth(baseline,baseline+limit,baseline+limit-1)
        self.assertEqual(growth,limit)
        self.assertLessEqual(growth,limit)

    def test_lower_larger_workload_peaks_keep_the_signed_comparison(self):
        self.assertEqual(self.growth(40*1024**2,38*1024**2,39*1024**2),-1024**2)

    def test_retained_610265c_observations_recompute_without_replaying_payloads(self):
        # Exact saved CI39775643190 values; this is arithmetic, not new ru_maxrss.
        self.assertEqual(self.growth(42172416,42164224,42266624),94208)


    def test_explicit_work_root_is_existing_and_does_not_silently_fall_back(self):
        with TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            self.assertEqual(self.module.checked_work_root(root),root)
            with self.assertRaises(FileNotFoundError):self.module.checked_work_root(root/"missing")
            file=root/"regular";file.write_bytes(b"synthetic")
            with self.assertRaises(ValueError):self.module.checked_work_root(file)
            (root/"alias").symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError):self.module.checked_work_root(root/"alias")

    def preflight_fixture(self,root):
        for name in ("source","target","prep","evidence"):(root/name).mkdir()

    def test_preflight_uses_actual_created_roots_and_records_supported_scope(self):
        with TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();self.preflight_fixture(root);output=root/"preflight.json"
            with patch("phase_tool.installation._linux_filesystem_type",return_value="ext4") as types, \
                    patch("phase_tool.installation._linux_kernel_release",return_value="synthetic-kernel"), \
                    patch("phase_tool.installation.qualify_host_authority_roots") as qualifier:
                report=self.module.resource_preflight(root,output)
            self.assertEqual(qualifier.call_args.args[0],{n:root/n for n in ("source","target","prep","evidence")})
            self.assertEqual(types.call_count,4)
            self.assertEqual(json.loads(output.read_bytes()),report)
            self.assertTrue(report["qualified"])
            self.assertTrue(all(v["filesystem"]=="ext4" for v in report["roots"].values()))
            self.assertNotIn("pass",report)  # Preflight alone is never benchmark acceptance.

    def test_preflight_preserves_actual_scope_rejection_and_exact_error_identity(self):
        from phase_tool.errors import PhaseError
        with TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();self.preflight_fixture(root);output=root/"preflight.json"
            error=PhaseError("guarantee.profile_scope_unsupported",details={"binding_id":"target","filesystem":"tmpfs"})
            with patch("phase_tool.installation._linux_filesystem_type",return_value="tmpfs"), \
                    patch("phase_tool.installation._linux_kernel_release",return_value="synthetic-kernel"), \
                    patch("phase_tool.installation.qualify_host_authority_roots",side_effect=error):
                with self.assertRaises(PhaseError) as got:self.module.resource_preflight(root,output)
            self.assertIs(got.exception,error)
            report=json.loads(output.read_bytes());self.assertFalse(report["qualified"])
            self.assertEqual(report["error"]["details"]["filesystem"],"tmpfs")
            self.assertTrue(all(not list((root/n).iterdir()) for n in ("source","target","prep","evidence")))

    def test_preflight_report_failure_does_not_replace_primary_scope_rejection(self):
        from phase_tool.errors import PhaseError
        with TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();self.preflight_fixture(root)
            error=PhaseError("guarantee.profile_scope_unsupported")
            with patch("phase_tool.installation._linux_filesystem_type",return_value="tmpfs"), \
                    patch("phase_tool.installation._linux_kernel_release",return_value="synthetic-kernel"), \
                    patch("phase_tool.installation.qualify_host_authority_roots",side_effect=error):
                with self.assertRaises(PhaseError) as got:self.module.resource_preflight(root,root/"missing/preflight.json")
            self.assertIs(got.exception,error)
            self.assertTrue(any("evidence unavailable" in n for n in error.__notes__))

    def test_parent_rejects_scope_before_input_generation_or_worker_and_passes_explicit_dir(self):
        from phase_tool.errors import PhaseError
        with TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();error=PhaseError("guarantee.profile_scope_unsupported")
            original=self.module.TemporaryDirectory
            with patch.object(sys,"argv",["resources","--output",str(root/"report.json"),"--work-root",str(root)]), \
                    patch.object(self.module,"TemporaryDirectory",wraps=original) as allocation, \
                    patch.object(self.module,"resource_preflight",side_effect=error), \
                    patch.object(self.module.hashlib,"sha256",side_effect=AssertionError("payload generation reached")), \
                    patch.object(self.module.subprocess,"run",side_effect=AssertionError("worker reached")):
                with self.assertRaises(PhaseError) as got:self.module.main()
            self.assertIs(got.exception,error);self.assertEqual(allocation.call_args.kwargs["dir"],root)
            self.assertEqual(list(root.iterdir()),[])

    def test_worker_counts_actual_inspect_calls_on_success_and_before_write_rejection(self):
        for succeeded in (False,True):
            with self.subTest(succeeded=succeeded),TemporaryDirectory() as temporary:
                class FakeApplication:
                    def publish_file(self,**kwargs):
                        if succeeded:self.inspect()
                        return SimpleNamespace(exit_code=0 if succeeded else 10,payload={"success":succeeded})
                    def inspect(self,**kwargs):return SimpleNamespace(payload={"target_verified":succeeded})
                printed=io.StringIO()
                with patch("phase_tool.application.PhaseApplication",FakeApplication), \
                        patch.object(self.module,"io_counts",return_value={"rchar":0}),redirect_stdout(printed):
                    exit_code=self.module.worker(Path(temporary))
                value=json.loads(printed.getvalue())
                self.assertEqual(exit_code,0 if succeeded else 1)
                self.assertEqual(value["technical_calls"],{"publish_file":1,"independent_inspect_inside_publish":int(succeeded),"cross_inspect":1})

    def test_worker_report_serialization_and_write_errors_do_not_replace_worker_failure(self):
        class FailedOutput:
            def write_text(self,*args,**kwargs):raise OSError("synthetic report unavailable")
        for report in ({"pass":False},{"not_json":object()}):
            with self.subTest(report=report):
                with self.assertRaisesRegex(RuntimeError,"synthetic worker exit7") as got:
                    self.module.fail_worker(FailedOutput(),report,"synthetic worker exit7")
                self.assertTrue(any("Failed worker report unavailable" in n for n in got.exception.__notes__))
        with TemporaryDirectory() as temporary:
            output=Path(temporary)/"failed.json"
            with self.assertRaisesRegex(RuntimeError,"synthetic worker exit7"):
                self.module.fail_worker(output,{"pass":False},"synthetic worker exit7")
            self.assertEqual(json.loads(output.read_bytes()),{"pass":False})

if __name__=='__main__':unittest.main()
