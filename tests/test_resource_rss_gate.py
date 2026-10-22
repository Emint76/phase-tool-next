"""Pure RSS-selection regressions, not new measured resource workloads."""
import importlib.util
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


if __name__=='__main__':unittest.main()
