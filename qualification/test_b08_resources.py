from dataclasses import replace
import unittest

from b08_resources import BUDGETS, CAMPAIGN_CAP, GIB, RESERVE, Sample, admit, monitor


class ResourceGateTests(unittest.TestCase):
    def test_both_profiles_accept_exact_floors_and_reject_one_byte_short(self):
        for lane, budget in BUDGETS.items():
            start = Sample(*(x * GIB for x in budget.floors), vhdx_bytes=30 * GIB)
            admit(lane, start, 0)
            for field, store in (("c_free", "C:"), ("ext4_free", "ext4"), ("s_free", "S:")):
                with self.subTest(lane=lane, store=store), self.assertRaisesRegex(ValueError, store):
                    admit(lane, replace(start, **{field: getattr(start, field) - 1}), 0)

    def test_retained_and_peak_are_added_before_admission(self):
        start = Sample(20 * GIB, 20 * GIB, 20 * GIB, 30 * GIB)
        remaining = CAMPAIGN_CAP - BUDGETS["REF"].campaign_peak
        admit("REF", start, remaining - 1)
        with self.assertRaisesRegex(ValueError, "campaign cap"):
            admit("REF", start, remaining)

    def test_runtime_guard_checks_actual_reserve_draw_and_vhdx_growth(self):
        start = Sample(20 * GIB, 20 * GIB, 20 * GIB, 30 * GIB)
        monitor("REF", start, replace(start, ext4_free=12 * GIB))
        with self.assertRaisesRegex(ValueError, "runtime reserve"):
            monitor("REF", start, replace(start, s_free=RESERVE - 1))
        with self.assertRaisesRegex(ValueError, "free-space draw"):
            monitor("REF", start, replace(start, ext4_free=11 * GIB))
        with self.assertRaisesRegex(ValueError, "VHDX growth"):
            monitor("REF", start, replace(start, vhdx_bytes=40 * GIB))


if __name__ == "__main__":
    unittest.main()
