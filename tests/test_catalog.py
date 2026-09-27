import unittest

from lss_stig import benchmarks
from lss_stig.lib.registry import get_control, load_benchmark, select_rules

KEY = "ubuntu2404_v1r6"


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.bench = benchmarks.activate(KEY)

    def test_release_and_counts_match_disa(self):
        b = load_benchmark(KEY)
        self.assertEqual(b.stig_id, "CAN_Ubuntu_24-04_STIG")
        self.assertIn("Release: 6", b.release_info)
        self.assertEqual(b.label, "Ubuntu 24.04 V1R6")
        sev = {}
        for r in b.rules:
            sev[r.severity] = sev.get(r.severity, 0) + 1
        self.assertEqual(sev, {"high": 16, "medium": 161, "low": 17})

    def test_ids_unique(self):
        for attr in ("vuln_id", "rule_id", "stig_id"):
            vals = [getattr(r, attr) for r in self.bench.rules]
            self.assertEqual(len(vals), len(set(vals)), attr)

    def test_every_rule_has_a_control(self):
        missing = [r.vuln_id for r in self.bench.rules
                   if get_control(KEY, r.vuln_id) is None]
        self.assertEqual(missing, [])

    def test_select_by_any_id_form(self):
        by_v = select_rules(self.bench, ["v-270647"])
        by_stig = select_rules(self.bench, ["UBTU-24-100030"])
        by_sv = select_rules(self.bench, [by_v[0].rule_id])
        self.assertEqual(by_v, by_stig)
        self.assertEqual(by_v, by_sv)

    def test_select_unknown_id_raises(self):
        with self.assertRaises(ValueError):
            select_rules(self.bench, ["V-000000"])

    def test_select_by_category(self):
        self.assertEqual(len(select_rules(self.bench, None, ["I"])), 16)
        self.assertEqual(len(select_rules(self.bench, None, ["III"])), 17)


if __name__ == "__main__":
    unittest.main()
