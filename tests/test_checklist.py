import json
import unittest

from lss_stig import benchmarks, checklist

KEY = "ubuntu2404_v1r6"
TARGET = {"target_type": "Computing", "host_name": "h", "ip_address": "", "mac_address": "",
          "fqdn": "h", "comments": "", "role": "None", "is_web_database": False,
          "technology_area": "", "web_db_site": "", "web_db_instance": "", "classification": None}


class ChecklistTests(unittest.TestCase):
    def setUp(self):
        self.bench = benchmarks.activate(KEY)
        self.results = {
            "V-270647": {"status": "pass", "detail": "", "evidence": "dpkg-query telnetd: not installed"},
            "V-270708": {"status": "fail", "detail": "X11Forwarding not set", "evidence": "sshd -T: x11forwarding yes"},
            "V-270748": {"status": "review", "detail": "1 member(s): bob", "evidence": ""},
            "V-270711": {"status": "na", "detail": "no GNOME desktop installed", "evidence": ""},
        }
        self.doc = checklist.build(self.bench, self.results, target=TARGET, title="t")

    def test_top_level_shape(self):
        for k in ("title", "id", "stigs", "active", "mode", "has_path", "target_data", "cklb_version"):
            self.assertIn(k, self.doc)
        self.assertEqual(self.doc["cklb_version"], "1.0")
        stig = self.doc["stigs"][0]
        self.assertEqual(stig["stig_id"], "CAN_Ubuntu_24-04_STIG")
        self.assertEqual(stig["size"], 194)
        self.assertEqual(len(stig["rules"]), 194)

    def test_every_rule_is_complete(self):
        stig = self.doc["stigs"][0]
        for r in stig["rules"]:
            self.assertEqual(r["stig_uuid"], stig["uuid"])
            self.assertIn(r["status"], {"not_a_finding", "open", "not_applicable", "not_reviewed"})
            self.assertTrue(r["rule_id_src"].endswith("_rule"))
            self.assertEqual(r["rule_id"] + "_rule", r["rule_id_src"])
            self.assertTrue(r["check_content"])
            self.assertTrue(r["group_tree"][0]["id"].startswith("V-"))

    def test_status_mapping_and_evidence(self):
        rules = {r["group_id"]: r for r in self.doc["stigs"][0]["rules"]}
        self.assertEqual(rules["V-270647"]["status"], "not_a_finding")
        self.assertEqual(rules["V-270708"]["status"], "open")
        self.assertIn("x11forwarding yes", rules["V-270708"]["finding_details"])
        self.assertEqual(rules["V-270748"]["status"], "not_reviewed")
        self.assertEqual(rules["V-270711"]["status"], "not_applicable")
        # untouched rules stay not_reviewed and say so
        self.assertEqual(rules["V-270645"]["status"], "not_reviewed")
        self.assertIn("not automated", rules["V-270645"]["comments"])

    def test_serializable(self):
        json.loads(json.dumps(self.doc))


if __name__ == "__main__":
    unittest.main()
