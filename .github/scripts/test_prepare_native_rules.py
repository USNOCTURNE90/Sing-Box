import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("prepare_native_rules", Path(__file__).with_name("prepare_native_rules.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class NativeRulesTest(unittest.TestCase):
    def documents(self):
        return {
            "USproxyRules.json": {"version": 1, "rules": [{
                "domain_suffix": ["google.com"], "ip_cidr": ["208.0.0.0/8", "199.0.0.0/8"], "ip_asn": ["20473"],
            }]},
            "MyDirectRules.json": {"version": 1, "rules": [{"domain": ["direct.example"], "ip_cidr": ["1.2.3.4/32"]}]},
            "LAN.json": {"version": 1, "rules": [{
                "domain": ["guzzoni.apple.com"], "domain_suffix": ["local", "ess.apple.com"], "ip_cidr": ["100.64.0.0/10"],
            }]},
        }

    def test_asn_expands_without_removing_explicit_ranges(self):
        original = self.documents()
        out = module.prepare(original, lambda _: ["45.32.0.0/16"])
        self.assertEqual(out["USproxyRules.json"]["rules"][0]["ip_cidr"], ["208.0.0.0/8", "199.0.0.0/8", "45.32.0.0/16"])
        self.assertNotIn("ip_asn", out["USproxyRules.json"]["rules"][0])
        self.assertIn("ip_asn", original["USproxyRules.json"]["rules"][0])

    def test_domain_exports_cannot_change_dns_into_ip_filter(self):
        out = module.prepare(self.documents(), lambda _: ["45.32.0.0/16"])
        self.assertEqual(out["USproxyRules-domain.json"]["rules"], [{"domain_suffix": ["google.com"]}])
        self.assertEqual(out["MyDirectRules-domain.json"]["rules"], [{"domain": ["direct.example"]}])

    def test_lan_and_system_are_separate(self):
        out = module.prepare(self.documents(), lambda _: ["45.32.0.0/16"])
        self.assertEqual(out["LAN.json"]["rules"], [{"domain_suffix": ["local"], "ip_cidr": ["100.64.0.0/10"]}])
        self.assertIn("guzzoni.apple.com", out["SYSTEM.json"]["rules"][0]["domain"])

    def test_empty_or_failed_asn_must_abort(self):
        with self.assertRaises(ValueError):
            module.prepare(self.documents(), lambda _: [])
        with self.assertRaises(ValueError):
            module.active_prefixes({"status": "error"})

    def test_only_current_announcements_are_used(self):
        payload = {"status": "ok", "data": {"query_endtime": "current", "prefixes": [
            {"prefix": "1.2.3.0/24", "timelines": [{"endtime": "current"}]},
            {"prefix": "1.2.4.0/24", "timelines": [{"endtime": "old"}]},
        ]}}
        self.assertEqual(module.active_prefixes(payload), ["1.2.3.0/24"])

    def test_repeated_preparation_is_idempotent(self):
        out = module.prepare(self.documents(), lambda _: ["45.32.0.0/16"])
        again = module.prepare({**self.documents(), **out}, lambda _: self.fail("Must not expand twice"))
        self.assertEqual(out, again)


if __name__ == "__main__":
    unittest.main()
