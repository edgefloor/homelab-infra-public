import unittest

from verify_crowdsec_ban import owned_exception, set_contains


class DecisionSetTests(unittest.TestCase):
    def test_cleanup_refuses_reused_foreign_rule_handle(self):
        document = {"nftables": [{"rule": {"handle": 12, "comment": "production"}}]}
        with self.assertRaisesRegex(RuntimeError, "ownership changed"):
            owned_exception(document, "12", "hla123abc")

    def test_cleanup_handles_owned_and_already_removed_rules(self):
        rule = {"handle": 12, "comment": "hla123abc"}
        self.assertEqual(
            owned_exception({"nftables": [{"rule": rule}]}, "12", "hla123abc"), rule
        )
        self.assertIsNone(owned_exception({"nftables": []}, "12", "hla123abc"))

    def test_rule_reference_does_not_keep_removed_decision_alive(self):
        document = {
            "nftables": [
                {"set": {"elem": []}},
                {"rule": {"expr": [{"match": {"right": "198.18.255.2"}}]}},
            ]
        }
        self.assertFalse(set_contains(document, "198.18.255.2"))

    def test_address_match_is_exact(self):
        document = {"nftables": [{"set": {"elem": ["198.18.255.20"]}}]}
        self.assertFalse(set_contains(document, "198.18.255.2"))

    def test_plain_and_timeout_wrapped_elements(self):
        for element in [
            "198.18.255.2",
            {"elem": {"val": "198.18.255.2", "expires": 1000}},
        ]:
            with self.subTest(element=element):
                self.assertTrue(
                    set_contains(
                        {"nftables": [{"set": {"elem": [element]}}]}, "198.18.255.2"
                    )
                )

    def test_ipv6_element(self):
        self.assertTrue(
            set_contains(
                {"nftables": [{"set": {"elem": ["2001:db8:ffff:214::2"]}}]},
                "2001:db8:ffff:214::2",
            )
        )
