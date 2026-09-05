#!/usr/bin/env python3

import pathlib
import sys
import tempfile
import unittest
from unittest import mock


LOOKUP_DIR = (
    pathlib.Path(__file__).parents[1] / "ansible/roles/tuwunel/files"
)
sys.path.insert(0, str(LOOKUP_DIR))

import ip_country_lookup as lookup  # noqa: E402
from ip_country_lookup import CountryDatabase, country_flag  # noqa: E402


class IpCountryLookupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.data_dir = pathlib.Path(self.temporary.name)
        (self.data_dir / "user-country-ipv4.csv").write_text(
            "1.0.0.0,1.0.0.255,AU\n"
            "1.0.1.0,1.0.3.255,CN\n"
            "8.8.8.0,8.8.8.255,US\n",
            encoding="ascii",
        )
        (self.data_dir / "user-country-ipv6.csv").write_text(
            "2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP\n"
            "2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n",
            encoding="ascii",
        )
        self.database = CountryDatabase(self.data_dir)

    def tearDown(self):
        self.temporary.cleanup()

    def test_finds_ipv4_and_ipv6_ranges(self):
        self.assertEqual(self.database.lookup("1.0.2.10"), "CN")
        self.assertEqual(self.database.lookup("2001:200::1234"), "JP")

    def test_returns_none_for_gaps_private_and_invalid_values(self):
        self.assertIsNone(self.database.lookup("1.0.4.1"))
        self.assertIsNone(self.database.lookup("10.42.0.10"))
        self.assertIsNone(self.database.lookup("not-an-ip"))

    def test_uses_ipv4_database_for_mapped_ipv6(self):
        self.assertEqual(self.database.lookup("::ffff:8.8.8.8"), "US")

    def test_converts_country_code_to_flag(self):
        self.assertEqual(country_flag("hu"), "🇭🇺")
        self.assertIsNone(country_flag("unknown"))

    def test_country_names_and_unknown_code_fallback(self):
        names = self.data_dir / "iso3166.tab"
        names.write_text("# Countries\nUS\tUnited States\nIT\tItaly\nFR\tFrance\n")
        lookup._country_names.cache_clear()
        self.addCleanup(lookup._country_names.cache_clear)
        with mock.patch.object(lookup, "COUNTRY_NAMES_PATH", names):
            self.assertEqual(lookup.country_name("us"), "United States")
            self.assertEqual(lookup.country_name("IT"), "Italy")
            self.assertEqual(lookup.country_name("FR"), "France")
            self.assertEqual(lookup.country_name("ZZ"), "ZZ")

    def test_missing_country_names_preserves_code(self):
        lookup._country_names.cache_clear()
        self.addCleanup(lookup._country_names.cache_clear)
        with mock.patch.object(lookup, "COUNTRY_NAMES_PATH", self.data_dir / "missing"):
            self.assertEqual(lookup.country_name("US"), "US")


if __name__ == "__main__":
    unittest.main()
