import importlib.util
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.request import Request


SOURCE = Path(__file__).resolve().parents[1] / 'ansible/roles/coredns/files/update_adblock.py'
SPEC = importlib.util.spec_from_file_location('coredns_adblock', SOURCE)
adblock = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(adblock)


class AdblockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.config = {'sources': ['https://example.com/hosts'], 'minimum_domains': 2,
                       'protected_domains': ['home.example'], 'allowlist': [], 'extra_domains': []}
        self.feed = ('0.0.0.0 ads.example tracker.example\n'
                     '0.0.0.0 home.example jf.home.example\n'
                     '0.0.0.0 ads.allowed.example\n127.0.0.1 localhost\n')

    def refresh(self, feed=None):
        return adblock.update(self.config, self.directory, True,
                              download=lambda _: self.feed if feed is None else feed)

    def output(self):
        return (self.directory / 'blocked.hosts').read_text()

    def test_blocks_both_address_families_and_protects_homelab(self):
        self.refresh()
        self.assertIn('0.0.0.0 ads.example\n:: ads.example\n', self.output())
        self.assertNotIn('home.example', self.output())
        self.assertNotIn('localhost', self.output())

    def test_allowlist_and_local_blocks_rebuild_without_network(self):
        self.refresh()
        self.config['allowlist'] = ['allowed.example', 'ads.example']
        self.config['extra_domains'] = ['custom.example', 'ads.example']
        adblock.update(self.config, self.directory)
        self.assertIn('0.0.0.0 custom.example', self.output())
        self.assertNotIn('ads.example', self.output())
        self.assertNotIn('ads.allowed.example', self.output())
        self.assertIn('tracker.example', self.output())

    def test_failed_download_keeps_both_last_good_files(self):
        self.refresh()
        before = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        def unavailable(_):
            raise OSError('network unavailable')
        with self.assertRaises(OSError):
            adblock.update(self.config, self.directory, True, unavailable)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.directory.iterdir()})

    def test_failure_of_later_source_keeps_both_last_good_files(self):
        self.refresh()
        before = {p.name: p.read_bytes() for p in self.directory.iterdir()}
        self.config['sources'].append('https://example.com/second-hosts')
        responses = iter(['0.0.0.0 new.example another.example', '<html>upstream error</html>'])
        with self.assertRaises(ValueError):
            adblock.update(self.config, self.directory, True, lambda _: next(responses))
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.directory.iterdir()})

    def test_empty_or_error_page_download_preserves_last_good_list(self):
        self.refresh()
        before = self.output()
        for feed in ('', '<html>upstream error</html>', '0.0.0.0 one.example'):
            with self.subTest(feed=feed), self.assertRaises(ValueError):
                self.refresh(feed)
            self.assertEqual(before, self.output())

    def test_invalid_exception_is_rejected_without_replacing_list(self):
        self.refresh()
        before = self.output()
        self.config['allowlist'] = ['https://ads.example']
        with self.assertRaises(ValueError):
            adblock.update(self.config, self.directory)
        self.assertEqual(before, self.output())

    def test_unchanged_refresh_does_not_replace_the_active_file(self):
        self.refresh()
        before = (self.directory / 'blocked.hosts').stat().st_mtime_ns
        self.assertEqual(0, self.refresh()['changed'])
        self.assertEqual(before, (self.directory / 'blocked.hosts').stat().st_mtime_ns)


class DownloadTests(unittest.TestCase):
    def test_redirect_rejects_insecure_hop_before_following_it(self):
        handler = adblock.HTTPSOnlyRedirectHandler()
        handler.parent = Mock()
        for target in ('http://example.com/hosts', 'ftp://example.com/hosts'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                handler.http_error_302(Request('https://example.com/hosts'), io.BytesIO(),
                                       302, 'Found', {'location': target})
            handler.parent.open.assert_not_called()

    def test_redirect_allows_https(self):
        handler = adblock.HTTPSOnlyRedirectHandler()
        handler.parent = Mock()
        request = Request('https://example.com/hosts')
        request.timeout = 30
        handler.http_error_302(request, io.BytesIO(), 302, 'Found',
                               {'location': 'https://mirror.example/hosts'})
        self.assertEqual('https://mirror.example/hosts',
                         handler.parent.open.call_args.args[0].full_url)

    def test_fetch_validates_transport_content_and_download_limit(self):
        with patch.object(adblock, 'build_opener') as build:
            with self.assertRaises(ValueError):
                adblock.fetch('http://example.com/hosts')
            build.assert_not_called()
            response = build.return_value.open.return_value.__enter__.return_value
            response.geturl.return_value = 'https://example.com/hosts'
            response.read.return_value = b'0.0.0.0 ads.example\n'
            self.assertEqual('0.0.0.0 ads.example\n', adblock.fetch('https://example.com/hosts'))
            self.assertIsInstance(build.call_args.args[0], adblock.HTTPSOnlyRedirectHandler)
            response.read.assert_called_once_with(adblock.MAX_BYTES + 1)
            with patch.object(adblock, 'MAX_BYTES', 8):
                response.read.return_value = b'123456789'
                with self.assertRaisesRegex(ValueError, 'size limit'):
                    adblock.fetch('https://example.com/hosts')
            response.read.return_value = b'\xff'
            with self.assertRaises(UnicodeDecodeError):
                adblock.fetch('https://example.com/hosts')
            response.geturl.return_value = 'http://example.com/hosts'
            with self.assertRaisesRegex(ValueError, 'away from HTTPS'):
                adblock.fetch('https://example.com/hosts')


if __name__ == '__main__':
    unittest.main()
