"""Offline unit tests for APEX. No network access is required."""
import json
import urllib.error
import urllib.request
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import apex


class URLValidationTests(unittest.TestCase):
    def test_adds_https_scheme(self):
        normalized, host = apex.normalize_https_url("example.com/path")
        self.assertEqual(normalized, "https://example.com/path")
        self.assertEqual(host, "example.com")

    def test_rejects_plain_http(self):
        with self.assertRaises(ValueError):
            apex.normalize_https_url("http://example.com")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(ValueError):
            apex.normalize_https_url("https://user:secret@example.com")

    def test_rejects_missing_hostname(self):
        with self.assertRaises(ValueError):
            apex.normalize_https_url("https://")

    def test_blocks_https_to_http_redirect(self):
        handler = apex.HTTPSOnlyRedirectHandler()
        request = urllib.request.Request("https://example.com/start")
        with self.assertRaises(urllib.error.URLError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://example.com/plain")

    def test_allows_https_redirect(self):
        handler = apex.HTTPSOnlyRedirectHandler()
        request = urllib.request.Request("https://example.com/start")
        redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://example.com/next")
        self.assertEqual(redirected.full_url, "https://example.com/next")


class PasswordTests(unittest.TestCase):
    def test_generator_length_and_character_classes(self):
        for length in (16, 24, 32, 63):
            password = apex.generate_password(length)
            self.assertEqual(len(password), length)
            self.assertTrue(any(c.islower() for c in password))
            self.assertTrue(any(c.isupper() for c in password))
            self.assertTrue(any(c.isdigit() for c in password))
            self.assertTrue(any(c in "!@#$%^&*()-_=+" for c in password))

    def test_generator_rejects_out_of_range(self):
        for length in (0, 7, 64, 100):
            with self.subTest(length=length):
                with self.assertRaises(ValueError):
                    apex.generate_password(length)

    def test_common_password_is_flagged(self):
        result = apex.password_audit("password123")
        self.assertEqual(result["rating"], "Weak / improve")
        self.assertTrue(result["findings"])

    def test_password_is_not_returned_in_audit(self):
        secret = "UniqueExample!7392"
        result = apex.password_audit(secret)
        self.assertNotIn(secret, json.dumps(result))


class ReportTests(unittest.TestCase):
    def test_checklist_is_nonempty(self):
        self.assertGreaterEqual(len(apex.router_checklist()), 5)

    def test_report_saved_as_json(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(apex, "REPORT_DIR", Path(directory)):
                path = apex.save_report({"tool": "APEX", "version": apex.VERSION})
                self.assertTrue(path.exists())
                self.assertEqual(json.loads(path.read_text())["tool"], "APEX")


if __name__ == "__main__":
    unittest.main(verbosity=2)
