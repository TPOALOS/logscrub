import io
import os
import tempfile
import unittest
from unittest import mock

import logscrub

# Fake values only; documentation ranges and obviously made-up strings.
JWT = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0In0" + "." + "abcDEF123xyz"
GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"  # secretscan:ignore
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIBOgIBAAJB\nabc\n-----END " + "RSA PRIVATE KEY-----"


def scrub(text, **kw):
    return logscrub.Scrubber(**kw).scrub(text)


class RuleTests(unittest.TestCase):
    def test_email(self):
        self.assertEqual(scrub("mail alice@example.com now"), "mail [REDACTED:EMAIL] now")

    def test_ipv4_and_ipv6(self):
        out = scrub("from 203.0.113.7 and 2001:db8::1 ok")
        self.assertNotIn("203.0.113.7", out)
        self.assertNotIn("2001:db8::1", out)

    def test_timestamps_not_ipv6(self):
        self.assertEqual(scrub("at 12:30:45 and 10:20:30:40"), "at 12:30:45 and 10:20:30:40")

    def test_version_numbers_survive(self):
        self.assertEqual(scrub("python 3.12.1 build 1.2.3"), "python 3.12.1 build 1.2.3")

    def test_jwt(self):
        self.assertNotIn(JWT, scrub("token=x Authorization: %s" % JWT))
        self.assertIn("JWT", scrub("jwt %s" % JWT))

    def test_bearer(self):
        out = scrub("Authorization: Bearer abcdef123456789")
        self.assertNotIn("abcdef123456789", out)
        self.assertTrue(out.startswith("Authorization: Bearer"))

    def test_key_value(self):
        out = scrub('db_password="hunter2hunter2" user=bob api_key: abc123xyz789')
        self.assertNotIn("hunter2hunter2", out)
        self.assertNotIn("abc123xyz789", out)
        self.assertIn("user=bob", out)

    def test_url_credentials(self):
        out = scrub("postgres://admin:s3cr3tpw@db.example.com:5432/app")
        self.assertNotIn("s3cr3tpw", out)
        self.assertNotIn("admin", out)
        self.assertIn("db.example.com", out)

    def test_tokens(self):
        out = scrub("a %s b %s" % (AWS, GH))
        self.assertNotIn(AWS, out)
        self.assertNotIn(GH, out)

    def test_private_key_multiline(self):
        out = scrub("before\n%s\nafter" % PEM)
        self.assertEqual(out, "before\n[REDACTED:PRIVATE_KEY]\nafter")

    def test_card_luhn(self):
        self.assertIn("CARD", scrub("card 4111 1111 1111 1111 paid"))
        self.assertEqual(scrub("order 1234567890123456"), "order 1234567890123456")

    def test_mac(self):
        self.assertIn("MAC", scrub("dev aa:bb:cc:dd:ee:ff up"))

    def test_home_path(self):
        out = scrub("File /Users/jdoe/app/main.py and /home/alice/x")
        self.assertNotIn("jdoe", out)
        self.assertNotIn("alice", out)
        self.assertIn("/app/main.py", out)

    def test_clean_text_unchanged(self):
        text = "INFO 2026-01-01 server started on port 8080"
        self.assertEqual(scrub(text), text)


class OptionTests(unittest.TestCase):
    def test_stable_numbering(self):
        out = scrub("a@example.com b@example.com a@example.com", stable=True)
        self.assertEqual(out, "[EMAIL_1] [EMAIL_2] [EMAIL_1]")

    def test_skip_and_only(self):
        self.assertIn("a@example.com", scrub("a@example.com 203.0.113.7", skip=["email"]))
        out = scrub("a@example.com 203.0.113.7", rules=["email"])
        self.assertIn("203.0.113.7", out)
        self.assertNotIn("a@example.com", out)

    def test_cli_file_and_stdout(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.log")
            with open(p, "w") as fh:
                fh.write("hi a@example.com\n")
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                self.assertEqual(logscrub.main([p]), 0)
            self.assertEqual(buf.getvalue(), "hi [REDACTED:EMAIL]\n")
        self.assertEqual(logscrub.main(["/nonexistent/file"]), 2)


if __name__ == "__main__":
    unittest.main()
