import contextlib
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
        out = scrub("postgres://admin:s3cr3tpw@db.example.com:5432/app")  # secretscan:ignore
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


def tok(*parts):
    return "".join(parts)


NEW_TOKENS = {
    "GITLAB_TOKEN": tok("glpat-", "abcdEFGH1234ijklMNOP5678"),  # secretscan:ignore
    "NPM_TOKEN": tok("npm_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"),  # secretscan:ignore
    "SENDGRID_KEY": tok("SG.", "a" * 22, ".", "b" * 43),  # secretscan:ignore
    "API_KEY": tok("sk-ant-", "api03-abcdEFGH1234ijklMNOP5678"),  # secretscan:ignore
    "WEBHOOK": tok("https://hooks.slack", ".com/services/T01ABCDEF/B02GHIJKL/", "x" * 24),
}


class NewRuleTests(unittest.TestCase):
    def test_each_new_token_redacted(self):
        for kind, value in NEW_TOKENS.items():
            with self.subTest(kind=kind):
                out = scrub("token seen: %s end" % value)
                self.assertNotIn(value, out)
                self.assertIn("[REDACTED:%s]" % kind, out)

    def test_openai_style_and_google_and_stripe_keys(self):
        for value in (tok("sk-", "proj-", "abcdEFGH1234ijklMNOP5678qrstUVWX"), tok("AIza", "SyA-" + "b" * 31),  # secretscan:ignore
                      tok("sk_live_", "a" * 24)):
            self.assertNotIn(value, scrub("k=%s" % value), value)

    def test_new_rules_listed(self):
        names = [n for n, _ in logscrub.RULES]
        for n in ("webhook-url", "gitlab-token", "npm-token", "pypi-token", "sendgrid-key", "ai-api-key"):
            self.assertIn(n, names)

    def test_short_look_alikes_untouched(self):
        self.assertEqual(scrub("sk-short npm_abc glpat-x"), "sk-short npm_abc glpat-x")

    def test_author_and_authenticated_are_not_secrets(self):
        self.assertEqual(scrub("author=Bob authenticated=true"), "author=Bob authenticated=true")

    def test_auth_headers_and_keys_still_redacted(self):
        self.assertNotIn("hunter22", scrub("auth=hunter22"))
        self.assertNotIn("hunter22", scrub("authorization: hunter22"))
        self.assertNotIn("hunter22", scrub("auth_token=hunter22"))

    def test_only_and_skip_work_with_new_rules(self):
        value = NEW_TOKENS["NPM_TOKEN"]
        self.assertEqual(scrub(value, rules=["email"]), value)
        self.assertEqual(scrub(value, skip=["npm-token"]), value)


class LiteralTests(unittest.TestCase):
    def test_literal_replaced_case_insensitively(self):
        out = scrub("host Db-Prod-01 and db-prod-01", literals=["db-prod-01"])
        self.assertEqual(out, "host [REDACTED:CUSTOM] and [REDACTED:CUSTOM]")

    def test_regex_metacharacters_are_literal(self):
        self.assertEqual(scrub("a.b a-b (x)", literals=["a.b", "(x)"]), "[REDACTED:CUSTOM] a-b [REDACTED:CUSTOM]")

    def test_stable_numbering_for_literals(self):
        out = scrub("acme and Globex and ACME", stable=True, literals=["acme", "globex"])
        self.assertEqual(out, "[CUSTOM_1] and [CUSTOM_2] and [CUSTOM_1]")

    def test_longest_literal_wins(self):
        self.assertEqual(scrub("acme corp", literals=["acme", "acme corp"]), "[REDACTED:CUSTOM]")

    def test_empty_literals_ignored(self):
        self.assertEqual(scrub("plain text", literals=["", ""]), "plain text")

    def test_literal_applied_even_with_only(self):
        self.assertEqual(scrub("acme", rules=["email"], literals=["acme"]), "[REDACTED:CUSTOM]")


def run_main(*argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), mock.patch("sys.stdin", io.StringIO(stdin)):
        code = logscrub.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_literal_and_report(self):
        code, out, err = run_main("--literal", "acme", "--report", stdin="acme mail bob@example.com acme\n")
        self.assertEqual(code, 0)
        self.assertNotIn("acme", out)
        self.assertIn("3 value(s) redacted", err)
        self.assertIn("CUSTOM=2", err)
        self.assertIn("EMAIL=1", err)

    def test_report_with_nothing_redacted(self):
        _, out, err = run_main("--report", stdin="nothing here\n")
        self.assertEqual(out, "nothing here\n")
        self.assertIn("0 value(s) redacted", err)

    def test_report_never_contains_the_values(self):
        _, _, err = run_main("--report", stdin="alice@example.com 203.0.113.7\n")
        self.assertNotIn("alice", err)
        self.assertNotIn("203.0.113", err)

    def test_literal_file_with_comments_and_blank_lines(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "words.txt")
            with open(p, "w") as fh:
                fh.write("# internal names\nwidget-api\n\n  Globex  \n")
            _, out, _ = run_main("--literal-file", p, stdin="widget-api talks to GLOBEX\n")
        self.assertEqual(out, "[REDACTED:CUSTOM] talks to [REDACTED:CUSTOM]\n")

    def test_missing_literal_file(self):
        self.assertEqual(run_main("--literal-file", "/nonexistent/words.txt", stdin="x")[0], 2)

    def test_existing_behaviour_unchanged(self):
        _, out, _ = run_main(stdin="mail alice@example.com now\n")
        self.assertEqual(out, "mail [REDACTED:EMAIL] now\n")


if __name__ == "__main__":
    unittest.main()
