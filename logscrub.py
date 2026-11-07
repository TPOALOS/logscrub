#!/usr/bin/env python3
"""logscrub - redact sensitive data from logs and text before you share them.

Pipe a log, stack trace or config through it, then paste the result into a bug
report, a support ticket or an AI assistant. Standard library only.

    some-command 2>&1 | python3 logscrub.py
    python3 logscrub.py app.log --stable > app.scrubbed.log
"""
import argparse
import collections
import ipaddress
import re
import sys

__version__ = "1.1.0"

PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{3,}")
BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
KV_SECRET = re.compile(
    r"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"auth(?!or(?!iz)|enticat)|credential)[A-Za-z0-9_.-]*)(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)")
AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
GITHUB_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")
SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
GITLAB_TOKEN = re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")
NPM_TOKEN = re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")
PYPI_TOKEN = re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b")
SENDGRID_KEY = re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")
AI_KEY = re.compile(r"\bsk-(?:ant-)?(?:proj-)?[A-Za-z0-9_-]{20,}\b")
GOOGLE_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
STRIPE_KEY = re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{24,}\b")
WEBHOOK = re.compile(
    r"https://(?:hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]{20,}|"
    r"(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{50,})")
URL_CREDS = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
IPV6 = re.compile(r"(?i)(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:.])")
MAC = re.compile(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
HOME = re.compile(r"(/Users/|/home/|C:\\Users\\)([^/\\\s:\"']+)")


def luhn_ok(digits):
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


class Scrubber:
    def __init__(self, stable=False, rules=None, skip=(), literals=()):
        self.stable = stable
        self.seen = {}
        self.counts = collections.Counter()
        # user-supplied words (internal hostnames, customer names); longest first so overlaps resolve sensibly
        words = sorted({w for w in literals if w}, key=len, reverse=True)
        self.literal_rx = re.compile("|".join(re.escape(w) for w in words), re.I) if words else None
        names = [n for n, _ in RULES]
        self.active = [n for n in (rules or names) if n in names and n not in set(skip)]

    def tag(self, kind, value):
        self.counts[kind] += 1
        if not self.stable:
            return "[REDACTED:%s]" % kind
        key = (kind, value)
        if key not in self.seen:
            n = 1 + sum(1 for k in self.seen if k[0] == kind)
            self.seen[key] = n
        return "[%s_%d]" % (kind, self.seen[key])

    def scrub(self, text):
        if self.literal_rx is not None:
            text = self.literal_rx.sub(lambda m: self.tag("CUSTOM", m.group(0).lower()), text)
        for name, fn in RULES:
            if name in self.active:
                text = fn(self, text)
        return text


def _simple(kind, rx):
    return lambda s, t: rx.sub(lambda m: s.tag(kind, m.group(0)), t)


def _private_key(s, t):
    return PRIVATE_KEY.sub(lambda m: s.tag("PRIVATE_KEY", m.group(0)), t)


def _bearer(s, t):
    return BEARER.sub(lambda m: m.group(1) + " " + s.tag("TOKEN", m.group(0)), t)


def _kv(s, t):
    def rep(m):
        value = m.group(3)
        if value.startswith("[REDACTED") or re.match(r"^\[[A-Z_]+_\d+\]$", value) \
                or value.lower() in ("bearer", "basic"):
            return m.group(0)
        return m.group(1) + m.group(2) + s.tag("SECRET", value)
    return KV_SECRET.sub(rep, t)


def _url_creds(s, t):
    return URL_CREDS.sub(lambda m: m.group(1) + s.tag("USER", m.group(2)) + ":" +
                         s.tag("SECRET", m.group(3)) + "@", t)


def _card(s, t):
    def rep(m):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            return s.tag("CARD", digits)
        return m.group(0)
    return CARD.sub(rep, t)


def _ipv6(s, t):
    def rep(m):
        text = m.group(0)
        try:
            ipaddress.IPv6Address(text)
        except ValueError:
            return text
        return s.tag("IP", text) if len(text) > 3 else text
    return IPV6.sub(rep, t)


def _home(s, t):
    return HOME.sub(lambda m: m.group(1) + s.tag("USER", m.group(2)), t)


# Order matters: multi-line and credential-bearing patterns run before generic ones.
RULES = [
    ("private-key", _private_key),
    ("jwt", _simple("JWT", JWT)),
    ("url-credentials", _url_creds),
    ("bearer", _bearer),
    ("aws-key", _simple("AWS_KEY", AWS_KEY)),
    ("github-token", _simple("GITHUB_TOKEN", GITHUB_TOKEN)),
    ("slack-token", _simple("SLACK_TOKEN", SLACK_TOKEN)),
    ("webhook-url", _simple("WEBHOOK", WEBHOOK)),
    ("gitlab-token", _simple("GITLAB_TOKEN", GITLAB_TOKEN)),
    ("npm-token", _simple("NPM_TOKEN", NPM_TOKEN)),
    ("pypi-token", _simple("PYPI_TOKEN", PYPI_TOKEN)),
    ("sendgrid-key", _simple("SENDGRID_KEY", SENDGRID_KEY)),
    ("ai-api-key", _simple("API_KEY", AI_KEY)),
    ("google-api-key", _simple("API_KEY", GOOGLE_KEY)),
    ("stripe-key", _simple("API_KEY", STRIPE_KEY)),
    ("key-value-secret", _kv),
    ("email", _simple("EMAIL", EMAIL)),
    ("card", _card),
    ("mac", _simple("MAC", MAC)),
    ("ipv4", _simple("IP", IPV4)),
    ("ipv6", _ipv6),
    ("home-path", _home),
]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Redact sensitive data from text.")
    ap.add_argument("file", nargs="?", default="-", help="input file (default: stdin)")
    ap.add_argument("--stable", action="store_true",
                    help="same value gets same numbered placeholder, e.g. [EMAIL_1]")
    ap.add_argument("--only", help="comma-separated rule names to apply")
    ap.add_argument("--skip", default="", help="comma-separated rule names to skip")
    ap.add_argument("--literal", action="append", default=[], metavar="TEXT",
                    help="also redact this exact text, case-insensitively (internal host, customer name); repeatable")
    ap.add_argument("--literal-file", metavar="FILE", help="file with one literal per line (# comments ok)")
    ap.add_argument("--report", action="store_true", help="print how many values of each kind were redacted to stderr")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)
    if args.list_rules:
        print("\n".join(n for n, _ in RULES))
        return 0
    only = args.only.split(",") if args.only else None
    literals = list(args.literal)
    if args.literal_file:
        try:
            with open(args.literal_file, encoding="utf-8", errors="replace") as fh:
                literals += [l.strip() for l in fh if l.strip() and not l.lstrip().startswith("#")]
        except OSError as exc:
            print("logscrub: %s" % exc, file=sys.stderr)
            return 2
    sc = Scrubber(args.stable, only, [x for x in args.skip.split(",") if x], literals)
    try:
        if args.file == "-":
            text = sys.stdin.read()
        else:
            with open(args.file, errors="replace") as fh:
                text = fh.read()
    except OSError as exc:
        print("logscrub: %s" % exc, file=sys.stderr)
        return 2
    sys.stdout.write(sc.scrub(text))
    if args.report:
        total = sum(sc.counts.values())
        detail = ", ".join("%s=%d" % (k, v) for k, v in sorted(sc.counts.items()))
        print("logscrub: %d value(s) redacted%s" % (total, " (%s)" % detail if detail else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
