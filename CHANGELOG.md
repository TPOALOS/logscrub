# Changelog

## 1.1.0

- New rules: GitLab, npm, PyPI, SendGrid, Google, Stripe and Anthropic/OpenAI-style keys, Slack/Discord webhook URLs
- `--literal` and `--literal-file` redact your own internal names (case-insensitive, exact text)
- `--report` prints redaction counts per kind to stderr
- Fix: `author=...` and `authenticated=...` are no longer treated as secrets
- Installable with pip (`logscrub` command), CI on Linux and macOS

## 1.0.0

Initial release.
