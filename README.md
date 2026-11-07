# logscrub

Redact sensitive data from logs, stack traces and config snippets **before** you
paste them into a bug report, a support ticket, a forum post or an AI assistant.
One file, standard library only, works as a pipe filter.

```bash
some-command 2>&1 | python3 logscrub.py
python3 logscrub.py app.log > app.scrubbed.log
python3 logscrub.py app.log --stable      # same value -> same placeholder
python3 logscrub.py app.log --literal acme-corp --literal db-prod-01 --report
python3 logscrub.py app.log --literal-file internal-names.txt
# or: pip install git+https://github.com/TPOALOS/logscrub && logscrub app.log
```

## Example

Input:

```
GET /login from 203.0.113.9 user=bob@example.com
Authorization: Bearer abcdef123456789
db url postgres://admin:changeme123@db.example.com/app
File "/Users/jdoe/project/main.py", line 3
```

Output with `--stable`:

```
GET /login from [IP_1] user=[EMAIL_1]
Authorization: Bearer [TOKEN_1]
db url postgres://[USER_1]:[SECRET_1]@db.example.com/app
File "/Users/[USER_2]/project/main.py", line 3
```

`--stable` keeps relationships visible (the same IP stays `[IP_1]` everywhere) so the
log is still debuggable.

## What it redacts

Run `python3 logscrub.py --list-rules` for the names. Private key blocks, JWTs,
credentials inside URLs, Bearer/Basic tokens, AWS/GitHub/Slack tokens,
`password/secret/token/api_key = value` pairs, e-mail addresses, credit card numbers
(Luhn-checked), MAC addresses, IPv4/IPv6 addresses, and user names in home paths. Also GitLab, npm,
PyPI, SendGrid, Google, Stripe and Anthropic/OpenAI-style keys and Slack/Discord webhook URLs.

Use `--only email,ipv4` or `--skip ipv4` to choose rules.

### Things only you know

Internal hostnames, customer names and project code names cannot be guessed. List them and they are redacted too
(case-insensitive, exact text, longest first):

```bash
logscrub app.log --literal acme-corp --literal 'db-prod-01'
logscrub app.log --literal-file internal-names.txt     # one per line, # comments ok
```

`--report` prints how many values of each kind were redacted to stderr (never the values), so you can see at a
glance whether the scrub did anything.

## Limits

Pattern based: it cannot know your internal hostnames or customer names unless you list them with `--literal`, and it cannot
see free-text secrets. Read the output before sharing it. Timestamps and version numbers are left alone.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
