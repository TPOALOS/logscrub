# logscrub

Redact sensitive data from logs, stack traces and config snippets **before** you
paste them into a bug report, a support ticket, a forum post or an AI assistant.
One file, standard library only, works as a pipe filter.

```bash
some-command 2>&1 | python3 logscrub.py
python3 logscrub.py app.log > app.scrubbed.log
python3 logscrub.py app.log --stable      # same value -> same placeholder
```

## Example

Input:

```
GET /login from 203.0.113.9 user=bob@example.com
Authorization: Bearer abcdef123456789
db url postgres://admin:s3cr3tpw@db.example.com/app
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
(Luhn-checked), MAC addresses, IPv4/IPv6 addresses, and user names in home paths.

Use `--only email,ipv4` or `--skip ipv4` to choose rules.

## Limits

Pattern based: it cannot know your internal hostnames, customer names or free-text
secrets. Read the output before sharing it. Timestamps and version numbers are left alone.

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS
