# dmarccheck

Validates that a domain's SPF, DKIM, and DMARC DNS records are present
and correctly formed — the proactive, setup-time counterpart to this
workspace's `mailtrace`, which analyzes an already-received email's
headers after the fact. This checks the DNS side before you send
anything: is SPF published and syntactically sane, is DMARC published
with a real policy, does a given DKIM selector actually resolve to a key.

## Usage

```bash
dmarccheck example.com
dmarccheck example.com --selector google      # also check a specific DKIM selector
```

Exit code `1` if anything is missing or malformed. DKIM is skipped
unless `--selector` is given — a DKIM selector is a value the sending
system chose (`google`, `selector1`, `s1`, ...) and isn't discoverable
from DNS alone, so there's no way to check "does this domain have DKIM"
in general, only "does DKIM exist at *this specific* selector."

## What's actually checked

- **SPF**: exactly one `v=spf1` TXT record at the domain itself, every
  space-separated term after it recognized as either a real mechanism
  (`a`, `mx`, `ptr`, `ip4:`, `ip6:`, `include:`, `exists:`, `all`,
  optionally CIDR-suffixed and qualifier-prefixed with `+`/`-`/`~`/`?`)
  or a real modifier (`redirect=`, `exp=`, or any vendor-specific
  `name=value` — RFC 7208 requires unknown modifiers to be silently
  accepted, not rejected).
- **DMARC**: exactly one `v=DMARC1` TXT record at `_dmarc.<domain>`,
  with a `p=` tag whose value is `none`, `quarantine`, or `reject`.
- **DKIM** (only with `--selector`): a TXT record at
  `<selector>._domainkey.<domain>` with either no `v=` tag (RFC 6376's
  implied default) or `v=DKIM1`, and a non-empty `p=` tag — an empty
  `p=` is DKIM's own documented "this key has been revoked" convention,
  correctly reported as invalid rather than a false pass.

## Status: built and verified against real, live DNS — including a real bug caught by a real domain's real record

- **17 unit tests** (`cargo test --lib`): SPF (a realistic multi-mechanism
  record, an unrecognized mechanism rejected, two records at once
  correctly rejected per RFC 7208, an unrelated TXT record at the same
  name ignored), DMARC (valid `p=reject`, missing `p=` tag, an invalid
  policy value), DKIM (missing, valid with explicit `v=DKIM1`, valid
  with the implied-default version, an empty `p=` correctly read as
  "revoked" rather than "present"), and the shared `tag=value` parser's
  whitespace handling.
- **A real bug caught live against a real domain's real SPF record, not
  a synthetic fixture**: `iana.org`'s actual published SPF record is
  `v=spf1 redirect=icann.org`. The first version of the mechanism
  checker only split tokens on `:` (the separator mechanisms use —
  `ip4:`, `include:`), so `redirect=icann.org` (a *modifier*, which uses
  `=`, not `:`, per RFC 7208 §6) was read as one unrecognized blob and
  the whole record was wrongly flagged invalid. Fixed by checking for a
  top-level `=` before any `:` and treating that shape as a modifier;
  added two regression tests (`redirect=` and `exp=`) plus a control
  test confirming a genuinely unrecognized bare token is still
  correctly rejected.
- **Live-verified against real, current DNS for multiple real domains**:
  `github.com` (a long, realistic multi-`include:` SPF record and a
  `p=quarantine` DMARC record, both parsed and validated correctly),
  `iana.org` (the `redirect=` case above, now passing), and a
  nonexistent DKIM selector against a real domain correctly reported as
  `MISSING` rather than crashing or false-passing.
- **Uses the sandbox's own system resolver, not a public one** —
  `TokioAsyncResolver::tokio_from_system_conf()` rather than forwarding
  through a well-known public DNS server, which this workspace's sibling
  tool `dnsblcheck` discovered gets deliberately blocked/rate-limited by
  at least one real DNSBL provider for exactly this kind of high-volume
  automated lookup.

**Not done / deliberately deferred**: DMARC's optional tags beyond `p=`
(`sp=`, `pct=`, `rua=`, `adkim=`/`aspf=` alignment mode) are shown as
part of the raw record but not individually validated. SPF's 10-lookup
limit (RFC 7208 caps the number of DNS-lookup-triggering mechanisms
`include:`/`a`/`mx`/`redirect`/`exists` a record may chain to) isn't
counted or enforced. DKIM key strength (RSA key size, correct base64
padding) isn't checked — presence and shape of the `p=` tag is, not
whether the key itself is cryptographically sound.
