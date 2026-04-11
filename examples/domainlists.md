# Example Downloadable Domain Lists

This file contains suggested domain-based feeds that work well with the Domain Lists feature.

## Compatibility Notes

- The service expects plain domain names, one per line.
- `#` and `;` comment lines are ignored.
- Only exact domain names are supported. There is no regex, wildcard, Adblock, or Pi-hole hosts parsing here.
- Feeds that use rules like `||example.com^`, `*.example.com`, `regex:`, or `0.0.0.0 example.com` are not directly compatible.
- Subdomains must appear explicitly in the feed if you want them resolved and loaded.
- Always review third-party feeds before production use.

---

## Good Feed Characteristics

Use feeds that contain lines like this:

```text
bad-domain.example
subdomain.bad-domain.example
tracker.example
```

Avoid feeds that contain lines like this:

```text
||bad-domain.example^
*.bad-domain.example
0.0.0.0 bad-domain.example
127.0.0.1 bad-domain.example
/bad-domain\.example/
```

---

## Suggested Domain Blocklist Sources

### HaGeZi DNS blocklists

HaGeZi publishes several domain-only lists that are a strong fit for this feature.

- TIF: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/tif.txt
- Threat Intelligence: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/threat.txt
- Malware: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/hoster.txt
- Fake/Scam: https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/fake.txt

Tip: Start with one smaller list first, measure the resolved IP count, then add more.

### URLHaus host list converted to domains

Use only if the source is provided as plain domains. Avoid URL-format feeds unless you pre-convert them externally.

### Curated internal lists

For high-confidence blocking, maintain a small user-controlled feed in a Git repository or internal web server.

Examples:

- Known phishing domains seen in your environment
- Known malware callback domains
- Known typo-squatted domains targeting your users

---

## Suggested Setup Patterns

### Conservative Threat Blocking

1. Create one deny Domain List for HaGeZi TIF.
2. Set fetch frequency to every 12 or 24 hours.
3. Set TTL to 3 to 7 days.
4. Review the resolved IP count before adding additional feeds.

### Layered Threat Blocking

1. Create separate Domain Lists for `tif.txt`, `threat.txt`, and `fake.txt`.
2. Keep each source in its own list so you can disable a noisy feed quickly.
3. Use the same deny list type for all of them unless you want different RouterOS handling later.

### Internal IOC Feed

1. Host a plain text file with exact domains on an internal HTTPS endpoint.
2. Add it as a deny Domain List.
3. Use a short fetch interval if your incident response process updates it frequently.

---

## Operational Notes

- Domain Lists resolve A records only, so domains with no current IPv4 answer will not produce loaded IP rows.
- Large public blocklists often contain many dead or sinkholed domains. That is normal.
- Resolved IPs can change frequently for CDN-backed or fast-flux domains.
- Exact-domain feeds are safer here than trying to approximate wildcard blocking in RouterOS address lists.
- Keep feeds separated by source so failures and false positives are easier to isolate.

---

## Recommended First Test

Before loading a large threat feed, test with a small exact-domain file containing a few resolvable domains:

```text
example.com
github.com
google.com
```

Once that works, switch the URL to a real threat feed.