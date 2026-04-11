# Example Downloadable IP Lists

This file contains commonly used IPv4/CIDR feeds that can be used with this service.

## Compatibility Notes

- The service expects plain IPv4 addresses or CIDR blocks, one per line.
- `#` and `;` comment lines are ignored.
- Domain blocklists (Pi-hole/adblock syntax) are not compatible without conversion.
- Always review third-party feeds before production use.

---

## Allow List Examples (Geo/Provider)

### Country allowlists (IPDeny)

Use these to allow traffic from specific countries.

- US: https://www.ipdeny.com/ipblocks/data/countries/us.zone
- CA: https://www.ipdeny.com/ipblocks/data/countries/ca.zone
- GB: https://www.ipdeny.com/ipblocks/data/countries/gb.zone
- AU: https://www.ipdeny.com/ipblocks/data/countries/au.zone
- DE: https://www.ipdeny.com/ipblocks/data/countries/de.zone

Tip: Add one country feed per list so you can toggle and monitor them independently.

### Cloudflare IPv4 ranges (allowlist for proxied origins)

- https://www.cloudflare.com/ips-v4

---

## Block List Examples (Threat/Abuse)

### Spamhaus DROP / EDROP

- DROP: https://www.spamhaus.org/drop/drop.txt
- EDROP: https://www.spamhaus.org/drop/edrop.txt

### Emerging Threats compromised IPs

- https://rules.emergingthreats.net/blockrules/compromised-ips.txt

### Abuse.ch Feodo Tracker IP blocklist

- https://feodotracker.abuse.ch/downloads/ipblocklist.txt

### Tor exit node list

- https://check.torproject.org/torbulkexitlist

---

## Suggested Setup Patterns

### Basic Geo-Allow + Threat-Deny

1. Allow list: one or more country feeds (for example `us.zone`).
2. Deny list: Spamhaus DROP + EDROP.
3. Optional deny list: Emerging Threats compromised IPs.

### Service Access Hardening

1. Allow list: Cloudflare IPv4 ranges (if app is behind Cloudflare).
2. Deny list: Spamhaus + abuse feeds.

---

## Operational Tips

- Use separate lists per source so failures are isolated and easier to troubleshoot.
- Start with conservative fetch/apply frequency (for example every 6 to 24 hours).
- Review your firewall rule precedence between `ip-whitelist-dynamic` and `ip-blacklist-dynamic`.
- Test in a lab/staging router before production rollout.
