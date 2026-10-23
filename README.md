<p align="center">
  <img src="assets/logo.svg" alt="Unwanted Threats" width="128" height="128" />
</p>

# Unwanted Threats

This repository aggregates multiple public threat intelligence feeds into consolidated JSON and text files.
The data is automatically refreshed (via GitHub Actions) and served from the `output` branch so it can be consumed over HTTPS.

---

## Using this list on your MikroTik

You can use the following script to fetch a blocklist and add its IPs to the unwanted-threats address list, allowing you to block traffic to and from known malicious hosts.

```rsc
:local name "[unwanted-threats]"
:local url "https://alessandromrc.github.io/unwanted-threats/ips.rsc"
:local fileName "unwanted-threats-ips.rsc"
:log info "$name fetch blocklist from $url"
/tool fetch url="$url" mode=https dst-path=$fileName idle-timeout="30s"
:if ([:len [/file find name=$fileName]] > 0) do={
    :log info "removing old ipv4 blocklist"
    /ip/firewall/address-list/remove [find where list="unwanted-threats"]
    :log info "removing old ipv6 blocklist"
    /ipv6/firewall/address-list/remove [find where list="unwanted-threats"]
    :log info "$name import;start"
    /import file-name=$fileName verbose=yes
    :log info "$name import:done"
} else={
    :log error "$name failed to fetch the blocklist"
}
```

## Using this list on OPNsense

OPNsense's `URL Table (IPs)` alias type fetches a plain list of one IPv4/IPv6 address or CIDR per line on a schedule — which is exactly what `networks.txt` and `networks6.txt` already are (no extra export file needed). `networks.txt` is a superset of `ips.txt`: it already contains every blocked IP as a `/32` alongside the CIDR ranges, so a single IPv4 alias covers both.

1. Go to **Firewall ▸ Aliases** and add a new alias.
2. **Name:** e.g. `unwanted_threats_v4`. **Type:** `URL Table (IPs)`.
3. **Content:** `https://alessandromrc.github.io/unwanted-threats/networks.txt`
4. **Refresh Frequency:** e.g. every 1 hour (matches how often this repo's data is refreshed).
5. Repeat with **Type:** `URL Table (IPs)` and **Content:** `https://alessandromrc.github.io/unwanted-threats/networks6.txt` for an IPv6 alias (e.g. `unwanted_threats_v6`).
6. Optionally add `https://alessandromrc.github.io/unwanted-threats/tor_exit_nodes.txt` as its own alias if you want to monitor/flag Tor exit traffic separately rather than block it.
7. Use the new alias(es) as the source/destination in a firewall rule (e.g. a block rule on WAN), or combine the v4/v6 aliases into one **Network group** alias if you want a single rule covering both.

Note: `hosts.txt` (domains) isn't importable through Firewall ▸ Aliases — OPNsense has no bulk URL-fetch alias type for FQDNs. Domain-based indicators would need to go through Unbound's DNS blocklist feature instead.

## Data Outputs

All generated files live in the `output` directory (and in the `output` branch when deployed).

| Data Type | File |
| --------- | ---- |
| **IP addresses (one per line)** | `ips.txt` |
| **IP addresses (JSON array)** | `ips.json` |
| **Hostnames/domains (one per line)** | `hosts.txt` |
| **Hostnames/domains (JSON array)** | `hosts.json` |
| **CIDR networks (one per line)** | `networks.txt` |
| **CIDR networks (JSON array)** | `networks.json` |
| **IPv6 CIDR networks (one per line)** | `networks6.txt` |
| **IPv6 CIDR networks (JSON array)** | `networks6.json` |
| **MikroTik IPv6 address-list script** | `networks6.rsc` |
| **Tor exit node IPs (one per line)** | `tor_exit_nodes.txt` |
| **Tor exit node IPs (JSON array)** | `tor_exit_nodes.json` |
| **MikroTik Tor exit-node address-list script** | `tor_exit_nodes.rsc` |
| **Summary / metadata** | `summary.json` |

Tor exit nodes are kept as a separate list rather than merged into the main blocklist above — like the UptimeRobot list, they are not inherently malicious and some networks may want to monitor/flag them rather than outright block them.

---

## Threat Intelligence Feeds

The script currently pulls from the following public feeds:

- AIP historical blacklist (CSV)
- Adblock NoCoin host file
- EmergingThreats Block IPs
- URLHaus hostfile (requires `ABUSECH_AUTH_KEY`, see below)
- Ipsum IP blacklist
- ThreatFox hostfile (requires `ABUSECH_AUTH_KEY`, see below)
- FireHOL DShield 7‑day IP set
- Spamhaus DROP (hijacked/malicious IPv4 netblocks)
- Spamhaus DROPv6 (hijacked/malicious IPv6 netblocks)
- Feodo Tracker botnet C2 IP blocklist (abuse.ch)
- Blocklist.de attacker IPs (SSH/mail/Apache brute force, last 48h)
- Phishing.Database active phishing domains
- Moyai threat feed

These are the concrete URLs wired into `main.js`:

- ```https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_historical_blacklist_prioritized_by_newest_attackers.csv```
- ```https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt```
- ```https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt```
- ```https://urlhaus-api.abuse.ch/v2/files/exports/<ABUSECH_AUTH_KEY>/hostfile.txt```
- ```https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt```
- ```https://threatfox-api.abuse.ch/v2/files/exports/<ABUSECH_AUTH_KEY>/hostfile.txt```
- ```https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield_7d.netset```
- ```https://www.spamhaus.org/drop/drop.txt```
- ```https://www.spamhaus.org/drop/dropv6.txt```
- ```https://feodotracker.abuse.ch/downloads/ipblocklist.txt```
- ```https://lists.blocklist.de/lists/all.txt```
- ```https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt```
- ```https://feed.moyai.one```

### abuse.ch Auth-Key (URLhaus / ThreatFox)

abuse.ch now requires a free personal Auth-Key for all URLhaus and ThreatFox exports (including the plain hostfile). Get one at [auth.abuse.ch](https://auth.abuse.ch/), then set it as the `ABUSECH_AUTH_KEY` environment variable:

- **Locally:** `export ABUSECH_AUTH_KEY="your-key"` before running `npm run start`.
- **GitHub Actions:** add it as a repository secret (**Settings ▸ Secrets and variables ▸ Actions ▸ New repository secret**, name `ABUSECH_AUTH_KEY`) — the workflow passes it through automatically.

The key is never written to any file in this repo; it's only read from the environment at runtime, and is redacted from `summary.json` and error messages. If `ABUSECH_AUTH_KEY` isn't set, the `urlhaus_hostfile` and `threatfox_hostfile` feeds are skipped and everything else runs normally.

---

## How it works

- `main.js` downloads each feed and parses IPv4 addresses, IPv4/IPv6 CIDRs, and hostnames/host-style indicators.
- All data is normalized, de‑duplicated, and written under `./output/`.
- A scheduled GitHub Actions workflow can run `node main.js` and deploy the `output` directory to the `output` branch using GitHub Pages, very similar to the `tor-monitoring` repository.

---

## Running locally

```bash
npm install
npm run start
```

The generated files will appear in the local `output` directory.

