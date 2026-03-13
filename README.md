# Unwanted Threats

This repository aggregates multiple public threat intelligence feeds into consolidated JSON and text files.  
The data is automatically refreshed (via GitHub Actions) and served from the `output` branch so it can be consumed over HTTPS.

---

## Data Outputs

All generated files live in the `output` directory (and in the `output` branch when deployed).

| Data Type | File |
| --------- | ---- |
| **IP addresses (one per line)** | `ips.txt` |
| **IP addresses (JSON array)** | `ips.json` |
| **Hostnames/domains (one per line)** | `hosts.txt` |
| **Hostnames/domains (JSON array)** | `hosts.json` |
| **Summary / metadata** | `summary.json` |

---

## Threat Intelligence Feeds

The script currently pulls from the following public feeds:

- AIP historical blacklist (CSV)  
- Adblock NoCoin host file  
- EmergingThreats Block IPs  
- URLHaus hostfile  
- Ipsum IP blacklist  
- ThreatFox hostfile  
- FireHOL DShield 7‑day IP set  

These are the concrete URLs wired into `main.js`:

- `https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_historical_blacklist_prioritized_by_newest_attackers.csv`
- `https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt`
- `https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt`
- `https://urlhaus.abuse.ch/downloads/hostfile/`
- `https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt`
- `https://threatfox.abuse.ch/downloads/hostfile/`
- `https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield_7d.netset`

---

## How it works

- `main.js` downloads each feed and parses IP addresses, CIDRs, and hostnames/host-style indicators.
- All data is normalized, de‑duplicated, and written under `./output/`.
- A scheduled GitHub Actions workflow can run `node main.js` and deploy the `output` directory to the `output` branch using GitHub Pages, very similar to the `tor-monitoring` repository.

---

## Running locally

```bash
npm install
npm run start
```

The generated files will appear in the local `output` directory.

