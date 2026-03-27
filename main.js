const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');

const OUTPUT_DIR = path.join(__dirname, 'output');

const FEEDS = [
  {
    name: 'AIP_historical_blacklist',
    type: 'csv_ip',
    url: 'https://mcfp.felk.cvut.cz/publicDatasets/CTU-AIPP-BlackList/Todays-Blacklists/AIP_historical_blacklist_prioritized_by_newest_attackers.csv'
  },
  {
    name: 'adblock_nocoin_hosts',
    type: 'hosts',
    url: 'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt'
  },
  {
    name: 'emerging_block_ips',
    type: 'plain_ip',
    url: 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'
  },
  {
    name: 'urlhaus_hostfile',
    type: 'hosts',
    url: 'https://urlhaus.abuse.ch/downloads/hostfile/'
  },
  {
    name: 'ipsum',
    type: 'csv_like_ip',
    url: 'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'
  },
  {
    name: 'threatfox_hostfile',
    type: 'hosts',
    url: 'https://threatfox.abuse.ch/downloads/hostfile/'
  },
  {
    name: 'dshield_7d',
    type: 'plain_ip_or_cidr',
    url: 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/dshield_7d.netset'
  }
];

const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const ipv4OrCidrRegex = /^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$/;
const hostnameRegex = /^(?!\d+\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

function isPrivateOrReserved(ip) {
  if (!ipv4Regex.test(ip)) return false;
  const parts = ip.split('.').map(Number);
  const [a, b] = parts;

  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;

  if (a === 127) return true;
  if (a === 169 && b === 254) return true;

  if (a === 0) return true;
  if (a >= 224 && a <= 239) return true;
  if (a >= 240) return true;

  if (a === 255 && b === 255 && parts[2] === 255 && parts[3] === 255) return true;

  return false;
}

async function downloadText(url) {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to download ${url}: ${res.status} ${res.statusText}`);
  }
  return res.text();
}

function parseCsvIpFeed(text) {
  const ips = new Set();
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(/[,\s;]+/);
    if (!parts.length) continue;
    const candidate = parts[0].trim();
    if (ipv4Regex.test(candidate) && !isPrivateOrReserved(candidate)) {
      ips.add(candidate);
    }
  }
  return { ips, hosts: new Set(), networks: new Set() };
}

function parseHostsFile(text) {
  const hosts = new Set();
  const ips = new Set();
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(/\s+/);
    if (parts.length < 2) continue;
    const maybeIp = parts[0];
    for (let i = 1; i < parts.length; i++) {
      const candidate = parts[i].trim();
      if (!candidate || candidate.startsWith('#')) break;
      if (hostnameRegex.test(candidate)) {
        hosts.add(candidate.toLowerCase());
      } else if (ipv4Regex.test(candidate) && !isPrivateOrReserved(candidate)) {
        ips.add(candidate);
      }
    }
    if (ipv4Regex.test(maybeIp) && !isPrivateOrReserved(maybeIp)) {
      ips.add(maybeIp);
    }
  }
  return { ips, hosts, networks: new Set() };
}

function parsePlainIpFeed(text) {
  const ips = new Set();
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const token = line.split(/\s+/)[0];
    if (ipv4Regex.test(token) && !isPrivateOrReserved(token)) {
      ips.add(token);
    }
  }
  return { ips, hosts: new Set(), networks: new Set() };
}

function parsePlainIpOrCidrFeed(text) {
  const ips = new Set();
  const networks = new Set();
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const token = line.split(/\s+/)[0];
    if (!ipv4OrCidrRegex.test(token)) continue;
    if (token.includes('/')) {
      const baseIp = token.split('/')[0];
      if (!isPrivateOrReserved(baseIp)) {
        networks.add(token);
      }
    } else {
      if (!isPrivateOrReserved(token)) {
        ips.add(token);
      }
    }
  }
  return { ips, hosts: new Set(), networks };
}

function parseCsvLikeIpFeed(text) {
  const ips = new Set();
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const token = line.split(/[,\s]+/)[0];
    if (ipv4Regex.test(token) && !isPrivateOrReserved(token)) {
      ips.add(token);
    }
  }
  return { ips, hosts: new Set(), networks: new Set() };
}

async function fetchAndParseFeed(feed) {
  try {
    const text = await downloadText(feed.url);
    if (feed.type === 'csv_ip') return { feed, ...parseCsvIpFeed(text) };
    if (feed.type === 'hosts') return { feed, ...parseHostsFile(text) };
    if (feed.type === 'plain_ip') return { feed, ...parsePlainIpFeed(text) };
    if (feed.type === 'plain_ip_or_cidr') return { feed, ...parsePlainIpOrCidrFeed(text) };
    if (feed.type === 'csv_like_ip') return { feed, ...parseCsvLikeIpFeed(text) };
    return { feed, ips: new Set(), hosts: new Set(), networks: new Set() };
  } catch (err) {
    return { feed, error: err.message, ips: new Set(), hosts: new Set(), networks: new Set() };
  }
}

function ensureOutputDir() {
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }
}

function writeArrayToTxt(filePath, arr) {
  fs.writeFileSync(filePath, arr.join('\n') + (arr.length ? '\n' : ''), 'utf8');
}

function writeJson(filePath, obj) {
  fs.writeFileSync(filePath, JSON.stringify(obj, null, 2), 'utf8');
}

function toMikrotikAddressListLine(address) {
  return `/ip firewall address-list add list=unwanted-threats address=${address} comment="unwanted-threats/mikrotik" timeout=48h;`;
}

function writeMikrotikRsc(filePath, addresses) {
  const lines = addresses.map(toMikrotikAddressListLine);
  writeArrayToTxt(filePath, lines);
}

async function main() {
  ensureOutputDir();

  const results = await Promise.all(FEEDS.map(fetchAndParseFeed));

  const allIps = new Set();
  const allHosts = new Set();
  const allNetworks = new Set();
  const perFeedSummary = [];

  for (const result of results) {
    const { feed, ips, hosts, networks, error } = result;

    if (ips) {
      ips.forEach(ip => allIps.add(ip));
    }
    if (hosts) {
      hosts.forEach(h => allHosts.add(h));
    }
    if (networks) {
      networks.forEach(n => allNetworks.add(n));
    }

    perFeedSummary.push({
      name: feed.name,
      url: feed.url,
      type: feed.type,
      counts: {
        ips: ips ? ips.size : 0,
        hosts: hosts ? hosts.size : 0,
        networks: networks ? networks.size : 0
      },
      error: error || null
    });
  }

  const ipsArray = Array.from(allIps).sort();
  const hostsArray = Array.from(allHosts).sort();

  const networksSet = new Set();
  allNetworks.forEach(n => networksSet.add(n));
  allIps.forEach(ip => networksSet.add(`${ip}/32`));
  const networksArray = Array.from(networksSet).sort();

  writeArrayToTxt(path.join(OUTPUT_DIR, 'ips.txt'), ipsArray);
  writeJson(path.join(OUTPUT_DIR, 'ips.json'), ipsArray);

  writeArrayToTxt(path.join(OUTPUT_DIR, 'hosts.txt'), hostsArray);
  writeJson(path.join(OUTPUT_DIR, 'hosts.json'), hostsArray);

  writeArrayToTxt(path.join(OUTPUT_DIR, 'networks.txt'), networksArray);
  writeJson(path.join(OUTPUT_DIR, 'networks.json'), networksArray);
  writeMikrotikRsc(path.join(OUTPUT_DIR, 'ips.rsc'), ipsArray);
  writeMikrotikRsc(path.join(OUTPUT_DIR, 'networks.rsc'), networksArray);

  writeJson(path.join(OUTPUT_DIR, 'summary.json'), {
    generated_at: new Date().toISOString(),
    total: {
      ips: ipsArray.length,
      hosts: hostsArray.length,
      networks: networksArray.length
    },
    per_feed: perFeedSummary
  });
}

main();

