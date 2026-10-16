const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');

const { FALSE_POSITIVES } = require('./false_positives');
const { uptime } = require('process');

console.log(`Loaded ${FALSE_POSITIVES.length} false positives from false_positives.js`);

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
  },
  {
    name: 'spamhaus_drop',
    type: 'plain_ip_or_cidr',
    url: 'https://www.spamhaus.org/drop/drop.txt'
  },
  {
    name: 'spamhaus_dropv6',
    type: 'plain_cidr_v6',
    url: 'https://www.spamhaus.org/drop/dropv6.txt'
  },
  {
    name: 'feodotracker_ips',
    type: 'plain_ip',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt'
  },
  {
    name: 'blocklistde_all',
    type: 'plain_ip',
    url: 'https://lists.blocklist.de/lists/all.txt'
  },
  {
    name: 'phishing_database_domains',
    type: 'plain_domain',
    url: 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt'
  }
];

const ipv4Regex = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const ipv4OrCidrRegex = /^(?:\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$/;
const hostnameRegex = /^(?!\d+\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
const ipv6CidrRegex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\/\d{1,3}$/;

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

function isFalsePositive(ip) {
  return FALSE_POSITIVES.includes(ip);
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

function parseCidrV6Feed(text) {
  const networks6 = new Set();
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith(';')) continue;
    const token = line.split(/\s+/)[0];
    if (ipv6CidrRegex.test(token)) {
      networks6.add(token.toLowerCase());
    }
  }
  return { ips: new Set(), hosts: new Set(), networks: new Set(), networks6 };
}

function parsePlainDomainFeed(text) {
  const hosts = new Set();
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const token = line.split(/\s+/)[0];
    if (hostnameRegex.test(token)) {
      hosts.add(token.toLowerCase());
    }
  }
  return { ips: new Set(), hosts, networks: new Set(), networks6: new Set() };
}

async function fetchAndParseFeed(feed) {
  try {
    const text = await downloadText(feed.url);
    if (feed.type === 'csv_ip') return { feed, ...parseCsvIpFeed(text) };
    if (feed.type === 'hosts') return { feed, ...parseHostsFile(text) };
    if (feed.type === 'plain_ip') return { feed, ...parsePlainIpFeed(text) };
    if (feed.type === 'plain_ip_or_cidr') return { feed, ...parsePlainIpOrCidrFeed(text) };
    if (feed.type === 'csv_like_ip') return { feed, ...parseCsvLikeIpFeed(text) };
    if (feed.type === 'plain_cidr_v6') return { feed, ...parseCidrV6Feed(text) };
    if (feed.type === 'plain_domain') return { feed, ...parsePlainDomainFeed(text) };
    return { feed, ips: new Set(), hosts: new Set(), networks: new Set(), networks6: new Set() };
  } catch (err) {
    return { feed, error: err.message, ips: new Set(), hosts: new Set(), networks: new Set(), networks6: new Set() };
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

function toMikrotikAddressListLine(address, list) {
  return `/ip firewall address-list add list=${list} address=${address} comment="${list}/mikrotik" timeout=48h;`;
}

function writeMikrotikRsc(filePath, addresses, listName = 'unwanted-threats') {
  const lines = addresses.map((address) => toMikrotikAddressListLine(address, listName));
  writeArrayToTxt(filePath, lines);
}

function toMikrotikV6AddressListLine(address, list) {
  return `/ipv6/firewall/address-list add list=${list} address=${address} comment="${list}/mikrotik" timeout=48h;`;
}

function writeMikrotikV6Rsc(filePath, addresses, listName = 'unwanted-threats') {
  const lines = addresses.map((address) => toMikrotikV6AddressListLine(address, listName));
  writeArrayToTxt(filePath, lines);
}

async function getUptimeRobotIPs() {
  const ips = new Set();
  const URL = 'https://cdn.uptimerobot.com/api/IPv4.txt';

  try {
    const text = await downloadText(URL);
    const lines = text.split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const token = line.split(/\s+/)[0];
      if (ipv4Regex.test(token) && !isPrivateOrReserved(token)) {
        ips.add(token);
      }
    }
  } catch (err) {
    console.error(`Error fetching UptimeRobot IPs: ${err.message}`);
  }
  return ips;
}

async function getTorExitNodes() {
  const ips = new Set();
  const URL = 'https://check.torproject.org/torbulkexitlist';

  try {
    const text = await downloadText(URL);
    const lines = text.split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const token = line.split(/\s+/)[0];
      if (ipv4Regex.test(token) && !isPrivateOrReserved(token)) {
        ips.add(token);
      }
    }
  } catch (err) {
    console.error(`Error fetching Tor exit nodes: ${err.message}`);
  }
  return ips;
}

async function main() {
  ensureOutputDir();

  const results = await Promise.all(FEEDS.map(fetchAndParseFeed));

  const allIps = new Set();
  const allHosts = new Set();
  const allNetworks = new Set();
  const allNetworks6 = new Set();
  const perFeedSummary = [];

  const uptimerobotIPs = await getUptimeRobotIPs();
  const torExitNodes = await getTorExitNodes();

  for (const result of results) {
    const { feed, ips, hosts, networks, networks6, error } = result;
    if (ips) {
      ips.forEach(ip => {
        if (!isFalsePositive(ip) && !(uptimerobotIPs.has(ip)))
        {
          allIps.add(ip);
        }
      });
    }
    if (hosts) {
      hosts.forEach(h => allHosts.add(h));
    }
    if (networks) {
      networks.forEach(n => allNetworks.add(n));
    }
    if (networks6) {
      networks6.forEach(n => allNetworks6.add(n));
    }

    perFeedSummary.push({
      name: feed.name,
      url: feed.url,
      type: feed.type,
      counts: {
        ips: ips ? ips.size : 0,
        hosts: hosts ? hosts.size : 0,
        networks: networks ? networks.size : 0,
        networks6: networks6 ? networks6.size : 0
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

  const networks6Array = Array.from(allNetworks6).sort();
  writeArrayToTxt(path.join(OUTPUT_DIR, 'networks6.txt'), networks6Array);
  writeJson(path.join(OUTPUT_DIR, 'networks6.json'), networks6Array);
  writeMikrotikV6Rsc(path.join(OUTPUT_DIR, 'networks6.rsc'), networks6Array);


  writeArrayToTxt(path.join(OUTPUT_DIR, 'uptimerobot_ips.txt'), Array.from(uptimerobotIPs).sort());
  writeJson(path.join(OUTPUT_DIR, 'uptimerobot_ips.json'), Array.from(uptimerobotIPs).sort());
  writeMikrotikRsc(path.join(OUTPUT_DIR, 'uptimerobot_ips.rsc'), Array.from(uptimerobotIPs).sort(), 'uptimerobot');
  writeMikrotikRsc(path.join(OUTPUT_DIR, 'uptimerobot_networks.rsc'), Array.from(uptimerobotIPs).map(ip => `${ip}/32`).sort(), 'uptimerobot');

  const torExitNodesArray = Array.from(torExitNodes).sort();
  writeArrayToTxt(path.join(OUTPUT_DIR, 'tor_exit_nodes.txt'), torExitNodesArray);
  writeJson(path.join(OUTPUT_DIR, 'tor_exit_nodes.json'), torExitNodesArray);
  writeMikrotikRsc(path.join(OUTPUT_DIR, 'tor_exit_nodes.rsc'), torExitNodesArray, 'tor-exit-nodes');

  writeJson(path.join(OUTPUT_DIR, 'summary.json'), {
    generated_at: new Date().toISOString(),
    total: {
      ips: ipsArray.length,
      hosts: hostsArray.length,
      networks: networksArray.length,
      networks6: networks6Array.length,
      tor_exit_nodes: torExitNodesArray.length
    },
    per_feed: perFeedSummary
  });
}

main();

