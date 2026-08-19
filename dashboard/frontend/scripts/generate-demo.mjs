/**
 * Builds a recorded 20-minute pipeline snapshot for the hosted dashboard.
 * Scenario matches scripts/gen_test_data.py: benign → UDP → SYN → ICMP → HTTP → recovery.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "public", "demo", "snapshot.json");
const EPOCH = 1_700_000_000;

function mulberry32(seed) {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

const rand = mulberry32(42);
const gauss = (mu, sig) => {
  const u = Math.max(rand(), 1e-9);
  const v = Math.max(rand(), 1e-9);
  return mu + sig * Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
};
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const pad = (n) => String(n).padStart(2, "0");
const ts = (epoch) => {
  const d = new Date(epoch * 1000);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
};

const PHASES = [
  { name: "benign", secs: 360, attack: null, pkt: [480, 70], bytes: [42000, 7000], src: [28, 4], dst: [14, 3], tcp: 0.62, udp: 0.28, icmp: 0.08, syn: 0.08, web: 0.22, topSrc: "10.0.0.14" },
  { name: "udp_flood", secs: 120, attack: "volumetric", pkt: [9800, 900], bytes: [1_150_000, 80_000], src: [420, 40], dst: [6, 1], tcp: 0.04, udp: 0.93, icmp: 0.02, syn: 0.03, web: 0.02, topSrc: "203.0.113.40" },
  { name: "syn_flood", secs: 120, attack: "network_protocols", pkt: [7200, 600], bytes: [360_000, 40_000], src: [310, 30], dst: [4, 1], tcp: 0.94, udp: 0.04, icmp: 0.01, syn: 0.88, web: 0.08, topSrc: "198.51.100.17" },
  { name: "icmp_flood", secs: 120, attack: "volumetric", pkt: [6400, 500], bytes: [720_000, 50_000], src: [260, 25], dst: [8, 2], tcp: 0.06, udp: 0.08, icmp: 0.84, syn: 0.02, web: 0.01, topSrc: "203.0.113.88" },
  { name: "http_flood", secs: 120, attack: "application_layer", pkt: [3100, 280], bytes: [2_400_000, 180_000], src: [90, 12], dst: [2, 0.4], tcp: 0.91, udp: 0.06, icmp: 0.02, syn: 0.18, web: 0.86, topSrc: "192.0.2.66" },
  { name: "recovery", secs: 360, attack: null, pkt: [510, 80], bytes: [45000, 8000], src: [30, 5], dst: [15, 3], tcp: 0.6, udp: 0.3, icmp: 0.08, syn: 0.09, web: 0.24, topSrc: "10.0.0.22" },
];

function severityName(level) {
  if (level <= 30) return "low";
  if (level <= 60) return "medium";
  if (level < 81) return "high";
  return "critical";
}

function rateLimitCmd(ip, rate, burst) {
  const name = `limit_${ip.replace(/[^A-Za-z0-9_]/g, "_")}`;
  return `iptables -A INPUT -s ${ip} -m hashlimit --hashlimit-above ${rate}/second --hashlimit-burst ${burst} --hashlimit-mode srcip --hashlimit-name ${name} -j DROP`;
}
function blockIpCmd(ip) {
  return `iptables -A INPUT -s ${ip} -j DROP`;
}
function blockPortCmd(ip, proto, port) {
  return `iptables -A INPUT -s ${ip} -p ${proto} --dport ${port} -j DROP`;
}

const network = [];
const scores = [];
const alerts = [];
const mitigations = [];
const notifications = [];
const typeCounts = { volumetric: 0, network_protocols: 0, application_layer: 0 };

let windowId = 1;
let t = EPOCH;
let alertId = 1;
let mitigationId = 1;

for (const phase of PHASES) {
  for (let i = 0; i < phase.secs; i += 1) {
    const pkt = Math.max(20, gauss(phase.pkt[0], phase.pkt[1]));
    const bytes = Math.max(800, gauss(phase.bytes[0], phase.bytes[1]));
    const src = Math.max(2, Math.round(gauss(phase.src[0], phase.src[1])));
    const dst = Math.max(1, Math.round(gauss(phase.dst[0], phase.dst[1])));
    const tcp = clamp(gauss(phase.tcp, 0.03), 0, 1);
    const udp = clamp(gauss(phase.udp, 0.03), 0, 1);
    const icmp = clamp(gauss(phase.icmp, 0.02), 0, 1);
    const sum = tcp + udp + icmp || 1;

    network.push({
      window_id: windowId,
      timestamp: ts(t),
      pkt_count: Math.round(pkt),
      byte_count: Math.round(bytes),
      src_ip_unique: src,
      dst_port_unique: dst,
      tcp_pct: (tcp / sum) * 100,
      udp_pct: (udp / sum) * 100,
      icmp_pct: (icmp / sum) * 100,
    });

    let anomaly = clamp(gauss(0.09, 0.04), 0.01, 0.22);
    let rf = clamp(gauss(0.06, 0.03), 0.01, 0.18);
    let predicted = null;
    if (phase.attack) {
      const ramp = Math.min(1, i / 12);
      anomaly = clamp(0.55 + ramp * 0.38 + gauss(0, 0.04), 0.48, 0.99);
      rf = clamp(0.62 + ramp * 0.32 + gauss(0, 0.05), 0.5, 0.99);
      predicted = phase.attack;
      typeCounts[predicted] += 1;
    }

    scores.push({
      window_id: windowId,
      timestamp: ts(t),
      anomaly_score: Number(anomaly.toFixed(4)),
      rf_attack_probability: Number(rf.toFixed(4)),
      predicted_attack_type: predicted,
    });

    const hybrid = 0.6 * anomaly + 0.4 * rf;
    const level = Math.round(hybrid * 100);
    const peak = phase.attack && i >= 18 && i % 18 === 0;
    if (peak && hybrid >= 0.5) {
      const ip = phase.topSrc;
      const sev = severityName(level);
      let ruleType = null;
      let target = ip;
      let cmd = null;
      if (level <= 30) {
        // alert only
      } else if (level <= 60) {
        ruleType = "rate_limit";
        cmd = rateLimitCmd(ip, 100, 200);
      } else if (level < 81) {
        if (phase.attack === "network_protocols") {
          ruleType = "block_port";
          target = `${ip}:tcp/80`;
          cmd = blockPortCmd(ip, "tcp", 80);
        } else {
          ruleType = "rate_limit";
          cmd = rateLimitCmd(ip, 25, 50);
        }
      } else {
        ruleType = "block_ip";
        cmd = blockIpCmd(ip);
      }

      alerts.push({
        alert_id: alertId,
        timestamp: ts(t),
        alert_type: phase.attack,
        severity: sev,
        anomaly_score: Number(hybrid.toFixed(4)),
        window_id: windowId,
        source_ips: JSON.stringify([ip]),
        description: `simulated; ${phase.name.replace("_", " ")}; level=${level}`,
      });

      if (ruleType) {
        mitigations.push({
          mitigation_id: mitigationId,
          timestamp: ts(t),
          rule_type: ruleType,
          target,
          iptables_cmd: cmd,
          notes: `simulated; command stored but not executed; level=${level}; type=${phase.attack}`,
          severity: sev,
          alert_type: phase.attack,
          anomaly_score: Number(hybrid.toFixed(4)),
        });
        mitigationId += 1;
      }

      if (hybrid >= 0.7) {
        notifications.push({
          id: `browser:${phase.attack}:${windowId}:${Math.floor(t)}`,
          timestamp: ts(t),
          channel: "browser",
          recipient: "dashboard",
          alert_type: phase.attack,
          status: "queued",
          epoch: Math.floor(t),
          window_id: windowId,
          score: Number(hybrid.toFixed(4)),
          title: `[Breakwater] ${sev.toUpperCase()} — ${phase.attack} detected`,
          message: `${phase.attack} attack detected with anomaly score ${hybrid.toFixed(3)}.`,
        });
      }
      alertId += 1;
    }

    windowId += 1;
    t += 1;
  }
}

const snapshot = {
  generated_at: "2026-08-20T00:00:00Z",
  note: "Recorded 20-minute synthetic run matching the Breakwater pipeline scenario. Mitigation commands are stored, not executed.",
  health: { ok: true, db_path: "demo/snapshot.json" },
  summary: {
    windows_count: network.length,
    scored_count: scores.length,
    alerts_count: alerts.length,
    mitigations_count: mitigations.length,
  },
  window_meta: {
    total: network.length,
    min_ts: network[0].timestamp,
    max_ts: network[network.length - 1].timestamp,
  },
  network,
  scores,
  attack_types: Object.entries(typeCounts).map(([type, count]) => ({ type, count })),
  alerts,
  mitigations,
  notifications,
  whitelist: { ips: ["10.8.0.2"], last_updated: network[40].timestamp },
  blacklist: { ips: [], last_updated: null },
  cooldown: { status: "ready", seconds: 0, alert_type: "application_layer" },
  pcap: {
    state: "completed",
    filename: "attack-test.pcap",
    effective_filename: "attack-test.pcap",
    default_filename: "attack-test.pcap",
    available_pcaps: ["benign-train.pcap", "attack-train.pcap", "benign-test.pcap", "attack-test.pcap"],
    message: "Hosted demo is a recorded pipeline run. Inject PCAPs locally with Docker Compose.",
    error: "",
    windows_before: 0,
    windows_after: network.length,
    scores_before: 0,
    scores_after: scores.length,
  },
};

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(snapshot));
console.log(`Wrote ${OUT}`);
console.log(`windows=${network.length} alerts=${alerts.length} mitigations=${mitigations.length}`);
