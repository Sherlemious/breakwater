const STATIC = import.meta.env.VITE_STATIC_DEMO === "true";
const API = import.meta.env.VITE_API_BASE || "/api";

let snapshotPromise = null;
let live = null;

function loadSnapshot() {
  if (!snapshotPromise) {
    snapshotPromise = fetch("/demo/snapshot.json").then((r) => {
      if (!r.ok) throw new Error(`Failed to load demo snapshot (${r.status})`);
      return r.json();
    }).then((data) => {
      live = {
        whitelist: { ips: [...(data.whitelist?.ips || [])], last_updated: data.whitelist?.last_updated || null },
        blacklist: { ips: [...(data.blacklist?.ips || [])], last_updated: data.blacklist?.last_updated || null },
        notifications: [...(data.notifications || [])],
      };
      return data;
    });
  }
  return snapshotPromise;
}

function page(items, limit, offset) {
  const sliced = items.slice(offset, offset + limit);
  const nextOffset = offset + sliced.length;
  return {
    items: sliced,
    total: items.length,
    limit,
    offset,
    next_offset: nextOffset,
    has_more: nextOffset < items.length,
  };
}

function parseQuery(path) {
  const url = new URL(path, "https://breakwater.local");
  const params = url.searchParams;
  return {
    pathname: url.pathname.replace(/\/$/, "") || "/",
    start: Number(params.get("start") || "0"),
    end: Number(params.get("end") || "500"),
    limit: Math.max(1, Math.min(Number(params.get("limit") || "50"), 200)),
    offset: Math.max(0, Number(params.get("offset") || "0")),
  };
}

function validIp(ip) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split(".").every((o) => Number(o) <= 255);
}

function nowStamp() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

async function handleStatic(path, init = {}) {
  const data = await loadSnapshot();
  const method = (init.method || "GET").toUpperCase();
  const { pathname, start, end, limit, offset } = parseQuery(path);
  const body = init.body ? JSON.parse(init.body) : {};

  if (pathname === "/health") return data.health;
  if (pathname === "/summary") return data.summary;
  if (pathname === "/window-meta") return data.window_meta;
  if (pathname === "/attack-types") return data.attack_types;
  if (pathname === "/anomaly-trend") return data.scores;
  if (pathname === "/network-series") {
    const length = Math.max(end - start + 1, 1);
    return data.network.slice(start, start + length);
  }
  if (pathname === "/score-series") {
    const length = Math.max(end - start + 1, 1);
    return data.scores.slice(start, start + length);
  }
  if (pathname === "/alerts") return page(data.alerts, limit, offset);
  if (pathname === "/mitigations") return data.mitigations;
  if (pathname === "/mitigation-events") return page(data.mitigations, limit, offset);
  if (pathname === "/notification-history") return live.notifications.slice(-50);
  if (pathname === "/cooldown-status") return data.cooldown;
  if (pathname === "/pcap-injection/status") return data.pcap;
  if (pathname === "/whitelist" && method === "GET") return live.whitelist;
  if (pathname === "/blacklist" && method === "GET") return live.blacklist;

  if (pathname === "/whitelist" && method === "POST") {
    const ip = String(body.ip || "").trim();
    if (!validIp(ip)) throw new Error("400 invalid ip [/whitelist]");
    live.blacklist.ips = live.blacklist.ips.filter((x) => x !== ip);
    if (!live.whitelist.ips.includes(ip)) live.whitelist.ips.push(ip);
    live.whitelist.last_updated = nowStamp();
    return { ...live.whitelist, restored_windows: 0 };
  }
  if (pathname.startsWith("/whitelist/") && method === "DELETE") {
    const ip = decodeURIComponent(pathname.slice("/whitelist/".length));
    live.whitelist.ips = live.whitelist.ips.filter((x) => x !== ip);
    return live.whitelist;
  }
  if (pathname === "/blacklist" && method === "POST") {
    const ip = String(body.ip || "").trim();
    if (!validIp(ip)) throw new Error("400 invalid ip [/blacklist]");
    live.whitelist.ips = live.whitelist.ips.filter((x) => x !== ip);
    if (!live.blacklist.ips.includes(ip)) live.blacklist.ips.push(ip);
    live.blacklist.last_updated = nowStamp();
    return { ...live.blacklist, affected_windows: 0 };
  }
  if (pathname.startsWith("/blacklist/") && method === "DELETE") {
    const ip = decodeURIComponent(pathname.slice("/blacklist/".length));
    live.blacklist.ips = live.blacklist.ips.filter((x) => x !== ip);
    return { ...live.blacklist, restored_windows: 0 };
  }
  if (pathname === "/test-notification" && method === "POST") {
    const entry = {
      id: `browser:test:manual:${Date.now()}`,
      timestamp: nowStamp(),
      channel: "browser",
      recipient: "dashboard",
      alert_type: "test",
      status: "queued",
      epoch: Math.floor(Date.now() / 1000),
      window_id: "manual-test",
      score: 1,
      title: "[Breakwater] Test browser notification",
      message: "Browser notifications are wired to the hosted demo.",
    };
    live.notifications.push(entry);
    return { ok: true, notification: entry };
  }
  if (pathname === "/pcap-injection" && method === "POST") {
    throw new Error("400 Hosted demo is a recorded run — inject PCAPs locally with Docker Compose [/pcap-injection]");
  }
  if (pathname === "/export-alerts.csv") {
    const lines = ["alert_id,timestamp,alert_type,severity,anomaly_score,description"];
    for (const r of data.alerts) {
      const desc = String(r.description || "").replaceAll('"', '""');
      lines.push(`${r.alert_id},${r.timestamp},${r.alert_type},${r.severity},${r.anomaly_score},"${desc}"`);
    }
    return { __csv: lines.join("\n") };
  }

  throw new Error(`404 unknown endpoint [${pathname}]`);
}

export async function req(path, init) {
  if (STATIC) return handleStatic(path, init);

  const url = `${API}${path}`;
  const r = await fetch(url, init);
  const text = await r.text();
  if (!r.ok) {
    let message = text.slice(0, 120) || r.statusText;
    try {
      const payload = JSON.parse(text);
      message = payload.error || payload.message || message;
    } catch {
      // keep truncated text
    }
    throw new Error(`${r.status} ${message} [${path}]`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`Bad JSON from ${path} — got: ${text.slice(0, 60)}`);
  }
}

export function exportAlertsHref() {
  return STATIC ? null : `${API}/export-alerts.csv`;
}

export async function downloadAlertsCsv() {
  if (!STATIC) {
    window.location.href = `${API}/export-alerts.csv`;
    return;
  }
  const payload = await handleStatic("/export-alerts.csv");
  const blob = new Blob([payload.__csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "alerts.csv";
  a.click();
  URL.revokeObjectURL(url);
}

export const isStaticDemo = STATIC;
export const REFRESH_MS = STATIC ? 60_000 : 5_000;
