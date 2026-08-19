import React from "react";
import { createRoot } from "react-dom/client";
import {
  Area, AreaChart, CartesianGrid, Cell, Legend,
  Line, LineChart, Pie, PieChart, ReferenceLine,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import "./styles.css";
import { req, REFRESH_MS, isStaticDemo, downloadAlertsCsv } from "./demoApi";

const PAGE_SIZE  = 40;
const C = {
  pkt:    "#3ea6ff",
  bytes:  "#ff8c00",
  tcp:    "#3ea6ff",
  udp:    "#f5c518",
  icmp:   "#00d68f",
  score:  "#ff3355",
  rf:     "#00c8a8",
  pie:    ["#ff3355", "#3ea6ff", "#b47aff", "#00d68f", "#f5c518"],
};

function usePolling(loader, deps = []) {
  const [data, setData]       = React.useState(null);
  const [error, setError]     = React.useState("");
  const [loading, setLoading] = React.useState(true);
  React.useEffect(() => {
    let dead = false;
    async function run() {
      try {
        const x = await loader();
        if (!dead) { setData(x); setError(""); }
      } catch (e) {
        if (!dead) setError(e.message);
      } finally {
        if (!dead) setLoading(false);
      }
    }
    run();
    const id = setInterval(run, REFRESH_MS);
    return () => { dead = true; clearInterval(id); };
  }, deps);
  return { data, error, loading };
}

function withPage(path, limit, offset) {
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}limit=${limit}&offset=${offset}`;
}

function usePagedPolling(path, pageSize = PAGE_SIZE) {
  const [items, setItems]             = React.useState([]);
  const [total, setTotal]             = React.useState(0);
  const [nextOffset, setNextOffset]   = React.useState(0);
  const [hasMore, setHasMore]         = React.useState(false);
  const [error, setError]             = React.useState("");
  const [loading, setLoading]         = React.useState(true);
  const [loadingMore, setLoadingMore] = React.useState(false);
  const busy = React.useRef(false);

  const loadPage = React.useCallback(async (offset, replace = false) => {
    if (busy.current) return;
    busy.current = true;
    if (offset === 0) setLoading(true);
    else setLoadingMore(true);
    try {
      const page = await req(withPage(path, pageSize, offset));
      const nextItems = page.items || [];
      setItems(prev => replace ? nextItems : [...prev, ...nextItems]);
      setTotal(Number(page.total || 0));
      setNextOffset(Number(page.next_offset ?? offset + nextItems.length));
      setHasMore(Boolean(page.has_more));
      setError("");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
      setLoadingMore(false);
      busy.current = false;
    }
  }, [path, pageSize]);

  React.useEffect(() => {
    loadPage(0, true);
  }, [loadPage]);

  const loadMore = React.useCallback(() => {
    if (!loading && !loadingMore && hasMore) loadPage(nextOffset, false);
  }, [hasMore, loadPage, loading, loadingMore, nextOffset]);

  return { data: items, total, hasMore, loading, loadingMore, error, loadMore };
}

function useClock() {
  const [t, setT] = React.useState(() => new Date().toLocaleTimeString());
  React.useEffect(() => {
    const id = setInterval(() => setT(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(id);
  }, []);
  return t;
}

// ── primitive components ──────────────────────────────────────────────────────
function Skeleton({ h = 16, w = "100%", mb = 8, mt = 0 }) {
  return (
    <span
      className="skeleton"
      style={{ height: h, width: w, marginBottom: mb, marginTop: mt, display: "block" }}
    />
  );
}

function LoadingBar({ active }) {
  return <div className={`loading-bar${active ? " loading-bar--active" : ""}`} />;
}

function PulsingDot({ color = "green" }) {
  return <span className={`pulse-dot pulse-dot--${color}`} />;
}

const TYPE_LABEL = {
  volumetric:        "Volumetric",
  network_protocols: "Protocol",
  application_layer: "App Layer",
  composite:         "Composite",
};
const TYPE_CLS = {
  volumetric:        "volumetric",
  network_protocols: "network-protocols",
  application_layer: "application-layer",
  composite:         "network-protocols",
};
const RULE_LABEL = { rate_limit: "Rate Limit", block_port: "Block Port", block_ip: "Block IP" };
const RULE_CLS   = { rate_limit: "rate-limit", block_port: "block-port", block_ip: "block-ip" };

function Badge({ cls, children }) {
  return <span className={`badge badge--${cls}`}>{children}</span>;
}
function SeverityBadge({ v }) {
  if (!v) return <span style={{ color: "var(--muted)" }}>—</span>;
  return <Badge cls={v}>{v}</Badge>;
}
function TypeBadge({ v }) {
  if (!v) return <span style={{ color: "var(--muted)" }}>—</span>;
  return <Badge cls={TYPE_CLS[v] || "volumetric"}>{TYPE_LABEL[v] || v}</Badge>;
}
function RuleBadge({ v }) {
  if (!v) return <span style={{ color: "var(--muted)" }}>—</span>;
  return <Badge cls={RULE_CLS[v] || "block-ip"}>{RULE_LABEL[v] || v}</Badge>;
}

// ── chart tooltip ─────────────────────────────────────────────────────────────
function ChartTip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      {label && <div className="chart-tooltip-label">{label}</div>}
      {payload.map((p, i) => (
        <div key={i} className="chart-tooltip-row">
          <span style={{ color: p.color }}>● </span>
          {p.name}: <strong>{typeof p.value === "number" ? p.value.toFixed(3) : p.value}</strong>
        </div>
      ))}
    </div>
  );
}

// ── Card ──────────────────────────────────────────────────────────────────────
function Card({ title, action, children }) {
  return (
    <section className="card">
      <div className="card-header">
        <h2>{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

// ── KPI card ──────────────────────────────────────────────────────────────────
function KpiCard({ label, value, variant, sub, loading }) {
  return (
    <div className={`kpi kpi--${variant}`}>
      <div className="kpi-label">{label}</div>
      {loading
        ? <Skeleton h={44} mt={10} mb={5} />
        : <div className="kpi-value">{value ?? "—"}</div>}
      <div className="kpi-sub">{sub}</div>
    </div>
  );
}

// ── IP list manager ───────────────────────────────────────────────────────────
function ListManager({ title, endpoint, state, setState, blacklist, onError, onSuccess }) {
  const [ip, setIp]     = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");

  async function add() {
    const v = ip.trim();
    if (!v) return;
    setBusy(true);
    setError("");
    try {
      setState(await req(`/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: v }),
      }));
      setIp("");
      onError?.("");
      await onSuccess?.();
    } catch (e) {
      const message = `${title}: ${e.message}`;
      setError(message);
      onError?.(message);
    } finally {
      setBusy(false);
    }
  }
  async function remove(v) {
    setError("");
    try {
      setState(await req(`/${endpoint}/${encodeURIComponent(v)}`, { method: "DELETE" }));
      onError?.("");
      await onSuccess?.();
    } catch (e) {
      const message = `${title}: ${e.message}`;
      setError(message);
      onError?.(message);
    }
  }

  return (
    <Card title={title}>
      <div className="input-row">
        <input
          type="text"
          value={ip}
          placeholder="Enter IP address"
          onChange={e => setIp(e.target.value)}
          onKeyDown={e => e.key === "Enter" && add()}
        />
        <button onClick={add} disabled={busy}>{busy ? "…" : "Add"}</button>
      </div>
      {error && <div className="list-error">{error}</div>}
      <div className="chips">
        {(state?.ips || []).map(x => (
          <button
            key={x}
            className={`chip${blacklist ? " chip--blacklist" : ""}`}
            onClick={() => remove(x)}
          >
            {x} <span className="chip-x">×</span>
          </button>
        ))}
        {!(state?.ips || []).length && (
          <span style={{ color: "var(--muted)", fontSize: 12 }}>No entries yet.</span>
        )}
      </div>
    </Card>
  );
}

// ── Email test widget ─────────────────────────────────────────────────────────
function supportsBrowserNotifications() {
  return typeof window !== "undefined" && "Notification" in window;
}

function notificationKey(n) {
  return n?.id || `${n?.channel || "local"}:${n?.alert_type || "unknown"}:${n?.window_id || ""}:${n?.epoch || n?.timestamp || ""}`;
}

function notificationBody(n) {
  const type = TYPE_LABEL[n?.alert_type] || n?.alert_type || "Alert";
  const score = typeof n?.score === "number" ? `score ${n.score.toFixed(3)}` : "";
  return n?.message || `${type} ${score}`.trim();
}

function BrowserNotify({ onTest }) {
  const [permission, setPermission] = React.useState(() =>
    supportsBrowserNotifications() ? window.Notification.permission : "unsupported"
  );
  const [status, setStatus] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  async function enable() {
    if (!supportsBrowserNotifications()) {
      setPermission("unsupported");
      return;
    }
    const next = await window.Notification.requestPermission();
    setPermission(next);
    setStatus(next === "granted" ? "enabled" : "blocked");
  }

  async function test() {
    setBusy(true);
    setStatus("");
    try {
      const r = await req("/test-notification", { method: "POST" });
      const entry = r.notification;
      onTest?.(entry);
      if (supportsBrowserNotifications() && window.Notification.permission === "granted") {
        new window.Notification(entry.title || "DDoS Sentinel alert", {
          body: notificationBody(entry),
          tag: notificationKey(entry),
        });
      }
      setStatus("sent");
    } catch {
      setStatus("err");
    }
    setBusy(false);
  }

  return (
    <div className="notify-controls">
      <button className="btn btn--outline" onClick={enable} disabled={permission === "granted" || permission === "unsupported"}>
        {permission === "granted" ? "Browser alerts on" : "Enable browser alerts"}
      </button>
      <button className="btn btn--outline" onClick={test} disabled={busy}>
        {busy ? "Sending..." : "Test alert"}
      </button>
      {status === "sent" && <span className="notify-status notify-status--ok">Queued</span>}
      {status === "enabled" && <span className="notify-status notify-status--ok">Enabled</span>}
      {status === "blocked" && <span className="notify-status notify-status--err">Blocked</span>}
      {status === "err" && <span className="notify-status notify-status--err">Failed</span>}
      {permission === "unsupported" && <span className="notify-status notify-status--err">Unsupported</span>}
    </div>
  );
}

function PcapInjection({ status, loading }) {
  const [filename, setFilename] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState("");
  const [error, setError] = React.useState("");
  const running = status?.state === "queued" || status?.state === "running";
  const fallback = status?.default_filename || "attack-test.pcap";

  async function inject() {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const result = await req("/pcap-injection", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename }),
      });
      setMessage(result.job?.message || `Queued ${result.job?.effective_filename || fallback}`);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const stateLabel = loading ? "Loading" : (status?.state || "idle");
  const effective = status?.effective_filename || fallback;

  return (
    <Card
      title="PCAP Injection"
      action={<Badge cls={running ? "medium" : status?.state === "failed" ? "critical" : "low"}>{stateLabel}</Badge>}
    >
      <div className="pcap-injector">
        <div className="input-row">
          <input
            type="text"
            list="pcap-files"
            value={filename}
            placeholder={fallback}
            onChange={e => setFilename(e.target.value)}
            onKeyDown={e => e.key === "Enter" && !busy && !running && inject()}
          />
          <datalist id="pcap-files">
            {(status?.available_pcaps || []).map(name => <option key={name} value={name} />)}
          </datalist>
          <button onClick={inject} disabled={busy || running || isStaticDemo}>
            {busy || running ? "Running..." : isStaticDemo ? "Local only" : "Inject"}
          </button>
        </div>
        <div className="pcap-meta">
          <span>Empty uses <strong>{fallback}</strong></span>
          <span>Current file <strong>{effective}</strong></span>
          {typeof status?.windows_before === "number" && typeof status?.windows_after === "number" && (
            <span>Windows <strong>{status.windows_before}</strong> {"->"} <strong>{status.windows_after}</strong></span>
          )}
        </div>
        {(message || status?.message) && (
          <div className="pcap-status pcap-status--ok">{message || status.message}</div>
        )}
        {(error || status?.error) && (
          <div className="pcap-status pcap-status--err">{error || status.error}</div>
        )}
      </div>
    </Card>
  );
}

function ToastStack({ toasts, onDismiss }) {
  if (!toasts.length) return null;
  return (
    <div className="toast-stack">
      {toasts.map(t => (
        <div className="toast" key={t.toastId || notificationKey(t)}>
          <button className="toast-close" onClick={() => onDismiss(t.toastId)}>x</button>
          <div className="toast-title">{t.title || "DDoS Sentinel alert"}</div>
          <div className="toast-body">{notificationBody(t)}</div>
          <div className="toast-meta">
            <TypeBadge v={t.alert_type} />
            <span className="mono">{t.timestamp?.slice(11, 19)}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Section label ─────────────────────────────────────────────────────────────
function SectionLabel({ icon, title, subtitle }) {
  return (
    <div className="section-label">
      <span className="section-label-icon">{icon}</span>
      <div>
        <div className="section-label-title">{title}</div>
        <div className="section-label-sub">{subtitle}</div>
      </div>
    </div>
  );
}

// ── Mitigation timeline ───────────────────────────────────────────────────────
const RULE_COLOR = { rate_limit: "var(--orange)", block_port: "var(--yellow)", block_ip: "var(--red)" };
const RULE_DESC  = {
  rate_limit:  "Rate throttling — token-bucket applied",
  block_port:  "Port block — iptables port DROP rule",
  block_ip:    "IP block — iptables full source DROP",
};

function InfiniteTableWrap({ children, hasMore, loadingMore, onLoadMore }) {
  function onScroll(e) {
    const el = e.currentTarget;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 40) onLoadMore?.();
  }
  return (
    <div className="table-wrap" onScroll={onScroll}>
      {children}
      {loadingMore && <div className="load-more-row">Loading more...</div>}
      {hasMore && !loadingMore && <div className="scroll-hint">Scroll for more</div>}
    </div>
  );
}

function MitigationTimeline({ events, loading, hasMore, loadingMore, onLoadMore }) {
  if (loading) return <>{[0,1,2].map(i => <Skeleton key={i} h={34} mb={4} />)}</>;
  if (!events?.length) return <div className="chart-empty">No mitigation actions recorded yet</div>;
  return (
    <InfiniteTableWrap hasMore={hasMore} loadingMore={loadingMore} onLoadMore={onLoadMore}>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Rule</th>
            <th>Type</th>
            <th>Severity</th>
            <th>Target IP</th>
            <th>Command</th>
          </tr>
        </thead>
        <tbody>
          {events.map((m, i) => {
            const color = RULE_COLOR[m.rule_type] || "var(--brand)";
            return (
              <tr key={m.mitigation_id ?? i}>
                <td className="mono" style={{ color: "var(--muted)", width: 32 }}>{i + 1}</td>
                <td><RuleBadge v={m.rule_type} /></td>
                <td><TypeBadge v={m.alert_type} /></td>
                <td><SeverityBadge v={m.severity} /></td>
                <td className="mono" style={{ color }}>{m.target}</td>
                <td className="mono" style={{ fontSize: 11, color: "var(--brand)", maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={m.iptables_cmd}>{m.iptables_cmd}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </InfiniteTableWrap>
  );
}

// ── App ───────────────────────────────────────────────────────────────────────
function App() {
  const clock = useClock();
  const [range, setRange] = React.useState([0, 299]);
  const [toasts, setToasts] = React.useState([]);
  const [dataRefreshKey, setDataRefreshKey] = React.useState(0);
  const seenNotifications = React.useRef(new Set());
  const notificationsPrimed = React.useRef(false);
  const rangePrimed = React.useRef(false);

  const dismissToast = React.useCallback((id) => {
    setToasts(prev => prev.filter(t => t.toastId !== id));
  }, []);

  const pushNotification = React.useCallback((entry) => {
    const toastId = notificationKey(entry);
    setToasts(prev => [{ ...entry, toastId }, ...prev.filter(t => t.toastId !== toastId)].slice(0, 3));
    window.setTimeout(() => {
      setToasts(prev => prev.filter(t => t.toastId !== toastId));
    }, 9000);
  }, []);

  const pushManualNotification = React.useCallback((entry) => {
    seenNotifications.current.add(notificationKey(entry));
    pushNotification(entry);
  }, [pushNotification]);

  const meta      = usePolling(() => req("/window-meta"), [dataRefreshKey]);
  const summary   = usePolling(() => req("/summary"), [dataRefreshKey]);
  const series    = usePolling(() => req(`/network-series?start=${range[0]}&end=${range[1]}`), [range[0], range[1], dataRefreshKey]);
  const scores    = usePolling(() => req(`/score-series?start=${range[0]}&end=${range[1]}`),   [range[0], range[1], dataRefreshKey]);
  const types     = usePolling(() => req("/attack-types"), [dataRefreshKey]);
  const alerts    = usePagedPolling(`/alerts?refresh=${dataRefreshKey}`);
  const mits      = usePolling(() => req("/mitigations"), [dataRefreshKey]);
  const mitEvents = usePagedPolling(`/mitigation-events?refresh=${dataRefreshKey}`);
  const notif     = usePolling(() => req("/notification-history"), []);
  const cool      = usePolling(() => req("/cooldown-status"), []);
  const pcap      = usePolling(() => req("/pcap-injection/status"), []);

  const [whitelist, setWhitelist] = React.useState({ ips: [] });
  const [blacklist, setBlacklist] = React.useState({ ips: [] });
  const [ipListError, setIpListError] = React.useState("");

  async function loadIpLists() {
    try {
      const [whitelistData, blacklistData] = await Promise.all([
        req("/whitelist"),
        req("/blacklist"),
      ]);
      setWhitelist(whitelistData);
      setBlacklist(blacklistData);
      setIpListError("");
    } catch (e) {
      setIpListError(`IP lists: ${e.message}`);
    }
  }

  React.useEffect(() => {
    loadIpLists();
  }, []);

  async function blacklistIp(v, windowId) {
    try {
      setBlacklist(await req("/blacklist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: v, window_id: windowId }),
      }));
      await loadIpLists();
      setDataRefreshKey(x => x + 1);
      setIpListError("");
    } catch (e) {
      setIpListError(`Blacklist: ${e.message}`);
    }
  }

  React.useEffect(() => {
    const total = Number(meta.data?.total || 0);
    if (total > 0 && !rangePrimed.current) {
      rangePrimed.current = true;
      setRange([Math.max(0, total - 300), total - 1]);
    } else if (total > 0 && range[1] > total - 1) {
      setRange([Math.max(0, total - 300), total - 1]);
    }
  }, [meta.data?.total, range[1]]);

  React.useEffect(() => {
    const rows = notif.data || [];
    if (!rows.length) return;

    const fresh = [];
    for (const n of rows) {
      const key = notificationKey(n);
      if (seenNotifications.current.has(key)) continue;
      seenNotifications.current.add(key);
      if (notificationsPrimed.current && n.channel !== "email") {
        fresh.push(n);
      }
    }

    if (!notificationsPrimed.current) {
      notificationsPrimed.current = true;
      return;
    }

    for (const entry of fresh) {
      pushNotification(entry);
      if (supportsBrowserNotifications() && window.Notification.permission === "granted") {
        new window.Notification(entry.title || "DDoS Sentinel alert", {
          body: notificationBody(entry),
          tag: notificationKey(entry),
        });
      }
    }
  }, [notif.data, pushNotification]);

  const anyLoading    = [meta, summary, series, scores, types, alerts, mits, pcap].some(x => x.loading);
  const errors        = [meta, summary, series, scores, types, alerts, mits, pcap]
                          .map(x => x.error).filter(Boolean);
  if (ipListError) errors.unshift(ipListError);
  const criticalCount = (alerts.data || []).filter(a => a.severity === "critical").length;
  const total         = Number(meta.data?.total || 0);

  return (
    <>
      <LoadingBar active={anyLoading} />
      <ToastStack toasts={toasts} onDismiss={dismissToast} />
      <main className="page">

        {/* ── Header ── */}
        <header className="hero">
          <div className="hero-brand">
            <div className="hero-icon">
              <img src="/favicon.svg" alt="" width="28" height="28" />
            </div>
            <div>
              <h1>BREAK<span>WATER</span></h1>
              <p>Hybrid ML + statistical DDoS detector — simulated mitigation</p>
            </div>
          </div>
          <div className="hero-right">
            {criticalCount > 0
              ? <div className="status-chip status-chip--critical">
                  <PulsingDot color="red" />
                  {criticalCount} critical alert{criticalCount > 1 ? "s" : ""}
                </div>
              : <div className="status-chip">
                  <PulsingDot color="green" />
                  System normal
                </div>}
            <span className="clock">{clock}</span>
          </div>
        </header>

        {isStaticDemo && (
          <div className="demo-banner">
            Recorded 20-minute pipeline run. Charts, alerts, and iptables strings are from the detector — rules are simulated, not applied. Inject PCAPs locally with Docker Compose.
          </div>
        )}

        {errors.length > 0 && (
          <div className="error-banner">⚠ {errors[0]}</div>
        )}

        {/* ── KPIs ── */}
        <section className="kpis">
          <KpiCard label="Windows"     value={summary.data?.windows_count}    variant="windows"     sub="traffic windows"  loading={summary.loading} />
          <KpiCard label="Scored"      value={summary.data?.scored_count}      variant="scored"      sub="anomaly scored"   loading={summary.loading} />
          <KpiCard label="Alerts"      value={summary.data?.alerts_count}      variant="alerts"      sub="active alerts"    loading={summary.loading} />
          <KpiCard label="Mitigations" value={summary.data?.mitigations_count} variant="mitigations" sub="rules applied"    loading={summary.loading} />
        </section>

        {/* ── Time Range ── */}
        <div style={{ marginBottom: 16 }}>
          <Card title="Window Range">
            <div className="slider-wrap">
              <div className="slider-track">
                <span className="slider-lbl">Start</span>
                <input type="range" min={0} max={Math.max(0, total - 1)} value={range[0]}
                  onChange={e => setRange([Math.min(Number(e.target.value), range[1]), range[1]])} />
              </div>
              <div className="slider-track">
                <span className="slider-lbl">End</span>
                <input type="range" min={0} max={Math.max(0, total - 1)} value={range[1]}
                  onChange={e => setRange([range[0], Math.max(Number(e.target.value), range[0])])} />
              </div>
            </div>
            <div className="slider-info">
              <span>Windows <strong>{range[0]}</strong> → <strong>{range[1]}</strong></span>
              {meta.data?.min_ts && (
                <span className="ts">{meta.data.min_ts.slice(0,16)} → {meta.data.max_ts?.slice(0,16)}</span>
              )}
            </div>
          </Card>
        </div>

        <div style={{ marginBottom: 16 }}>
          <PcapInjection status={pcap.data} loading={pcap.loading} />
        </div>

        {/* ── Traffic charts ── */}
        <div className="grid two">
          <Card title="Packets &amp; Bytes per Second">
            <div className="chart">
              {series.loading ? <Skeleton h={260} /> : (series.data || []).length === 0
                ? <div className="chart-empty">No data in range</div>
                : <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={series.data}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                      <XAxis dataKey="timestamp" hide tick={{ fill: "var(--muted)", fontSize: 10 }} />
                      <YAxis tick={{ fill: "var(--muted)", fontSize: 11 }} />
                      <Tooltip content={<ChartTip />} />
                      <Legend wrapperStyle={{ fontSize: 12, color: "var(--ink-dim)" }} />
                      <Line type="monotone" dataKey="pkt_count"  stroke={C.pkt}   dot={false} strokeWidth={2} name="Pkts/s" />
                      <Line type="monotone" dataKey="byte_count" stroke={C.bytes} dot={false} strokeWidth={2} name="Bytes/s" />
                    </LineChart>
                  </ResponsiveContainer>}
            </div>
          </Card>

          <Card title="Protocol Distribution">
            <div className="chart">
              {series.loading ? <Skeleton h={260} /> : (series.data || []).length === 0
                ? <div className="chart-empty">No data in range</div>
                : <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={series.data}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                      <XAxis dataKey="timestamp" hide />
                      <YAxis tick={{ fill: "var(--muted)", fontSize: 11 }} />
                      <Tooltip content={<ChartTip />} />
                      <Legend wrapperStyle={{ fontSize: 12, color: "var(--ink-dim)" }} />
                      <Area type="monotone" dataKey="tcp_pct"  stackId="1" stroke={C.tcp}  fill={C.tcp}  fillOpacity={0.35} name="TCP %" />
                      <Area type="monotone" dataKey="udp_pct"  stackId="1" stroke={C.udp}  fill={C.udp}  fillOpacity={0.35} name="UDP %" />
                      <Area type="monotone" dataKey="icmp_pct" stackId="1" stroke={C.icmp} fill={C.icmp} fillOpacity={0.35} name="ICMP %" />
                    </AreaChart>
                  </ResponsiveContainer>}
            </div>
          </Card>
        </div>

        {/* ── Dataset 1: Detection ── */}
        <SectionLabel
          icon="🔍"
          title="Dataset 1 — Model Detection Output"
          subtitle="Anomaly scores and RF attack probabilities computed by the detection model against the traffic baseline"
        />
        <div className="grid two">
          <Card
            title="Anomaly Score & RF Attack Probability"
            action={
              <span style={{ display: "flex", gap: 10, fontSize: 11, alignItems: "center", flexWrap: "wrap" }}>
                <span><span style={{ color: C.score }}>●</span> Anomaly</span>
                <span><span style={{ color: C.rf }}>●</span> RF Prob</span>
                <span><span style={{ color: "var(--orange)" }}>—</span> 0.7</span>
                <span style={{ color: "var(--muted)", margin: "0 2px" }}>|</span>
                <span><span style={{ color: "var(--orange)" }}>│</span> rate limit</span>
                <span><span style={{ color: "var(--yellow)" }}>│</span> block port</span>
                <span><span style={{ color: "var(--red)" }}>│</span> block ip</span>
              </span>
            }
          >
            <div className="chart">
              {scores.loading ? <Skeleton h={260} /> : (scores.data || []).length === 0
                ? <div className="chart-empty">No scored windows in range — run the detection model first</div>
                : <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={scores.data}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                      <XAxis dataKey="timestamp" hide />
                      <YAxis domain={[0, 1]} tick={{ fill: "var(--muted)", fontSize: 11 }} />
                      <Tooltip content={<ChartTip />} />
                      <Line type="monotone" dataKey="anomaly_score"        stroke={C.score} dot={false} strokeWidth={2} name="Anomaly" />
                      <Line type="monotone" dataKey="rf_attack_probability" stroke={C.rf}   dot={false} strokeWidth={2} name="RF Prob" />
                      <ReferenceLine y={0.7} stroke="var(--orange)" strokeDasharray="4 3" label={{ value: "0.7 threshold", fill: "var(--orange)", fontSize: 10, position: "insideTopLeft" }} />
                      {(mitEvents.data || []).map(m => {
                        const scoreRows = scores.data || [];
                        const closest = scoreRows.reduce((best, row) => {
                          const d = Math.abs(new Date(row.timestamp) - new Date(m.timestamp));
                          return d < best.d ? { d, ts: row.timestamp } : best;
                        }, { d: Infinity, ts: null });
                        if (!closest.ts) return null;
                        const color = RULE_COLOR[m.rule_type] || "var(--red)";
                        return (
                          <ReferenceLine
                            key={m.mitigation_id}
                            x={closest.ts}
                            stroke={color}
                            strokeOpacity={0.75}
                            strokeWidth={1.5}
                            strokeDasharray="3 3"
                          />
                        );
                      })}
                    </LineChart>
                  </ResponsiveContainer>}
            </div>
          </Card>

          <Card title="Predicted Attack Types">
            <div className="chart">
              {types.loading ? <Skeleton h={260} /> : (types.data || []).length === 0
                ? <div className="chart-empty">No attack classifications yet</div>
                : <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={types.data} dataKey="count" nameKey="type"
                           outerRadius={110} innerRadius={52} paddingAngle={3}
                           label={({ name, percent }) => `${(percent * 100).toFixed(0)}%`}
                           labelLine={false}>
                        {(types.data || []).map((_, i) => (
                          <Cell key={i} fill={C.pie[i % C.pie.length]} />
                        ))}
                      </Pie>
                      <Tooltip content={<ChartTip />} />
                      <Legend
                        formatter={v => TYPE_LABEL[v] || v}
                        wrapperStyle={{ fontSize: 12, color: "var(--ink-dim)" }}
                      />
                    </PieChart>
                  </ResponsiveContainer>}
            </div>
          </Card>
        </div>

        {/* ── Dataset 2: Mitigation Actions ── */}
        <SectionLabel
          icon="🛡"
          title="Dataset 2 — Mitigation Response Layer"
          subtitle="Actions automatically executed by the mitigation engine at each flagged timestamp — rate limiting, port blocks, and IP drops"
        />
        <Card title="Mitigation Actions Timeline">
          <MitigationTimeline
            events={mitEvents.data}
            loading={mitEvents.loading}
            hasMore={mitEvents.hasMore}
            loadingMore={mitEvents.loadingMore}
            onLoadMore={mitEvents.loadMore}
          />
        </Card>

        {/* ── Alerts ── */}
        <div style={{ marginBottom: 16 }}>
        <Card
            title="Recent Alerts"
            action={
              <button className="btn btn--outline" type="button" onClick={() => downloadAlertsCsv()}>
                Export CSV
              </button>
            }
          >
            {alerts.loading
              ? <>{[0,1,2,3].map(i => <Skeleton key={i} h={34} mb={4} />)}</>
              : <InfiniteTableWrap hasMore={alerts.hasMore} loadingMore={alerts.loadingMore} onLoadMore={alerts.loadMore}>
                  <table>
                    <thead>
                      <tr><th>Time</th><th>Type</th><th>Severity</th><th>Score</th><th>Source IPs</th></tr>
                    </thead>
                    <tbody>
                      {(alerts.data || []).map(a => {
                        let srcIps = [];
                        try { srcIps = JSON.parse(a.source_ips || "[]"); } catch {}
                        return (
                          <tr key={a.alert_id}>
                            <td className="mono">{a.timestamp?.slice(11, 19)}</td>
                            <td><TypeBadge v={a.alert_type} /></td>
                            <td><SeverityBadge v={a.severity} /></td>
                            <td className="mono">{Number(a.anomaly_score).toFixed(3)}</td>
                            <td className="mono src-ips">
                              {srcIps.slice(0, 3).map(srcIp => {
                                const listed = (blacklist.ips || []).includes(srcIp);
                                return (
                                  <button
                                    key={srcIp}
                                    className={`src-ip-action${listed ? " src-ip-action--listed" : ""}`}
                                    onClick={() => !listed && blacklistIp(srcIp, a.window_id)}
                                    disabled={listed}
                                    title={listed ? "Already blacklisted" : `Blacklist ${srcIp}`}
                                  >
                                    {srcIp}{listed ? "" : " + blacklist"}
                                  </button>
                                );
                              })}
                              {srcIps.length > 3 && <span style={{ color: "var(--muted)" }}> +{srcIps.length - 3}</span>}
                              {!srcIps.length && <span style={{ color: "var(--muted)" }}>—</span>}
                            </td>
                          </tr>
                        );
                      })}
                      {!(alerts.data || []).length && (
                        <tr><td colSpan={5} className="td-empty">No alerts yet</td></tr>
                      )}
                    </tbody>
                  </table>
                </InfiniteTableWrap>}
          </Card>
        </div>

        {/* ── IP Lists ── */}
        <div className="grid two">
          <ListManager title="Whitelist" endpoint="whitelist" state={whitelist} setState={setWhitelist} onError={setIpListError} onSuccess={async () => { await loadIpLists(); setDataRefreshKey(x => x + 1); }} />
          <ListManager title="Blacklist" endpoint="blacklist" state={blacklist} setState={setBlacklist} blacklist onError={setIpListError} onSuccess={async () => { await loadIpLists(); setDataRefreshKey(x => x + 1); }} />
        </div>

        {/* ── Notifications ── */}
        <div className="grid two">
          <Card title="Notification Cooldown">
            <div className={`cooldown-box cooldown-box--${cool.data?.status || "idle"}`}>
              {cool.data?.status === "in_cooldown"
                ? `⏱ Cooldown — ${cool.data.alert_type}: ${cool.data.seconds}s remaining`
                : cool.data?.status === "ready"
                ? `✓ Ready — last type: ${cool.data.alert_type}`
                : "No notifications triggered yet"}
            </div>
            <BrowserNotify onTest={pushManualNotification} />
          </Card>

          <Card title="Notification History">
            <ul className="history">
              {(notif.data || []).slice().reverse().slice(0, 15).map((n, i) => (
                <li key={`${n.timestamp}-${i}`}>
                  <TypeBadge v={n.alert_type} />
                  <span className={`channel-tag channel-tag--${n.channel || "local"}`}>{n.channel || "local"}</span>
                  <span className="mono">{n.timestamp?.slice(11, 19)}</span>
                  <span className={`notify-status ${(n.status === "queued" || n.status === "success") ? "notify-status--ok" : "notify-status--err"}`}>{n.status}</span>
                </li>
              ))}
              {!notif.data?.length && (
                <li style={{ color: "var(--muted)" }}>No notification history yet.</li>
              )}
            </ul>
          </Card>
        </div>

      </main>
    </>
  );
}

createRoot(document.getElementById("root")).render(<App />);
