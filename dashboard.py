"""
🛡️  DDoS Mitigation Dashboard — Sub-Project D
Non-event driven dashboard that reads from:
  1. State Store (data/ folder) — baseline, windows, anomaly scores, alerts, rules
  2. Mitigation Service (C) — current rules and whitelist/blacklist
  3. Baseline Service (A) — baseline statistics
  4. Detection Service (B) — anomaly detection scores
  5. Local JSON files — configuration and user edits

Implements: D.1-D.9
Frameworks: Plotly Dash (Python, reactive callbacks)
Deploy: Docker container with mounted data volume
"""

from dotenv import load_dotenv
load_dotenv()

import dash
from dash import dcc, html, callback, Input, Output, State, ALL, ctx
from dash import dash_table
import plotly.graph_objects as go
import pandas as pd
import numpy as np
import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import threading
import time
import requests
import logging
import ipaddress
from notifier import notification_manager

# ============= LOGGING SETUP =============
Path("logs").mkdir(exist_ok=True)

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.getenv("LOG_FILE", "logs/dashboard.log")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# ============= CONFIG =============
DATA_DIR = os.getenv("DATA_DIR", "data")
SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "")
MITIGATION_SERVICE_URL = os.getenv("MITIGATION_SERVICE_URL", "http://localhost:5001")
BASELINE_SERVICE_URL = os.getenv("BASELINE_SERVICE_URL", "http://localhost:5002")
DETECTION_SERVICE_URL = os.getenv("DETECTION_SERVICE_URL", "http://localhost:5003")
DEBUG = os.getenv("DASH_DEBUG", "True").lower() == "true"
ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", "0.70"))
REFRESH_INTERVAL_SEC = int(os.getenv("REFRESH_INTERVAL_SEC", "5"))
PORT = int(os.getenv("DASH_PORT", os.getenv("PORT", "8050")))

# Ensure data directory exists
Path(DATA_DIR).mkdir(exist_ok=True)

print(f"🛡️  DDoS Dashboard starting...")
print(f"   DATA_DIR: {DATA_DIR}")
print(f"   MITIGATION_SERVICE: {MITIGATION_SERVICE_URL}")
print(f"   BASELINE_SERVICE: {BASELINE_SERVICE_URL}")
print(f"   DETECTION_SERVICE: {DETECTION_SERVICE_URL}")
print(f"   ANOMALY_THRESHOLD: {ANOMALY_THRESHOLD}")

# ============= STATE MANAGEMENT (Non-Event Driven) =============
"""
Instead of event-driven callbacks, we:
1. Load all state from disk at startup
2. Update state in memory at fixed intervals
3. Write back only whitelist/blacklist changes
4. Dashboard polls services for real-time data
"""

class DashboardState:
    """Central state manager - loads from disk and services"""
    
    def __init__(self):
        self.windows_df = None
        self.scores_df = None
        self.rules_log = {"rules": []}
        self.alerts_log = {"alerts": []}
        self.sent_alerts = set()
        self.whitelist = {"ips": []}
        self.blacklist = {"ips": []}
        self.baseline_data = {}
        self.detection_data = {}
        self.mitigation_data = {}
        self.last_load_time = None
        self._sqlite_missing_tables_warned = False
        self.load_all()
    
    def load_all(self):
        """Load all state from disk at once"""
        try:
            sqlite_loaded = self._load_sqlite_state()

            # Load traffic windows (from A)
            if not sqlite_loaded and os.path.exists(f"{DATA_DIR}/all_windows.parquet"):
                self.windows_df = pd.read_parquet(f"{DATA_DIR}/all_windows.parquet")
                if 'timestamp' in self.windows_df.columns:
                    self.windows_df['timestamp'] = pd.to_datetime(self.windows_df['timestamp'])
                logger.info(f"✅ Loaded {len(self.windows_df)} traffic windows from A")
            
            # Load anomaly scores (from B)
            if not sqlite_loaded and os.path.exists(f"{DATA_DIR}/anomaly_scores.parquet"):
                self.scores_df = pd.read_parquet(f"{DATA_DIR}/anomaly_scores.parquet")
                if 'timestamp' in self.scores_df.columns:
                    self.scores_df['timestamp'] = pd.to_datetime(self.scores_df['timestamp'])
                logger.info(f"✅ Loaded {len(self.scores_df)} anomaly scores from B")
            
            # Load logs (from C)
            if not sqlite_loaded and os.path.exists(f"{DATA_DIR}/rules_log.json"):
                with open(f"{DATA_DIR}/rules_log.json") as f:
                    self.rules_log = json.load(f)
                logger.info(f"✅ Loaded {len(self.rules_log.get('rules', []))} rules from C")
            
            if not sqlite_loaded and os.path.exists(f"{DATA_DIR}/alerts_log.json"):
                with open(f"{DATA_DIR}/alerts_log.json") as f:
                    self.alerts_log = json.load(f)
                logger.info(f"✅ Loaded {len(self.alerts_log.get('alerts', []))} alerts from C")
            
            # Load whitelist/blacklist (D manages)
            if os.path.exists(f"{DATA_DIR}/whitelist.json"):
                with open(f"{DATA_DIR}/whitelist.json") as f:
                    self.whitelist = json.load(f)
            else:
                self._save_whitelist()
            
            if os.path.exists(f"{DATA_DIR}/blacklist.json"):
                with open(f"{DATA_DIR}/blacklist.json") as f:
                    self.blacklist = json.load(f)
            else:
                self._save_blacklist()
            
            self.last_load_time = datetime.now()
            
        except Exception as e:
            logger.error(f"❌ Error loading state: {e}")

    def _load_sqlite_state(self):
        """Load pipeline outputs directly from SQLite when available."""
        if not SQLITE_DB_PATH or not os.path.exists(SQLITE_DB_PATH):
            return False

        conn = sqlite3.connect(SQLITE_DB_PATH)
        try:
            tables = pd.read_sql_query(
                "SELECT name FROM sqlite_master WHERE type = 'table'",
                conn,
            )
            table_names = set(tables["name"].tolist())
            required_tables = {
                "traffic_windows",
                "window_anomaly_scores",
                "active_alerts",
                "active_mitigations",
            }
            missing_tables = sorted(required_tables - table_names)
            if missing_tables:
                if not self._sqlite_missing_tables_warned:
                    logger.warning(
                        "SQLite DB is not initialized yet; run the pipeline first. Missing tables: %s",
                        ", ".join(missing_tables),
                    )
                    self._sqlite_missing_tables_warned = True
                return False

            windows = pd.read_sql_query(
                """
                SELECT
                    window_id,
                    datetime(ts, 'unixepoch') AS timestamp,
                    pkt_s AS pkt_count,
                    bytes_s AS byte_count,
                    unique_src_ips AS src_ip_unique,
                    COALESCE(unique_dst_ips, 0) AS dst_port_unique,
                    COALESCE(proto_tcp_frac, 0.0) * 100.0 AS tcp_pct,
                    COALESCE(proto_udp_frac, 0.0) * 100.0 AS udp_pct,
                    COALESCE(proto_icmp_frac, 0.0) * 100.0 AS icmp_pct,
                    top_src_ip,
                    top_dst_port,
                    label,
                    label_detail
                FROM traffic_windows
                ORDER BY ts, window_id
                """,
                conn,
            )
            scores = pd.read_sql_query(
                """
                SELECT
                    tw.window_id,
                    datetime(tw.ts, 'unixepoch') AS timestamp,
                    was.anomaly_score,
                    was.statistical_score,
                    was.rf_attack_probability,
                    was.predicted_attack_type,
                    was.attack_type_confidence,
                    was.triggered_features,
                    was.explanation
                FROM traffic_windows tw
                JOIN window_anomaly_scores was ON was.window_id = tw.window_id
                ORDER BY tw.ts, tw.window_id
                """,
                conn,
            )
            alerts = pd.read_sql_query(
                """
                SELECT
                    alert_id,
                    datetime(created_at, 'unixepoch') AS timestamp,
                    alert_type AS type,
                    severity,
                    anomaly_score,
                    description,
                    source_ips,
                    triggered_features
                FROM active_alerts
                ORDER BY created_at, alert_id
                """,
                conn,
            )
            rules = pd.read_sql_query(
                """
                SELECT
                    mitigation_id,
                    datetime(applied_at, 'unixepoch') AS timestamp,
                    rule_type,
                    target AS target_ip,
                    iptables_cmd AS action,
                    1.0 AS confidence,
                    notes
                FROM active_mitigations
                ORDER BY applied_at, mitigation_id
                """,
                conn,
            )
        finally:
            conn.close()

        if len(windows) == 0:
            return False

        windows["timestamp"] = pd.to_datetime(windows["timestamp"])
        if len(scores) > 0:
            scores["timestamp"] = pd.to_datetime(scores["timestamp"])
        if len(alerts) > 0:
            alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])
        if len(rules) > 0:
            rules["timestamp"] = pd.to_datetime(rules["timestamp"])

        self.windows_df = windows
        self.scores_df = scores
        self.alerts_log = {"alerts": alerts.to_dict("records")}
        self.rules_log = {"rules": rules.to_dict("records")}
        self._sqlite_missing_tables_warned = False
        logger.info(
            "✅ Loaded SQLite pipeline state: %s windows, %s scores, %s alerts, %s rules",
            len(windows),
            len(scores),
            len(alerts),
            len(rules),
        )
        return True
    
    def reload_if_changed(self):
        """Reload files from disk (called periodically)"""
        try:
            self.load_all()
        except Exception as e:
            logger.error(f"❌ Error reloading state: {e}")
    
    def query_baseline_service(self):
        """Query baseline service (A) for baseline statistics"""
        try:
            response = requests.get(f"{BASELINE_SERVICE_URL}/api/baseline", timeout=2)
            if response.status_code == 200:
                self.baseline_data = response.json()
                logger.info(f"✅ Got baseline from service A")
                return self.baseline_data
        except requests.exceptions.RequestException as e:
            logger.debug(f"⚠️  Cannot reach baseline service A: {e}")
        return {}
    
    def query_detection_service(self):
        """Query detection service (B) for real-time anomaly scores"""
        try:
            response = requests.get(f"{DETECTION_SERVICE_URL}/api/scores/latest", timeout=2)
            if response.status_code == 200:
                self.detection_data = response.json()
                logger.info(f"✅ Got detection data from service B")
                return self.detection_data
        except requests.exceptions.RequestException as e:
            logger.debug(f"⚠️  Cannot reach detection service B: {e}")
        return {}
    
    def query_mitigation_service(self):
        """Query mitigation service (C) for active rules"""
        try:
            response = requests.get(f"{MITIGATION_SERVICE_URL}/api/rules", timeout=2)
            if response.status_code == 200:
                self.mitigation_data = response.json()
                logger.info(f"✅ Got rules from service C")
                return self.mitigation_data
        except requests.exceptions.RequestException as e:
            logger.debug(f"⚠️  Cannot reach mitigation service C: {e}")
        return {}
    
    def _save_whitelist(self):
        """Write whitelist to disk"""
        self.whitelist['last_updated'] = datetime.now().isoformat()
        with open(f"{DATA_DIR}/whitelist.json", 'w') as f:
            json.dump(self.whitelist, f, indent=2)
        logger.info("💾 Whitelist saved")
    
    def _save_blacklist(self):
        """Write blacklist to disk"""
        self.blacklist['last_updated'] = datetime.now().isoformat()
        with open(f"{DATA_DIR}/blacklist.json", 'w') as f:
            json.dump(self.blacklist, f, indent=2)
        logger.info("💾 Blacklist saved")
    
    def add_to_whitelist(self, ip):
        """Add IP to whitelist"""
        if ip not in self.whitelist.get('ips', []):
            self.whitelist['ips'].append(ip)
            self._save_whitelist()
            logger.info(f"✅ Added {ip} to whitelist")
    
    def remove_from_whitelist(self, ip):
        """Remove IP from whitelist"""
        if ip in self.whitelist.get('ips', []):
            self.whitelist['ips'].remove(ip)
            self._save_whitelist()
            logger.info(f"✅ Removed {ip} from whitelist")
    
    def add_to_blacklist(self, ip):
        """Add IP to blacklist"""
        if ip not in self.blacklist.get('ips', []):
            self.blacklist['ips'].append(ip)
            self._save_blacklist()
            logger.info(f"✅ Added {ip} to blacklist")
    
    def remove_from_blacklist(self, ip):
        """Remove IP from blacklist"""
        if ip in self.blacklist.get('ips', []):
            self.blacklist['ips'].remove(ip)
            self._save_blacklist()
            logger.info(f"✅ Removed {ip} from blacklist")

# Initialize state manager (loads at startup)
state = DashboardState()

# ============= BACKGROUND THREAD: Periodic State Reload =============
"""
This thread reloads state from disk every REFRESH_INTERVAL_SEC seconds
Non-blocking, doesn't interfere with dashboard
Also queries services A, B, C for real-time data
"""

def background_state_reloader():
    """Runs in background, reloads state periodically and queries services"""
    while True:
        time.sleep(REFRESH_INTERVAL_SEC)
        state.reload_if_changed()
        state.query_baseline_service()
        state.query_detection_service()
        state.query_mitigation_service()

# Start background thread (daemon = stops when app stops)
reloader_thread = threading.Thread(target=background_state_reloader, daemon=True)
reloader_thread.start()

# ============= HELPER FUNCTIONS =============

def check_service_health(url):
    """Check if a service is responding"""
    try:
        response = requests.get(url, timeout=2)
        return response.status_code == 200
    except:
        return False

def generate_whitelist_table():
    """Generate whitelist table (D.4)"""
    data = [{"ip": ip, "action": "❌"} for ip in state.whitelist.get('ips', [])]
    
    return dash_table.DataTable(
        id='whitelist-table',
        columns=[
            {"name": "IP Address", "id": "ip"},
            {"name": "Remove", "id": "action"},
        ],
        data=data,
        style_cell={'padding': '8px'},
        style_header={'fontWeight': 'bold', 'background': '#e8f5e9'},
        editable=False,
        page_size=3,
    ) if data else html.Div(
        "No IPs in whitelist",
        style={"color": "#666", "padding": "10px"}
    )

def generate_blacklist_table():
    """Generate blacklist table (D.4)"""
    data = [{"ip": ip, "action": "❌"} for ip in state.blacklist.get('ips', [])]
    
    return dash_table.DataTable(
        id='blacklist-table',
        columns=[
            {"name": "IP Address", "id": "ip"},
            {"name": "Remove", "id": "action"},
        ],
        data=data,
        style_cell={'padding': '8px'},
        style_header={'fontWeight': 'bold', 'background': '#ffebee'},
        editable=False,
        page_size=3,
    ) if data else html.Div(
        "No IPs in blacklist",
        style={"color": "#666", "padding": "10px"}
    )

# ============= INITIALIZE DASH APP =============
app = dash.Dash(__name__)
app.title = "DDoS Mitigation Dashboard — Team 059"

# ============= LAYOUT =============
app.layout = html.Div([
    # Hidden stores for state
    dcc.Store(id='state-store', data={'last_update': datetime.now().isoformat()}),
    dcc.Interval(id='interval-state-update', interval=REFRESH_INTERVAL_SEC * 1000, n_intervals=0),
    dcc.Download(id='download-alerts'),
    
    # Header
    html.Div([
        html.Div([
            html.H1("🛡️ DDoS Mitigation Dashboard", style={"margin": 0, "color": "#1f77b4"}),
            html.P("Team 059 — Real-time network anomaly detection and mitigation control", 
                   style={"color": "#666", "marginTop": 5, "fontSize": "14px"})
        ]),
        html.Div([
            html.Small("Sub-Project D: Dashboard & Alerts (D.1-D.9)", style={"color": "#999"}),
        ], style={"textAlign": "right"})
    ], style={
        "display": "flex",
        "justifyContent": "space-between",
        "padding": "20px 30px",
        "background": "#f8f9fa",
        "borderBottom": "2px solid #1f77b4",
        "marginBottom": 30
    }),
    
    # Main container
    html.Div([
        # ===== STATUS BANNER =====
        html.Div([
            html.Div([
                html.Span("📊 Data Status: ", style={"fontWeight": "bold"}),
                html.Span(id='data-status', style={"color": "#28a745"}),
            ], style={"padding": "10px", "background": "#e8f5e9", "borderRadius": "4px", "marginBottom": "10px"}),

            html.Div([
                html.Span("⏱️ System Status: ", style={"fontWeight": "bold"}),
                html.Span(id='system-status', style={"color": "#1f77b4"}),
            ], style={"padding": "10px", "background": "#e3f2fd", "borderRadius": "4px"}),
        ], style={"marginBottom": 20}),
        
        # ===== TIME SLIDER (D.2) =====
        html.Div([
            html.Label("📅 Time Range Selection (D.2):", style={"fontWeight": "bold", "fontSize": "14px"}),
            dcc.RangeSlider(
                id='time-slider',
                min=0,
                max=max(len(state.windows_df) - 1, 0) if state.windows_df is not None else 0,
                value=[0, max(len(state.windows_df) - 1, 0)] if state.windows_df is not None else [0, 0],
                marks={
                    0: "Start",
                    max(len(state.windows_df) // 2, 1): "Mid" if state.windows_df is not None else "",
                    max(len(state.windows_df) - 1, 0): "End"
                } if state.windows_df is not None else {},
                tooltip={"placement": "bottom", "always_visible": True},
                step=1,
            ),
            html.Div(id='time-range-display', style={"marginTop": 10, "color": "#666", "fontSize": "12px"})
        ], style={
            "padding": "20px",
            "background": "#f0f0f0",
            "borderRadius": "8px",
            "marginBottom": 30
        }),
        
        # ===== NETWORK STATISTICS GRAPHS (D.1) =====
        html.Div([
            html.H3("📊 Network Statistics (D.1)", style={"marginBottom": 15}),
            html.Div([
                dcc.Graph(id='packets-graph'),
                dcc.Graph(id='bytes-graph'),
            ], style={"display": "flex", "gap": "20px", "marginBottom": 20}),
            
            html.Div([
                dcc.Graph(id='src-ips-graph'),
                dcc.Graph(id='dst-ports-graph'),
            ], style={"display": "flex", "gap": "20px", "marginBottom": 20}),
            
            html.Div([
                dcc.Graph(id='protocol-distribution-graph'),
            ], style={"marginBottom": 20}),
        ], style={
            "padding": "20px",
            "background": "white",
            "borderRadius": "8px",
            "border": "1px solid #e0e0e0",
            "marginBottom": 30
        }),
        
        # ===== ANOMALY SCORE GRAPH (D.3) =====
        html.Div([
            html.H3("🚨 Anomaly Detection Score (D.3)", style={"marginBottom": 15}),
            dcc.Graph(id='anomaly-graph'),
            html.P("Red zones = anomaly detected (score > threshold)", style={"color": "#d62728", "fontSize": "12px"})
        ], style={
            "padding": "20px",
            "background": "white",
            "borderRadius": "8px",
            "border": "1px solid #e0e0e0",
            "marginBottom": 30
        }),
        
        # ===== ALERTS SECTION (D.5) & NOTIFICATIONS (D.7-D.9) =====
        html.Div([
            html.H3("📢 Detected Alerts (D.5) & Notifications (D.7-D.9)", style={"marginBottom": 15}),
            
            html.Div([
                html.Div(id='alerts-list', style={
                    "flex": 1,
                    "overflowY": "auto",
                    "maxHeight": "300px",
                    "borderRight": "1px solid #e0e0e0",
                    "paddingRight": 15,
                    "marginBottom": "20px"
                }),
                html.Div(id='alert-drill-down', style={
                    "flex": 1,
                    "paddingLeft": 15
                }),
            ], style={"display": "flex", "gap": "20px", "marginBottom": 15}),

            # Cool-down status (D.9)
            html.Div(id='cooldown-status', style={
                "marginBottom": "10px",
                "padding": "10px",
                "background": "#e3f2fd",
                "borderRadius": "4px",
                "fontSize": "12px",
                "color": "#1f77b4"
            }),

            # Export button
            html.Button(
                "📥 Export Alerts CSV",
                id="export-alerts-btn",
                n_clicks=0,
                style={
                    "padding": "8px 12px",
                    "background": "#1f77b4",
                    "color": "white",
                    "border": "none",
                    "borderRadius": "4px",
                    "cursor": "pointer",
                    "marginRight": "10px"
                }
            ),

            # Notification history (D.7-D.9)
            html.Div([
                html.H4("📧 Notification History (D.7-D.9)", style={"marginTop": "15px", "marginBottom": "10px"}),
                html.Div(id='notification-history', style={
                    "overflowY": "auto",
                    "maxHeight": "200px",
                    "background": "#f9f9f9",
                    "padding": "10px",
                    "borderRadius": "4px",
                    "fontSize": "11px"
                })
            ]),

        ], style={
            "padding": "20px",
            "background": "#fff3cd",
            "borderRadius": "8px",
            "border": "1px solid #ffc107",
            "marginBottom": 30
        }),
        
        # ===== MITIGATION RULES (from Service C) =====
        html.Div([
            html.H3("🔧 Applied Mitigation Rules (from C)", style={"marginBottom": 15}),
            html.Div(id='rules-container', style={"minHeight": "100px"}),
        ], style={
            "padding": "20px",
            "background": "white",
            "borderRadius": "8px",
            "border": "1px solid #e0e0e0",
            "marginBottom": 30
        }),
        
        # ===== IP MANAGEMENT (D.4) =====
        html.Div([
            html.H3("⚡ Trusted IP Management (D.4)", style={"marginBottom": 15}),
            html.Div([
                # Whitelist
                html.Div([
                    html.H4("✅ Whitelist (Never Rate-Limited)", style={"color": "#28a745"}),
                    html.P("Add trusted IPs that should never be blocked:", style={"color": "#666", "fontSize": "12px"}),
                    html.Div([
                        dcc.Input(
                            id='whitelist-input',
                            type='text',
                            placeholder='Enter IP (e.g., 10.0.0.1)',
                            style={"flex": 1, "padding": "8px", "borderRadius": "4px", "border": "1px solid #ddd"}
                        ),
                        html.Button(
                            'Add',
                            id='whitelist-add-btn',
                            n_clicks=0,
                            style={
                                "padding": "8px 16px",
                                "marginLeft": 10,
                                "background": "#28a745",
                                "color": "white",
                                "border": "none",
                                "borderRadius": "4px",
                                "cursor": "pointer"
                            }
                        ),
                    ], style={"display": "flex", "gap": "10px", "marginBottom": 10}),
                    
                    html.Div(
                        id='whitelist-table-container',
                        children=generate_whitelist_table(),
                        style={"marginBottom": 20}
                    ),
                ], style={"flex": 1, "marginRight": 15}),
                
                # Blacklist
                html.Div([
                    html.H4("❌ Blacklist (Always Block)", style={"color": "#dc3545"}),
                    html.P("Add malicious IPs to permanently block:", style={"color": "#666", "fontSize": "12px"}),
                    html.Div([
                        dcc.Input(
                            id='blacklist-input',
                            type='text',
                            placeholder='Enter IP (e.g., 192.168.1.50)',
                            style={"flex": 1, "padding": "8px", "borderRadius": "4px", "border": "1px solid #ddd"}
                        ),
                        html.Button(
                            'Add',
                            id='blacklist-add-btn',
                            n_clicks=0,
                            style={
                                "padding": "8px 16px",
                                "marginLeft": 10,
                                "background": "#dc3545",
                                "color": "white",
                                "border": "none",
                                "borderRadius": "4px",
                                "cursor": "pointer"
                            }
                        ),
                    ], style={"display": "flex", "gap": "10px", "marginBottom": 10}),
                    
                    html.Div(
                        id='blacklist-table-container',
                        children=generate_blacklist_table()
                    ),
                ], style={"flex": 1}),
            ], style={"display": "flex", "gap": "30px"}),
        ], style={
            "padding": "20px",
            "background": "#f8f9fa",
            "borderRadius": "8px",
            "border": "1px solid #dee2e6",
            "marginBottom": 30
        }),
        
    ], style={"padding": "0 30px", "maxWidth": "1600px", "margin": "0 auto"})
    
], style={"minHeight": "100vh", "background": "#f5f5f5", "fontFamily": "Arial, sans-serif"})

# ============= CALLBACKS =============

MAX_GRAPH_POINTS = int(os.getenv("MAX_GRAPH_POINTS", "2500"))
MAX_ALERT_HIGHLIGHTS = int(os.getenv("MAX_ALERT_HIGHLIGHTS", "200"))

def downsample_for_plot(df, max_points=MAX_GRAPH_POINTS):
    """Keep browser payloads small while preserving the selected range shape."""
    if df is None or len(df) <= max_points:
        return df

    step = max(len(df) // max_points, 1)
    return df.iloc[::step].copy()

# Periodic state refresh trigger
@callback(
    Output('state-store', 'data'),
    Input('interval-state-update', 'n_intervals'),
    prevent_initial_call=False
)
def update_state_periodic(n):
    """Called every REFRESH_INTERVAL_SEC to trigger data reload"""
    return {'last_update': datetime.now().isoformat(), 'n_intervals': n}

# Update time slider range dynamically
@callback(
    [Output('time-slider', 'max'),
     Output('time-slider', 'value'),
     Output('time-slider', 'marks')],
    Input('state-store', 'data')
)
def refresh_slider(store_data):
    """Update slider when data changes"""
    if state.windows_df is None or len(state.windows_df) == 0:
        return 0, [0, 0], {}

    max_idx = len(state.windows_df) - 1
    marks = {
        0: "Start",
        max(max_idx // 2, 1): "Mid",
        max_idx: "End"
    }

    return max_idx, [0, max_idx], marks

# Data status display
@callback(
    Output('data-status', 'children'),
    Input('state-store', 'data')
)
def update_data_status(store_data):
    """Display data loading status"""
    if state.windows_df is None or len(state.windows_df) == 0:
        return "⚠️  No data loaded"
    
    last_ts = state.windows_df['timestamp'].iloc[-1] if 'timestamp' in state.windows_df.columns else None
    num_alerts = len(state.alerts_log.get('alerts', []))
    
    return f"✅ {len(state.windows_df)} windows | {num_alerts} alerts | Last: {last_ts.strftime('%H:%M:%S') if last_ts else 'N/A'}"

# System status display (services A, B, C health)
@callback(
    Output('system-status', 'children'),
    Input('state-store', 'data')
)
def update_system_status(data):
    """Show system health status for all services"""
    try:
        baseline_ok = check_service_health(f"{BASELINE_SERVICE_URL}/api/baseline")
        detection_ok = check_service_health(f"{DETECTION_SERVICE_URL}/api/scores/latest")
        mitigation_ok = check_service_health(f"{MITIGATION_SERVICE_URL}/api/rules")
        
        all_ok = baseline_ok and detection_ok and mitigation_ok
        
        status = []
        status.append(f"A: {'✅' if baseline_ok else '⚠️'}")
        status.append(f"B: {'✅' if detection_ok else '⚠️'}")
        status.append(f"C: {'✅' if mitigation_ok else '⚠️'}")
        
        color = "#28a745" if all_ok else "#ff9800"
        return html.Span(" | ".join(status), style={"color": color})
    except:
        return "⚠️  Unable to determine status"

# D.2: Time slider display
@callback(
    Output('time-range-display', 'children'),
    Input('time-slider', 'value')
)
def update_time_display(slider_range):
    """Show time range selected by slider"""
    if state.windows_df is None or len(state.windows_df) == 0:
        return "No data loaded"

    if not slider_range or len(slider_range) != 2:
        return "Invalid time range"

    start_idx, end_idx = sorted(slider_range)
    
    # Clamp to valid range
    start_idx = max(0, min(start_idx, len(state.windows_df) - 1))
    end_idx = max(0, min(end_idx, len(state.windows_df) - 1))

    start_ts = state.windows_df.iloc[start_idx]['timestamp']
    end_ts = state.windows_df.iloc[end_idx]['timestamp']
    duration_min = (end_ts - start_ts).total_seconds() / 60

    return f"📍 {start_ts.strftime('%H:%M:%S')} → {end_ts.strftime('%H:%M:%S')} ({duration_min:.1f} min)"

# D.1 + D.3: All graphs update on time slider change
@callback(
    [Output('packets-graph', 'figure'),
     Output('bytes-graph', 'figure'),
     Output('src-ips-graph', 'figure'),
     Output('dst-ports-graph', 'figure'),
     Output('protocol-distribution-graph', 'figure'),
     Output('anomaly-graph', 'figure'),
     Output('alerts-list', 'children'),
     Output('rules-container', 'children')],
    Input('time-slider', 'value')
)
def update_all_graphs(slider_range):
    """Update all graphs based on time slider (D.1, D.2, D.3)"""
    if state.windows_df is None or len(state.windows_df) == 0:
        empty_fig = go.Figure().add_annotation(text="No data loaded")
        return empty_fig, empty_fig, empty_fig, empty_fig, empty_fig, empty_fig, [], []
    
    start_idx, end_idx = sorted(slider_range)
    df_slice = state.windows_df.iloc[start_idx:end_idx + 1].copy()
    scores_slice = state.scores_df.iloc[start_idx:end_idx + 1].copy() if state.scores_df is not None else None
    df_plot = downsample_for_plot(df_slice)
    scores_plot = downsample_for_plot(scores_slice)
    
    # ===== GRAPH 1: Packet count (D.1) =====
    fig1 = go.Figure()
    fig1.add_trace(go.Scatter(
        x=df_plot['timestamp'],
        y=df_plot.get('pkt_count', []),
        mode='lines',
        name='Packets/sec',
        line=dict(color='#1f77b4', width=2),
        fill='tozeroy',
        fillcolor='rgba(31, 119, 180, 0.2)'
    ))
    fig1.update_layout(
        title="Packet Rate Over Time",
        xaxis_title="Time",
        yaxis_title="Packets/sec",
        hovermode='x unified',
        height=350,
        margin=dict(l=50, r=20, t=40, b=40)
    )
    
    # ===== GRAPH 2: Byte count (D.1) =====
    fig2 = go.Figure()
    fig2.add_trace(go.Scatter(
        x=df_plot['timestamp'],
        y=df_plot.get('byte_count', []),
        mode='lines',
        name='Bytes/sec',
        line=dict(color='#ff7f0e', width=2),
        fill='tozeroy',
        fillcolor='rgba(255, 127, 14, 0.2)'
    ))
    fig2.update_layout(
        title="Byte Rate Over Time",
        xaxis_title="Time",
        yaxis_title="Bytes/sec",
        hovermode='x unified',
        height=350,
        margin=dict(l=50, r=20, t=40, b=40)
    )
    
    # ===== GRAPH 3: Unique source IPs (D.1) =====
    fig3 = go.Figure()
    fig3.add_trace(go.Scatter(
        x=df_plot['timestamp'],
        y=df_plot.get('src_ip_unique', []),
        mode='lines+markers',
        name='Unique Sources',
        line=dict(color='#2ca02c', width=2),
        marker=dict(size=5)
    ))
    fig3.update_layout(
        title="Source IP Diversity",
        xaxis_title="Time",
        yaxis_title="# Unique IPs",
        hovermode='x unified',
        height=350,
        margin=dict(l=50, r=20, t=40, b=40)
    )
    
    # ===== GRAPH 4: Destination ports (D.1) =====
    fig4 = go.Figure()
    fig4.add_trace(go.Scatter(
        x=df_plot['timestamp'],
        y=df_plot.get('dst_port_unique', []),
        mode='lines+markers',
        name='Unique Dest Ports',
        line=dict(color='#9467bd', width=2),
        marker=dict(size=5)
    ))
    fig4.update_layout(
        title="Destination Port Diversity",
        xaxis_title="Time",
        yaxis_title="# Unique Ports",
        hovermode='x unified',
        height=350,
        margin=dict(l=50, r=20, t=40, b=40)
    )
    
    # ===== GRAPH 5: Protocol distribution (D.1) =====
    fig5 = go.Figure()
    if 'tcp_pct' in df_plot.columns:
        fig5.add_trace(go.Scatter(
            x=df_plot['timestamp'],
            y=df_plot['tcp_pct'],
            mode='lines',
            name='TCP %',
            stackgroup='one',
            fillcolor='rgba(31, 119, 180, 0.5)'
        ))
    if 'udp_pct' in df_plot.columns:
        fig5.add_trace(go.Scatter(
            x=df_plot['timestamp'],
            y=df_plot['udp_pct'],
            mode='lines',
            name='UDP %',
            stackgroup='one',
            fillcolor='rgba(255, 127, 14, 0.5)'
        ))
    if 'icmp_pct' in df_plot.columns:
        fig5.add_trace(go.Scatter(
            x=df_plot['timestamp'],
            y=df_plot['icmp_pct'],
            mode='lines',
            name='ICMP %',
            stackgroup='one',
            fillcolor='rgba(44, 160, 44, 0.5)'
        ))
    fig5.update_layout(
        title="Protocol Distribution",
        xaxis_title="Time",
        yaxis_title="Percentage",
        hovermode='x unified',
        height=350,
        margin=dict(l=50, r=20, t=40, b=40)
    )
    
    # ===== GRAPH 6: Anomaly score with alerts (D.3) =====
    fig6 = go.Figure()
    if scores_plot is not None and len(scores_plot) > 0:
        fig6.add_trace(go.Scatter(
            x=scores_plot['timestamp'],
            y=scores_plot['anomaly_score'],
            mode='lines',
            name='Anomaly Score',
            line=dict(color='#d62728', width=2),
            fill='tozeroy',
            fillcolor='rgba(214, 39, 40, 0.2)'
        ))
        
        # Add threshold line
        fig6.add_hline(
            y=ANOMALY_THRESHOLD,
            line_dash="dash",
            line_color="red",
            annotation_text=f"Threshold ({ANOMALY_THRESHOLD})",
            annotation_position="right"
        )
        
        # Highlight alert windows (where score > threshold)
        alerts_in_range = scores_slice[scores_slice['anomaly_score'] > ANOMALY_THRESHOLD]
        alerts_in_range = downsample_for_plot(alerts_in_range, MAX_ALERT_HIGHLIGHTS)
        
        for idx, row in alerts_in_range.iterrows():
            # Find matching alert from alerts_log
            matching_alert = None
            for alert in state.alerts_log.get('alerts', []):
                alert_ts = pd.to_datetime(alert['timestamp'])
                if abs((alert_ts - row['timestamp']).total_seconds()) < 5:
                    matching_alert = alert
                    break
            
            if matching_alert:
                alert_id = matching_alert.get('alert_id', f'alert_{idx}')
                
                # Send notification (D.7, D.8, D.9)
                if alert_id not in state.sent_alerts:
                    state.sent_alerts.add(alert_id)
                    
                    ta_email = os.getenv('TA_EMAIL_ADDRESS', '')
                    channels = ['email'] if ta_email else ['local']
                    results = notification_manager.send_alert(
                        alert=matching_alert,
                        channels=channels,
                        ta_email=ta_email or None
                    )
                    logger.info(f"🔔 Notification queued for {alert_id}: {results}")
            
            # Add vertical rectangle to highlight alert
            fig6.add_vrect(
                x0=row['timestamp'],
                x1=row['timestamp'] + timedelta(seconds=5),
                opacity=0.2,
                fillcolor="red",
                layer="below",
                line_width=0
            )
    
    fig6.update_layout(
        title="Anomaly Score with Alert Windows (D.3)",
        xaxis_title="Time",
        yaxis_title="Score (0-1)",
        hovermode='x unified',
        height=400,
        margin=dict(l=50, r=20, t=40, b=40)
    )
    
    # ===== ALERTS LIST (D.5 - clickable) =====
    alerts_children = []
    for idx, alert in enumerate(state.alerts_log.get('alerts', [])):
        alert_ts = pd.to_datetime(alert['timestamp'])
        if df_slice['timestamp'].min() <= alert_ts <= df_slice['timestamp'].max():
            alerts_children.append(
                html.Div([
                    html.Div(
                        [
                            html.Strong(alert['alert_id']),
                            html.Span(f" • {alert_ts.strftime('%H:%M:%S')}", style={"color": "#666", "fontSize": "12px"}),
                        ],
                        id={'type': 'alert-item', 'index': idx},
                        n_clicks=0,
                        style={
                            "padding": "10px",
                            "background": "#fff3cd",
                            "border": "1px solid #ffc107",
                            "borderRadius": "4px",
                            "cursor": "pointer",
                            "marginBottom": 5,
                            "userSelect": "none"
                        }
                    ),
                ], style={"marginBottom": 5})
            )
    
    if not alerts_children:
        alerts_children = html.Div("No alerts in this time range", style={"color": "#666", "fontSize": "12px"})
    
    # ===== RULES TABLE (from mitigation service C) =====
    rules_data = []
    for rule in state.rules_log.get('rules', []):
        rule_ts = pd.to_datetime(rule['timestamp'])
        if df_slice['timestamp'].min() <= rule_ts <= df_slice['timestamp'].max():
            rules_data.append(rule)
    
    if rules_data:
        rules_table = dash_table.DataTable(
            columns=[
                {"name": "Timestamp", "id": "timestamp"},
                {"name": "Type", "id": "rule_type"},
                {"name": "Target IP", "id": "target_ip"},
                {"name": "Action", "id": "action"},
                {"name": "Confidence", "id": "confidence"},
            ],
            data=[{
                "timestamp": pd.to_datetime(r['timestamp']).strftime('%H:%M:%S'),
                "rule_type": r.get('rule_type', ''),
                "target_ip": r.get('target_ip', ''),
                "action": r.get('action', '')[:50] + "..." if len(str(r.get('action', ''))) > 50 else r.get('action', ''),
                "confidence": f"{r.get('confidence', 0):.2f}",
            } for r in rules_data],
            style_cell={'textAlign': 'left', 'fontSize': '12px'},
            style_header={'fontWeight': 'bold', 'background': '#f0f0f0'},
            page_size=5,
        )
    else:
        rules_table = html.Div("No mitigation rules in this time range", style={"color": "#666", "padding": "10px"})
    
    return fig1, fig2, fig3, fig4, fig5, fig6, alerts_children, rules_table

# D.5: Alert drill-down (click alert → show details)
@callback(
    Output('alert-drill-down', 'children'),
    Input({'type': 'alert-item', 'index': ALL}, 'n_clicks'),
    prevent_initial_call=True
)
def show_alert_details(n_clicks):
    """Show detailed alert information when clicked (D.5)"""
    if not n_clicks or sum(n_clicks) == 0:
        return "👈 Click an alert to see details"
    
    if not ctx.triggered:
        return "👈 Click an alert to see details"
    
    try:
        alert_idx = int(ctx.triggered[0]['prop_id'].split('"index":')[1].rstrip('}'))
    except:
        return "Error parsing alert"
    
    if alert_idx >= len(state.alerts_log.get('alerts', [])):
        return "Alert not found"
    
    alert = state.alerts_log['alerts'][alert_idx]
    alert_ts = pd.to_datetime(alert['timestamp'])
    
    return html.Div([
        html.H5(f"Alert #{alert['alert_id']}", style={"color": "#d62728"}),
        html.Div([
            html.P(f"⏱️  Timestamp: {alert_ts.strftime('%Y-%m-%d %H:%M:%S')}", style={"marginBottom": 5}),
            html.P(f"📊 Type: {alert.get('type', 'unknown').upper()}", style={"marginBottom": 5}),
            html.P(f"📈 Anomaly Score: {alert.get('anomaly_score', 0):.2f} / 1.00", style={
                "marginBottom": 5,
                "fontWeight": "bold",
                "color": "#d62728" if alert.get('anomaly_score', 0) > 0.7 else "#666"
            }),
            html.P(f"📝 Description:", style={"marginBottom": 5, "fontWeight": "bold"}),
            html.P(alert.get('description', 'No description'), style={
                "marginLeft": 15,
                "color": "#666",
                "fontSize": "12px",
                "lineHeight": "1.6"
            }),
        ])
    ], style={"padding": "10px", "background": "#fff9e6", "borderRadius": "4px"})

# D.9: Show cool-down status
@callback(
    Output('cooldown-status', 'children'),
    Input('state-store', 'data')
)
def show_cooldown_status(data):
    """Display D.9 notification cool-down status"""
    if not state.alerts_log.get('alerts'):
        return "ℹ️  No alerts to show cool-down status"
    
    last_alert = state.alerts_log['alerts'][-1]
    alert_type = last_alert.get('type', 'unknown')
    
    status = notification_manager.get_alert_status(alert_type)
    
    if status['status'] == 'in_cooldown':
        return f"⏳ Notification cool-down active for '{alert_type}': {status['seconds']} remaining (D.9)"
    elif status['status'] == 'ready':
        return f"✅ Ready to send new '{alert_type}' alert (D.9)"
    else:
        return "ℹ️  No notification history yet"

# D.7-D.9: Show notification history
@callback(
    Output('notification-history', 'children'),
    Input('state-store', 'data')
)
def show_notification_history(data):
    """Display notification history (D.7-D.9)"""
    history = notification_manager.get_notification_history()
    
    if not history:
        return html.Div("No notifications sent yet", style={"color": "#999"})
    
    items = []
    for notif in reversed(history[-10:]):
        status_emoji = "✅" if "success" in str(notif.get('status', '')) else "❌"
        items.append(
            html.Div([
                html.Span(f"{status_emoji} {notif['channel']} → {notif['recipient']}", style={"fontWeight": "bold"}),
                html.Span(f" ({notif.get('alert_type', 'unknown')})", style={"color": "#666"}),
                html.Span(f" at {notif['timestamp'][:19]}", style={"color": "#999", "fontSize": "11px"})
            ], style={"padding": "5px", "borderBottom": "1px solid #ddd", "fontSize": "11px"})
        )
    
    return html.Div(items) if items else html.Div("No notifications", style={"color": "#999"})

# D.4: Whitelist add IP
@callback(
    Output('whitelist-table-container', 'children'),
    Input('whitelist-add-btn', 'n_clicks'),
    State('whitelist-input', 'value'),
    prevent_initial_call=True
)
def add_whitelist_ip(n_clicks, ip_value):
    """Add IP to whitelist (D.4)"""
    if not ip_value:
        return generate_whitelist_table()

    try:
        ipaddress.ip_address(ip_value)
    except ValueError:
        return html.Div(
            "❌ Invalid IP address",
            style={"color": "red", "padding": "10px"}
        )

    state.add_to_whitelist(ip_value)
    return generate_whitelist_table()

# D.4: Blacklist add IP
@callback(
    Output('blacklist-table-container', 'children'),
    Input('blacklist-add-btn', 'n_clicks'),
    State('blacklist-input', 'value'),
    prevent_initial_call=True
)
def add_blacklist_ip(n_clicks, ip_value):
    """Add IP to blacklist (D.4)"""
    if not ip_value:
        return generate_blacklist_table()

    try:
        ipaddress.ip_address(ip_value)
    except ValueError:
        return html.Div(
            "❌ Invalid IP address",
            style={"color": "red", "padding": "10px"}
        )

    state.add_to_blacklist(ip_value)
    return generate_blacklist_table()

# Export alerts to CSV
@callback(
    Output("download-alerts", "data"),
    Input("export-alerts-btn", "n_clicks"),
    prevent_initial_call=True
)
def export_alerts(n):
    """Export alerts to CSV file"""
    if not state.alerts_log.get("alerts"):
        return dash.no_update

    df = pd.DataFrame(state.alerts_log["alerts"])
    return dcc.send_data_frame(df.to_csv, "alerts.csv", index=False)

# ============= RUN SERVER =============
if __name__ == "__main__":
    print("\n" + "="*60)
    print("🚀 DDoS Dashboard (Sub-Project D) starting...")
    print("   Implements: D.1-D.9")
    print("   Team 059 — GUC CSEN 1001")
    print("="*60)
    print(f"\n📍 Open http://localhost:{PORT} in your browser")
    print(f"📊 Data directory: {DATA_DIR}")
    print(f"🔄 State reload interval: {REFRESH_INTERVAL_SEC} seconds")
    print(f"🌐 Services:")
    print(f"   • Baseline (A): {BASELINE_SERVICE_URL}")
    print(f"   • Detection (B): {DETECTION_SERVICE_URL}")
    print(f"   • Mitigation (C): {MITIGATION_SERVICE_URL}\n")
    
    app.run_server(debug=DEBUG, host='0.0.0.0', port=PORT)
