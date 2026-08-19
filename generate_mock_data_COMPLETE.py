"""
📊 Generate Mock Data for Local Testing
Creates realistic sample data in data/ folder for development and testing
when teammates' actual services (A, B, C) aren't ready yet
"""

import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import os

# Create data folder
os.makedirs('data', exist_ok=True)

print("📊 Generating mock data for DDoS Dashboard testing...\n")

# ============= 1. BASELINE.JSON (from Sub-Project A) =============
print("1️⃣  Creating baseline.json (from A)...")

baseline = {
    "mode": "learn",
    "features": ["pkt_count", "byte_count", "src_ip_unique", "dst_port_unique", "tcp_pct", "udp_pct", "icmp_pct"],
    "window_size_sec": 5,
    "stats": {
        "pkt_count": {
            "mean": 500.0,
            "std": 80.0,
            "p25": 450.0,
            "p50": 500.0,
            "p75": 550.0,
            "min": 100.0,
            "max": 1000.0
        },
        "byte_count": {
            "mean": 50000.0,
            "std": 8000.0,
            "p25": 45000.0,
            "p50": 50000.0,
            "p75": 55000.0,
            "min": 10000.0,
            "max": 100000.0
        },
        "src_ip_unique": {
            "mean": 30.0,
            "std": 5.0,
            "p25": 27.0,
            "p50": 30.0,
            "p75": 33.0
        },
        "dst_port_unique": {
            "mean": 15.0,
            "std": 3.0,
            "p25": 13.0,
            "p50": 15.0,
            "p75": 17.0
        },
        "tcp_pct": {"mean": 60.0, "std": 10.0},
        "udp_pct": {"mean": 30.0, "std": 5.0},
        "icmp_pct": {"mean": 10.0, "std": 2.0}
    },
    "training_period": "2026-05-01 to 2026-05-08",
    "last_updated": datetime.now().isoformat()
}

with open('data/baseline.json', 'w') as f:
    json.dump(baseline, f, indent=2)

print("   ✅ baseline.json created\n")

# ============= 2. ALL_WINDOWS.PARQUET (from Sub-Project A) =============
print("2️⃣  Creating all_windows.parquet (from A)...")

windows_data = []
base_time = datetime.now() - timedelta(minutes=100)

for i in range(100):
    timestamp = base_time + timedelta(minutes=i)
    
    # Normal traffic first 70 windows, attack windows 70-100
    if i < 70:
        pkt_count = np.random.normal(500, 80)
        byte_count = np.random.normal(50000, 8000)
        src_ip_unique = np.random.normal(30, 5)
        dst_port_unique = np.random.normal(15, 3)
    else:
        # Attack: 5x traffic increase
        pkt_count = np.random.normal(2500, 300)
        byte_count = np.random.normal(250000, 30000)
        src_ip_unique = np.random.normal(8, 2)  # Few sources (concentrated attack)
        dst_port_unique = np.random.normal(50, 10)  # Many ports (scanning)
    
    windows_data.append({
        'timestamp': timestamp.isoformat(),
        'window_id': f'w_{i:04d}',
        'pkt_count': max(0, pkt_count),
        'byte_count': max(0, byte_count),
        'src_ip_unique': max(1, src_ip_unique),
        'dst_port_unique': max(1, dst_port_unique),
        'tcp_pct': np.clip(60 + np.random.normal(0, 10), 0, 100),
        'udp_pct': np.clip(30 + np.random.normal(0, 5), 0, 100),
        'icmp_pct': np.clip(10 + np.random.normal(0, 2), 0, 100),
    })

windows_df = pd.DataFrame(windows_data)
windows_df.to_parquet('data/all_windows.parquet', index=False)

print(f"   ✅ all_windows.parquet created ({len(windows_df)} windows)\n")

# ============= 3. ANOMALY_SCORES.PARQUET (from Sub-Project B) =============
print("3️⃣  Creating anomaly_scores.parquet (from B)...")

scores_data = []

for i in range(100):
    timestamp = base_time + timedelta(minutes=i)
    
    # Normal: score ~0.1-0.3, Attack: score ~0.85-0.95
    if i < 70:
        anomaly_score = np.random.normal(0.15, 0.05)
        triggered_by = 'none'
        metric = 'none'
        observed_value = 500
        threshold = 1000
        reason = 'Normal traffic'
    else:
        anomaly_score = np.clip(np.random.normal(0.88, 0.05), 0.7, 1.0)
        triggered_by = ['packet_spike', 'source_concentration', 'port_scanning'][i % 3]
        metric = ['pkt_count', 'src_ip_unique', 'dst_port_unique'][i % 3]
        observed_value = [2500, 8, 50][i % 3]
        threshold = [1000, 30, 20][i % 3]
        reason = f'Attack detected: {triggered_by}'
    
    scores_data.append({
        'timestamp': timestamp.isoformat(),
        'window_id': f'w_{i:04d}',
        'anomaly_score': np.clip(anomaly_score, 0, 1),
        'triggered_by': triggered_by,
        'metric': metric,
        'observed_value': observed_value,
        'threshold': threshold,
        'reason': reason
    })

scores_df = pd.DataFrame(scores_data)
scores_df.to_parquet('data/anomaly_scores.parquet', index=False)

print(f"   ✅ anomaly_scores.parquet created ({len(scores_df)} scores)\n")

# ============= 4. ALERTS_LOG.JSON (from Sub-Project C) =============
print("4️⃣  Creating alerts_log.json (from C)...")

alerts = []

for i in range(70, 100):
    timestamp = base_time + timedelta(minutes=i)
    alert_type = ['volumetric', 'protocol', 'application'][i % 3]
    
    alerts.append({
        'alert_id': f'alert_{i:04d}',
        'timestamp': timestamp.isoformat(),
        'type': alert_type,
        'anomaly_score': np.clip(np.random.normal(0.88, 0.05), 0.7, 1.0),
        'description': f'{alert_type.capitalize()} DDoS attack detected at {timestamp.strftime("%H:%M:%S")} — {100-i} seconds of attack detected'
    })

alerts_log = {'alerts': alerts}

with open('data/alerts_log.json', 'w') as f:
    json.dump(alerts_log, f, indent=2)

print(f"   ✅ alerts_log.json created ({len(alerts)} alerts)\n")

# ============= 5. RULES_LOG.JSON (from Sub-Project C) =============
print("5️⃣  Creating rules_log.json (from C)...")

rules = []

for i in range(70, 100, 5):
    timestamp = base_time + timedelta(minutes=i)
    rule_type = ['rate_limit', 'block_port', 'block_ip'][(i // 5) % 3]
    
    rules.append({
        'timestamp': timestamp.isoformat(),
        'rule_type': rule_type,
        'target_ip': f'192.168.{(i // 5) % 256}.{(i % 256)}',
        'action': f'iptables -A INPUT -p tcp --dport 80 -m limit --limit 50/minute -j ACCEPT',
        'confidence': np.clip(np.random.normal(0.92, 0.05), 0.8, 1.0)
    })

rules_log = {'rules': rules}

with open('data/rules_log.json', 'w') as f:
    json.dump(rules_log, f, indent=2)

print(f"   ✅ rules_log.json created ({len(rules)} rules)\n")

# ============= 6. WHITELIST.JSON (created by D) =============
print("6️⃣  Creating whitelist.json (D manages)...")

whitelist = {
    'ips': [
        '10.0.0.1',
        '10.0.0.2',
    ],
    'last_updated': datetime.now().isoformat()
}

with open('data/whitelist.json', 'w') as f:
    json.dump(whitelist, f, indent=2)

print("   ✅ whitelist.json created\n")

# ============= 7. BLACKLIST.JSON (created by D) =============
print("7️⃣  Creating blacklist.json (D manages)...")

blacklist = {
    'ips': [
        '203.0.113.5',
        '198.51.100.20',
    ],
    'last_updated': datetime.now().isoformat()
}

with open('data/blacklist.json', 'w') as f:
    json.dump(blacklist, f, indent=2)

print("   ✅ blacklist.json created\n")

# ============= SUMMARY =============
print("="*60)
print("✅ Mock data generation complete!")
print("="*60)
print("\n📂 Created files in data/ folder:")
print("   • baseline.json")
print("   • all_windows.parquet")
print("   • anomaly_scores.parquet")
print("   • alerts_log.json")
print("   • rules_log.json")
print("   • whitelist.json")
print("   • blacklist.json")
print("\n🚀 Next steps:")
print("   1. Run dashboard: python dashboard.py")
print("   2. Open: http://localhost:8050")
print("   3. Drag time slider to see attack (windows 70-100)")
print("   4. Check notifications when email is enabled")
print("\n📧 To test email notifications:")
print("   1. Update .env: EMAIL_ENABLED=True")
print("   2. Add Gmail + app password")
print("   3. Add TA_EMAIL_ADDRESS=test@example.com")
print("   4. Restart dashboard")
print("   5. See 'Notification History' show sent emails")
print()