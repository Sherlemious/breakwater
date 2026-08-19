"""
🔔 Notification System — Sub-Project D (D.7, D.8, D.9)
Sends alerts via email, Slack, WhatsApp, SMS with cool-down suppression

Features:
  D.7 — Live channel delivery (email/Slack/WhatsApp/SMS)
  D.8 — Insightful alert content (timestamp, score, type, metric)
  D.9 — Cool-down suppression (~120 sec) + fatigue control
"""

import json
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import os
from pathlib import Path
from typing import Dict, List, Optional
import requests
from dotenv import load_dotenv
import logging

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============= CONFIG =============
COOLDOWN_SEC = int(os.getenv("ALERT_COOLDOWN_SEC", "120"))  # D.9: ~120 seconds
NOTIFICATION_LOG_FILE = os.getenv("NOTIFICATION_LOG_FILE", "data/notification_log.json")

# Email config (D.7 - email channel)
EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "True").lower() == "true"
EMAIL_PROVIDER = os.getenv("EMAIL_PROVIDER", "gmail")
EMAIL_FROM = os.getenv("EMAIL_FROM", "ddos-monitor@your-domain.com")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
EMAIL_SMTP_HOST = os.getenv("EMAIL_SMTP_HOST", "smtp.gmail.com")
EMAIL_SMTP_PORT = int(os.getenv("EMAIL_SMTP_PORT", "587"))

# Slack config (D.7 - Slack channel)
SLACK_ENABLED = os.getenv("SLACK_ENABLED", "False").lower() == "true"
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")

# WhatsApp config (D.7 - WhatsApp channel, via Twilio)
WHATSAPP_ENABLED = os.getenv("WHATSAPP_ENABLED", "False").lower() == "true"
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_PHONE_FROM = os.getenv("TWILIO_PHONE_FROM", "")
TWILIO_PHONE_TO = os.getenv("TWILIO_PHONE_TO", "")

# SMS config (D.7 - SMS channel, via Twilio)
SMS_ENABLED = os.getenv("SMS_ENABLED", "False").lower() == "true"

# Credential-free local/dashboard channel
LOCAL_NOTIFICATIONS_ENABLED = os.getenv("LOCAL_NOTIFICATIONS_ENABLED", "True").lower() == "true"

# ============= NOTIFICATION MANAGER (D.7, D.8, D.9) =============

class NotificationManager:
    """
    Manages alert notifications across multiple channels with cool-down suppression.
    
    Design:
      - Non-event driven: called from dashboard callbacks
      - Tracks last alert time per anomaly type to suppress duplicates (D.9)
      - Sends rich alert content with timestamp, score, type, description (D.8)
      - Supports multiple channels: email, Slack, WhatsApp, SMS (D.7)
      - Cool-down: first alert sent immediately, then suppressed for ~120 sec
    """
    
    def __init__(self, cooldown_sec: int = COOLDOWN_SEC):
        self.cooldown_sec = cooldown_sec
        self.last_alert_time: Dict[str, float] = {}  # anomaly_type -> last_send_time
        self.notification_history: List[Dict] = []
        self.load_notification_history()
    
    def load_notification_history(self):
        """Load previous notification history from disk"""
        try:
            if os.path.exists(NOTIFICATION_LOG_FILE):
                with open(NOTIFICATION_LOG_FILE) as f:
                    data = json.load(f)
                    self.notification_history = data.get('notifications', [])
                    # Restore last alert times
                    for notif in self.notification_history:
                        alert_type = notif.get('alert_type', 'unknown')
                        last_time = notif.get('timestamp')
                        if last_time:
                            self.last_alert_time[alert_type] = datetime.fromisoformat(last_time).timestamp()
                    logger.info(f"✅ Loaded {len(self.notification_history)} notification history")
        except Exception as e:
            logger.warning(f"⚠️  Could not load notification history: {e}")
    
    def save_notification_history(self):
        """Save notification history to disk (for persistence)"""
        try:
            Path(os.path.dirname(NOTIFICATION_LOG_FILE)).mkdir(parents=True, exist_ok=True)
            with open(NOTIFICATION_LOG_FILE, 'w') as f:
                json.dump({
                    'notifications': self.notification_history[-100:],  # Keep last 100
                    'last_updated': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.error(f"❌ Could not save notification history: {e}")
    
    def should_send_alert(self, alert_id: str, alert_type: str) -> tuple[bool, str]:
        """
        D.9: Cooldown suppression logic
        
        Returns: (should_send: bool, reason: str)
        
        Rules:
          1. First alert ever → SEND immediately
          2. Same alert_type within COOLDOWN_SEC → SUPPRESS (fatigue control)
          3. Same alert_type after COOLDOWN_SEC → SEND (let it through)
          4. Different alert_type → SEND immediately
        """
        now = datetime.now().timestamp()
        
        # First alert of this type
        if alert_type not in self.last_alert_time:
            self.last_alert_time[alert_type] = now
            return True, "First alert of this type"
        
        # Time since last alert
        time_since_last = now - self.last_alert_time[alert_type]
        
        # Still in cooldown period
        if time_since_last < self.cooldown_sec:
            remaining = self.cooldown_sec - time_since_last
            return False, f"In cooldown period ({remaining:.0f}s remaining)"
        
        # Cooldown expired, allow new alert
        self.last_alert_time[alert_type] = now
        return True, f"Cooldown expired ({time_since_last:.0f}s since last)"
    
    def format_alert_content(self, alert: Dict) -> Dict:
        """
        D.8: Format alert content with insightful information
        
        Returns dict with rich alert details for all channels
        """
        alert_id = alert.get('alert_id', 'unknown')
        alert_type = alert.get('type', 'unknown')
        timestamp = alert.get('timestamp', '')
        anomaly_score = alert.get('anomaly_score', 0)
        description = alert.get('description', '')
        
        # Parse timestamp
        try:
            ts = datetime.fromisoformat(timestamp)
            ts_formatted = ts.strftime('%Y-%m-%d %H:%M:%S')
        except:
            ts_formatted = timestamp
        
        # Build insightful content
        content = {
            'title': f"🚨 DDoS Alert Detected",
            'alert_id': alert_id,
            'type': alert_type.upper(),
            'timestamp': ts_formatted,
            'anomaly_score': f"{anomaly_score:.2f} / 1.00",
            'severity': self._calculate_severity(anomaly_score),
            'description': description,
            'full_alert': alert,
        }
        
        return content
    
    def _calculate_severity(self, score: float) -> str:
        """Calculate severity based on anomaly score"""
        if score >= 0.9:
            return "🔴 CRITICAL"
        elif score >= 0.8:
            return "🟠 HIGH"
        elif score >= 0.7:
            return "🟡 MEDIUM"
        else:
            return "🟢 LOW"
    
    # ============= EMAIL CHANNEL (D.7) =============
    
    def send_email(self, alert: Dict, to_address: str) -> bool:
        """D.7: Send alert via email with D.8 rich content"""
        if not EMAIL_ENABLED:
            logger.info("❌ Email notifications disabled")
            return False
        
        if not EMAIL_PASSWORD:
            logger.error("❌ Email password not configured in .env")
            return False
        
        try:
            content = self.format_alert_content(alert)
            
            # Build email body
            body = f"""
DDoS Alert Notification
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Alert ID:        {content['alert_id']}
Type:            {content['type']}
Timestamp:       {content['timestamp']}
Severity:        {content['severity']}
Anomaly Score:   {content['anomaly_score']}

Description:
{content['description']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Action Required:
1. Check dashboard: http://localhost:8050
2. Review anomaly score graph
3. Verify mitigation rules applied
4. Consider whitelist/blacklist adjustments

---
DDoS Mitigation System
Generated at: {datetime.now().isoformat()}
"""
            
            # Create email message
            msg = MIMEText(body)
            msg['Subject'] = f"🚨 DDoS Alert: {content['type']}"
            msg['From'] = EMAIL_FROM
            msg['To'] = to_address
            
            # Send email
            with smtplib.SMTP(EMAIL_SMTP_HOST, EMAIL_SMTP_PORT) as server:
                server.starttls()
                server.login(EMAIL_FROM, EMAIL_PASSWORD)
                server.send_message(msg)
            
            logger.info(f"✅ Email sent to {to_address}")
            
            # Log notification
            self._log_notification('email', to_address, alert, 'success')
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to send email: {e}")
            self._log_notification('email', to_address, alert, f'failed: {e}')
            return False
    
    # ============= SLACK CHANNEL (D.7) =============
    
    def send_slack(self, alert: Dict, webhook_url: Optional[str] = None) -> bool:
        """D.7: Send alert to Slack with D.8 rich content"""
        if not SLACK_ENABLED:
            logger.info("❌ Slack notifications disabled")
            return False
        
        url = webhook_url or SLACK_WEBHOOK_URL
        if not url:
            logger.error("❌ Slack webhook URL not configured")
            return False
        
        try:
            content = self.format_alert_content(alert)
            
            # Build Slack message (rich formatting)
            slack_message = {
                "text": f"🚨 DDoS Alert: {content['type']}",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🛡️  DDoS Attack Detected"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Alert ID:*\n{content['alert_id']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Type:*\n{content['type']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Timestamp:*\n{content['timestamp']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Severity:*\n{content['severity']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Anomaly Score:*\n{content['anomaly_score']}"
                            },
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Description:*\n{content['description']}"
                        }
                    },
                    {
                        "type": "divider"
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "📊 Check dashboard for more details: http://localhost:8050"
                        }
                    }
                ]
            }
            
            # Send to Slack
            response = requests.post(url, json=slack_message, timeout=5)
            
            if response.status_code == 200:
                logger.info("✅ Slack message sent")
                self._log_notification('slack', 'webhook', alert, 'success')
                return True
            else:
                logger.error(f"❌ Slack returned status {response.status_code}")
                self._log_notification('slack', 'webhook', alert, f'failed: {response.status_code}')
                return False
                
        except Exception as e:
            logger.error(f"❌ Failed to send Slack message: {e}")
            self._log_notification('slack', 'webhook', alert, f'failed: {e}')
            return False
    
    # ============= WHATSAPP CHANNEL (D.7) =============
    
    def send_whatsapp(self, alert: Dict, to_number: Optional[str] = None) -> bool:
        """D.7: Send alert via WhatsApp (Twilio) with D.8 rich content"""
        if not WHATSAPP_ENABLED:
            logger.info("❌ WhatsApp notifications disabled")
            return False
        
        if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_FROM]):
            logger.error("❌ Twilio credentials not configured")
            return False
        
        to = to_number or TWILIO_PHONE_TO
        if not to:
            logger.error("❌ Recipient WhatsApp number not configured")
            return False
        
        try:
            from twilio.rest import Client
            
            content = self.format_alert_content(alert)
            
            # Build WhatsApp message
            message_text = f"""
🚨 DDoS ALERT

Type: {content['type']}
Score: {content['anomaly_score']}
Severity: {content['severity']}
Time: {content['timestamp']}

{content['description']}

Check dashboard: http://localhost:8050
"""
            
            # Send via Twilio
            client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
            message = client.messages.create(
                from_=f"whatsapp:{TWILIO_PHONE_FROM}",
                body=message_text,
                to=f"whatsapp:{to}"
            )
            
            logger.info(f"✅ WhatsApp message sent to {to}")
            self._log_notification('whatsapp', to, alert, 'success')
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to send WhatsApp message: {e}")
            self._log_notification('whatsapp', to, alert, f'failed: {e}')
            return False
    
    # ============= SMS CHANNEL (D.7) =============
    
    def send_sms(self, alert: Dict, to_number: Optional[str] = None) -> bool:
        """D.7: Send alert via SMS (Twilio) with D.8 content"""
        if not SMS_ENABLED:
            logger.info("❌ SMS notifications disabled")
            return False
        
        if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_FROM]):
            logger.error("❌ Twilio credentials not configured")
            return False
        
        to = to_number or TWILIO_PHONE_TO
        if not to:
            logger.error("❌ Recipient phone number not configured")
            return False
        
        try:
            from twilio.rest import Client
            
            content = self.format_alert_content(alert)
            
            # Build SMS message (keep short)
            message_text = f"🚨 DDoS Alert: {content['type']} | Score: {content['anomaly_score']} | {content['timestamp']}"
            
            # Send via Twilio
            client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
            message = client.messages.create(
                from_=TWILIO_PHONE_FROM,
                body=message_text,
                to=to
            )
            
            logger.info(f"✅ SMS sent to {to}")
            self._log_notification('sms', to, alert, 'success')
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to send SMS: {e}")
            self._log_notification('sms', to, alert, f'failed: {e}')
            return False
    
    # ============= UNIFIED SEND METHOD =============

    def send_local(self, alert: Dict) -> bool:
        """Record a dashboard-local notification when external credentials are unavailable."""
        if not LOCAL_NOTIFICATIONS_ENABLED:
            logger.info("Local notifications disabled")
            return False

        content = self.format_alert_content(alert)
        logger.warning(
            "Local alert queued: %s | %s | %s",
            content["type"],
            content["anomaly_score"],
            content["description"],
        )
        self._log_notification("local", "dashboard", alert, "queued")
        return True
    
    def send_alert(self, 
                   alert: Dict, 
                   channels: List[str] = None,
                   ta_email: Optional[str] = None,
                   ta_slack_webhook: Optional[str] = None,
                   ta_whatsapp: Optional[str] = None,
                   ta_sms: Optional[str] = None) -> Dict[str, bool]:
        """
        D.7+D.8+D.9: Send alert across multiple channels
        
        Args:
          alert: Alert dict with id, type, timestamp, anomaly_score, description
          channels: List of channels to send to ['email', 'slack', 'whatsapp', 'sms']
          ta_*: TA-supplied addresses for each channel (used during demo)
        
        Returns:
          Dict mapping channel name -> success boolean
        
        Process:
          1. Check if should send based on cool-down (D.9)
          2. Format rich alert content (D.8)
          3. Send to all enabled channels (D.7)
          4. Log notification history
        """
        
        alert_id = alert.get('alert_id', 'unknown')
        alert_type = alert.get('type', 'unknown')
        
        # D.9: Check cool-down suppression
        should_send, reason = self.should_send_alert(alert_id, alert_type)
        
        if not should_send:
            logger.info(f"⏳ Alert {alert_id} suppressed by cool-down: {reason}")
            return {'suppressed': True, 'reason': reason}
        
        logger.info(f"✅ Alert {alert_id} passed cool-down check: {reason}")
        
        # Default to all enabled channels if not specified
        if channels is None:
            channels = []
            if EMAIL_ENABLED:
                channels.append('email')
            if SLACK_ENABLED:
                channels.append('slack')
            if WHATSAPP_ENABLED:
                channels.append('whatsapp')
            if SMS_ENABLED:
                channels.append('sms')
            if LOCAL_NOTIFICATIONS_ENABLED and not channels:
                channels.append('local')
        
        results = {}
        
        # D.7: Send to each channel
        if 'email' in channels and ta_email:
            results['email'] = self.send_email(alert, ta_email)
        
        if 'slack' in channels and ta_slack_webhook:
            results['slack'] = self.send_slack(alert, ta_slack_webhook)
        
        if 'whatsapp' in channels and ta_whatsapp:
            results['whatsapp'] = self.send_whatsapp(alert, ta_whatsapp)
        
        if 'sms' in channels and ta_sms:
            results['sms'] = self.send_sms(alert, ta_sms)

        if 'local' in channels:
            results['local'] = self.send_local(alert)
        
        # Save history
        self.save_notification_history()
        
        return results
    
    def _log_notification(self, channel: str, recipient: str, alert: Dict, status: str):
        """Log notification to history"""
        self.notification_history.append({
            'timestamp': datetime.now().isoformat(),
            'channel': channel,
            'recipient': recipient,
            'alert_id': alert.get('alert_id'),
            'alert_type': alert.get('type'),
            'anomaly_score': alert.get('anomaly_score'),
            'status': status,
        })
    
    def get_notification_history(self) -> List[Dict]:
        """Return notification history for dashboard display"""
        return self.notification_history[-20:]  # Last 20 notifications
    
    def get_alert_status(self, alert_type: str) -> Dict:
        """Get current cool-down status for an alert type"""
        if alert_type not in self.last_alert_time:
            return {'status': 'never_sent'}
        
        now = datetime.now().timestamp()
        last_send = self.last_alert_time[alert_type]
        time_since = now - last_send
        
        if time_since < self.cooldown_sec:
            return {
                'status': 'in_cooldown',
                'time_remaining': self.cooldown_sec - time_since,
                'seconds': f"{(self.cooldown_sec - time_since):.0f}s"
            }
        else:
            return {
                'status': 'ready',
                'time_since_last': time_since,
                'can_send': True
            }


# ============= INITIALIZE GLOBAL NOTIFICATION MANAGER =============
notification_manager = NotificationManager(cooldown_sec=COOLDOWN_SEC)

if __name__ == "__main__":
    # Test notification manager
    print("🔔 Notification Manager Test")
    print("="*60)
    
    # Create sample alert
    test_alert = {
        'alert_id': 'alert_001',
        'type': 'volumetric',
        'timestamp': datetime.now().isoformat(),
        'anomaly_score': 0.85,
        'description': 'Sudden spike in packet rate from 192.168.1.50 — 5x baseline'
    }
    
    print(f"\n✅ Formatted alert content:")
    content = notification_manager.format_alert_content(test_alert)
    for key, value in content.items():
        if key != 'full_alert':
            print(f"   {key}: {value}")
    
    print(f"\n✅ Cool-down check:")
    should_send, reason = notification_manager.should_send_alert('alert_001', 'volumetric')
    print(f"   Should send: {should_send} ({reason})")
    
    print(f"\n✅ Cool-down check (immediate repeat):")
    should_send, reason = notification_manager.should_send_alert('alert_001', 'volumetric')
    print(f"   Should send: {should_send} ({reason})")
    
    print(f"\n✅ Notification history:")
    history = notification_manager.get_notification_history()
    print(f"   Total notifications logged: {len(notification_manager.notification_history)}")
