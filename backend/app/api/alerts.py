from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
import json

from app.database import get_db
from app.models import Alert, AlertRule, User, NotificationPreference
import app.schemas as schemas
from app.config import settings

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

class AlertManager:
    """Comprehensive alert management system"""
    
    def __init__(self):
        self.alert_channels = {}
        
    def create_alert(
        self,
        db: Session,
        title: str,
        description: str,
        severity: str,
        source: str,
        metadata: Dict,
        rule_id: Optional[int] = None
    ) -> Alert:
        """Create and store a new alert"""
        alert = Alert(
            title=title,
            description=description,
            severity=severity,
            source=source,
            metadata=metadata,
            rule_id=rule_id,
            created_at=datetime.utcnow(),
            is_acknowledged=False,
            is_resolved=False
        )
        
        db.add(alert)
        db.commit()
        db.refresh(alert)
        
        # Trigger notifications
        self._trigger_notifications(db, alert)
        
        return alert
    
    def _trigger_notifications(self, db: Session, alert: Alert):
        """Trigger notifications for alert"""
        # Get users who should receive notifications
        users = db.query(User).filter(
            User.is_active == True,
            User.notification_preferences.any(
                NotificationPreference.alert_severity == alert.severity
            )
        ).all()
        
        for user in users:
            prefs = user.notification_preferences
            for pref in prefs:
                if pref.alert_severity == alert.severity:
                    self._send_notification(user, alert, pref.channel)
    
    def _send_notification(self, user: User, alert: Alert, channel: str):
        """Send notification via specified channel"""
        if channel == "email":
            self._send_email_alert(user, alert)
        elif channel == "slack":
            self._send_slack_alert(user, alert)
        elif channel == "webhook":
            self._send_webhook_alert(user, alert)
        elif channel == "sms":
            self._send_sms_alert(user, alert)
    
    def _send_email_alert(self, user: User, alert: Alert):
        """Send email alert"""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[ForenX Alert] {alert.severity.upper()}: {alert.title}"
            msg['From'] = settings.EMAIL_FROM
            msg['To'] = user.email
            
            # HTML email content
            html = f"""
            <html>
            <body>
                <h2>🔔 ForenX Security Alert</h2>
                <p><strong>Severity:</strong> {alert.severity.upper()}</p>
                <p><strong>Title:</strong> {alert.title}</p>
                <p><strong>Description:</strong> {alert.description}</p>
                <p><strong>Time:</strong> {alert.created_at}</p>
                <p><strong>Source:</strong> {alert.source}</p>
                <hr>
                <p><a href="{settings.BASE_URL}/alerts/{alert.id}">View Alert in ForenX</a></p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(html, 'html'))
            
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
                    server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.send_message(msg)
                
        except Exception as e:
            print(f"Failed to send email alert: {e}")
    
    def _send_slack_alert(self, user: User, alert: Alert):
        """Send Slack alert"""
        try:
            webhook_url = settings.SLACK_WEBHOOK_URL
            if not webhook_url:
                return
            
            severity_colors = {
                "critical": "#ff0000",
                "high": "#ff6b00",
                "medium": "#ffd000",
                "low": "#00a8ff"
            }
            
            payload = {
                "attachments": [{
                    "color": severity_colors.get(alert.severity, "#cccccc"),
                    "title": f"🔔 {alert.severity.upper()}: {alert.title}",
                    "text": alert.description,
                    "fields": [
                        {"title": "Source", "value": alert.source, "short": True},
                        {"title": "Time", "value": str(alert.created_at), "short": True}
                    ],
                    "footer": "ForenX Security Alert",
                    "ts": datetime.timestamp(alert.created_at)
                }]
            }
            
            requests.post(webhook_url, json=payload)
            
        except Exception as e:
            print(f"Failed to send Slack alert: {e}")
    
    def _send_webhook_alert(self, user: User, alert: Alert):
        """Send webhook alert"""
        try:
            webhook_urls = settings.WEBHOOK_URLS.split(',') if settings.WEBHOOK_URLS else []
            
            payload = {
                "event": "security_alert",
                "alert": {
                    "id": alert.id,
                    "title": alert.title,
                    "description": alert.description,
                    "severity": alert.severity,
                    "source": alert.source,
                    "timestamp": alert.created_at.isoformat(),
                    "metadata": alert.metadata
                },
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "username": user.username
                }
            }
            
            for url in webhook_urls:
                requests.post(url.strip(), json=payload, timeout=5)
                
        except Exception as e:
            print(f"Failed to send webhook alert: {e}")
    
    def _send_sms_alert(self, user: User, alert: Alert):
        """Send SMS alert (Twilio integration)"""
        try:
            if not settings.TWILIO_ACCOUNT_SID:
                return
            
            from twilio.rest import Client
            
            client = Client(
                settings.TWILIO_ACCOUNT_SID,
                settings.TWILIO_AUTH_TOKEN
            )
            
            message = client.messages.create(
                body=f"ForenX Alert [{alert.severity.upper()}]: {alert.title} - {alert.description[:100]}...",
                from_=settings.TWILIO_PHONE_NUMBER,
                to=user.phone_number  # Assuming user has phone_number field
            )
            
        except Exception as e:
            print(f"Failed to send SMS alert: {e}")

# Initialize alert manager
alert_manager = AlertManager()

@router.post("/trigger", response_model=schemas.Alert)
async def trigger_alert(
    alert_data: schemas.AlertCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """Trigger a new alert"""
    alert = alert_manager.create_alert(
        db=db,
        title=alert_data.title,
        description=alert_data.description,
        severity=alert_data.severity,
        source=alert_data.source,
        metadata=alert_data.metadata,
        rule_id=alert_data.rule_id
    )
    
    return alert

@router.get("/", response_model=List[schemas.Alert])
async def get_alerts(
    severity: Optional[str] = None,
    source: Optional[str] = None,
    acknowledged: Optional[bool] = None,
    resolved: Optional[bool] = None,
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """Get alerts with filtering"""
    query = db.query(Alert).filter(
        Alert.created_at >= datetime.utcnow() - timedelta(hours=hours)
    )
    
    if severity:
        query = query.filter(Alert.severity == severity)
    
    if source:
        query = query.filter(Alert.source == source)
    
    if acknowledged is not None:
        query = query.filter(Alert.is_acknowledged == acknowledged)
    
    if resolved is not None:
        query = query.filter(Alert.is_resolved == resolved)
    
    return query.order_by(Alert.created_at.desc()).limit(100).all()

@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    db: Session = Depends(get_db)
):
    """Acknowledge an alert"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.is_acknowledged = True
    alert.acknowledged_at = datetime.utcnow()
    db.commit()
    
    return {"message": "Alert acknowledged"}

@router.post("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    resolution_notes: str,
    db: Session = Depends(get_db)
):
    """Resolve an alert with notes"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.is_resolved = True
    alert.resolved_at = datetime.utcnow()
    alert.resolution_notes = resolution_notes
    db.commit()
    
    return {"message": "Alert resolved"}

@router.get("/stats")
async def get_alert_stats(db: Session = Depends(get_db)):
    """Get alert statistics"""
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    last_30d = now - timedelta(days=30)
    
    stats = {
        "last_24h": {
            "total": db.query(Alert).filter(Alert.created_at >= last_24h).count(),
            "critical": db.query(Alert).filter(
                Alert.created_at >= last_24h,
                Alert.severity == "critical"
            ).count(),
            "high": db.query(Alert).filter(
                Alert.created_at >= last_24h,
                Alert.severity == "high"
            ).count(),
            "unacknowledged": db.query(Alert).filter(
                Alert.created_at >= last_24h,
                Alert.is_acknowledged == False
            ).count()
        },
        "last_7d": {
            "total": db.query(Alert).filter(Alert.created_at >= last_7d).count(),
            "by_severity": {
                sev: db.query(Alert).filter(
                    Alert.created_at >= last_7d,
                    Alert.severity == sev
                ).count()
                for sev in ["critical", "high", "medium", "low"]
            }
        },
        "last_30d": {
            "total": db.query(Alert).filter(Alert.created_at >= last_30d).count(),
            "resolved": db.query(Alert).filter(
                Alert.created_at >= last_30d,
                Alert.is_resolved == True
            ).count(),
            "mttr": self._calculate_mttr(db, last_30d)  # Mean Time To Resolution
        }
    }
    
    return stats

def _calculate_mttr(self, db: Session, since: datetime) -> Optional[float]:
    """Calculate Mean Time To Resolution"""
    resolved_alerts = db.query(Alert).filter(
        Alert.created_at >= since,
        Alert.is_resolved == True,
        Alert.resolved_at.isnot(None)
    ).all()
    
    if not resolved_alerts:
        return None
    
    total_seconds = sum(
        (alert.resolved_at - alert.created_at).total_seconds()
        for alert in resolved_alerts
    )
    
    return total_seconds / len(resolved_alerts)

# Alert rules management
@router.post("/rules", response_model=schemas.AlertRule)
async def create_alert_rule(
    rule_data: schemas.AlertRuleCreate,
    db: Session = Depends(get_db)
):
    """Create a new alert rule"""
    rule = AlertRule(
        name=rule_data.name,
        description=rule_data.description,
        condition=rule_data.condition,
        severity=rule_data.severity,
        is_active=rule_data.is_active,
        action=rule_data.action,
        created_at=datetime.utcnow()
    )
    
    db.add(rule)
    db.commit()
    db.refresh(rule)
    
    return rule

@router.get("/rules", response_model=List[schemas.AlertRule])
async def get_alert_rules(
    active: Optional[bool] = None,
    db: Session = Depends(get_db)
):
    """Get alert rules"""
    query = db.query(AlertRule)
    
    if active is not None:
        query = query.filter(AlertRule.is_active == active)
    
    return query.order_by(AlertRule.created_at.desc()).all()

# Built-in alert rules
DEFAULT_ALERT_RULES = [
    {
        "name": "High Risk SQL Injection",
        "description": "Alert on high confidence SQL injection attempts",
        "condition": "sql_injection_risk >= 80",
        "severity": "critical",
        "action": "alert_email,alert_slack,block_ip_temporary"
    },
    {
        "name": "Brute Force Attack",
        "description": "Multiple failed login attempts from single IP",
        "condition": "failed_logins >= 10 within 5 minutes",
        "severity": "high",
        "action": "alert_email,rate_limit_ip"
    },
    {
        "name": "Data Exfiltration",
        "description": "Large data transfers from sensitive endpoints",
        "condition": "data_transfer > 100MB within 1 hour",
        "severity": "high",
        "action": "alert_email,alert_slack,review_user"
    },
    {
        "name": "Port Scanning",
        "description": "Multiple 404 errors indicating port scanning",
        "condition": "404_errors >= 50 within 1 minute",
        "severity": "medium",
        "action": "alert_email,block_ip_24h"
    }
]

@router.post("/rules/default")
async def create_default_rules(db: Session = Depends(get_db)):
    """Create default alert rules"""
    created = 0
    for rule_data in DEFAULT_ALERT_RULES:
        # Check if rule already exists
        existing = db.query(AlertRule).filter(
            AlertRule.name == rule_data["name"]
        ).first()
        
        if not existing:
            rule = AlertRule(
                name=rule_data["name"],
                description=rule_data["description"],
                condition=rule_data["condition"],
                severity=rule_data["severity"],
                action=rule_data["action"],
                is_active=True,
                created_at=datetime.utcnow()
            )
            db.add(rule)
            created += 1
    
    db.commit()
    return {"message": f"Created {created} default alert rules"}
