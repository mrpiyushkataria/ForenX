# /backend/app/analysis/sql_injection.py
import re
from sqlalchemy.orm import Session
from typing import List, Dict, Tuple
from app.models import LogEvent
import app.schemas as schemas

class SQLInjectionDetector:
    """Advanced SQL injection detection with heuristic scoring."""
    
    # Critical SQLi patterns (OWASP based)
    SQLI_PATTERNS = {
        'tautology': [
            r"'.*or.*'.*='.*'",
            r"'.*or.*1=1",
            r"'.*or.*'1'='1'"
        ],
        'union': [
            r"union.*select",
            r"union.*all.*select"
        ],
        'piggyback': [
            r";\s*(drop|create|alter|truncate)",
            r";\s*--"
        ],
        'blind': [
            r"if\(",
            r"case.*when",
            r"sleep\(",
            r"benchmark\(",
            r"waitfor.*delay"
        ],
        'error_based': [
            r"convert\(",
            r"cast\(",
            r"extractvalue\(",
            r"updatexml\("
        ]
    }
    
    def __init__(self, confidence_threshold: float = 0.7):
        self.confidence_threshold = confidence_threshold
        
    def detect_in_events(self, db: Session, hours: int = 24) -> List[Dict]:
        """
        Detect SQL injection attempts across all log sources.
        """
        from sqlalchemy import and_, or_
        from datetime import datetime, timedelta
        
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Get all events with potential SQLi indicators
        events = db.query(LogEvent).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                or_(
                    LogEvent.source == 'mysql',
                    LogEvent.payload.contains('select'),
                    LogEvent.payload.contains('union'),
                    LogEvent.payload.contains('--'),
                    LogEvent.endpoint.contains('?')
                )
            )
        ).all()
        
        findings = []
        for event in events:
            score, patterns = self.analyze_payload(event.payload or "")
            
            if score >= 60:  # Threshold for reporting
                findings.append({
                    "timestamp": event.timestamp,
                    "source": event.source,
                    "ip": event.ip,
                    "endpoint": event.endpoint,
                    "payload": event.payload[:500] if event.payload else "",
                    "risk_score": score,
                    "confidence": min(95, score),
                    "matched_patterns": patterns,
                    "evidence_id": event.id,
                    "recommended_action": "Block IP & review database"
                })
        
        # Sort by risk score
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
    
    def analyze_payload(self, payload: str) -> Tuple[int, List[str]]:
        """
        Analyze a single payload for SQL injection patterns.
        Returns: (risk_score, matched_patterns)
        """
        if not payload:
            return 0, []
        
        payload_lower = payload.lower()
        score = 0
        matched_patterns = []
        
        # Check each pattern category
        for category, patterns in self.SQLI_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, payload_lower, re.IGNORECASE):
                    matched_patterns.append(f"{category}:{pattern}")
                    
                    # Weight different categories
                    if category in ['union', 'piggyback']:
                        score += 25
                    elif category in ['blind', 'error_based']:
                        score += 20
                    else:
                        score += 15
        
        # Additional heuristics
        if payload.count("'") > 5:  # Excessive quotes
            score += 10
            matched_patterns.append("excessive_quotes")
        
        if len(payload) > 1000:  # Very long payload
            score += 15
            matched_patterns.append("long_payload")
        
        # Cap at 100
        return min(100, score), matched_patterns

# Example usage in main.py
@app.get("/api/sqli-detection/")
async def get_sqli_findings(
    hours: int = 24,
    min_score: int = 60,
    db: Session = Depends(get_db)
):
    """API endpoint for SQL injection findings."""
    detector = SQLInjectionDetector()
    findings = detector.detect_in_events(db, hours)
    
    # Filter by minimum score
    filtered = [f for f in findings if f['risk_score'] >= min_score]
    
    return {
        "total_scanned": len(findings),
        "high_risk_findings": len(filtered),
        "findings": filtered[:50]  # Limit response
    }
