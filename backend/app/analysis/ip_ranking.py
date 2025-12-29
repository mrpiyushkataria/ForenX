from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List
import app.models as models
import app.schemas as schemas
from app.utils.risk import calculate_risk_score

def analyze_ip_behavior(db: Session, limit: int = 10) -> List[schemas.IPAnalysis]:
    """
    Rank IPs by malicious behavior patterns.
    Implements Core Tool Module #3: IP Ranking.
    """
    # Get IP statistics
    ip_stats = db.query(
        models.LogEvent.ip,
        func.count(models.LogEvent.id).label('total_requests'),
        func.group_concat(func.distinct(models.LogEvent.endpoint)).label('endpoints'),
        func.min(models.LogEvent.timestamp).label('first_seen'),
        func.max(models.LogEvent.timestamp).label('last_seen')
    ).group_by(
        models.LogEvent.ip
    ).order_by(
        desc('total_requests')
    ).limit(limit).all()
    
    results = []
    for stat in ip_stats:
        # Calculate time window in minutes
        time_window_minutes = 1
        if stat.first_seen and stat.last_seen:
            time_diff = (stat.last_seen - stat.first_seen).total_seconds() / 60
            time_window_minutes = max(1, time_diff)
        
        # Calculate requests per minute
        rpm = stat.total_requests / time_window_minutes
        
        # Calculate automation confidence (simple heuristic)
        automation_confidence = min(95.0, (rpm / 10) * 100)  # Scale based on RPM
        
        # Calculate risk score
        risk_score = calculate_risk_score(
            hit_count=stat.total_requests,
            data_volume=0,  # Would need to sum per IP
            unique_ips=1,   # This is per IP analysis
            requests_per_minute=rpm
        )
        
        # Parse endpoints into list
        endpoints = stat.endpoints.split(',') if stat.endpoints else []
        
        results.append(schemas.IPAnalysis(
            ip=stat.ip,
            total_requests=stat.total_requests,
            endpoints_accessed=endpoints[:10],  # Limit for display
            requests_per_minute=round(rpm, 2),
            automation_confidence=round(automation_confidence, 1),
            risk_score=risk_score
        ))
    
    return results
