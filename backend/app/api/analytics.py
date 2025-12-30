from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict, List
from datetime import datetime, timedelta
from collections import Counter

from app.database import get_db
from app.models import LogEvent

router = APIRouter(prefix="/api/analytics", tags=["analytics"])

@router.get("/")
async def get_analytics(
    hours: int = 24,
    db: Session = Depends(get_db)
):
    """Get comprehensive analytics data"""
    try:
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Get recent logs
        recent_logs = db.query(LogEvent).filter(
            LogEvent.timestamp >= time_threshold
        ).all()
        
        if not recent_logs:
            return {
                "message": "No data available for the selected time range",
                "top_endpoints": [],
                "top_ips": [],
                "status_distribution": {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0},
                "statistics": {
                    "total_requests": 0,
                    "total_threats": 0,
                    "unique_ips": 0
                }
            }
        
        # Calculate statistics
        total_logs = len(recent_logs)
        
        # Get top endpoints
        endpoint_counter = Counter(log.endpoint for log in recent_logs if log.endpoint)
        top_endpoints = [
            {"endpoint": endpoint, "count": count} 
            for endpoint, count in endpoint_counter.most_common(10)
        ]
        
        # Get top IPs
        ip_counter = Counter(log.ip for log in recent_logs if log.ip)
        top_ips = [
            {"ip": ip, "count": count} 
            for ip, count in ip_counter.most_common(10)
        ]
        
        # Status distribution
        status_distribution = {
            "2xx": len([log for log in recent_logs if log.status and 200 <= log.status < 300]),
            "3xx": len([log for log in recent_logs if log.status and 300 <= log.status < 400]),
            "4xx": len([log for log in recent_logs if log.status and 400 <= log.status < 500]),
            "5xx": len([log for log in recent_logs if log.status and 500 <= log.status < 600])
        }
        
        # Method distribution
        method_counter = Counter(log.method for log in recent_logs if log.method)
        
        return {
            "top_endpoints": top_endpoints,
            "top_ips": top_ips,
            "status_distribution": status_distribution,
            "method_distribution": dict(method_counter),
            "statistics": {
                "total_requests": total_logs,
                "unique_ips": len(ip_counter),
                "total_threats": len([log for log in recent_logs if log.risk_score and log.risk_score > 70]),
                "time_range_hours": hours
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
