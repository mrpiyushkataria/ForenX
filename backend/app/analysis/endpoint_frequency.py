from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List
import app.models as models
import app.schemas as schemas
from app.utils.risk import calculate_risk_score

def analyze_endpoint_abuse(db: Session, limit: int = 10, min_hits: int = 1) -> List[schemas.EndpointAnalysis]:
    """
    Detect abused endpoints by frequency and data volume.
    Implements Core Tool Module #3: Endpoint Frequency Analysis.
    """
    # Query database for endpoint statistics
    endpoint_stats = db.query(
        models.LogEvent.endpoint,
        func.count(models.LogEvent.id).label('total_hits'),
        func.count(func.distinct(models.LogEvent.ip)).label('unique_ips'),
        func.sum(models.LogEvent.response_size).label('total_data_volume'),
        func.avg(models.LogEvent.response_size).label('avg_response_size')
    ).filter(
        models.LogEvent.endpoint.isnot(None),
        models.LogEvent.endpoint != ''
    ).group_by(
        models.LogEvent.endpoint
    ).having(
        func.count(models.LogEvent.id) >= min_hits
    ).order_by(
        desc('total_hits')
    ).limit(limit).all()
    
    # Convert to analysis results with risk scoring
    results = []
    for stat in endpoint_stats:
        # Calculate risk based on hits, data volume, and unique IPs
        risk_score = calculate_risk_score(
            hit_count=stat.total_hits,
            data_volume=stat.total_data_volume or 0,
            unique_ips=stat.unique_ips
        )
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "High"
        elif risk_score >= 40:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        results.append(schemas.EndpointAnalysis(
            endpoint=stat.endpoint,
            total_hits=stat.total_hits,
            unique_ips=stat.unique_ips,
            total_data_volume=stat.total_data_volume or 0,
            avg_response_size=int(stat.avg_response_size or 0),
            risk_score=risk_score,
            risk_level=risk_level
        ))
    
    return results
