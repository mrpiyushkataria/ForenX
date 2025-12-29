# /backend/app/analysis/correlation.py
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from sqlalchemy.orm import Session, aliased
from sqlalchemy import and_, or_, func
import app.models as models

class ForensicCorrelationEngine:
    """
    Critical component: Correlates events across web → app → database layers.
    Implements timeline reconstruction for incident response.
    """
    
    def __init__(self, time_window_seconds: int = 5):
        self.time_window = timedelta(seconds=time_window_seconds)
    
    def correlate_attack_chain(self, db: Session, start_time: datetime, 
                               end_time: datetime) -> List[Dict]:
        """
        Reconstruct attack chains across log layers.
        Returns correlated events showing complete attack timeline.
        """
        # Query events from all sources in time window
        web_events = db.query(models.LogEvent).filter(
            and_(
                models.LogEvent.timestamp.between(start_time, end_time),
                models.LogEvent.source.in_(['nginx', 'apache'])
            )
        ).order_by(models.LogEvent.timestamp).all()
        
        app_events = db.query(models.LogEvent).filter(
            and_(
                models.LogEvent.timestamp.between(start_time, end_time),
                models.LogEvent.source == 'php'
            )
        ).order_by(models.LogEvent.timestamp).all()
        
        db_events = db.query(models.LogEvent).filter(
            and_(
                models.LogEvent.timestamp.between(start_time, end_time),
                models.LogEvent.source == 'mysql'
            )
        ).order_by(models.LogEvent.timestamp).all()
        
        # Correlation logic
        correlated_chains = []
        
        for web_event in web_events:
            chain = {
                'initial_request': web_event,
                'application_errors': [],
                'database_queries': [],
                'timeline': [],
                'confidence': 0.0
            }
            
            # Find related application errors (within time window)
            for app_event in app_events:
                time_diff = abs((app_event.timestamp - web_event.timestamp).total_seconds())
                if (time_diff <= self.time_window.total_seconds() and 
                    app_event.ip == web_event.ip):
                    chain['application_errors'].append(app_event)
            
            # Find related database queries
            for db_event in db_events:
                time_diff = abs((db_event.timestamp - web_event.timestamp).total_seconds())
                if time_diff <= self.time_window.total_seconds() * 2:  # Slightly wider window for DB
                    chain['database_queries'].append(db_event)
            
            # Build timeline
            all_events = [web_event] + chain['application_errors'] + chain['database_queries']
            chain['timeline'] = sorted(all_events, key=lambda x: x.timestamp)
            
            # Calculate correlation confidence
            chain['confidence'] = self._calculate_confidence(chain)
            
            if chain['confidence'] > 0.3:  # Only include meaningful correlations
                correlated_chains.append(chain)
        
        return sorted(correlated_chains, key=lambda x: x['confidence'], reverse=True)
    
    def _calculate_confidence(self, chain: Dict) -> float:
        """Calculate confidence score for correlation."""
        confidence = 0.0
        
        # Same IP boosts confidence
        if chain['initial_request'].ip:
            confidence += 0.3
        
        # Application errors after web request
        if chain['application_errors']:
            confidence += 0.3
            
            # Check if errors contain SQL or security keywords
            for error in chain['application_errors']:
                if error.payload and any(keyword in error.payload.lower() 
                                       for keyword in ['sql', 'error', 'exception', 'warning']):
                    confidence += 0.2
        
        # Database queries after web request
        if chain['database_queries']:
            confidence += 0.4
            
            # Suspicious queries increase confidence
            for query in chain['database_queries']:
                if query.payload and any(keyword in query.payload.lower()
                                       for keyword in ['select', 'union', 'insert', 'delete']):
                    confidence += 0.1
        
        return min(1.0, confidence)
    
    def find_data_exfiltration(self, db: Session, hours: int = 1) -> List[Dict]:
        """
        Detect potential data exfiltration patterns.
        Looks for: large data transfers, suspicious endpoints, rapid sequential requests.
        """
        from sqlalchemy import extract
        
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Find endpoints with large data transfers
        large_transfers = db.query(
            models.LogEvent.ip,
            models.LogEvent.endpoint,
            func.sum(models.LogEvent.response_size).label('total_bytes'),
            func.count(models.LogEvent.id).label('request_count'),
            func.min(models.LogEvent.timestamp).label('first_request'),
            func.max(models.LogEvent.timestamp).label('last_request')
        ).filter(
            models.LogEvent.timestamp >= time_threshold,
            models.LogEvent.response_size > 10000,  # > 10KB per request
            models.LogEvent.status == 200
        ).group_by(
            models.LogEvent.ip,
            models.LogEvent.endpoint
        ).having(
            func.sum(models.LogEvent.response_size) > 1000000  # > 1MB total
        ).all()
        
        findings = []
        for transfer in large_transfers:
            # Calculate data rate
            time_diff = (transfer.last_request - transfer.first_request).total_seconds()
            if time_diff > 0:
                bytes_per_second = transfer.total_bytes / time_diff
            else:
                bytes_per_second = transfer.total_bytes
            
            # Check for suspicious patterns
            suspicious = False
            reasons = []
            
            if bytes_per_second > 50000:  # > 50KB/s
                suspicious = True
                reasons.append(f"High data rate: {bytes_per_second:.0f} B/s")
            
            if transfer.request_count > 100:
                suspicious = True
                reasons.append(f"High request count: {transfer.request_count}")
            
            if any(export_keyword in (transfer.endpoint or "").lower()
                  for export_keyword in ['export', 'download', 'backup', 'dump']):
                suspicious = True
                reasons.append("Suspicious endpoint name")
            
            if suspicious:
                findings.append({
                    'ip': transfer.ip,
                    'endpoint': transfer.endpoint,
                    'total_bytes': transfer.total_bytes,
                    'request_count': transfer.request_count,
                    'duration_seconds': time_diff,
                    'bytes_per_second': bytes_per_second,
                    'suspicious_reasons': reasons,
                    'risk_score': min(95, int(bytes_per_second / 1000) + len(reasons) * 10),
                    'first_seen': transfer.first_request,
                    'last_seen': transfer.last_request
                })
        
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
