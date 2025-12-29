import re
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
from collections import defaultdict
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, desc

from app.models import LogEvent
import app.schemas as schemas

class DataExfiltrationDetector:
    """
    Advanced data exfiltration detection engine.
    Detects data dumping, export abuse, and sensitive data leaks.
    """
    
    def __init__(
        self,
        data_threshold_mb: int = 100,  # 100MB threshold
        request_threshold: int = 1000,  # 1000 requests threshold
        time_window_hours: int = 1
    ):
        self.data_threshold_bytes = data_threshold_mb * 1024 * 1024
        self.request_threshold = request_threshold
        self.time_window = timedelta(hours=time_window_hours)
        
        # Sensitive data patterns
        self.SENSITIVE_PATTERNS = {
            'api_keys': [
                r'[A-Za-z0-9]{32,}',  # General API keys
                r'sk_live_[A-Za-z0-9]{24,}',  # Stripe keys
                r'AKIA[0-9A-Z]{16}',  # AWS keys
                r'ssh-rsa AAAAB3NzaC1yc2',  # SSH keys
            ],
            'tokens': [
                r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',  # JWT
                r'ghp_[A-Za-z0-9]{36}',  # GitHub tokens
                r'xox[baprs]-[A-Za-z0-9]{10,48}',  # Slack tokens
            ],
            'credentials': [
                r'["\']?(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
                r'["\']?(api[_-]?key|secret)["\']?\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            ],
            'personal_data': [
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b[A-Z][a-z]+ [A-Z][a-z]+\b',  # Full names
                r'\b\d{10,}\b',  # Phone numbers
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
            ]
        }
        
        # Data export endpoints
        self.EXPORT_ENDPOINTS = [
            '/export', '/download', '/backup', '/dump',
            '/api/export', '/api/download', '/data/export',
            '/reports/export', '/users/export', '/database/backup',
            '/sql/dump', '/csv/export', '/excel/export'
        ]
        
        # Sensitive data endpoints
        self.SENSITIVE_ENDPOINTS = [
            '/api/users', '/users/', '/customers/', '/patients/',
            '/api/orders', '/orders/', '/transactions/', '/payments/',
            '/api/documents', '/documents/', '/files/', '/attachments/',
            '/admin/', '/config/', '/settings/', '/secrets/'
        ]
    
    def detect_large_data_transfers(self, db: Session, hours: int = 1) -> List[Dict]:
        """
        Detect unusually large data transfers that could indicate exfiltration.
        """
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Get large transfers grouped by IP and endpoint
        large_transfers = db.query(
            LogEvent.ip,
            LogEvent.endpoint,
            func.sum(LogEvent.response_size).label('total_bytes'),
            func.count(LogEvent.id).label('request_count'),
            func.min(LogEvent.timestamp).label('first_request'),
            func.max(LogEvent.timestamp).label('last_request'),
            func.avg(LogEvent.response_size).label('avg_size')
        ).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                LogEvent.response_size > 1024,  # > 1KB per request
                LogEvent.status == 200,
                LogEvent.method == 'GET'
            )
        ).group_by(
            LogEvent.ip, LogEvent.endpoint
        ).having(
            func.sum(LogEvent.response_size) > self.data_threshold_bytes
        ).all()
        
        findings = []
        for transfer in large_transfers:
            # Calculate transfer characteristics
            time_diff = (transfer.last_request - transfer.first_request).total_seconds()
            bytes_per_second = transfer.total_bytes / max(1, time_diff)
            
            # Check if endpoint is sensitive
            is_sensitive = self._is_sensitive_endpoint(transfer.endpoint)
            is_export = self._is_export_endpoint(transfer.endpoint)
            
            # Calculate risk score
            risk_score = self._calculate_transfer_risk(
                transfer.total_bytes,
                transfer.request_count,
                bytes_per_second,
                is_sensitive,
                is_export
            )
            
            if risk_score >= 50:
                findings.append({
                    "detection_type": "large_data_transfer",
                    "ip": transfer.ip,
                    "endpoint": transfer.endpoint,
                    "total_bytes": transfer.total_bytes,
                    "total_mb": round(transfer.total_bytes / (1024 * 1024), 2),
                    "request_count": transfer.request_count,
                    "time_window_seconds": time_diff,
                    "bytes_per_second": round(bytes_per_second, 2),
                    "avg_request_size": round(transfer.avg_size or 0, 2),
                    "is_sensitive_endpoint": is_sensitive,
                    "is_export_endpoint": is_export,
                    "risk_score": risk_score,
                    "confidence": min(95, risk_score * 0.8),
                    "time_range": f"{transfer.first_request} to {transfer.last_request}",
                    "recommended_action": "Investigate user, review access logs, check for unauthorized access"
                })
        
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
    
    def detect_export_abuse(self, db: Session, hours: int = 24) -> List[Dict]:
        """
        Detect abuse of export/download endpoints.
        """
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Get export endpoint activity
        export_activity = db.query(
            LogEvent.ip,
            LogEvent.endpoint,
            func.count(LogEvent.id).label('export_count'),
            func.sum(LogEvent.response_size).label('total_exported'),
            func.count(func.distinct(LogEvent.timestamp.date())).label('unique_days'),
            func.min(LogEvent.timestamp).label('first_export'),
            func.max(LogEvent.timestamp).label('last_export')
        ).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                self._is_export_endpoint_filter()
            )
        ).group_by(
            LogEvent.ip, LogEvent.endpoint
        ).having(
            func.count(LogEvent.id) >= 5  # At least 5 exports
        ).all()
        
        findings = []
        for activity in export_activity:
            # Calculate export characteristics
            time_diff = (activity.last_export - activity.first_export).total_seconds() / 3600  # hours
            
            # High frequency exports
            if time_diff > 0:
                exports_per_hour = activity.export_count / time_diff
            else:
                exports_per_hour = activity.export_count
            
            # Multiple days of exports is suspicious
            is_multi_day = activity.unique_days > 1
            
            risk_score = self._calculate_export_risk(
                activity.export_count,
                activity.total_exported or 0,
                exports_per_hour,
                is_multi_day
            )
            
            if risk_score >= 40:
                findings.append({
                    "detection_type": "export_endpoint_abuse",
                    "ip": activity.ip,
                    "endpoint": activity.endpoint,
                    "export_count": activity.export_count,
                    "total_exported_bytes": activity.total_exported or 0,
                    "unique_days": activity.unique_days,
                    "exports_per_hour": round(exports_per_hour, 2),
                    "time_range_hours": round(time_diff, 2),
                    "is_multi_day_activity": is_multi_day,
                    "risk_score": risk_score,
                    "confidence": min(90, risk_score * 0.7),
                    "first_export": activity.first_export,
                    "last_export": activity.last_export,
                    "recommended_action": "Review export permissions, implement export quotas, audit user activity"
                })
        
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
    
    def detect_sensitive_data_leaks(self, db: Session, hours: int = 24) -> List[Dict]:
        """
        Detect potential sensitive data leaks in responses.
        """
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Get responses that might contain sensitive data
        # Note: This requires response body analysis, which may not be in logs
        # For now, we'll analyze endpoints and request patterns
        
        sensitive_endpoints = db.query(
            LogEvent.ip,
            LogEvent.endpoint,
            func.count(LogEvent.id).label('request_count'),
            func.sum(LogEvent.response_size).label('total_data'),
            func.min(LogEvent.timestamp).label('first_access'),
            func.max(LogEvent.timestamp).label('last_access')
        ).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                self._is_sensitive_endpoint_filter(),
                LogEvent.status == 200,
                LogEvent.response_size > 0
            )
        ).group_by(
            LogEvent.ip, LogEvent.endpoint
        ).all()
        
        findings = []
        for endpoint_activity in sensitive_endpoints:
            # Check for bulk access patterns
            if endpoint_activity.request_count >= 100:
                time_diff = (endpoint_activity.last_access - endpoint_activity.first_access).total_seconds()
                requests_per_second = endpoint_activity.request_count / max(1, time_diff)
                
                # Bulk access to sensitive endpoints
                if requests_per_second > 0.5:  # More than 1 request every 2 seconds
                    risk_score = self._calculate_leak_risk(
                        endpoint_activity.request_count,
                        endpoint_activity.total_data or 0,
                        requests_per_second
                    )
                    
                    findings.append({
                        "detection_type": "sensitive_data_bulk_access",
                        "ip": endpoint_activity.ip,
                        "endpoint": endpoint_activity.endpoint,
                        "request_count": endpoint_activity.request_count,
                        "total_data_bytes": endpoint_activity.total_data or 0,
                        "requests_per_second": round(requests_per_second, 2),
                        "time_window_seconds": time_diff,
                        "risk_score": risk_score,
                        "confidence": min(85, risk_score * 0.75),
                        "first_access": endpoint_activity.first_access,
                        "last_access": endpoint_activity.last_access,
                        "recommended_action": "Review user permissions, implement data access monitoring, check for compromised accounts"
                    })
        
        # Also check for specific sensitive data patterns in payloads if available
        sensitive_payloads = db.query(LogEvent).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                LogEvent.payload.isnot(None),
                LogEvent.payload != ''
            )
        ).limit(1000).all()  # Limit for performance
        
        for event in sensitive_payloads:
            if event.payload:
                sensitive_types = self._detect_sensitive_data(event.payload)
                if sensitive_types:
                    findings.append({
                        "detection_type": "sensitive_data_in_payload",
                        "timestamp": event.timestamp,
                        "ip": event.ip,
                        "endpoint": event.endpoint,
                        "sensitive_data_types": sensitive_types,
                        "payload_sample": event.payload[:200],
                        "risk_score": 70,
                        "confidence": 80,
                        "evidence_id": event.id,
                        "recommended_action": "Investigate data exposure, implement data masking, review API security"
                    })
        
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
    
    def detect_database_dumping(self, db: Session, hours: int = 1) -> List[Dict]:
        """
        Detect potential database dumping activities.
        Looks for patterns in MySQL logs or web requests that resemble dumping.
        """
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Check MySQL logs for dumping patterns
        mysql_dumps = db.query(LogEvent).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                LogEvent.source == 'mysql',
                LogEvent.payload.isnot(None),
                or_(
                    LogEvent.payload.like('SELECT * FROM %'),
                    LogEvent.payload.like('SELECT % FROM %'),
                    LogEvent.payload.like('SHOW TABLES'),
                    LogEvent.payload.like('INFORMATION_SCHEMA%'),
                    LogEvent.payload.like('UNION SELECT%')
                )
            )
        ).all()
        
        findings = []
        for event in mysql_dumps:
            # Analyze query characteristics
            query = event.payload or ''
            is_select_all = 'SELECT * FROM' in query.upper()
            has_multiple_tables = query.upper().count('FROM') > 1
            has_limit = 'LIMIT' in query.upper()
            is_info_schema = 'INFORMATION_SCHEMA' in query.upper()
            
            risk_score = self._calculate_dump_risk(
                is_select_all,
                has_multiple_tables,
                has_limit,
                is_info_schema
            )
            
            if risk_score >= 50:
                findings.append({
                    "detection_type": "database_dumping_suspected",
                    "timestamp": event.timestamp,
                    "source_ip": event.ip or 'database',
                    "query_type": "SELECT",
                    "query_sample": query[:500],
                    "is_select_all": is_select_all,
                    "has_multiple_tables": has_multiple_tables,
                    "has_limit": has_limit,
                    "is_info_schema": is_info_schema,
                    "risk_score": risk_score,
                    "confidence": min(80, risk_score * 0.7),
                    "evidence_id": event.id,
                    "recommended_action": "Review database access logs, check user permissions, implement query monitoring"
                })
        
        # Also check web requests for common dump tools/patterns
        dump_patterns = [
            '/phpmyadmin/', '/adminer/', '/mysql/dump',
            'mysqldump', 'pg_dump', 'mongodump',
            'SELECT+*+FROM', 'UNION+SELECT'
        ]
        
        for pattern in dump_patterns:
            dump_requests = db.query(LogEvent).filter(
                and_(
                    LogEvent.timestamp >= time_threshold,
                    or_(
                        LogEvent.endpoint.like(f'%{pattern}%'),
                        LogEvent.payload.like(f'%{pattern}%')
                    )
                )
            ).limit(10).all()
            
            for event in dump_requests:
                findings.append({
                    "detection_type": "dump_tool_detected",
                    "timestamp": event.timestamp,
                    "ip": event.ip,
                    "endpoint": event.endpoint,
                    "detected_pattern": pattern,
                    "risk_score": 60,
                    "confidence": 70,
                    "evidence_id": event.id,
                    "recommended_action": "Block access to dump tools, review server security, implement access controls"
                })
        
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
    
    def _is_sensitive_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint is sensitive"""
        if not endpoint:
            return False
        
        endpoint_lower = endpoint.lower()
        return any(sensitive in endpoint_lower for sensitive in self.SENSITIVE_ENDPOINTS)
    
    def _is_export_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint is an export endpoint"""
        if not endpoint:
            return False
        
        endpoint_lower = endpoint.lower()
        return any(export in endpoint_lower for export in self.EXPORT_ENDPOINTS)
    
    def _is_sensitive_endpoint_filter(self):
        """Create SQL filter for sensitive endpoints"""
        from sqlalchemy import or_
        
        filters = []
        for endpoint in self.SENSITIVE_ENDPOINTS:
            filters.append(LogEvent.endpoint.like(f'%{endpoint}%'))
        
        return or_(*filters) if filters else None
    
    def _is_export_endpoint_filter(self):
        """Create SQL filter for export endpoints"""
        from sqlalchemy import or_
        
        filters = []
        for endpoint in self.EXPORT_ENDPOINTS:
            filters.append(LogEvent.endpoint.like(f'%{endpoint}%'))
        
        return or_(*filters) if filters else None
    
    def _detect_sensitive_data(self, text: str) -> List[str]:
        """Detect sensitive data patterns in text"""
        detected_types = []
        
        for data_type, patterns in self.SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    detected_types.append(data_type)
                    break  # Found one pattern for this type
        
        return detected_types
    
    def _calculate_transfer_risk(
        self,
        total_bytes: int,
        request_count: int,
        bytes_per_second: float,
        is_sensitive: bool,
        is_export: bool
    ) -> int:
        """Calculate risk score for data transfers"""
        score = 0
        
        # Size factor
        gb = total_bytes / (1024 ** 3)
        if gb >= 1:
            score += 40
        elif gb >= 0.1:  # 100MB
            score += 30
        elif gb >= 0.01:  # 10MB
            score += 20
        elif gb >= 0.001:  # 1MB
            score += 10
        
        # Speed factor
        mbps = bytes_per_second / (1024 * 1024)
        if mbps >= 10:
            score += 30
        elif mbps >= 1:
            score += 20
        elif mbps >= 0.1:
            score += 10
        
        # Request count factor
        if request_count >= 1000:
            score += 30
        elif request_count >= 100:
            score += 20
        elif request_count >= 10:
            score += 10
        
        # Context factors
        if is_sensitive:
            score += 20
        
        if is_export:
            score += 15
        
        return min(100, score)
    
    def _calculate_export_risk(
        self,
        export_count: int,
        total_bytes: int,
        exports_per_hour: float,
        is_multi_day: bool
    ) -> int:
        """Calculate risk score for export abuse"""
        score = 0
        
        # Export frequency
        if export_count >= 50:
            score += 40
        elif export_count >= 20:
            score += 30
        elif export_count >= 10:
            score += 20
        elif export_count >= 5:
            score += 10
        
        # Export rate
        if exports_per_hour >= 10:
            score += 30
        elif exports_per_hour >= 5:
            score += 20
        elif exports_per_hour >= 1:
            score += 10
        
        # Data volume
        mb = total_bytes / (1024 * 1024)
        if mb >= 1000:
            score += 40
        elif mb >= 100:
            score += 30
        elif mb >= 10:
            score += 20
        elif mb >= 1:
            score += 10
        
        # Multi-day activity
        if is_multi_day:
            score += 15
        
        return min(100, score)
    
    def _calculate_leak_risk(
        self,
        request_count: int,
        total_bytes: int,
        requests_per_second: float
    ) -> int:
        """Calculate risk score for data leaks"""
        score = 0
        
        # Request volume
        if request_count >= 1000:
            score += 40
        elif request_count >= 500:
            score += 30
        elif request_count >= 100:
            score += 20
        elif request_count >= 50:
            score += 10
        
        # Request rate
        if requests_per_second >= 5:
            score += 30
        elif requests_per_second >= 1:
            score += 20
        elif requests_per_second >= 0.1:
            score += 10
        
        # Data volume
        mb = total_bytes / (1024 * 1024)
        if mb >= 100:
            score += 30
        elif mb >= 10:
            score += 20
        elif mb >= 1:
            score += 10
        
        return min(100, score)
    
    def _calculate_dump_risk(
        self,
        is_select_all: bool,
        has_multiple_tables: bool,
        has_limit: bool,
        is_info_schema: bool
    ) -> int:
        """Calculate risk score for database dumping"""
        score = 0
        
        if is_select_all:
            score += 30
        
        if has_multiple_tables:
            score += 25
        
        if not has_limit:  # No LIMIT is more suspicious
            score += 20
        
        if is_info_schema:
            score += 25
        
        return min(100, score)
    
    def generate_data_protection_recommendations(self, findings: List[Dict]) -> Dict:
        """Generate data protection recommendations"""
        recommendations = {
            "data_classification": "Implement data classification policy",
            "access_controls": [
                "Implement least privilege principle",
                "Use role-based access control (RBAC)",
                "Regular access reviews"
            ],
            "monitoring": [
                "Implement Data Loss Prevention (DLP)",
                "Monitor data egress points",
                "Alert on large data transfers"
            ],
            "technical_controls": [
                "Encrypt sensitive data at rest and in transit",
                "Implement data masking",
                "Use tokenization for sensitive data"
            ]
        }
        
        # Add specific recommendations based on findings
        for finding in findings:
            detection_type = finding.get("detection_type", "")
            
            if "large_data_transfer" in detection_type:
                recommendations["monitoring"].append(
                    f"Set threshold alerts for {finding.get('ip')} at {finding.get('bytes_per_second')} B/s"
                )
            
            if "export_endpoint_abuse" in detection_type:
                recommendations["access_controls"].append(
                    f"Review export permissions for {finding.get('endpoint')}"
                )
            
            if "sensitive_data" in detection_type:
                recommendations["technical_controls"].append(
                    "Implement data classification and tagging"
                )
        
        # Remove duplicates
        for key in recommendations:
            if isinstance(recommendations[key], list):
                recommendations[key] = list(set(recommendations[key]))
        
        return recommendations
