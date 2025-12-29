import re
from typing import List, Dict, Tuple
from sqlalchemy.orm import Session
from datetime import datetime, timedelta

from app.models import LogEvent
import app.schemas as schemas

class XSSDetector:
    """
    Advanced Cross-Site Scripting (XSS) detection engine.
    Detects reflected, stored, and DOM-based XSS attempts.
    """
    
    # XSS attack patterns (OWASP XSS Filter Evasion Cheat Sheet based)
    XSS_PATTERNS = {
        'basic_script': [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'alert\(.*?\)',
            r'confirm\(.*?\)',
            r'prompt\(.*?\)'
        ],
        'event_handlers': [
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',
            r'onfocus\s*=',
            r'onblur\s*='
        ],
        'svg_xss': [
            r'<svg.*?>',
            r'<img.*?src=.*?>',
            r'<iframe.*?>',
            r'<object.*?>',
            r'<embed.*?>'
        ],
        'data_protocol': [
            r'data:text/html',
            r'data:text/javascript',
            r'data:image/svg\+xml'
        ],
        'encoding_evasion': [
            r'&#x?[0-9a-f]+;',
            r'\\u[0-9a-f]{4}',
            r'\\x[0-9a-f]{2}'
        ],
        'special_chars': [
            r'%3C', r'%3E',  # URL encoded < >
            r'&lt;', r'&gt;',  # HTML entities
            r'\x3C', r'\x3E'   # Hex encoded
        ],
        'bypass_attempts': [
            r'<scr<script>ipt>',  # Nested tags
            r'<SCRipt>',  # Mixed case
            r'<script/xss>',
            r'<script\n>',
            r'<script\t>'
        ]
    }
    
    # Suspicious parameter names
    SUSPICIOUS_PARAMS = [
        'q', 'search', 'query', 'term', 'keywords',
        'name', 'title', 'description', 'content',
        'url', 'redirect', 'return', 'next',
        'email', 'username', 'user', 'login',
        'comment', 'message', 'feedback',
        'id', 'ref', 'referrer'
    ]
    
    def __init__(self, confidence_threshold: float = 0.6):
        self.confidence_threshold = confidence_threshold
        
    def detect_in_events(self, db: Session, hours: int = 24) -> List[Dict]:
        """
        Detect XSS attempts in web request payloads.
        """
        from sqlalchemy import and_, or_
        
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Get events with potential XSS indicators
        events = db.query(LogEvent).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                LogEvent.payload.isnot(None),
                LogEvent.payload != '',
                or_(
                    LogEvent.source.in_(['nginx', 'apache']),
                    LogEvent.method.in_(['GET', 'POST', 'PUT'])
                )
            )
        ).all()
        
        findings = []
        for event in events:
            if event.payload:
                score, patterns, context = self.analyze_payload(event.payload, event.endpoint)
                
                if score >= 50:  # Medium threshold for XSS
                    findings.append({
                        "timestamp": event.timestamp,
                        "source": event.source,
                        "ip": event.ip,
                        "endpoint": event.endpoint,
                        "method": event.method,
                        "payload_sample": event.payload[:200],
                        "risk_score": score,
                        "confidence": min(95, score),
                        "matched_patterns": patterns,
                        "attack_context": context,
                        "evidence_id": event.id,
                        "recommended_action": "Block IP, sanitize input, implement CSP"
                    })
        
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
    
    def analyze_payload(self, payload: str, endpoint: str = None) -> Tuple[int, List[str], str]:
        """
        Analyze payload for XSS patterns with context awareness.
        Returns: (risk_score, matched_patterns, context)
        """
        if not payload:
            return 0, [], "no_payload"
        
        payload_lower = payload.lower()
        score = 0
        matched_patterns = []
        
        # Check each pattern category
        for category, patterns in self.XSS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, payload_lower, re.IGNORECASE):
                    matched_patterns.append(f"{category}:{pattern}")
                    
                    # Weight different categories
                    if category in ['basic_script', 'svg_xss', 'data_protocol']:
                        score += 25
                    elif category in ['event_handlers', 'bypass_attempts']:
                        score += 20
                    else:
                        score += 15
        
        # Context analysis
        context = self._analyze_context(payload, endpoint)
        
        # Context modifiers
        if context == "reflected_param":
            score += 20  # Reflected XSS is more dangerous
        
        if self._contains_encoded_xss(payload):
            score += 15
            matched_patterns.append("encoded_xss")
        
        if self._is_suspicious_parameter(payload, endpoint):
            score += 10
            matched_patterns.append("suspicious_parameter")
        
        # Length heuristic (very long payloads)
        if len(payload) > 500:
            score += 10
            matched_patterns.append("long_payload")
        
        # Cap at 100
        return min(100, score), matched_patterns, context
    
    def _analyze_context(self, payload: str, endpoint: str) -> str:
        """Analyze the context where XSS might occur"""
        if not endpoint:
            return "unknown"
        
        # Check if payload appears in URL parameters
        if '?' in endpoint and payload:
            # Simple check: see if payload values appear after ?
            query_part = endpoint.split('?')[1]
            param_pairs = query_part.split('&')
            
            for param_pair in param_pairs:
                if '=' in param_pair:
                    param_name, param_value = param_pair.split('=', 1)
                    if payload in param_value or param_value in payload:
                        return "reflected_param"
        
        # Check common XSS injection points
        xss_keywords = ['search', 'q', 'query', 'comment', 'message']
        for keyword in xss_keywords:
            if keyword in endpoint.lower():
                return f"potential_{keyword}_injection"
        
        return "generic"
    
    def _contains_encoded_xss(self, payload: str) -> bool:
        """Check for encoded XSS attempts"""
        # Common encoded patterns
        encoded_patterns = [
            r'%3Cscript%3E',  # URL encoded <script>
            r'&lt;script&gt;',  # HTML entities
            r'\x3cscript\x3e',  # Hex encoded
            r'\\u003cscript\\u003e',  # Unicode
        ]
        
        for pattern in encoded_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        
        return False
    
    def _is_suspicious_parameter(self, payload: str, endpoint: str) -> bool:
        """Check if payload is in a suspicious parameter"""
        if not endpoint or '?' not in endpoint:
            return False
        
        query_part = endpoint.split('?')[1]
        param_pairs = query_part.split('&')
        
        for param_pair in param_pairs:
            if '=' in param_pair:
                param_name, param_value = param_pair.split('=', 1)
                
                # Check if parameter name is suspicious
                if any(suspicious in param_name.lower() for suspicious in self.SUSPICIOUS_PARAMS):
                    # Check if payload matches parameter value
                    if payload in param_value or param_value in payload:
                        return True
        
        return False
    
    def detect_stored_xss_indicators(self, db: Session) -> List[Dict]:
        """
        Detect indicators of potential stored XSS.
        Looks for POST/PUT requests with XSS patterns to data storage endpoints.
        """
        from sqlalchemy import and_, or_
        
        # Endpoints that typically store data
        storage_endpoints = [
            '/api/comments', '/api/posts', '/api/articles',
            '/api/messages', '/api/feedback', '/api/reviews',
            '/admin/content', '/wp-admin/post.php',
            '/submit', '/post', '/comment'
        ]
        
        time_threshold = datetime.utcnow() - timedelta(hours=24)
        
        events = db.query(LogEvent).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                LogEvent.method.in_(['POST', 'PUT']),
                LogEvent.payload.isnot(None),
                LogEvent.payload != '',
                or_(
                    *[LogEvent.endpoint.like(f'%{ep}%') for ep in storage_endpoints]
                )
            )
        ).all()
        
        findings = []
        for event in events:
            score, patterns, _ = self.analyze_payload(event.payload, event.endpoint)
            
            if score >= 40:
                findings.append({
                    "type": "stored_xss_indicator",
                    "timestamp": event.timestamp,
                    "ip": event.ip,
                    "endpoint": event.endpoint,
                    "method": event.method,
                    "risk_score": score + 10,  # Bonus for storage context
                    "confidence": min(95, score),
                    "matched_patterns": patterns,
                    "evidence": f"POST/PUT to storage endpoint with XSS patterns",
                    "severity": "HIGH" if score >= 60 else "MEDIUM"
                })
        
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
    
    def generate_csp_report(self, findings: List[Dict]) -> Dict:
        """
        Generate Content Security Policy recommendations based on findings.
        """
        directives = {
            "default-src": ["'self'"],
            "script-src": ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:"],
            "connect-src": ["'self'"],
            "font-src": ["'self'"],
            "object-src": ["'none'"],
            "media-src": ["'self'"],
            "frame-src": ["'none'"],
            "sandbox": ["allow-forms", "allow-same-origin", "allow-scripts"],
            "report-uri": ["/api/csp-report"],
            "require-trusted-types-for": ["'script'"]
        }
        
        # Adjust based on findings
        for finding in findings:
            if "svg_xss" in str(finding.get("matched_patterns", [])):
                directives["img-src"].remove("data:")
            
            if "data_protocol" in str(finding.get("matched_patterns", [])):
                directives["script-src"].remove("'unsafe-inline'")
                directives["script-src"].remove("'unsafe-eval'")
        
        return {
            "csp_directives": directives,
            "csp_header": "; ".join([f"{k} {' '.join(v)}" for k, v in directives.items()]),
            "recommendations": [
                "Implement strict CSP",
                "Use trusted types for DOM manipulation",
                "Sanitize all user inputs",
                "Use HTTP-only cookies",
                "Implement X-Frame-Options: DENY"
            ]
        }
