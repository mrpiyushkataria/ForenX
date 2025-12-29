import re
from datetime import datetime, timedelta
from typing import List, Dict, Set
from collections import defaultdict
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

from app.models import LogEvent
import app.schemas as schemas

class ScannerDetector:
    """
    Advanced web scanner and reconnaissance detection.
    Detects vulnerability scanners, crawlers, and reconnaissance tools.
    """
    
    def __init__(self):
        # Known scanner user agents
        self.SCANNER_USER_AGENTS = [
            # Commercial scanners
            'Nessus', 'Qualys', 'Acunetix', 'Netsparker', 'AppScan',
            'Burp Suite', 'OWASP ZAP', 'Nikto', 'sqlmap', 'WPScan',
            # Open source scanners
            'Nikto', 'Arachni', 'W3AF', 'Skipfish', 'Wfuzz',
            'DirBuster', 'Gobuster', 'FFuF', 'dirsearch',
            # Reconnaissance tools
            'nmap', 'masscan', 'zmap', 'Shodan',
            # Generic crawlers/bots (some legitimate)
            'bot', 'crawler', 'spider', 'scanner', 'checker'
        ]
        
        # Scanner path patterns
        self.SCANNER_PATHS = [
            # Common vulnerability paths
            '/phpmyadmin/', '/admin/', '/wp-admin/', '/administrator/',
            '/backup/', '/dump/', '/sql/', '/database/',
            '/config/', '/settings/', '/.env', '/.git/',
            # Common exploit paths
            '/shell', '/cmd', '/exec', '/system',
            '/cgi-bin/', '/proc/', '/etc/passwd',
            # Framework-specific
            '/vendor/', '/composer.json', '/package.json',
            '/README.md', '/LICENSE', '/CHANGELOG'
        ]
        
        # Suspicious request patterns
        self.SUSPICIOUS_PATTERNS = [
            # SQL injection attempts
            r'[\'"]\s*(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s*[\'"]?',
            # Path traversal
            r'(\.\./){2,}', r'%2e%2e%2f', r'\.\.%2f',
            # Command injection
            r'(\|\||&&|;|\`|\$\(|\n|\r)',
            # XSS attempts
            r'<script', r'javascript:', r'on\w+\s*=',
            # File inclusion
            r'(include|require)(_once)?\s*[\'"]',
            # Information disclosure
            r'phpinfo\(\)', r'server-info', r'server-status'
        ]
    
    def detect_web_scanners(self, db: Session, hours: int = 1) -> List[Dict]:
        """
        Detect web vulnerability scanners.
        """
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Get requests with scanner indicators
        scanner_indicators = db.query(LogEvent).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                or_(
                    # Scanner user agents
                    *[LogEvent.payload.like(f'%{agent}%') for agent in self.SCANNER_USER_AGENTS],
                    # Scanner paths
                    *[LogEvent.endpoint.like(f'%{path}%') for path in self.SCANNER_PATHS],
                    # Suspicious patterns in payload
                    *[LogEvent.payload.regexp_match(pattern) for pattern in self.SUSPICIOUS_PATTERNS]
                )
            )
        ).all()
        
        # Group by IP
        ip_activity = defaultdict(lambda: {
            'requests': [],
            'user_agents': set(),
            'endpoints': set(),
            'suspicious_patterns': set(),
            'timestamps': []
        })
        
        for event in scanner_indicators:
            ip_data = ip_activity[event.ip]
            ip_data['requests'].append(event)
            ip_data['timestamps'].append(event.timestamp)
            
            # Extract user agent from payload
            if event.payload:
                ua = self._extract_user_agent(event.payload)
                if ua:
                    ip_data['user_agents'].add(ua)
            
            if event.endpoint:
                ip_data['endpoints'].add(event.endpoint)
            
            # Check for suspicious patterns
            if event.payload:
                for pattern in self.SUSPICIOUS_PATTERNS:
                    if re.search(pattern, event.payload, re.IGNORECASE):
                        ip_data['suspicious_patterns'].add(pattern)
                        break
        
        findings = []
        for ip, data in ip_activity.items():
            if len(data['requests']) >= 5:  # Minimum requests for scanner detection
                # Calculate metrics
                request_count = len(data['requests'])
                unique_endpoints = len(data['endpoints'])
                unique_user_agents = len(data['user_agents'])
                suspicious_patterns = len(data['suspicious_patterns'])
                
                # Time analysis
                if len(data['timestamps']) >= 2:
                    time_range = max(data['timestamps']) - min(data['timestamps'])
                    requests_per_second = request_count / max(1, time_range.total_seconds())
                else:
                    requests_per_second = request_count
                
                # Determine scanner type
                scanner_type = self._determine_scanner_type(
                    data['user_agents'],
                    data['endpoints'],
                    data['suspicious_patterns']
                )
                
                risk_score = self._calculate_scanner_risk(
                    request_count,
                    unique_endpoints,
                    unique_user_agents,
                    suspicious_patterns,
                    requests_per_second,
                    scanner_type
                )
                
                if risk_score >= 40:
                    findings.append({
                        "detection_type": "web_scanner",
                        "ip": ip,
                        "scanner_type": scanner_type,
                        "request_count": request_count,
                        "unique_endpoints": unique_endpoints,
                        "unique_user_agents": list(data['user_agents'])[:5],
                        "suspicious_patterns": list(data['suspicious_patterns'])[:10],
                        "endpoints_sampled": list(data['endpoints'])[:10],
                        "requests_per_second": round(requests_per_second, 2),
                        "time_range": f"{min(data['timestamps'])} to {max(data['timestamps'])}",
                        "risk_score": risk_score,
                        "confidence": min(95, risk_score * 0.8),
                        "recommended_action": "Block IP, implement WAF rules, review server logs"
                    })
        
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
    
    def detect_crawlers_bots(self, db: Session, hours: int = 1) -> List[Dict]:
        """
        Detect automated crawlers and bots (both legitimate and malicious).
        """
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Get requests that look like crawlers
        crawler_requests = db.query(
            LogEvent.ip,
            func.count(LogEvent.id).label('request_count'),
            func.count(func.distinct(LogEvent.endpoint)).label('unique_endpoints'),
            func.min(LogEvent.timestamp).label('first_request'),
            func.max(LogEvent.timestamp).label('last_request')
        ).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                LogEvent.payload.isnot(None),
                or_(
                    *[LogEvent.payload.like(f'%{bot}%') for bot in ['bot', 'crawler', 'spider']]
                )
            )
        ).group_by(LogEvent.ip).having(
            func.count(LogEvent.id) >= 10  # Minimum requests
        ).all()
        
        findings = []
        for crawler in crawler_requests:
            # Calculate metrics
            time_diff = (crawler.last_request - crawler.first_request).total_seconds()
            requests_per_second = crawler.request_count / max(1, time_diff)
            
            # Get user agents for this IP
            user_agents = db.query(
                func.distinct(LogEvent.payload)
            ).filter(
                and_(
                    LogEvent.timestamp >= time_threshold,
                    LogEvent.ip == crawler.ip,
                    LogEvent.payload.isnot(None),
                    or_(
                        *[LogEvent.payload.like(f'%{bot}%') for bot in ['bot', 'crawler', 'spider']]
                    )
                )
            ).limit(5).all()
            
            ua_list = [ua[0][:100] for ua in user_agents if ua[0]]
            
            # Determine if malicious
            is_malicious = self._is_malicious_crawler(
                crawler.request_count,
                crawler.unique_endpoints,
                requests_per_second,
                ua_list
            )
            
            risk_score = self._calculate_crawler_risk(
                crawler.request_count,
                crawler.unique_endpoints,
                requests_per_second,
                is_malicious
            )
            
            findings.append({
                "detection_type": "crawler_bot",
                "ip": crawler.ip,
                "is_malicious": is_malicious,
                "request_count": crawler.request_count,
                "unique_endpoints": crawler.unique_endpoints,
                "requests_per_second": round(requests_per_second, 2),
                "user_agents": ua_list,
                "time_range": f"{crawler.first_request} to {crawler.last_request}",
                "risk_score": risk_score,
                "confidence": min(90, risk_score * 0.7),
                "recommended_action": "Verify robots.txt, implement rate limiting, check for content scraping"
            })
        
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
    
    def detect_port_scanners(self, db: Session, hours: int = 1) -> List[Dict]:
        """
        Detect port scanning activity from web logs.
        Looks for requests to non-existent endpoints on unusual ports.
        """
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Get 404 errors to unusual endpoints
        not_found_requests = db.query(
            LogEvent.ip,
            func.count(LogEvent.id).label('error_count'),
            func.count(func.distinct(LogEvent.endpoint)).label('unique_errors'),
            func.min(LogEvent.timestamp).label('first_error'),
            func.max(LogEvent.timestamp).label('last_error')
        ).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                LogEvent.status == 404,
                LogEvent.endpoint.isnot(None)
            )
        ).group_by(LogEvent.ip).having(
            func.count(LogEvent.id) >= 20  # High 404 count indicates scanning
        ).all()
        
        findings = []
        for scan in not_found_requests:
            # Calculate scan metrics
            time_diff = (scan.last_error - scan.first_error).total_seconds()
            errors_per_second = scan.error_count / max(1, time_diff)
            
            # Get sample endpoints to analyze patterns
            endpoints = db.query(
                LogEvent.endpoint
            ).filter(
                and_(
                    LogEvent.timestamp >= time_threshold,
                    LogEvent.ip == scan.ip,
                    LogEvent.status == 404
                )
            ).limit(20).all()
            
            endpoint_samples = [ep[0] for ep in endpoints if ep[0]]
            
            # Analyze for scanning patterns
            is_port_scan = self._detect_port_scan_patterns(endpoint_samples)
            is_dir_scan = self._detect_directory_scan_patterns(endpoint_samples)
            
            scan_type = "unknown"
            if is_port_scan:
                scan_type = "port_scan"
            elif is_dir_scan:
                scan_type = "directory_scan"
            
            risk_score = self._calculate_scan_risk(
                scan.error_count,
                scan.unique_errors,
                errors_per_second,
                scan_type
            )
            
            if risk_score >= 50:
                findings.append({
                    "detection_type": "port_directory_scan",
                    "ip": scan.ip,
                    "scan_type": scan_type,
                    "error_count": scan.error_count,
                    "unique_errors": scan.unique_errors,
                    "errors_per_second": round(errors_per_second, 2),
                    "endpoint_samples": endpoint_samples[:10],
                    "time_range": f"{scan.first_error} to {scan.last_error}",
                    "risk_score": risk_score,
                    "confidence": min(85, risk_score * 0.75),
                    "recommended_action": "Block IP, implement fail2ban, monitor for further reconnaissance"
                })
        
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
    
    def _extract_user_agent(self, payload: str) -> Optional[str]:
        """Extract User-Agent from payload"""
        if not payload:
            return None
        
        # Look for User-Agent header
        ua_patterns = [
            r'User-Agent:\s*([^\r\n]+)',
            r'"user-agent"\s*:\s*"([^"]+)"',
            r'user-agent=([^&\s]+)'
        ]
        
        for pattern in ua_patterns:
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                return match.group(1).strip()[:200]
        
        return None
    
    def _determine_scanner_type(
        self,
        user_agents: Set[str],
        endpoints: Set[str],
        suspicious_patterns: Set[str]
    ) -> str:
        """Determine the type of scanner based on indicators"""
        scanner_type = "unknown"
        
        # Check for specific scanner signatures
        ua_str = ' '.join(user_agents).lower()
        endpoints_str = ' '.join(endpoints).lower()
        
        if any(scanner in ua_str for scanner in ['nessus', 'qualys', 'acunetix']):
            scanner_type = "commercial_vulnerability_scanner"
        elif any(scanner in ua_str for scanner in ['burp', 'zap', 'nikto']):
            scanner_type = "security_testing_tool"
        elif any(scanner in ua_str for scanner in ['sqlmap', 'wpscan']):
            scanner_type = "specific_vulnerability_scanner"
        elif any(scanner in ua_str for scanner in ['nmap', 'masscan']):
            scanner_type = "port_scanner"
        elif 'sql' in endpoints_str or 'union' in ' '.join(suspicious_patterns).lower():
            scanner_type = "sql_injection_scanner"
        elif 'script' in endpoints_str or 'xss' in endpoints_str:
            scanner_type = "xss_scanner"
        elif len(endpoints) > 50 and '/admin' in endpoints_str:
            scanner_type = "admin_panel_scanner"
        elif any(ep for ep in endpoints if '.git' in ep or '.env' in ep):
            scanner_type = "information_disclosure_scanner"
        
        return scanner_type
    
    def _is_malicious_crawler(
        self,
        request_count: int,
        unique_endpoints: int,
        requests_per_second: float,
        user_agents: List[str]
    ) -> bool:
        """Determine if crawler is malicious"""
        # High request rate
        if requests_per_second > 10:
            return True
        
        # High unique endpoint exploration
        if unique_endpoints > 100 and request_count > 200:
            return True
        
        # Suspicious user agents
        malicious_agents = ['sqlmap', 'nikto', 'acunetix', 'nessus', 'anonymous']
        for ua in user_agents:
            if any(malicious in ua.lower() for malicious in malicious_agents):
                return True
        
        # No user agent or fake user agent
        if not user_agents or any('curl' in ua.lower() for ua in user_agents):
            if requests_per_second > 2:
                return True
        
        return False
    
    def _detect_port_scan_patterns(self, endpoints: List[str]) -> bool:
        """Detect port scanning patterns in endpoints"""
        if not endpoints:
            return False
        
        # Check for numeric patterns that look like ports
        port_patterns = [
            r':\d{2,5}/',  # :8080/
            r'/\d{2,5}$',  # /8080
            r'\.\d{3,5}$'  # .8080
        ]
        
        port_count = 0
        for endpoint in endpoints:
            for pattern in port_patterns:
                if re.search(pattern, endpoint):
                    port_count += 1
                    break
        
        # If more than 30% of endpoints look like ports
        return port_count > len(endpoints) * 0.3
    
    def _detect_directory_scan_patterns(self, endpoints: List[str]) -> bool:
        """Detect directory brute force patterns"""
        if not endpoints:
            return False
        
        # Common directory names in brute force attempts
        common_dirs = [
            'admin', 'backup', 'config', 'database', 'sql',
            'wp-admin', 'phpmyadmin', 'administrator',
            'cgi-bin', 'bin', 'etc', 'proc', 'sys',
            '.git', '.svn', '.env', '.htaccess'
        ]
        
        dir_count = 0
        for endpoint in endpoints:
            endpoint_lower = endpoint.lower()
            if any(dir_name in endpoint_lower for dir_name in common_dirs):
                dir_count += 1
        
        # If many common directories are accessed
        return dir_count > len(endpoints) * 0.4
    
    def _calculate_scanner_risk(
        self,
        request_count: int,
        unique_endpoints: int,
        unique_user_agents: int,
        suspicious_patterns: int,
        requests_per_second: float,
        scanner_type: str
    ) -> int:
        """Calculate risk score for scanner detection"""
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
        
        # Endpoint diversity
        if unique_endpoints >= 200:
            score += 30
        elif unique_endpoints >= 100:
            score += 20
        elif unique_endpoints >= 50:
            score += 10
        
        # Request rate
        if requests_per_second >= 20:
            score += 30
        elif requests_per_second >= 10:
            score += 20
        elif requests_per_second >= 5:
            score += 10
        
        # Suspicious patterns
        if suspicious_patterns >= 5:
            score += 25
        elif suspicious_patterns >= 3:
            score += 15
        elif suspicious_patterns >= 1:
            score += 5
        
        # Scanner type modifiers
        type_scores = {
            "commercial_vulnerability_scanner": 20,
            "security_testing_tool": 15,
            "specific_vulnerability_scanner": 25,
            "port_scanner": 20,
            "sql_injection_scanner": 30,
            "xss_scanner": 25,
            "admin_panel_scanner": 20,
            "information_disclosure_scanner": 25
        }
        
        score += type_scores.get(scanner_type, 10)
        
        return min(100, score)
    
    def _calculate_crawler_risk(
        self,
        request_count: int,
        unique_endpoints: int,
        requests_per_second: float,
        is_malicious: bool
    ) -> int:
        """Calculate risk score for crawler detection"""
        score = 0
        
        # Basic metrics
        if request_count >= 500:
            score += 30
        elif request_count >= 200:
            score += 20
        elif request_count >= 50:
            score += 10
        
        if unique_endpoints >= 100:
            score += 20
        elif unique_endpoints >= 50:
            score += 10
        
        if requests_per_second >= 5:
            score += 20
        elif requests_per_second >= 2:
            score += 10
        
        # Malicious modifier
        if is_malicious:
            score += 30
        
        return min(100, score)
    
    def _calculate_scan_risk(
        self,
        error_count: int,
        unique_errors: int,
        errors_per_second: float,
        scan_type: str
    ) -> int:
        """Calculate risk score for scan detection"""
        score = 0
        
        # Error volume
        if error_count >= 500:
            score += 40
        elif error_count >= 200:
            score += 30
        elif error_count >= 100:
            score += 20
        elif error_count >= 50:
            score += 10
        
        # Error diversity
        if unique_errors >= 100:
            score += 30
        elif unique_errors >= 50:
            score += 20
        elif unique_errors >= 20:
            score += 10
        
        # Error rate
        if errors_per_second >= 10:
            score += 30
        elif errors_per_second >= 5:
            score += 20
        elif errors_per_second >= 1:
            score += 10
        
        # Scan type modifier
        if scan_type == "port_scan":
            score += 20
        elif scan_type == "directory_scan":
            score += 15
        
        return min(100, score)
    
    def generate_scanner_protection_recommendations(self, findings: List[Dict]) -> Dict:
        """Generate protection recommendations against scanners"""
        recommendations = {
            "immediate_actions": [],
            "waf_rules": [],
            "server_configuration": [],
            "monitoring": []
        }
        
        for finding in findings:
            detection_type = finding.get("detection_type", "")
            scanner_type = finding.get("scanner_type", "")
            ip = finding.get("ip", "")
            
            if detection_type == "web_scanner":
                recommendations["immediate_actions"].append(f"Block IP {ip}")
                
                if "sql_injection" in scanner_type:
                    recommendations["waf_rules"].extend([
                        "Enable SQL injection protection",
                        "Block requests with SQL keywords"
                    ])
                
                if "xss" in scanner_type:
                    recommendations["waf_rules"].extend([
                        "Enable XSS protection",
                        "Sanitize all user inputs"
                    ])
            
            elif detection_type == "port_directory_scan":
                recommendations["server_configuration"].extend([
                    "Configure fail2ban for repeated 404s",
                    "Hide server banners and version info",
                    "Use non-standard ports for services"
                ])
                
                recommendations["monitoring"].append(
                    f"Monitor IP {ip} for further reconnaissance"
                )
        
        # General recommendations
        recommendations["general"] = [
            "Implement rate limiting per IP",
            "Use Web Application Firewall (WAF)",
            "Regular security scanning",
            "Keep software updated",
            "Use security headers (X-Content-Type-Options, X-Frame-Options, etc.)"
        ]
        
        # Remove duplicates
        for key in recommendations:
            recommendations[key] = list(set(recommendations[key]))
        
        return recommendations
