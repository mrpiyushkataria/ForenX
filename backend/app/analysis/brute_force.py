import re
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
from collections import defaultdict
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

from app.models import LogEvent
import app.schemas as schemas

class BruteForceDetector:
    """
    Advanced brute force attack detection.
    Detects credential stuffing, password spraying, and login flooding.
    """
    
    def __init__(
        self,
        failed_threshold: int = 10,  # Failed attempts per IP per hour
        success_ratio_threshold: float = 0.1,  # Max 10% success rate
        time_window_minutes: int = 5
    ):
        self.failed_threshold = failed_threshold
        self.success_ratio_threshold = success_ratio_threshold
        self.time_window = timedelta(minutes=time_window_minutes)
        
        # Login endpoint patterns
        self.LOGIN_ENDPOINTS = [
            '/login', '/signin', '/auth', '/authenticate',
            '/wp-login.php', '/admin/login', '/api/login',
            '/oauth/token', '/token', '/sessions'
        ]
        
        # Failed status codes and patterns
        self.FAILED_PATTERNS = [
            (401, 'Unauthorized'),
            (403, 'Forbidden'),
            (422, 'Unprocessable Entity')
        ]
        
        # Success patterns
        self.SUCCESS_PATTERNS = [
            (200, 'OK'),
            (302, 'Found'),  # Redirect after login
            (303, 'See Other')
        ]
    
    def detect_credential_stuffing(self, db: Session, hours: int = 1) -> List[Dict]:
        """
        Detect credential stuffing attacks.
        Multiple failed logins from same IP with different usernames.
        """
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Get failed login attempts
        failed_logins = db.query(LogEvent).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                self._is_login_endpoint(LogEvent.endpoint),
                or_(
                    *[LogEvent.status == code for code, _ in self.FAILED_PATTERNS]
                )
            )
        ).all()
        
        # Group by IP and analyze
        ip_data = defaultdict(lambda: {
            'attempts': 0,
            'usernames': set(),
            'endpoints': set(),
            'timestamps': []
        })
        
        for event in failed_logins:
            ip_data[event.ip]['attempts'] += 1
            ip_data[event.ip]['timestamps'].append(event.timestamp)
            
            # Extract username from payload if possible
            username = self._extract_username(event.payload, event.endpoint)
            if username:
                ip_data[event.ip]['usernames'].add(username)
            
            ip_data[event.ip]['endpoints'].add(event.endpoint)
        
        # Analyze for credential stuffing
        findings = []
        for ip, data in ip_data.items():
            if data['attempts'] >= self.failed_threshold:
                # Check for multiple usernames from same IP
                unique_usernames = len(data['usernames'])
                
                if unique_usernames >= 3:  # Multiple usernames indicates stuffing
                    # Calculate attempt rate
                    if len(data['timestamps']) >= 2:
                        time_range = max(data['timestamps']) - min(data['timestamps'])
                        minutes = max(1, time_range.total_seconds() / 60)
                        attempts_per_minute = data['attempts'] / minutes
                    else:
                        attempts_per_minute = data['attempts']
                    
                    risk_score = self._calculate_bruteforce_score(
                        data['attempts'],
                        unique_usernames,
                        attempts_per_minute
                    )
                    
                    findings.append({
                        "attack_type": "credential_stuffing",
                        "ip": ip,
                        "attempts": data['attempts'],
                        "unique_usernames": unique_usernames,
                        "endpoints": list(data['endpoints']),
                        "attempts_per_minute": round(attempts_per_minute, 2),
                        "time_range": f"{min(data['timestamps'])} to {max(data['timestamps'])}",
                        "risk_score": risk_score,
                        "confidence": min(95, risk_score * 0.8),
                        "evidence_count": data['attempts'],
                        "recommended_action": "Block IP, enable account lockout, implement CAPTCHA"
                    })
        
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
    
    def detect_password_spraying(self, db: Session, hours: int = 6) -> List[Dict]:
        """
        Detect password spraying attacks.
        Same password used across multiple usernames.
        """
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Get login attempts with payloads
        login_attempts = db.query(LogEvent).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                self._is_login_endpoint(LogEvent.endpoint),
                LogEvent.payload.isnot(None),
                LogEvent.payload != ''
            )
        ).all()
        
        # Extract credentials from payloads
        attempts = []
        for event in login_attempts:
            credentials = self._extract_credentials(event.payload)
            if credentials:
                attempts.append({
                    'ip': event.ip,
                    'timestamp': event.timestamp,
                    'endpoint': event.endpoint,
                    'status': event.status,
                    'username': credentials.get('username'),
                    'password_hash': hash(credentials.get('password', ''))  # Hash for comparison
                })
        
        # Group by IP and analyze password reuse
        ip_data = defaultdict(lambda: {
            'attempts': [],
            'password_hashes': set(),
            'usernames': set()
        })
        
        for attempt in attempts:
            ip_data[attempt['ip']]['attempts'].append(attempt)
            if attempt['password_hash']:
                ip_data[attempt['ip']]['password_hashes'].add(attempt['password_hash'])
            if attempt['username']:
                ip_data[attempt['ip']]['usernames'].add(attempt['username'])
        
        # Detect password spraying
        findings = []
        for ip, data in ip_data.items():
            if len(data['attempts']) >= 5:  # Minimum attempts for spraying detection
                # Password spraying: few passwords used across many usernames
                password_count = len(data['password_hashes'])
                username_count = len(data['usernames'])
                
                if username_count >= 3 and password_count <= 2:
                    # Calculate statistics
                    failed_attempts = sum(1 for a in data['attempts'] if a['status'] in [401, 403])
                    success_attempts = sum(1 for a in data['attempts'] if a['status'] in [200, 302])
                    
                    risk_score = self._calculate_spraying_score(
                        len(data['attempts']),
                        username_count,
                        password_count,
                        failed_attempts,
                        success_attempts
                    )
                    
                    findings.append({
                        "attack_type": "password_spraying",
                        "ip": ip,
                        "total_attempts": len(data['attempts']),
                        "unique_usernames": username_count,
                        "unique_passwords": password_count,
                        "failed_attempts": failed_attempts,
                        "successful_attempts": success_attempts,
                        "success_rate": round(success_attempts / len(data['attempts']) * 100, 2),
                        "risk_score": risk_score,
                        "confidence": min(90, risk_score * 0.7),
                        "time_range": f"{min(a['timestamp'] for a in data['attempts'])} to {max(a['timestamp'] for a in data['attempts'])}",
                        "recommended_action": "Block IP, enforce strong passwords, monitor for compromised accounts"
                    })
        
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
    
    def detect_login_flooding(self, db: Session, window_minutes: int = 5) -> List[Dict]:
        """
        Detect login flooding/DoS attacks on authentication endpoints.
        """
        time_threshold = datetime.utcnow() - timedelta(minutes=window_minutes)
        
        # Get all login attempts in time window
        login_attempts = db.query(
            LogEvent.ip,
            func.count(LogEvent.id).label('attempts'),
            func.min(LogEvent.timestamp).label('first_attempt'),
            func.max(LogEvent.timestamp).label('last_attempt')
        ).filter(
            and_(
                LogEvent.timestamp >= time_threshold,
                self._is_login_endpoint(LogEvent.endpoint)
            )
        ).group_by(LogEvent.ip).all()
        
        findings = []
        for attempt in login_attempts:
            if attempt.attempts >= 20:  # High threshold for flooding
                # Calculate rate
                time_diff = (attempt.last_attempt - attempt.first_attempt).total_seconds()
                if time_diff > 0:
                    attempts_per_second = attempt.attempts / time_diff
                else:
                    attempts_per_second = attempt.attempts
                
                # Get success/failure ratio
                success_failure = db.query(
                    func.sum(func.case((LogEvent.status.in_([200, 302]), 1), else_=0)).label('success'),
                    func.sum(func.case((LogEvent.status.in_([401, 403]), 1), else_=0)).label('failed')
                ).filter(
                    and_(
                        LogEvent.timestamp >= time_threshold,
                        LogEvent.ip == attempt.ip,
                        self._is_login_endpoint(LogEvent.endpoint)
                    )
                ).first()
                
                success_count = success_failure.success or 0
                failed_count = success_failure.failed or 0
                success_rate = success_count / attempt.attempts if attempt.attempts > 0 else 0
                
                # Low success rate indicates brute force
                if success_rate < self.success_ratio_threshold:
                    risk_score = self._calculate_flooding_score(
                        attempt.attempts,
                        attempts_per_second,
                        success_rate
                    )
                    
                    findings.append({
                        "attack_type": "login_flooding",
                        "ip": attempt.ip,
                        "attempts": attempt.attempts,
                        "time_window_seconds": time_diff,
                        "attempts_per_second": round(attempts_per_second, 2),
                        "successful_logins": success_count,
                        "failed_logins": failed_count,
                        "success_rate": round(success_rate * 100, 2),
                        "risk_score": risk_score,
                        "confidence": min(95, risk_score * 0.9),
                        "time_range": f"{attempt.first_attempt} to {attempt.last_attempt}",
                        "recommended_action": "Rate limit IP, implement exponential backoff, enable WAF rules"
                    })
        
        return sorted(findings, key=lambda x: x['risk_score'], reverse=True)
    
    def _is_login_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint is a login endpoint"""
        if not endpoint:
            return False
        
        endpoint_lower = endpoint.lower()
        return any(login_ep in endpoint_lower for login_ep in self.LOGIN_ENDPOINTS)
    
    def _extract_username(self, payload: str, endpoint: str) -> Optional[str]:
        """Extract username from login payload"""
        if not payload:
            return None
        
        # Common username field patterns
        username_patterns = [
            r'username[=:]["\']?([^&"\'\s]+)',
            r'user[=:]["\']?([^&"\'\s]+)',
            r'email[=:]["\']?([^&"\'\s]+)',
            r'login[=:]["\']?([^&"\'\s]+)',
            r'["\']?user["\']?\s*:\s*["\']([^"\']+)["\']',
            r'["\']?email["\']?\s*:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in username_patterns:
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_credentials(self, payload: str) -> Optional[Dict]:
        """Extract username and password from payload"""
        if not payload:
            return None
        
        credentials = {}
        
        # Extract username
        username = self._extract_username(payload, '')
        if username:
            credentials['username'] = username
        
        # Extract password
        password_patterns = [
            r'password[=:]["\']?([^&"\'\s]+)',
            r'pass[=:]["\']?([^&"\'\s]+)',
            r'pwd[=:]["\']?([^&"\'\s]+)',
            r'["\']?password["\']?\s*:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in password_patterns:
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                credentials['password'] = match.group(1)
                break
        
        return credentials if credentials else None
    
    def _calculate_bruteforce_score(
        self,
        attempts: int,
        unique_usernames: int,
        attempts_per_minute: float
    ) -> int:
        """Calculate risk score for brute force attacks"""
        score = 0
        
        # Attempt count factor
        if attempts >= 100:
            score += 40
        elif attempts >= 50:
            score += 30
        elif attempts >= 20:
            score += 20
        elif attempts >= 10:
            score += 10
        
        # Username variety factor
        if unique_usernames >= 10:
            score += 30
        elif unique_usernames >= 5:
            score += 20
        elif unique_usernames >= 3:
            score += 10
        
        # Rate factor
        if attempts_per_minute >= 60:
            score += 30
        elif attempts_per_minute >= 30:
            score += 20
        elif attempts_per_minute >= 10:
            score += 10
        
        return min(100, score)
    
    def _calculate_spraying_score(
        self,
        total_attempts: int,
        unique_usernames: int,
        unique_passwords: int,
        failed_attempts: int,
        successful_attempts: int
    ) -> int:
        """Calculate risk score for password spraying"""
        score = 0
        
        # High attempts with few passwords
        if unique_usernames >= 10 and unique_passwords <= 2:
            score += 40
        elif unique_usernames >= 5 and unique_passwords <= 2:
            score += 30
        elif unique_usernames >= 3 and unique_passwords <= 2:
            score += 20
        
        # Success rate (low is suspicious for spraying)
        if total_attempts > 0:
            success_rate = successful_attempts / total_attempts
            if success_rate < 0.05:  # Less than 5% success
                score += 30
            elif success_rate < 0.1:  # Less than 10% success
                score += 20
        
        # High failure count
        if failed_attempts >= 20:
            score += 30
        elif failed_attempts >= 10:
            score += 20
        
        return min(100, score)
    
    def _calculate_flooding_score(
        self,
        attempts: int,
        attempts_per_second: float,
        success_rate: float
    ) -> int:
        """Calculate risk score for login flooding"""
        score = 0
        
        # High attempt rate
        if attempts_per_second >= 10:
            score += 40
        elif attempts_per_second >= 5:
            score += 30
        elif attempts_per_second >= 2:
            score += 20
        elif attempts_per_second >= 1:
            score += 10
        
        # Low success rate (indicates brute force)
        if success_rate < 0.01:  # Less than 1% success
            score += 30
        elif success_rate < 0.05:  # Less than 5% success
            score += 20
        elif success_rate < 0.1:  # Less than 10% success
            score += 10
        
        # High total attempts
        if attempts >= 100:
            score += 30
        elif attempts >= 50:
            score += 20
        elif attempts >= 20:
            score += 10
        
        return min(100, score)
    
    def generate_defense_recommendations(self, findings: List[Dict]) -> Dict:
        """Generate defense recommendations based on findings"""
        recommendations = {
            "immediate_actions": [],
            "short_term_actions": [],
            "long_term_actions": []
        }
        
        for finding in findings:
            attack_type = finding.get("attack_type", "")
            
            if attack_type == "credential_stuffing":
                recommendations["immediate_actions"].extend([
                    f"Block IP {finding['ip']}",
                    "Enable account lockout (5 failed attempts)",
                    "Implement CAPTCHA on login page"
                ])
                recommendations["long_term_actions"].extend([
                    "Implement multi-factor authentication",
                    "Use passwordless authentication",
                    "Deploy bot detection service"
                ])
            
            elif attack_type == "password_spraying":
                recommendations["immediate_actions"].extend([
                    f"Block IP {finding['ip']}",
                    "Reset passwords for affected accounts",
                    "Enable suspicious activity alerts"
                ])
                recommendations["short_term_actions"].extend([
                    "Enforce strong password policy",
                    "Implement breached password checking",
                    "Rate limit login attempts per IP"
                ])
            
            elif attack_type == "login_flooding":
                recommendations["immediate_actions"].extend([
                    f"Rate limit IP {finding['ip']} (10 req/min)",
                    "Enable WAF rule for login flooding",
                    "Implement IP reputation blocking"
                ])
                recommendations["short_term_actions"].extend([
                    "Deploy DDoS protection",
                    "Implement exponential backoff",
                    "Use CDN for login pages"
                ])
        
        # Remove duplicates
        for key in recommendations:
            recommendations[key] = list(set(recommendations[key]))
        
        return recommendations
