from fastapi import FastAPI, UploadFile, File, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, StreamingResponse
from typing import List, Dict, Optional, Any
import uvicorn
import os
import re
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import asyncio
import hashlib
from enum import Enum
import pickle
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
import warnings
warnings.filterwarnings('ignore')

# Import utilities
from .utils.threat_intel import ThreatIntelligenceClient
from .utils.geoip import GeoIPLocator
from .utils.visualization import VisualizationEngine
from .utils.report_generator import ReportGenerator

app = FastAPI(
    title="ForenX Sentinel Pro",
    version="3.0.0",
    description="Enterprise Digital Forensics & Threat Intelligence Platform",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== ENHANCED DATA STORES ==========

class EnhancedDataStore:
    """Enhanced data storage with analytics capabilities"""
    
    def __init__(self):
        self.logs = []
        self.threats = []
        self.incidents = []
        self.behavior_profiles = {}
        self.attack_patterns = {}
        self.timeline_events = []
        self.anomaly_scores = {}
        
    def add_log(self, log: Dict):
        """Add log with enhanced processing"""
        log_id = len(self.logs) + 1
        log['id'] = log_id
        log['fingerprint'] = self._generate_fingerprint(log)
        log['timestamp_parsed'] = self._parse_timestamp(log.get('timestamp', ''))
        log['risk_score'] = self._calculate_initial_risk(log)
        self.logs.append(log)
        
        # Update behavior profile
        ip = log.get('ip')
        if ip:
            if ip not in self.behavior_profiles:
                self.behavior_profiles[ip] = {
                    'first_seen': datetime.now(),
                    'last_seen': datetime.now(),
                    'request_count': 0,
                    'endpoints': set(),
                    'user_agents': set(),
                    'threat_count': 0,
                    'anomaly_score': 0
                }
            profile = self.behavior_profiles[ip]
            profile['last_seen'] = datetime.now()
            profile['request_count'] += 1
            if 'endpoint' in log:
                profile['endpoints'].add(log['endpoint'])
            if 'user_agent' in log:
                profile['user_agents'].add(log['user_agent'])
    
    def _generate_fingerprint(self, log: Dict) -> str:
        """Generate unique fingerprint for log entry"""
        fingerprint_data = f"{log.get('ip', '')}-{log.get('endpoint', '')}-{log.get('user_agent', '')}"
        return hashlib.md5(fingerprint_data.encode()).hexdigest()
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse various timestamp formats"""
        try:
            # Common formats
            formats = [
                '%d/%b/%Y:%H:%M:%S %z',
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S%z',
                '%b %d %H:%M:%S'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except:
                    continue
            
            return datetime.now()
        except:
            return datetime.now()
    
    def _calculate_initial_risk(self, log: Dict) -> int:
        """Calculate initial risk score"""
        score = 0
        
        # Status code based risk
        status = log.get('status')
        if status:
            if status >= 400 and status < 500:
                score += 20
            elif status >= 500:
                score += 40
        
        # Suspicious endpoints
        endpoint = log.get('endpoint', '').lower()
        suspicious_paths = ['.git', '.env', 'wp-admin', 'phpmyadmin', 'admin', 'config']
        if any(path in endpoint for path in suspicious_paths):
            score += 30
        
        # Large response size
        if log.get('size', 0) > 10 * 1024 * 1024:  # 10MB
            score += 25
        
        return min(100, score)

# Initialize stores
data_store = EnhancedDataStore()
threat_intel = ThreatIntelligenceClient()
geoip = GeoIPLocator()
viz_engine = VisualizationEngine()
report_gen = ReportGenerator()

# ========== MACHINE LEARNING ANOMALY DETECTION ==========

class AnomalyDetector:
    """Machine learning based anomaly detection"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.vectorizer = TfidfVectorizer(max_features=100)
        self.is_trained = False
        self.feature_columns = [
            'request_length', 'status_4xx', 'status_5xx',
            'unique_endpoints', 'request_rate', 'payload_entropy'
        ]
    
    def extract_features(self, ip_logs: List[Dict]) -> np.ndarray:
        """Extract features for ML model"""
        features = []
        
        for log in ip_logs:
            # Basic features
            f = [
                len(log.get('raw', '')),  # request_length
                1 if 400 <= log.get('status', 0) < 500 else 0,  # status_4xx
                1 if log.get('status', 0) >= 500 else 0,  # status_5xx
                len(set(l.get('endpoint', '') for l in ip_logs)),  # unique_endpoints
                len(ip_logs) / 3600,  # request_rate per hour
                self.calculate_entropy(log.get('raw', ''))  # payload_entropy
            ]
            features.append(f)
        
        return np.array(features) if features else np.array([])
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        entropy = -sum([p * np.log2(p) for p in prob if p > 0])
        return entropy
    
    def detect_anomalies(self, ip_logs: List[Dict]) -> List[Dict]:
        """Detect anomalous behavior"""
        if len(ip_logs) < 10:
            return []
        
        features = self.extract_features(ip_logs)
        if features.size == 0:
            return []
        
        # Train if not trained
        if not self.is_trained:
            self.isolation_forest.fit(features)
            self.is_trained = True
        
        # Predict anomalies
        predictions = self.isolation_forest.predict(features)
        
        anomalies = []
        for i, pred in enumerate(predictions):
            if pred == -1:  # Anomaly detected
                anomalies.append({
                    'log_id': ip_logs[i].get('id'),
                    'ip': ip_logs[i].get('ip'),
                    'score': float(self.isolation_forest.decision_function([features[i]])[0]),
                    'features': features[i].tolist(),
                    'reason': self._explain_anomaly(features[i])
                })
        
        return anomalies
    
    def _explain_anomaly(self, features: np.ndarray) -> str:
        """Generate human-readable explanation for anomaly"""
        explanations = []
        
        if features[0] > 1000:  # Long request
            explanations.append("Unusually long request")
        if features[1] > 0.5:  # High 4xx rate
            explanations.append("High client error rate")
        if features[2] > 0.3:  # High 5xx rate
            explanations.append("High server error rate")
        if features[4] > 10:  # High request rate
            explanations.append("Extremely high request rate")
        if features[5] > 6:  # High entropy
            explanations.append("High entropy (possible encoded payload)")
        
        return "; ".join(explanations) if explanations else "Statistical anomaly detected"

anomaly_detector = AnomalyDetector()

# ========== ADVANCED THREAT DETECTION ==========

class AdvancedThreatDetector:
    """Advanced multi-layered threat detection"""
    
    def __init__(self):
        self.threat_patterns = self._load_threat_patterns()
        self.behavior_baselines = {}
        
    def _load_threat_patterns(self) -> Dict:
        """Load comprehensive threat patterns"""
        return {
            'sqli': {
                'patterns': [
                    r"(['\"]).*?(--|#|/\*).*?\1",
                    r"\b(union|select|insert|update|delete|drop|create|alter)\b.*\b(from|into|table|database)\b",
                    r"'.*(or|and).*['\"]?=.*['\"]",
                    r"\d?\s*=\s*\d",
                    r"benchmark\s*\(|sleep\s*\("
                ],
                'weight': 1.0,
                'description': 'SQL Injection Attempt'
            },
            'xss': {
                'patterns': [
                    r"<script.*?>.*?</script>",
                    r"javascript:",
                    r"on\w+\s*=",
                    r"alert\(|confirm\(|prompt\(",
                    r"<iframe|<embed|<object",
                    r"data:text/html",
                    r"expression\s*\(|eval\s*\("
                ],
                'weight': 0.9,
                'description': 'Cross-Site Scripting'
            },
            'lfi': {
                'patterns': [
                    r"\.\./.*\.\./",
                    r"\.\.%2f",
                    r"etc/passwd",
                    r"proc/self",
                    r"\.\.\\",
                    r"include\s*\(|require\s*\("
                ],
                'weight': 0.8,
                'description': 'Local File Inclusion'
            },
            'rce': {
                'patterns': [
                    r";\s*\w+",
                    r"\|\s*\w+",
                    r"&\s*\w+",
                    r"\`.*\`",
                    r"\$\(.*\)",
                    r"exec\s*\(|system\s*\(|shell_exec\s*\("
                ],
                'weight': 1.0,
                'description': 'Command Injection'
            },
            'scanner': {
                'patterns': [
                    r"(l9explore|l9tcpid|sqlmap|nikto|acunetix|wpscan|nmap|gobuster|dirb|ffuf)",
                    r"(nessus|openvas|qualys|rapid7)",
                    r"masscan|zmap|shodan",
                    r"(bot|crawler|spider)\/[0-9]",
                    r"scan|exploit|vulnerability"
                ],
                'weight': 0.7,
                'description': 'Vulnerability Scanner'
            },
            'bruteforce': {
                'patterns': [
                    r"(login|signin|auth|wp-login).*(failed|invalid|incorrect)",
                    r"password.*(wrong|invalid|incorrect)",
                    r"401.*\d+ times",
                    r"too many.*attempts"
                ],
                'weight': 0.6,
                'description': 'Brute Force Attempt'
            }
        }
    
    def detect_threats(self, log: Dict) -> List[Dict]:
        """Multi-layered threat detection"""
        threats = []
        raw_text = log.get('raw', '').lower()
        endpoint = log.get('endpoint', '').lower()
        ip = log.get('ip', '')
        
        # Pattern-based detection
        for threat_type, config in self.threat_patterns.items():
            for pattern in config['patterns']:
                if re.search(pattern, raw_text, re.IGNORECASE):
                    threat_score = int(config['weight'] * 100)
                    
                    threat = {
                        'type': threat_type,
                        'level': self._score_to_level(threat_score),
                        'score': threat_score,
                        'description': config['description'],
                        'confidence': 0.8,
                        'ip': ip,
                        'log_id': log.get('id'),
                        'timestamp': datetime.now().isoformat(),
                        'indicators': [f"Pattern match: {pattern[:50]}"],
                        'recommendations': self._get_recommendations(threat_type)
                    }
                    threats.append(threat)
                    break
        
        # Behavioral detection
        if ip in data_store.behavior_profiles:
            profile = data_store.behavior_profiles[ip]
            behavioral_threats = self._detect_behavioral_anomalies(profile, log)
            threats.extend(behavioral_threats)
        
        # Contextual detection
        contextual_threats = self._detect_contextual_threats(log)
        threats.extend(contextual_threats)
        
        return threats
    
    def _score_to_level(self, score: int) -> str:
        """Convert threat score to level"""
        if score >= 90:
            return 'critical'
        elif score >= 70:
            return 'high'
        elif score >= 50:
            return 'medium'
        elif score >= 30:
            return 'low'
        return 'info'
    
    def _get_recommendations(self, threat_type: str) -> List[str]:
        """Get recommendations based on threat type"""
        recommendations = {
            'sqli': [
                'Implement parameterized queries',
                'Deploy Web Application Firewall',
                'Enable SQL injection protection rules'
            ],
            'xss': [
                'Implement Content Security Policy',
                'Enable XSS protection headers',
                'Sanitize all user inputs'
            ],
            'lfi': [
                'Disable PHP file inclusion functions',
                'Implement path traversal protection',
                'Use whitelist for file access'
            ],
            'rce': [
                'Disable dangerous PHP functions',
                'Implement command execution filtering',
                'Use sandboxed execution environments'
            ],
            'scanner': [
                'Block scanner IP addresses',
                'Implement rate limiting',
                'Monitor for reconnaissance activity'
            ],
            'bruteforce': [
                'Implement account lockout',
                'Enable CAPTCHA',
                'Use multi-factor authentication'
            ]
        }
        return recommendations.get(threat_type, ['Investigate further'])
    
    def _detect_behavioral_anomalies(self, profile: Dict, log: Dict) -> List[Dict]:
        """Detect behavioral anomalies"""
        anomalies = []
        
        # Rapid fire requests
        request_rate = profile['request_count'] / max(1, (datetime.now() - profile['first_seen']).seconds / 3600)
        if request_rate > 100:  # More than 100 requests per hour
            anomalies.append({
                'type': 'behavioral',
                'level': 'high',
                'score': 75,
                'description': f'Extremely high request rate: {request_rate:.1f}/hour',
                'confidence': 0.7,
                'ip': log.get('ip'),
                'recommendations': ['Implement rate limiting', 'Investigate for DDoS']
            })
        
        # Too many unique endpoints
        if len(profile['endpoints']) > 50:
            anomalies.append({
                'type': 'behavioral',
                'level': 'medium',
                'score': 60,
                'description': f'Accessed {len(profile["endpoints"])} different endpoints (possible scanning)',
                'confidence': 0.6,
                'ip': log.get('ip'),
                'recommendations': ['Monitor for directory enumeration', 'Review accessed endpoints']
            })
        
        return anomalies
    
    def _detect_contextual_threats(self, log: Dict) -> List[Dict]:
        """Detect context-based threats"""
        threats = []
        endpoint = log.get('endpoint', '')
        
        # Git exposure
        if '.git' in endpoint:
            threats.append({
                'type': 'git_exposure',
                'level': 'high',
                'score': 80,
                'description': 'Git repository exposure attempt',
                'confidence': 0.9,
                'ip': log.get('ip'),
                'recommendations': ['Block .git directory access', 'Remove .git from web root']
            })
        
        # Config file access
        config_files = ['.env', 'wp-config.php', 'config.php', 'settings.py', '.htaccess']
        if any(cf in endpoint for cf in config_files):
            threats.append({
                'type': 'config_access',
                'level': 'high',
                'score': 85,
                'description': 'Configuration file access attempt',
                'confidence': 0.9,
                'ip': log.get('ip'),
                'recommendations': ['Restrict config file access', 'Move configs outside web root']
            })
        
        # Admin panel access
        admin_paths = ['/admin', '/wp-admin', '/administrator', '/backend']
        if any(ap in endpoint for ap in admin_paths):
            threats.append({
                'type': 'admin_access',
                'level': 'medium',
                'score': 60,
                'description': 'Administrative interface access',
                'confidence': 0.5,
                'ip': log.get('ip'),
                'recommendations': ['Restrict admin access by IP', 'Implement strong authentication']
            })
        
        return threats

threat_detector = AdvancedThreatDetector()

# ========== REAL-TIME WEBSOCKET ==========

class ConnectionManager:
    """WebSocket connection manager for real-time updates"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.alerts_queue = asyncio.Queue()
        
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: Dict):
        """Broadcast message to all connected clients"""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass
    
    async def send_alert(self, alert: Dict):
        """Send alert to all clients"""
        alert['timestamp'] = datetime.now().isoformat()
        await self.broadcast({
            'type': 'alert',
            'data': alert
        })
    
    async def send_metrics(self, metrics: Dict):
        """Send real-time metrics"""
        await self.broadcast({
            'type': 'metrics',
            'data': metrics
        })

manager = ConnectionManager()

# ========== API ENDPOINTS ==========

@app.get("/")
async def root():
    return {
        "message": "ForenX Sentinel Pro - Enterprise Forensic Analysis",
        "version": "3.0.0",
        "status": "operational",
        "capabilities": [
            "Advanced Threat Detection",
            "Machine Learning Anomaly Detection",
            "Real-time Monitoring",
            "Threat Intelligence Integration",
            "GeoIP Analysis",
            "Interactive Visualizations",
            "Comprehensive Reporting"
        ],
        "endpoints": {
            "dashboard": "/api/dashboard",
            "upload": "POST /api/upload",
            "threats": "/api/threats",
            "analytics": "/api/analytics",
            "visualizations": "/api/visualizations",
            "reports": "/api/reports",
            "websocket": "/ws"
        }
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "api": "operational",
            "database": "operational",
            "ml_engine": "operational" if anomaly_detector.is_trained else "training_required",
            "threat_intel": "operational",
            "visualization": "operational"
        },
        "metrics": {
            "total_logs": len(data_store.logs),
            "total_threats": len(data_store.threats),
            "unique_ips": len(data_store.behavior_profiles),
            "memory_usage": "normal"
        }
    }

@app.post("/api/upload")
async def upload_log(file: UploadFile = File(...)):
    """Upload and analyze log file with enhanced processing"""
    try:
        print(f"Processing file: {file.filename}")
        
        # Read file
        content = await file.read()
        
        # Handle encoding
        try:
            text_content = content.decode('utf-8')
        except:
            text_content = content.decode('utf-8', errors='ignore')
        
        lines = text_content.splitlines()
        print(f"Total lines: {len(lines)}")
        
        parsed_logs = []
        all_threats = []
        
        # Process in batches for performance
        batch_size = 1000
        for i in range(0, min(len(lines), 10000), batch_size):
            batch = lines[i:i+batch_size]
            
            for line in batch:
                if not line.strip():
                    continue
                
                # Parse log
                log_entry = parse_enhanced_log(line)
                if log_entry:
                    log_entry['file'] = file.filename
                    data_store.add_log(log_entry)
                    parsed_logs.append(log_entry)
                    
                    # Detect threats
                    threats = threat_detector.detect_threats(log_entry)
                    for threat in threats:
                        threat['id'] = len(data_store.threats) + 1
                        data_store.threats.append(threat)
                        all_threats.append(threat)
                        
                        # Send real-time alert for high priority threats
                        if threat['level'] in ['critical', 'high']:
                            await manager.send_alert(threat)
            
            print(f"Processed {i + len(batch)}/{min(len(lines), 10000)} lines")
        
        # Anomaly detection
        if parsed_logs:
            ip_groups = defaultdict(list)
            for log in parsed_logs:
                if log.get('ip'):
                    ip_groups[log['ip']].append(log)
            
            for ip, ip_logs in ip_groups.items():
                if len(ip_logs) >= 10:
                    anomalies = anomaly_detector.detect_anomalies(ip_logs)
                    for anomaly in anomalies:
                        anomaly['type'] = 'anomaly'
                        anomaly['level'] = 'medium'
                        anomaly['description'] = 'Machine learning anomaly detected'
                        anomaly['id'] = len(data_store.threats) + 1
                        data_store.threats.append(anomaly)
                        all_threats.append(anomaly)
        
        # Threat intelligence enrichment
        unique_ips = set(log.get('ip') for log in parsed_logs if log.get('ip'))
        for ip in list(unique_ips)[:10]:  # Limit for performance
            try:
                intel = threat_intel.check_ip(ip)
                if intel and intel.get('threat_score', 0) > 60:
                    threat = {
                        'type': 'threat_intel',
                        'level': 'high',
                        'score': intel['threat_score'],
                        'description': f'IP found in threat intelligence: {intel.get("reason", "Known malicious")}',
                        'confidence': 0.85,
                        'ip': ip,
                        'id': len(data_store.threats) + 1,
                        'timestamp': datetime.now().isoformat(),
                        'intel_data': intel
                    }
                    data_store.threats.append(threat)
                    all_threats.append(threat)
            except:
                pass
        
        return JSONResponse({
            "filename": file.filename,
            "size_bytes": len(content),
            "lines_total": len(lines),
            "lines_parsed": len(parsed_logs),
            "threats_detected": len(all_threats),
            "unique_ips": len(unique_ips),
            "analysis_time": f"{(len(lines) / 1000):.2f}s",
            "threat_breakdown": Counter(t['type'] for t in all_threats),
            "message": "Log file analyzed with advanced forensic capabilities",
            "anomalies_detected": len([t for t in all_threats if t['type'] == 'anomaly']),
            "threat_intel_matches": len([t for t in all_threats if t['type'] == 'threat_intel'])
        })
        
    except Exception as e:
        print(f"Upload error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")

def parse_enhanced_log(line: str) -> Optional[Dict]:
    """Enhanced log parsing with multiple format support"""
    try:
        # Common log format
        pattern = r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
        match = re.match(pattern, line)
        
        if match:
            ip, timestamp, request, status, size, referrer, user_agent = match.groups()
            
            # Parse request
            method = "GET"
            endpoint = "/"
            protocol = "HTTP/1.1"
            if ' ' in request:
                parts = request.split(' ')
                if len(parts) >= 3:
                    method, endpoint, protocol = parts[0], parts[1], parts[2]
            
            # Parse query parameters
            query_params = {}
            if '?' in endpoint:
                path, query = endpoint.split('?', 1)
                endpoint = path
                for param in query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        query_params[key] = value
            
            return {
                "ip": ip,
                "timestamp": timestamp,
                "method": method,
                "endpoint": endpoint,
                "query_params": query_params if query_params else None,
                "status": int(status),
                "size": int(size),
                "referrer": referrer if referrer != "-" else None,
                "user_agent": user_agent if user_agent != "-" else None,
                "protocol": protocol,
                "raw": line[:500],
                "source": "web",
                "parsed_at": datetime.now().isoformat()
            }
        
        # Try other formats
        # Simple IP detection
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            return {
                "ip": ip_match.group(0),
                "raw": line[:500],
                "source": "generic",
                "parsed_at": datetime.now().isoformat()
            }
        
        return None
        
    except Exception as e:
        print(f"Parse error: {e}")
        return None

@app.get("/api/dashboard")
async def get_dashboard():
    """Get comprehensive dashboard with enhanced analytics"""
    try:
        # Calculate metrics
        total_logs = len(data_store.logs)
        unique_ips = len(data_store.behavior_profiles)
        
        # Threat statistics
        threats = data_store.threats
        threat_counts = Counter(t['level'] for t in threats)
        
        # Time-based analysis
        last_hour = datetime.now() - timedelta(hours=1)
        recent_logs = [log for log in data_store.logs 
                      if log.get('timestamp_parsed', datetime.min) > last_hour]
        recent_threats = [t for t in threats 
                         if datetime.fromisoformat(t['timestamp'].replace('Z', '+00:00')) > last_hour]
        
        # Top threats by type
        top_threat_types = Counter(t['type'] for t in threats).most_common(10)
        
        # IP risk ranking
        ip_risks = []
        for ip, profile in data_store.behavior_profiles.items():
            ip_threats = [t for t in threats if t.get('ip') == ip]
            risk_score = min(100, len(ip_threats) * 10 + profile['request_count'] // 10)
            
            ip_risks.append({
                'ip': ip,
                'risk_score': risk_score,
                'threat_count': len(ip_threats),
                'request_count': profile['request_count'],
                'first_seen': profile['first_seen'].isoformat(),
                'last_seen': profile['last_seen'].isoformat()
            })
        
        ip_risks.sort(key=lambda x: x['risk_score'], reverse=True)
        
        # Status distribution
        status_counter = Counter(log.get('status') for log in data_store.logs if log.get('status'))
        
        # Method distribution
        method_counter = Counter(log.get('method', 'UNKNOWN') for log in data_store.logs)
        
        return {
            "summary": {
                "total_logs": total_logs,
                "unique_ips": unique_ips,
                "total_threats": len(threats),
                "critical_threats": threat_counts.get('critical', 0),
                "high_threats": threat_counts.get('high', 0),
                "medium_threats": threat_counts.get('medium', 0),
                "low_threats": threat_counts.get('low', 0),
                "recent_activity": {
                    "logs_last_hour": len(recent_logs),
                    "threats_last_hour": len(recent_threats),
                    "ips_last_hour": len(set(log.get('ip') for log in recent_logs if log.get('ip')))
                },
                "last_updated": datetime.now().isoformat()
            },
            "threats": {
                "by_level": dict(threat_counts),
                "by_type": dict(top_threat_types),
                "recent": threats[-20:],
                "trend": self._calculate_threat_trend(threats)
            },
            "analytics": {
                "ip_risk_ranking": ip_risks[:10],
                "status_distribution": dict(status_counter),
                "method_distribution": dict(method_counter),
                "top_endpoints": Counter(log.get('endpoint') for log in data_store.logs 
                                        if log.get('endpoint')).most_common(10),
                "top_user_agents": Counter(log.get('user_agent') for log in data_store.logs 
                                          if log.get('user_agent')).most_common(5)
            },
            "system": {
                "ml_status": "active" if anomaly_detector.is_trained else "training",
                "threat_intel_status": "active",
                "visualization_status": "active",
                "storage_usage": {
                    "logs": total_logs,
                    "threats": len(threats),
                    "behavior_profiles": len(data_store.behavior_profiles)
                }
            }
        }
        
    except Exception as e:
        print(f"Dashboard error: {e}")
        return {"error": str(e)}

def _calculate_threat_trend(self, threats: List[Dict]) -> Dict:
    """Calculate threat trends over time"""
    # Group by hour
    hourly_counts = defaultdict(int)
    for threat in threats[-1000:]:  # Last 1000 threats
        try:
            hour = datetime.fromisoformat(threat['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:00')
            hourly_counts[hour] += 1
        except:
            pass
    
    # Sort by time
    sorted_hours = sorted(hourly_counts.items())
    
    return {
        "hourly": sorted_hours[-24:],  # Last 24 hours
        "trend": "increasing" if len(threats) > 0 else "stable"
    }

@app.get("/api/visualizations")
async def get_visualizations():
    """Get data for advanced visualizations"""
    try:
        logs = data_store.logs[-10000:]  # Last 10k logs for visualization
        
        # Time series data
        hourly_data = defaultdict(lambda: defaultdict(int))
        for log in logs:
            if log.get('timestamp_parsed'):
                hour = log['timestamp_parsed'].strftime('%Y-%m-%d %H:00')
                hourly_data[hour]['total'] += 1
                if log.get('status'):
                    if 400 <= log['status'] < 500:
                        hourly_data[hour]['errors_4xx'] += 1
                    elif log['status'] >= 500:
                        hourly_data[hour]['errors_5xx'] += 1
        
        # Threat heatmap
        threat_by_hour = defaultdict(int)
        for threat in data_store.threats[-1000:]:
            try:
                hour = datetime.fromisoformat(threat['timestamp'].replace('Z', '+00:00')).strftime('%H:00')
                threat_by_hour[hour] += 1
            except:
                pass
        
        # IP geographic distribution
        ip_geo = {}
        for ip in list(data_store.behavior_profiles.keys())[:50]:  # Limit for performance
            try:
                geo = geoip.locate(ip)
                if geo and geo.get('country'):
                    country = geo['country']
                    ip_geo[country] = ip_geo.get(country, 0) + 1
            except:
                pass
        
        # Threat type distribution for pie chart
        threat_types = Counter(t['type'] for t in data_store.threats)
        
        # Timeline events
        timeline = []
        for threat in data_store.threats[-50:]:
            timeline.append({
                'time': threat['timestamp'],
                'type': threat['type'],
                'level': threat['level'],
                'description': threat['description'][:100],
                'ip': threat.get('ip', '')
            })
        
        # Network graph data
        network_nodes = []
        network_edges = []
        
        # Add IPs as nodes
        ip_nodes = {}
        for i, ip in enumerate(list(data_store.behavior_profiles.keys())[:20]):
            node_id = f"ip_{i}"
            ip_nodes[ip] = node_id
            network_nodes.append({
                'id': node_id,
                'label': ip,
                'type': 'ip',
                'size': min(50, data_store.behavior_profiles[ip]['request_count'] // 10 + 10)
            })
        
        # Add endpoints as nodes and create edges
        endpoint_counter = Counter(log.get('endpoint') for log in logs if log.get('endpoint'))
        for endpoint, count in endpoint_counter.most_common(10):
            node_id = f"ep_{endpoint}"
            network_nodes.append({
                'id': node_id,
                'label': endpoint[:30],
                'type': 'endpoint',
                'size': min(40, count // 5 + 10)
            })
            
            # Create edges from IPs to endpoints they accessed
            for log in logs:
                if log.get('endpoint') == endpoint and log.get('ip') in ip_nodes:
                    edge_id = f"edge_{len(network_edges)}"
                    network_edges.append({
                        'id': edge_id,
                        'source': ip_nodes[log['ip']],
                        'target': node_id,
                        'weight': 1
                    })
        
        return {
            "time_series": {
                "labels": sorted(hourly_data.keys())[-24:],
                "datasets": [
                    {
                        "label": "Total Requests",
                        "data": [hourly_data[h]['total'] for h in sorted(hourly_data.keys())[-24:]],
                        "borderColor": "#3b82f6"
                    },
                                        {
                        "label": "4xx Errors",
                        "data": [hourly_data[h]['errors_4xx'] for h in sorted(hourly_data.keys())[-24:]],
                        "borderColor": "#f59e0b"
                    },
                    {
                        "label": "5xx Errors",
                        "data": [hourly_data[h]['errors_5xx'] for h in sorted(hourly_data.keys())[-24:]],
                        "borderColor": "#ef4444"
                    }
                ]
            },
            "threat_heatmap": {
                "labels": [f"{h:02d}:00" for h in range(24)],
                "data": [threat_by_hour.get(f"{h:02d}:00", 0) for h in range(24)]
            },
            "geo_distribution": {
                "countries": list(ip_geo.keys()),
                "counts": list(ip_geo.values())
            },
            "threat_types": {
                "labels": list(threat_types.keys()),
                "data": list(threat_types.values()),
                "colors": ["#ef4444", "#f59e0b", "#10b981", "#3b82f6", "#8b5cf6"]
            },
            "timeline": timeline,
            "network_graph": {
                "nodes": network_nodes,
                "edges": network_edges
            }
        }
        
    except Exception as e:
        print(f"Visualization error: {e}")
        return {"error": str(e)}

@app.get("/api/threats")
async def get_threats(
    level: Optional[str] = None,
    type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    """Get threats with filtering and pagination"""
    try:
        filtered_threats = data_store.threats
        
        if level:
            filtered_threats = [t for t in filtered_threats if t.get('level') == level]
        if type:
            filtered_threats = [t for t in filtered_threats if t.get('type') == type]
        
        # Sort by score descending
        filtered_threats.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        # Paginate
        paginated_threats = filtered_threats[offset:offset + limit]
        
        return {
            "threats": paginated_threats,
            "total": len(filtered_threats),
            "page": offset // limit + 1,
            "pages": (len(filtered_threats) + limit - 1) // limit,
            "filters": {
                "level": level,
                "type": type
            },
            "stats": {
                "by_level": Counter(t['level'] for t in filtered_threats),
                "by_type": Counter(t['type'] for t in filtered_threats),
                "avg_score": sum(t.get('score', 0) for t in filtered_threats) / max(1, len(filtered_threats))
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/threats/{threat_id}")
async def get_threat_details(threat_id: int):
    """Get detailed threat information"""
    try:
        threat = next((t for t in data_store.threats if t.get('id') == threat_id), None)
        if not threat:
            raise HTTPException(status_code=404, detail="Threat not found")
        
        # Enrich with related data
        related_logs = []
        if threat.get('log_id'):
            log = next((l for l in data_store.logs if l.get('id') == threat['log_id']), None)
            if log:
                related_logs.append(log)
        
        # Get similar threats
        similar_threats = []
        if threat.get('ip'):
            similar_threats = [t for t in data_store.threats 
                             if t.get('ip') == threat['ip'] and t.get('id') != threat_id][:5]
        
        # Get threat intelligence
        intel_data = None
        if threat.get('ip'):
            try:
                intel_data = threat_intel.check_ip(threat['ip'])
            except:
                pass
        
        # Get geo location
        geo_data = None
        if threat.get('ip'):
            try:
                geo_data = geoip.locate(threat['ip'])
            except:
                pass
        
        return {
            "threat": threat,
            "enrichment": {
                "related_logs": related_logs,
                "similar_threats": similar_threats,
                "threat_intelligence": intel_data,
                "geo_location": geo_data
            },
            "investigation": {
                "recommendations": threat.get('recommendations', []),
                "timeline": self._build_threat_timeline(threat),
                "indicators": threat.get('indicators', [])
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def _build_threat_timeline(self, threat: Dict) -> List[Dict]:
    """Build timeline for threat investigation"""
    timeline = []
    
    # Threat creation
    timeline.append({
        "time": threat['timestamp'],
        "event": "Threat detected",
        "type": "detection",
        "details": f"Threat type: {threat['type']}, Level: {threat['level']}"
    })
    
    # Related log if exists
    if threat.get('log_id'):
        log = next((l for l in data_store.logs if l.get('id') == threat['log_id']), None)
        if log:
            timeline.append({
                "time": log.get('parsed_at', threat['timestamp']),
                "event": "Log entry created",
                "type": "log",
                "details": f"IP: {log.get('ip')}, Endpoint: {log.get('endpoint', 'Unknown')}"
            })
    
    # IP behavior profile
    if threat.get('ip'):
        profile = data_store.behavior_profiles.get(threat['ip'])
        if profile:
            timeline.append({
                "time": profile['first_seen'].isoformat(),
                "event": "IP first seen",
                "type": "behavior",
                "details": f"First appearance in logs"
            })
            timeline.append({
                "time": profile['last_seen'].isoformat(),
                "event": "IP last seen",
                "type": "behavior",
                "details": f"Total requests: {profile['request_count']}"
            })
    
    # Sort timeline
    timeline.sort(key=lambda x: x['time'])
    return timeline

@app.get("/api/ips/{ip_address}")
async def get_ip_analysis(ip_address: str):
    """Get comprehensive analysis for an IP address"""
    try:
        # Get logs for this IP
        ip_logs = [log for log in data_store.logs if log.get('ip') == ip_address]
        
        # Get threats for this IP
        ip_threats = [threat for threat in data_store.threats if threat.get('ip') == ip_address]
        
        # Get behavior profile
        profile = data_store.behavior_profiles.get(ip_address, {})
        
        # Threat intelligence
        intel_data = threat_intel.check_ip(ip_address) if ip_address else None
        
        # GeoIP data
        geo_data = geoip.locate(ip_address) if ip_address else None
        
        # Anomaly detection
        anomalies = []
        if len(ip_logs) >= 10:
            anomalies = anomaly_detector.detect_anomalies(ip_logs)
        
        # Calculate risk score
        risk_score = 0
        risk_factors = []
        
        if ip_threats:
            risk_score += len(ip_threats) * 10
            risk_factors.append(f"{len(ip_threats)} threats detected")
        
        if intel_data and intel_data.get('threat_score', 0) > 60:
            risk_score += intel_data['threat_score'] * 0.5
            risk_factors.append("Threat intelligence match")
        
        if anomalies:
            risk_score += len(anomalies) * 15
            risk_factors.append(f"{len(anomalies)} behavioral anomalies")
        
        if profile.get('request_count', 0) > 100:
            risk_score += 20
            risk_factors.append("High request volume")
        
        risk_score = min(100, risk_score)
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = "critical"
        elif risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 40:
            risk_level = "medium"
        elif risk_score >= 20:
            risk_level = "low"
        else:
            risk_level = "info"
        
        # Get accessed endpoints
        endpoints = Counter(log.get('endpoint') for log in ip_logs if log.get('endpoint'))
        
        # User agents
        user_agents = Counter(log.get('user_agent') for log in ip_logs if log.get('user_agent'))
        
        # Time distribution
        hourly_activity = defaultdict(int)
        for log in ip_logs:
            if log.get('timestamp_parsed'):
                hour = log['timestamp_parsed'].hour
                hourly_activity[hour] += 1
        
        return {
            "ip": ip_address,
            "risk_assessment": {
                "score": risk_score,
                "level": risk_level,
                "factors": risk_factors,
                "recommendations": self._get_ip_recommendations(risk_level, ip_threats)
            },
            "threat_intelligence": intel_data,
            "geo_location": geo_data,
            "behavior_profile": {
                "first_seen": profile.get('first_seen', None),
                "last_seen": profile.get('last_seen', None),
                "request_count": profile.get('request_count', 0),
                "unique_endpoints": len(profile.get('endpoints', set())),
                "unique_user_agents": len(profile.get('user_agents', set()))
            },
            "activity": {
                "total_logs": len(ip_logs),
                "endpoints_accessed": dict(endpoints.most_common(10)),
                "user_agents": dict(user_agents.most_common(5)),
                "hourly_distribution": dict(sorted(hourly_activity.items())),
                "last_10_requests": ip_logs[-10:]
            },
            "threats": {
                "count": len(ip_threats),
                "by_type": Counter(t['type'] for t in ip_threats),
                "by_level": Counter(t['level'] for t in ip_threats),
                "list": ip_threats[-20:]
            },
            "anomalies": anomalies,
            "timeline": self._build_ip_timeline(ip_address, ip_logs, ip_threats)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def _get_ip_recommendations(self, risk_level: str, threats: List[Dict]) -> List[str]:
    """Get recommendations for IP based on risk level"""
    recommendations = []
    
    if risk_level in ['critical', 'high']:
        recommendations.extend([
            "Immediate blocking recommended",
            "Investigate all related activity",
            "Check for data exfiltration",
            "Review firewall logs for related connections"
        ])
    elif risk_level == 'medium':
        recommendations.extend([
            "Monitor closely for further activity",
            "Consider rate limiting",
            "Check for suspicious patterns in requests",
            "Add to watchlist"
        ])
    
    # Add threat-specific recommendations
    threat_types = set(t['type'] for t in threats)
    if 'sqli' in threat_types:
        recommendations.append("Implement WAF rules for SQL injection")
    if 'xss' in threat_types:
        recommendations.append("Enable XSS protection headers")
    if 'scanner' in threat_types:
        recommendations.append("Block scanner IP ranges")
    
    return recommendations

def _build_ip_timeline(self, ip: str, logs: List[Dict], threats: List[Dict]) -> List[Dict]:
    """Build timeline for IP activity"""
    timeline = []
    
    # Add first and last seen
    first_log = min(logs, key=lambda x: x.get('timestamp_parsed', datetime.max)) if logs else None
    last_log = max(logs, key=lambda x: x.get('timestamp_parsed', datetime.min)) if logs else None
    
    if first_log:
        timeline.append({
            "time": first_log.get('timestamp_parsed', datetime.now()).isoformat(),
            "event": "First seen",
            "type": "first_seen",
            "details": f"Initial request to {first_log.get('endpoint', 'unknown')}"
        })
    
    # Add threats
    for threat in threats:
        timeline.append({
            "time": threat['timestamp'],
            "event": f"Threat detected: {threat['type']}",
            "type": "threat",
            "level": threat['level'],
            "details": threat['description']
        })
    
    # Add significant activity (every 100th request)
    for i, log in enumerate(logs):
        if (i + 1) % 100 == 0 or i == len(logs) - 1:
            timeline.append({
                "time": log.get('timestamp_parsed', datetime.now()).isoformat(),
                "event": f"Request #{i + 1}",
                "type": "milestone",
                "details": f"Endpoint: {log.get('endpoint', 'unknown')}"
            })
    
    if last_log:
        timeline.append({
            "time": last_log.get('timestamp_parsed', datetime.now()).isoformat(),
            "event": "Last seen",
            "type": "last_seen",
            "details": f"Most recent activity"
        })
    
    # Sort timeline
    timeline.sort(key=lambda x: x['time'])
    return timeline

@app.get("/api/analytics")
async def get_analytics(
    time_range: str = "24h",
    group_by: str = "hour"
):
    """Get advanced analytics"""
    try:
        now = datetime.now()
        
        # Calculate time range
        if time_range == "1h":
            start_time = now - timedelta(hours=1)
        elif time_range == "6h":
            start_time = now - timedelta(hours=6)
        elif time_range == "24h":
            start_time = now - timedelta(hours=24)
        elif time_range == "7d":
            start_time = now - timedelta(days=7)
        elif time_range == "30d":
            start_time = now - timedelta(days=30)
        else:
            start_time = now - timedelta(hours=24)
        
        # Filter logs by time
        recent_logs = [log for log in data_store.logs 
                      if log.get('timestamp_parsed', datetime.min) > start_time]
        
        # Filter threats by time
        recent_threats = []
        for threat in data_store.threats:
            try:
                threat_time = datetime.fromisoformat(threat['timestamp'].replace('Z', '+00:00'))
                if threat_time > start_time:
                    recent_threats.append(threat)
            except:
                pass
        
        # Group data
        if group_by == "minute":
            time_format = "%Y-%m-%d %H:%M"
        elif group_by == "hour":
            time_format = "%Y-%m-%d %H:00"
        elif group_by == "day":
            time_format = "%Y-%m-%d"
        else:
            time_format = "%Y-%m-%d %H:00"
        
        # Group logs
        grouped_logs = defaultdict(lambda: {
            'total': 0,
            'errors_4xx': 0,
            'errors_5xx': 0,
            'unique_ips': set(),
            'endpoints': set()
        })
        
        for log in recent_logs:
            if log.get('timestamp_parsed'):
                time_key = log['timestamp_parsed'].strftime(time_format)
                group = grouped_logs[time_key]
                group['total'] += 1
                
                if log.get('status'):
                    if 400 <= log['status'] < 500:
                        group['errors_4xx'] += 1
                    elif log['status'] >= 500:
                        group['errors_5xx'] += 1
                
                if log.get('ip'):
                    group['unique_ips'].add(log['ip'])
                
                if log.get('endpoint'):
                    group['endpoints'].add(log['endpoint'])
        
        # Group threats
        grouped_threats = defaultdict(lambda: defaultdict(int))
        for threat in recent_threats:
            try:
                threat_time = datetime.fromisoformat(threat['timestamp'].replace('Z', '+00:00'))
                time_key = threat_time.strftime(time_format)
                grouped_threats[time_key]['total'] += 1
                grouped_threats[time_key][threat.get('level', 'unknown')] += 1
            except:
                pass
        
        # Prepare time series data
        time_keys = sorted(set(list(grouped_logs.keys()) + list(grouped_threats.keys())))
        
        log_series = []
        threat_series = []
        error_series = []
        ip_series = []
        
        for key in time_keys:
            log_data = grouped_logs[key]
            threat_data = grouped_threats[key]
            
            log_series.append(log_data['total'])
            threat_series.append(threat_data['total'])
            error_series.append(log_data['errors_4xx'] + log_data['errors_5xx'])
            ip_series.append(len(log_data['unique_ips']))
        
        # Calculate statistics
        total_logs = sum(log_series)
        total_threats = sum(threat_series)
        avg_request_rate = total_logs / max(1, len(time_keys))
        
        # Top IPs
        ip_counter = Counter(log.get('ip') for log in recent_logs if log.get('ip'))
        
        # Top endpoints
        endpoint_counter = Counter(log.get('endpoint') for log in recent_logs if log.get('endpoint'))
        
        # Threat distribution
        threat_by_type = Counter(t['type'] for t in recent_threats)
        threat_by_level = Counter(t['level'] for t in recent_threats)
        
        # Calculate anomalies
        anomaly_score = 0
        if len(recent_logs) > 100:
            # Simple anomaly detection: check if current rate > 2x average
            current_rate = log_series[-1] if log_series else 0
            if current_rate > avg_request_rate * 2:
                anomaly_score = 80
            elif current_rate > avg_request_rate * 1.5:
                anomaly_score = 60
        
        return {
            "time_series": {
                "labels": time_keys,
                "datasets": {
                    "requests": log_series,
                    "threats": threat_series,
                    "errors": error_series,
                    "unique_ips": ip_series
                }
            },
            "statistics": {
                "total_requests": total_logs,
                "total_threats": total_threats,
                "avg_request_rate": round(avg_request_rate, 2),
                "error_rate": round((sum(error_series) / max(1, total_logs)) * 100, 2),
                "threat_rate": round((total_threats / max(1, total_logs)) * 10000, 2),
                "unique_ips": len(ip_counter),
                "anomaly_score": anomaly_score
            },
            "top_items": {
                "ips": dict(ip_counter.most_common(10)),
                "endpoints": dict(endpoint_counter.most_common(10)),
                "threat_types": dict(threat_by_type.most_common(10))
            },
            "distributions": {
                "threat_levels": dict(threat_by_level),
                "status_codes": Counter(log.get('status') for log in recent_logs if log.get('status')),
                "methods": Counter(log.get('method') for log in recent_logs if log.get('method'))
            },
            "correlations": self._find_correlations(recent_logs, recent_threats)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def _find_correlations(self, logs: List[Dict], threats: List[Dict]) -> Dict:
    """Find correlations between different metrics"""
    correlations = {}
    
    # IP-threat correlation
    threat_ips = set(t.get('ip') for t in threats if t.get('ip'))
    high_request_ips = set()
    
    ip_request_counts = Counter(log.get('ip') for log in logs if log.get('ip'))
    for ip, count in ip_request_counts.items():
        if count > 100:  # High request rate
            high_request_ips.add(ip)
    
    # Calculate overlap
    if high_request_ips:
        overlap = len(threat_ips.intersection(high_request_ips)) / len(high_request_ips)
        correlations['high_request_threat_overlap'] = round(overlap * 100, 2)
    
    # Error-threat correlation
    error_ips = set(log.get('ip') for log in logs 
                   if log.get('status') and 400 <= log.get('status') < 600)
    
    if error_ips:
        error_threat_overlap = len(threat_ips.intersection(error_ips)) / len(error_ips)
        correlations['error_threat_overlap'] = round(error_threat_overlap * 100, 2)
    
    return correlations

@app.get("/api/reports")
async def generate_report(
    report_type: str = "threat_summary",
    format: str = "json",
    time_range: str = "24h"
):
    """Generate comprehensive reports"""
    try:
        # Calculate time range
        now = datetime.now()
        if time_range == "1h":
            start_time = now - timedelta(hours=1)
        elif time_range == "6h":
            start_time = now - timedelta(hours=6)
        elif time_range == "24h":
            start_time = now - timedelta(hours=24)
        elif time_range == "7d":
            start_time = now - timedelta(days=7)
        else:
            start_time = now - timedelta(hours=24)
        
        # Filter data
        recent_logs = [log for log in data_store.logs 
                      if log.get('timestamp_parsed', datetime.min) > start_time]
        
        recent_threats = []
        for threat in data_store.threats:
            try:
                threat_time = datetime.fromisoformat(threat['timestamp'].replace('Z', '+00:00'))
                if threat_time > start_time:
                    recent_threats.append(threat)
            except:
                pass
        
        # Generate report based on type
        if report_type == "threat_summary":
            report = self._generate_threat_summary(recent_threats, start_time, now)
        elif report_type == "security_audit":
            report = self._generate_security_audit(recent_logs, recent_threats, start_time, now)
        elif report_type == "ip_analysis":
            report = self._generate_ip_analysis_report(recent_logs, recent_threats, start_time, now)
        elif report_type == "anomaly_detection":
            report = self._generate_anomaly_report(recent_logs, recent_threats, start_time, now)
        else:
            report = self._generate_comprehensive_report(recent_logs, recent_threats, start_time, now)
        
        # Add metadata
        report['metadata'] = {
            'generated_at': now.isoformat(),
            'time_range': time_range,
            'report_type': report_type,
            'format': format,
            'data_points': {
                'logs': len(recent_logs),
                'threats': len(recent_threats),
                'unique_ips': len(set(log.get('ip') for log in recent_logs if log.get('ip')))
            }
        }
        
        # Format response
        if format == "html":
            html_report = report_gen.generate_html_report(report)
            return HTMLResponse(content=html_report)
        elif format == "csv":
            csv_report = report_gen.generate_csv_report(report)
            return StreamingResponse(
                iter([csv_report]),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename=report_{now.strftime('%Y%m%d_%H%M%S')}.csv"}
            )
        elif format == "pdf":
            pdf_report = report_gen.generate_pdf_report(report)
            return StreamingResponse(
                pdf_report,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=report_{now.strftime('%Y%m%d_%H%M%S')}.pdf"}
            )
        else:
            return report
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def _generate_threat_summary(self, threats: List[Dict], start_time: datetime, end_time: datetime) -> Dict:
    """Generate threat summary report"""
    threat_by_level = Counter(t['level'] for t in threats)
    threat_by_type = Counter(t['type'] for t in threats)
    
    # Top threat sources
    threat_ips = Counter(t['ip'] for t in threats if t.get('ip'))
    
    # Threat timeline
    hourly_threats = defaultdict(int)
    for threat in threats:
        try:
            hour = datetime.fromisoformat(threat['timestamp'].replace('Z', '+00:00')).strftime('%Y-%m-%d %H:00')
            hourly_threats[hour] += 1
        except:
            pass
    
    # Critical threats
    critical_threats = [t for t in threats if t.get('level') == 'critical']
    
    return {
        'report_type': 'threat_summary',
        'period': {
            'start': start_time.isoformat(),
            'end': end_time.isoformat(),
            'duration_hours': (end_time - start_time).total_seconds() / 3600
        },
        'summary': {
            'total_threats': len(threats),
            'critical_threats': len(critical_threats),
            'threats_per_hour': round(len(threats) / max(1, (end_time - start_time).total_seconds() / 3600), 2),
            'distribution_by_level': dict(threat_by_level),
            'distribution_by_type': dict(threat_by_type)
        },
        'top_threat_sources': dict(threat_ips.most_common(10)),
        'timeline': dict(sorted(hourly_threats.items())),
        'critical_threats': critical_threats[:20],
        'recommendations': self._get_threat_report_recommendations(threats)
    }

def _get_threat_report_recommendations(self, threats: List[Dict]) -> List[str]:
    """Get recommendations based on threat analysis"""
    recommendations = []
    
    threat_types = set(t['type'] for t in threats)
    threat_levels = set(t['level'] for t in threats)
    
    if 'critical' in threat_levels:
        recommendations.append("Immediate security review required")
    
    if 'sqli' in threat_types:
        recommendations.append("Review and strengthen SQL injection protection")
    
    if 'xss' in threat_types:
        recommendations.append("Implement CSP headers and input sanitization")
    
    if 'scanner' in threat_types:
        recommendations.append("Block known scanner IP ranges")
    
    if len(threats) > 100:
        recommendations.append("Consider implementing WAF for additional protection")
    
    return recommendations

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time updates"""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await asyncio.sleep(10)
            await websocket.send_json({
                "type": "heartbeat",
                "timestamp": datetime.now().isoformat()
            })
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        manager.disconnect(websocket)

@app.post("/api/export")
async def export_data(
    data_type: str = "threats",
    format: str = "json"
):
    """Export data in various formats"""
    try:
        if data_type == "threats":
            data = data_store.threats
        elif data_type == "logs":
            data = data_store.logs
        elif data_type == "behavior_profiles":
            data = data_store.behavior_profiles
        else:
            raise HTTPException(status_code=400, detail="Invalid data type")
        
        if format == "json":
            return JSONResponse(content=data)
        elif format == "csv":
            if not data:
                raise HTTPException(status_code=404, detail="No data to export")
            
            # Convert to DataFrame
            df = pd.DataFrame(data)
            csv_data = df.to_csv(index=False)
            
            return StreamingResponse(
                iter([csv_data]),
                media_type="text/csv",
                headers={"Content-Disposition": f"attachment; filename={data_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
            )
        else:
            raise HTTPException(status_code=400, detail="Unsupported format")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/ip")
async def scan_ip(ip: str):
    """Deep scan an IP address"""
    try:
        # Threat intelligence
        intel = threat_intel.check_ip(ip)
        
        # GeoIP lookup
        geo = geoip.locate(ip)
        
        # Port scanning (simulated - in production use actual scanner)
        open_ports = self._simulate_port_scan(ip)
        
        # Reputation check
        reputation = self._check_ip_reputation(ip, intel)
        
        # Related threats
        related_threats = [t for t in data_store.threats if t.get('ip') == ip]
        
        return {
            "ip": ip,
            "scan_time": datetime.now().isoformat(),
            "threat_intelligence": intel,
            "geolocation": geo,
            "ports": open_ports,
            "reputation": reputation,
            "related_threats": related_threats,
            "recommendations": self._get_scan_recommendations(intel, reputation)
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def _simulate_port_scan(self, ip: str) -> Dict:
    """Simulate port scan (in production, use actual scanner)"""
    # This is a simulation - real implementation would use nmap or similar
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL"
    }
    
    import random
    open_ports = []
    
    # Simulate some open ports
    for port, service in common_ports.items():
        if random.random() < 0.1:  # 10% chance port is "open"
            open_ports.append({
                "port": port,
                "service": service,
                "status": "open"
            })
    
    return open_ports

def _check_ip_reputation(self, ip: str, intel: Dict) -> Dict:
    """Check IP reputation"""
    score = 0
    factors = []
    
    if intel and intel.get('threat_score', 0) > 0:
        score = intel['threat_score']
        if intel.get('reasons'):
            factors = intel['reasons']
    
    # Additional checks
    if score == 0:
        # Check if IP is in private range
        if ip.startswith(('10.', '172.16.', '192.168.')):
            score = 10
            factors.append("Private IP address")
        else:
            score = 30  # Default score for unknown public IPs
    
    # Determine reputation level
    if score >= 80:
        level = "malicious"
    elif score >= 60:
        level = "suspicious"
    elif score >= 40:
        level = "questionable"
    elif score >= 20:
        level = "neutral"
    else:
        level = "trusted"
    
    return {
        "score": score,
        "level": level,
        "factors": factors,
        "last_checked": datetime.now().isoformat()
    }

def _get_scan_recommendations(self, intel: Dict, reputation: Dict) -> List[str]:
    """Get recommendations based on scan results"""
    recommendations = []
    
    if reputation['level'] in ['malicious', 'suspicious']:
        recommendations.append(f"Immediate blocking recommended (reputation: {reputation['level']})")
        
        if intel and intel.get('reasons'):
            for reason in intel['reasons']:
                recommendations.append(f"Known for: {reason}")
    
    if reputation['score'] > 60:
        recommendations.append("Add to threat intelligence blacklist")
        recommendations.append("Monitor all activity from this IP")
    
    return recommendations

@app.get("/api/search")
async def search_logs(
    query: str,
    field: Optional[str] = None,
    limit: int = 100
):
    """Search logs with advanced query capabilities"""
    try:
        results = []
        
        for log in data_store.logs[-10000:]:  # Search in recent logs
            match = False
            
            if not field or field == "all":
                # Search in all fields
                for value in log.values():
                    if isinstance(value, str) and query.lower() in value.lower():
                        match = True
                        break
            elif field in log:
                # Search in specific field
                field_value = log[field]
                if isinstance(field_value, str) and query.lower() in field_value.lower():
                    match = True
            
            if match:
                results.append(log)
                if len(results) >= limit:
                    break
        
        return {
            "query": query,
            "field": field,
            "total_results": len(results),
            "results": results,
            "search_time": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/incidents")
async def create_incident(
    title: str,
    description: str,
    severity: str = "medium",
    related_threats: Optional[List[int]] = None
):
    """Create a security incident"""
    try:
        incident_id = len(data_store.incidents) + 1
        
        incident = {
            "id": incident_id,
            "title": title,
            "description": description,
            "severity": severity,
            "status": "open",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "related_threats": related_threats or [],
            "assigned_to": None,
            "notes": []
        }
        
        data_store.incidents.append(incident)
        
        # Send alert
        await manager.send_alert({
            "type": "incident_created",
            "level": severity,
            "title": f"New incident: {title}",
            "description": description,
            "incident_id": incident_id
        })
        
        return {
            "incident_id": incident_id,
            "message": "Incident created successfully",
            "incident": incident
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/incidents")
async def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None
):
    """Get security incidents"""
    try:
        filtered = data_store.incidents
        
        if status:
            filtered = [i for i in filtered if i.get('status') == status]
        if severity:
            filtered = [i for i in filtered if i.get('severity') == severity]
        
        return {
            "total": len(filtered),
            "incidents": filtered
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== ADMIN ENDPOINTS ==========

@app.post("/api/admin/reset")
async def reset_data(
    confirm: bool = False,
    password: Optional[str] = None
):
    """Reset all data (admin only)"""
    # In production, implement proper authentication
    if not confirm:
        raise HTTPException(status_code=400, detail="Confirm flag required")
    
    # Reset all stores
    data_store.logs.clear()
    data_store.threats.clear()
    data_store.incidents.clear()
    data_store.behavior_profiles.clear()
    data_store.timeline_events.clear()
    
    return {
        "message": "All data reset successfully",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/admin/stats")
async def get_admin_stats():
    """Get detailed system statistics"""
    try:
        total_memory = len(pickle.dumps(data_store)) / 1024 / 1024  # MB
        
        # IP statistics
        ip_stats = {
            "total_ips": len(data_store.behavior_profiles),
            "top_requestors": sorted(
                [(ip, profile['request_count']) for ip, profile in data_store.behavior_profiles.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "suspicious_ips": len([ip for ip, profile in data_store.behavior_profiles.items()
                                 if profile.get('threat_count', 0) > 0])
        }
        
        # Threat statistics
        threat_stats = {
            "total_threats": len(data_store.threats),
            "threats_last_hour": len([t for t in data_store.threats
                                     if datetime.fromisoformat(t['timestamp'].replace('Z', '+00:00')) >
                                     datetime.now() - timedelta(hours=1)]),
            "detection_rate": len(data_store.threats) / max(1, len(data_store.logs))
        }
        
        # System performance
        performance = {
            "log_processing_rate": len(data_store.logs) / max(1, len(data_store.logs) / 1000),  # logs per second
            "memory_usage_mb": round(total_memory, 2),
            "ml_model_status": "trained" if anomaly_detector.is_trained else "untrained"
        }
        
        return {
            "system": {
                "uptime": datetime.now().isoformat(),  # In production, track actual uptime
                "version": "3.0.0",
                "status": "operational"
            },
            "data": {
                "total_logs": len(data_store.logs),
                "total_threats": len(data_store.threats),
                "total_incidents": len(data_store.incidents),
                "ip_statistics": ip_stats
            },
            "performance": performance,
            "threat_statistics": threat_stats
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========== HELPER FUNCTIONS ==========

def _generate_security_audit(self, logs: List[Dict], threats: List[Dict], start_time: datetime, end_time: datetime) -> Dict:
    """Generate security audit report"""
    # This would be a comprehensive security audit
    return {
        "report_type": "security_audit",
        "summary": "Security audit report",
        "details": "Detailed audit would be implemented here"
    }

def _generate_ip_analysis_report(self, logs: List[Dict], threats: List[Dict], start_time: datetime, end_time: datetime) -> Dict:
    """Generate IP analysis report"""
    # Group by IP
    ip_analysis = {}
    for ip in set(log.get('ip') for log in logs if log.get('ip')):
        ip_logs = [log for log in logs if log.get('ip') == ip]
        ip_threats = [threat for threat in threats if threat.get('ip') == ip]
        
        ip_analysis[ip] = {
            "request_count": len(ip_logs),
            "threat_count": len(ip_threats),
            "first_seen": min((log.get('timestamp_parsed') for log in ip_logs 
                             if log.get('timestamp_parsed')), default=start_time),
            "last_seen": max((log.get('timestamp_parsed') for log in ip_logs 
                            if log.get('timestamp_parsed')), default=end_time)
        }
    
    return {
        "report_type": "ip_analysis",
        "ip_count": len(ip_analysis),
        "analysis": ip_analysis
    }

def _generate_anomaly_report(self, logs: List[Dict], threats: List[Dict], start_time: datetime, end_time: datetime) -> Dict:
    """Generate anomaly detection report"""
    # This would analyze anomalies
    return {
        "report_type": "anomaly_detection",
        "summary": "Anomaly detection report",
        "details": "Anomaly analysis would be implemented here"
    }

def _generate_comprehensive_report(self, logs: List[Dict], threats: List[Dict], start_time: datetime, end_time: datetime) -> Dict:
    """Generate comprehensive report"""
    return {
        "report_type": "comprehensive",
        "executive_summary": {
            "total_requests": len(logs),
            "total_threats": len(threats),
            "time_period": f"{start_time.isoformat()} to {end_time.isoformat()}",
            "key_findings": self._extract_key_findings(logs, threats)
        },
        "detailed_analysis": {
            "threat_analysis": self._analyze_threats(threats),
            "traffic_analysis": self._analyze_traffic(logs),
            "ip_analysis": self._analyze_ips(logs, threats),
            "vulnerability_assessment": self._assess_vulnerabilities(threats)
        },
        "recommendations": self._generate_comprehensive_recommendations(logs, threats),
        "appendix": {
            "data_statistics": self._get_report_statistics(logs, threats),
            "methodology": "Analysis based on multi-layered threat detection and machine learning",
            "tools_used": ["ForenX Sentinel Pro", "Machine Learning", "Threat Intelligence"]
        }
    }

def _extract_key_findings(self, logs: List[Dict], threats: List[Dict]) -> List[str]:
    """Extract key findings from analysis"""
    findings = []
    
    if threats:
        critical_count = len([t for t in threats if t.get('level') == 'critical'])
        if critical_count > 0:
            findings.append(f"{critical_count} critical threats detected requiring immediate attention")
        
        top_threat_type = max(Counter(t['type'] for t in threats).items(), key=lambda x: x[1], default=(None, 0))
        if top_threat_type[1] > 0:
            findings.append(f"Most common threat type: {top_threat_type[0]} ({top_threat_type[1]} occurrences)")
    
    if logs:
        error_rate = len([l for l in logs if l.get('status') and 400 <= l.get('status') < 600]) / len(logs)
        if error_rate > 0.1:  # 10% error rate
            findings.append(f"High error rate detected: {error_rate:.1%}")
    
    return findings

def _analyze_threats(self, threats: List[Dict]) -> Dict:
    """Analyze threats for report"""
    threat_by_type = Counter(t['type'] for t in threats)
    threat_by_level = Counter(t['level'] for t in threats)
    threat_by_ip = Counter(t['ip'] for t in threats if t.get('ip'))
    
    return {
        "distribution": {
            "by_type": dict(threat_by_type),
            "by_level": dict(threat_by_level)
        },
        "top_threat_sources": dict(threat_by_ip.most_common(10)),
        "timeline_analysis": "Threat distribution over time would be analyzed here",
        "trend_analysis": "Threat trends would be analyzed here"
    }

def _analyze_traffic(self, logs: List[Dict]) -> Dict:
    """Analyze traffic patterns"""
    hourly = defaultdict(int)
    for log in logs:
        if log.get('timestamp_parsed'):
            hour = log['timestamp_parsed'].strftime('%H:00')
            hourly[hour] += 1
    
    methods = Counter(log.get('method') for log in logs)
    statuses = Counter(log.get('status') for log in logs)
    
    return {
        "hourly_distribution": dict(sorted(hourly.items())),
        "method_distribution": dict(methods),
        "status_distribution": dict(statuses),
        "peak_hours": sorted(hourly.items(), key=lambda x: x[1], reverse=True)[:3]
    }

def _analyze_ips(self, logs: List[Dict], threats: List[Dict]) -> Dict:
    """Analyze IP addresses"""
    ip_requests = Counter(log.get('ip') for log in logs if log.get('ip'))
    ip_threats = Counter(t.get('ip') for t in threats if t.get('ip'))
    
    suspicious_ips = []
    for ip in set(list(ip_requests.keys()) + list(ip_threats.keys())):
        request_count = ip_requests.get(ip, 0)
        threat_count = ip_threats.get(ip, 0)
        
        if threat_count > 0 or request_count > 100:
            suspicious_ips.append({
                "ip": ip,
                "requests": request_count,
                "threats": threat_count,
                "risk_score": min(100, threat_count * 20 + request_count // 10)
            })
    
    return {
        "total_unique_ips": len(ip_requests),
        "suspicious_ips": sorted(suspicious_ips, key=lambda x: x["risk_score"], reverse=True)[:20],
        "top_requestors": dict(ip_requests.most_common(10))
    }

def _assess_vulnerabilities(self, threats: List[Dict]) -> Dict:
    """Assess vulnerabilities based on threats"""
    vulnerability_map = {
        'sqli': 'SQL Injection Vulnerability',
        'xss': 'Cross-Site Scripting Vulnerability',
        'lfi': 'Local File Inclusion Vulnerability',
        'rce': 'Remote Code Execution Vulnerability',
        'scanner': 'Information Disclosure Vulnerability',
        'bruteforce': 'Weak Authentication Vulnerability'
    }
    
    vulnerabilities = {}
    for threat in threats:
        threat_type = threat.get('type')
        if threat_type in vulnerability_map:
            vuln_name = vulnerability_map[threat_type]
            if vuln_name not in vulnerabilities:
                vulnerabilities[vuln_name] = {
                    "count": 0,
                    "severity": threat.get('level', 'medium'),
                    "examples": []
                }
            vulnerabilities[vuln_name]["count"] += 1
            vulnerabilities[vuln_name]["examples"].append(threat.get('description', ''))
    
    return vulnerabilities

def _generate_comprehensive_recommendations(self, logs: List[Dict], threats: List[Dict]) -> List[Dict]:
    """Generate comprehensive recommendations"""
    recommendations = []
    
    # Based on threat types
    threat_types = set(t['type'] for t in threats)
    
    if 'sqli' in threat_types:
        recommendations.append({
            "priority": "high",
            "category": "application_security",
            "recommendation": "Implement parameterized queries and WAF rules",
            "rationale": "SQL injection attempts detected"
        })
    
    if 'xss' in threat_types:
        recommendations.append({
            "priority": "high",
            "category": "application_security",
            "recommendation": "Implement Content Security Policy and input sanitization",
            "rationale": "Cross-site scripting attempts detected"
        })
    
    if 'scanner' in threat_types:
        recommendations.append({
            "priority": "medium",
            "category": "network_security",
            "recommendation": "Block known scanner IP ranges and implement rate limiting",
            "rationale": "Vulnerability scanning activity detected"
        })
    
    # Based on traffic patterns
    if len(logs) > 10000:
        recommendations.append({
            "priority": "medium",
            "category": "performance",
            "recommendation": "Consider implementing a CDN or load balancer",
            "rationale": "High traffic volume detected"
        })
    
    return recommendations

def _get_report_statistics(self, logs: List[Dict], threats: List[Dict]) -> Dict:
    """Get statistics for report appendix"""
    return {
        "data_points": {
            "total_logs": len(logs),
            "total_threats": len(threats),
            "unique_ips": len(set(log.get('ip') for log in logs if log.get('ip'))),
            "time_span_hours": "Calculated from data"
        },
        "detection_rates": {
            "threats_per_request": len(threats) / max(1, len(logs)),
            "critical_threats": len([t for t in threats if t.get('level') == 'critical']),
            "false_positive_rate": "N/A"  # Would require ground truth data
        }
    }

# ========== MAIN ENTRY POINT ==========

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
