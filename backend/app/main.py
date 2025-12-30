from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from typing import List, Dict, Optional
import uvicorn
import os
import re
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import json
from enum import Enum

app = FastAPI(
    title="ForenX Sentinel",
    version="2.0.0",
    description="Professional Digital Forensics & Log Analysis Platform",
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

# In-memory storage for demo (replace with database in production)
log_store = []
threat_analysis = []
attack_patterns = []

class ThreatLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class AttackType(Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    BRUTE_FORCE = "brute_force"
    DIRECTORY_SCAN = "directory_scan"
    GIT_EXPOSURE = "git_exposure"
    PORT_SCAN = "port_scan"
    DATA_EXFILTRATION = "data_exfiltration"
    SCANNER = "vulnerability_scanner"

# ========== LOG PARSING ENGINE ==========

def parse_nginx_log(line: str) -> Optional[Dict]:
    """Parse Nginx combined log format"""
    pattern = r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
    match = re.match(pattern, line)
    
    if match:
        ip, timestamp, request, status, size, referrer, user_agent = match.groups()
        
        # Parse request
        method, endpoint, protocol = "GET", "/", "HTTP/1.1"
        if ' ' in request:
            parts = request.split(' ')
            if len(parts) >= 3:
                method, endpoint, protocol = parts[0], parts[1], parts[2]
        
        return {
            "ip": ip,
            "timestamp": timestamp,
            "method": method,
            "endpoint": endpoint,
            "status": int(status),
            "size": int(size),
            "referrer": referrer if referrer != "-" else None,
            "user_agent": user_agent if user_agent != "-" else None,
            "raw": line,
            "source": "nginx"
        }
    return None

def parse_apache_log(line: str) -> Optional[Dict]:
    """Parse Apache combined log format"""
    pattern = r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
    match = re.match(pattern, line)
    
    if match:
        ip, ident, user, timestamp, request, status, size, referrer, user_agent = match.groups()
        
        method, endpoint, protocol = "GET", "/", "HTTP/1.1"
        if ' ' in request:
            parts = request.split(' ')
            if len(parts) >= 3:
                method, endpoint, protocol = parts[0], parts[1], parts[2]
        
        return {
            "ip": ip,
            "timestamp": timestamp,
            "method": method,
            "endpoint": endpoint,
            "status": int(status),
            "size": int(size),
            "referrer": referrer if referrer != "-" else None,
            "user_agent": user_agent if user_agent != "-" else None,
            "raw": line,
            "source": "apache"
        }
    return None

# ========== THREAT DETECTION ENGINE ==========

class ThreatDetector:
    """Advanced threat detection engine"""
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = {
        "sql_injection": [
            r"(['\"])?.*(OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*\1",
            r".*['\"]\s*=\s*['\"]",
            r".*--.*",
            r".*;.*",
            r".*/\*.*\*/.*"
        ],
        "xss": [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"alert\(.*?\)",
            r"<iframe.*?>",
            r"<img.*?onerror=.*?>"
        ],
        "directory_traversal": [
            r".*\.\./.*",
            r".*\.\.%2f.*",
            r".*etc/passwd.*",
            r".*proc/self.*",
            r".*\.git/.*",
            r".*\.env.*",
            r".*wp-config\.php.*",
            r".*\.htaccess.*"
        ],
        "command_injection": [
            r".*;\s*\w+.*",
            r".*\|\s*\w+.*",
            r".*&\s*\w+.*",
            r".*\`.*\`.*",
            r".*\$\("
        ],
        "scanners": [
            r"l9explore",
            r"l9tcpid",
            r"sqlmap",
            r"nikto",
            r"nessus",
            r"acunetix",
            r"wpscan",
            r"nmap",
            r"gobuster",
            r"dirb",
            r"ffuf"
        ]
    }
    
    @staticmethod
    def detect_threats(log_entry: Dict) -> List[Dict]:
        """Detect threats in a single log entry"""
        threats = []
        
        # Check endpoint for threats
        endpoint = log_entry.get("endpoint", "")
        user_agent = log_entry.get("user_agent", "")
        raw = log_entry.get("raw", "")
        
        # Git exposure attempts (from your logs)
        if ".git/config" in endpoint or ".git/HEAD" in endpoint:
            threats.append({
                "type": AttackType.GIT_EXPOSURE.value,
                "level": ThreatLevel.HIGH.value,
                "description": "Git repository exposure attempt",
                "confidence": 0.9,
                "indicators": ["Git config file access attempt"],
                "recommendation": "Block .git directory access in web server config"
            })
        
        # Directory scanning
        suspicious_dirs = [".git", ".env", "wp-admin", "phpmyadmin", "admin", "config", "backup"]
        if any(dir in endpoint.lower() for dir in suspicious_dirs):
            threats.append({
                "type": AttackType.DIRECTORY_SCAN.value,
                "level": ThreatLevel.MEDIUM.value,
                "description": "Suspicious directory access",
                "confidence": 0.7,
                "indicators": [f"Access to {endpoint}"],
                "recommendation": "Review access logs and consider blocking"
            })
        
        # Scanner detection
        for scanner_pattern in ThreatDetector.SUSPICIOUS_PATTERNS["scanners"]:
            if re.search(scanner_pattern, user_agent, re.IGNORECASE):
                threats.append({
                    "type": AttackType.SCANNER.value,
                    "level": ThreatLevel.MEDIUM.value,
                    "description": f"Vulnerability scanner detected: {scanner_pattern}",
                    "confidence": 0.8,
                    "indicators": [f"User-Agent: {user_agent}"],
                    "recommendation": "Monitor for further reconnaissance activity"
                })
        
        # SQL Injection patterns
        for pattern in ThreatDetector.SUSPICIOUS_PATTERNS["sql_injection"]:
            if re.search(pattern, raw, re.IGNORECASE):
                threats.append({
                    "type": AttackType.SQL_INJECTION.value,
                    "level": ThreatLevel.HIGH.value,
                    "description": "SQL injection attempt detected",
                    "confidence": 0.6,
                    "indicators": ["SQL keywords in request"],
                    "recommendation": "Implement WAF rules for SQL injection"
                })
                break
        
        # XSS patterns
        for pattern in ThreatDetector.SUSPICIOUS_PATTERNS["xss"]:
            if re.search(pattern, raw, re.IGNORECASE):
                threats.append({
                    "type": AttackType.XSS.value,
                    "level": ThreatLevel.HIGH.value,
                    "description": "Cross-site scripting attempt detected",
                    "confidence": 0.7,
                    "indicators": ["XSS patterns in request"],
                    "recommendation": "Implement Content Security Policy (CSP)"
                })
                break
        
        return threats
    
    @staticmethod
    def analyze_behavior(logs: List[Dict]) -> List[Dict]:
        """Analyze behavioral patterns across multiple logs"""
        findings = []
        
        # Group by IP
        ip_logs = defaultdict(list)
        for log in logs:
            ip_logs[log["ip"]].append(log)
        
        # Analyze each IP's behavior
        for ip, ip_log_entries in ip_logs.items():
            # Check for scanning behavior (many different endpoints)
            endpoints = set(log["endpoint"] for log in ip_log_entries)
            if len(endpoints) > 20:  # More than 20 different endpoints
                findings.append({
                    "ip": ip,
                    "type": "scanning_behavior",
                    "level": ThreatLevel.MEDIUM.value,
                    "description": f"IP accessed {len(endpoints)} different endpoints (possible scanning)",
                    "confidence": 0.75,
                    "endpoint_count": len(endpoints),
                    "sample_endpoints": list(endpoints)[:5]
                })
            
            # Check for rapid requests (more than 10 requests per minute)
            if len(ip_log_entries) > 10:
                timestamps = [log.get("timestamp", "") for log in ip_log_entries]
                # Simple time analysis - in production, parse timestamps properly
                if len(ip_log_entries) > 50:
                    findings.append({
                        "ip": ip,
                        "type": "rapid_requests",
                        "level": ThreatLevel.MEDIUM.value,
                        "description": f"IP made {len(ip_log_entries)} requests (possible automated tool)",
                        "confidence": 0.7,
                        "request_count": len(ip_log_entries)
                    })
        
        return findings

# ========== ANALYTICS ENGINE ==========

class AnalyticsEngine:
    """Generate analytics and insights from logs"""
    
    @staticmethod
    def get_top_ips(logs: List[Dict], limit: int = 10) -> List[Dict]:
        """Get top IPs by request count"""
        ip_counter = Counter(log["ip"] for log in logs)
        return [
            {"ip": ip, "count": count, "percentage": (count / len(logs)) * 100}
            for ip, count in ip_counter.most_common(limit)
        ]
    
    @staticmethod
    def get_top_endpoints(logs: List[Dict], limit: int = 10) -> List[Dict]:
        """Get top endpoints by request count"""
        endpoint_counter = Counter(log["endpoint"] for log in logs)
        return [
            {"endpoint": endpoint, "count": count}
            for endpoint, count in endpoint_counter.most_common(limit)
        ]
    
    @staticmethod
    def get_status_distribution(logs: List[Dict]) -> Dict:
        """Get HTTP status code distribution"""
        status_counter = Counter(log["status"] for log in logs)
        total = len(logs)
        return {
            "2xx": sum(count for status, count in status_counter.items() if 200 <= status < 300),
            "3xx": sum(count for status, count in status_counter.items() if 300 <= status < 400),
            "4xx": sum(count for status, count in status_counter.items() if 400 <= status < 500),
            "5xx": sum(count for status, count in status_counter.items() if 500 <= status < 600),
            "details": {str(k): v for k, v in status_counter.items()}
        }
    
    @staticmethod
    def get_threat_summary(threats: List[Dict]) -> Dict:
        """Generate threat summary"""
        threat_counter = Counter(threat.get("type", "unknown") for threat in threats)
        level_counter = Counter(threat.get("level", "info") for threat in threats)
        
        return {
            "total_threats": len(threats),
            "by_type": dict(threat_counter),
            "by_level": dict(level_counter),
            "critical_count": sum(1 for t in threats if t.get("level") == ThreatLevel.CRITICAL.value),
            "high_count": sum(1 for t in threats if t.get("level") == ThreatLevel.HIGH.value)
        }

# ========== API ENDPOINTS ==========

@app.get("/")
async def root():
    return {
        "message": "ForenX Sentinel Forensic Analysis Engine",
        "version": "2.0.0",
        "endpoints": {
            "dashboard": "/api/dashboard",
            "upload": "/api/upload",
            "threats": "/api/threats",
            "analytics": "/api/analytics",
            "export": "/api/export",
            "docs": "/docs"
        }
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "analysis_engine": "operational",
            "threat_detection": "operational",
            "log_parsing": "operational"
        }
    }

@app.post("/api/upload")
async def upload_log(file: UploadFile = File(...)):
    """Upload and analyze log file"""
    try:
        global log_store, threat_analysis, attack_patterns
        
        # Read file
        content = await file.read()
        lines = content.decode('utf-8').splitlines()
        
        # Parse logs
        parsed_logs = []
        threats_found = []
        
        for line in lines[:5000]:  # Limit for demo
            if not line.strip():
                continue
            
            log_entry = None
            
            # Try different parsers
            if ' - - [' in line and '] "' in line:
                log_entry = parse_nginx_log(line) or parse_apache_log(line)
            
            if log_entry:
                log_entry["id"] = len(log_store) + 1
                log_entry["upload_time"] = datetime.now().isoformat()
                
                # Detect threats
                entry_threats = ThreatDetector.detect_threats(log_entry)
                if entry_threats:
                    for threat in entry_threats:
                        threat["log_id"] = log_entry["id"]
                        threat["timestamp"] = datetime.now().isoformat()
                        threats_found.append(threat)
                
                parsed_logs.append(log_entry)
        
        # Store logs
        log_store.extend(parsed_logs)
        threat_analysis.extend(threats_found)
        
        # Behavioral analysis
        behavior_findings = ThreatDetector.analyze_behavior(parsed_logs)
        threat_analysis.extend(behavior_findings)
        
        # Update attack patterns
        attack_patterns = list(set(
            pattern.get("type", "unknown") 
            for pattern in threats_found + behavior_findings
        ))
        
        return JSONResponse({
            "filename": file.filename,
            "size_bytes": len(content),
            "lines_total": len(lines),
            "lines_parsed": len(parsed_logs),
            "threats_detected": len(threats_found),
            "behavioral_findings": len(behavior_findings),
            "message": "Log file analyzed with forensic capabilities",
            "sample_threats": threats_found[:3] if threats_found else [],
            "analysis_complete": True
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")

@app.get("/api/dashboard")
async def get_dashboard():
    """Get comprehensive dashboard data"""
    analytics = AnalyticsEngine()
    
    # Basic stats
    total_logs = len(log_store)
    unique_ips = len(set(log.get("ip") for log in log_store))
    
    # Threat summary
    threat_summary = analytics.get_threat_summary(threat_analysis) if threat_analysis else {
        "total_threats": 0,
        "by_type": {},
        "by_level": {},
        "critical_count": 0,
        "high_count": 0
    }
    
    # Top data
    top_ips = analytics.get_top_ips(log_store, 10)
    top_endpoints = analytics.get_top_endpoints(log_store, 10)
    status_dist = analytics.get_status_distribution(log_store)
    
    # Recent threats
    recent_threats = threat_analysis[-10:] if threat_analysis else []
    
    return {
        "summary": {
            "total_logs": total_logs,
            "unique_ips": unique_ips,
            "total_threats": threat_summary["total_threats"],
            "critical_threats": threat_summary["critical_count"],
            "high_threats": threat_summary["high_count"],
            "last_updated": datetime.now().isoformat()
        },
        "threats": {
            "summary": threat_summary,
            "recent": recent_threats,
            "attack_patterns": attack_patterns
        },
        "analytics": {
            "top_ips": top_ips,
            "top_endpoints": top_endpoints,
            "status_distribution": status_dist
        },
        "system": {
            "status": "operational",
            "version": "2.0.0",
            "analysis_capabilities": [
                "SQL Injection Detection",
                "XSS Detection", 
                "Directory Scanning",
                "Git Exposure Detection",
                "Behavioral Analysis",
                "Scanner Identification"
            ]
        }
    }

@app.get("/api/threats")
async def get_threats(
    level: Optional[str] = None,
    type: Optional[str] = None,
    limit: int = 50
):
    """Get threat findings with filtering"""
    filtered = threat_analysis.copy()
    
    if level:
        filtered = [t for t in filtered if t.get("level") == level]
    
    if type:
        filtered = [t for t in filtered if t.get("type") == type]
    
    return {
        "count": len(filtered),
        "threats": filtered[-limit:],
        "filters_applied": {
            "level": level,
            "type": type
        }
    }

@app.get("/api/analytics")
async def get_analytics():
    """Get detailed analytics"""
    analytics = AnalyticsEngine()
    
    return {
        "top_ips": analytics.get_top_ips(log_store, 20),
        "top_endpoints": analytics.get_top_endpoints(log_store, 20),
        "status_distribution": analytics.get_status_distribution(log_store),
        "request_methods": Counter(log.get("method", "UNKNOWN") for log in log_store),
        "user_agents": Counter(
            log.get("user_agent", "Unknown")[:50] 
            for log in log_store 
            if log.get("user_agent")
        ).most_common(10),
        "time_analysis": {
            "logs_per_hour": min(1000, len(log_store)),  # Simplified for demo
            "peak_hour": "18:00"  # Would calculate from timestamps
        }
    }

@app.get("/api/logs")
async def get_logs(
    ip: Optional[str] = None,
    endpoint: Optional[str] = None,
    limit: int = 100
):
    """Get logs with filtering"""
    filtered = log_store.copy()
    
    if ip:
        filtered = [log for log in filtered if log.get("ip") == ip]
    
    if endpoint:
        filtered = [log for log in filtered if endpoint in log.get("endpoint", "")]
    
    return {
        "count": len(filtered),
        "logs": filtered[-limit:],
        "filters": {
            "ip": ip,
            "endpoint": endpoint
        }
    }

@app.get("/api/export")
async def export_data(format: str = "json"):
    """Export data in various formats"""
    if format == "json":
        return {
            "logs": log_store[-1000:],
            "threats": threat_analysis,
            "summary": AnalyticsEngine.get_threat_summary(threat_analysis) if threat_analysis else {},
            "export_time": datetime.now().isoformat()
        }
    elif format == "csv":
        # Simplified CSV export
        csv_lines = ["timestamp,ip,endpoint,status,threat_level,threat_type"]
        for threat in threat_analysis[-100:]:
            csv_lines.append(
                f"{threat.get('timestamp', '')},"
                f"{threat.get('ip', '')},"
                f"{threat.get('endpoint', '')},"
                f"{threat.get('status', '')},"
                f"{threat.get('level', '')},"
                f"{threat.get('type', '')}"
            )
        return "\n".join(csv_lines)
    
    return {"error": "Unsupported format"}

@app.get("/api/ip/{ip_address}")
async def get_ip_analysis(ip_address: str):
    """Get detailed analysis for a specific IP"""
    ip_logs = [log for log in log_store if log.get("ip") == ip_address]
    ip_threats = [t for t in threat_analysis if t.get("ip") == ip_address]
    
    if not ip_logs:
        return {"error": "IP not found in logs"}
    
    # Analyze IP behavior
    endpoints = set(log.get("endpoint") for log in ip_logs)
    statuses = Counter(log.get("status") for log in ip_logs)
    methods = Counter(log.get("method") for log in ip_logs)
    
    # Risk score calculation
    risk_score = 0
    risk_factors = []
    
    if len(endpoints) > 10:
        risk_score += 30
        risk_factors.append(f"Accessed {len(endpoints)} different endpoints")
    
    if any(threat.get("level") in ["high", "critical"] for threat in ip_threats):
        risk_score += 40
        risk_factors.append("High/critical threats detected")
    
    if len(ip_logs) > 100:
        risk_score += 20
        risk_factors.append(f"High volume: {len(ip_logs)} requests")
    
    risk_level = "low"
    if risk_score >= 70:
        risk_level = "critical"
    elif risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 30:
        risk_level = "medium"
    
    return {
        "ip": ip_address,
        "analysis": {
            "total_requests": len(ip_logs),
            "unique_endpoints": len(endpoints),
            "first_seen": min(log.get("timestamp", "") for log in ip_logs) if ip_logs else "",
            "last_seen": max(log.get("timestamp", "") for log in ip_logs) if ip_logs else "",
            "status_distribution": dict(statuses),
            "method_distribution": dict(methods),
            "sample_endpoints": list(endpoints)[:10]
        },
        "threats": {
            "count": len(ip_threats),
            "list": ip_threats,
            "by_type": Counter(t.get("type") for t in ip_threats)
        },
        "risk_assessment": {
            "score": risk_score,
            "level": risk_level,
            "factors": risk_factors,
            "recommendations": [
                "Monitor for further activity" if risk_level in ["low", "medium"] else "Consider blocking IP",
                "Review accessed endpoints for sensitivity",
                "Check if IP appears in threat intelligence feeds"
            ]
        }
    }

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
