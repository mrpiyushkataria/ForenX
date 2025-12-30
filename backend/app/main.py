from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Dict, Optional
import uvicorn
import os
import re
from datetime import datetime
from collections import defaultdict, Counter
import json

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

# In-memory storage for demo
log_store = []
threat_analysis = []

# ========== SIMPLIFIED LOG PARSING ==========

def parse_log_line(line: str) -> Optional[Dict]:
    """Parse common log formats"""
    try:
        # Skip empty lines
        if not line.strip():
            return None
            
        # Common log pattern: IP - - [timestamp] "request" status size
        pattern = r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)'
        match = re.search(pattern, line)
        
        if match:
            ip, timestamp, request, status, size = match.groups()
            
            # Parse request method and endpoint
            method = "GET"
            endpoint = "/"
            if ' ' in request:
                parts = request.split(' ')
                if len(parts) >= 2:
                    method = parts[0]
                    endpoint = parts[1]
            
            return {
                "ip": ip,
                "timestamp": timestamp,
                "method": method,
                "endpoint": endpoint,
                "status": int(status),
                "size": int(size),
                "raw": line[:200],  # Store first 200 chars
                "source": "web",
                "parsed_at": datetime.now().isoformat()
            }
        
        # Try to extract IP and basic info from any line
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            return {
                "ip": ip_match.group(0),
                "raw": line[:200],
                "source": "generic",
                "parsed_at": datetime.now().isoformat()
            }
            
        return None
        
    except Exception as e:
        print(f"Error parsing line: {e}")
        return None

# ========== SIMPLIFIED THREAT DETECTION ==========

def detect_threats_simple(log_entry: Dict) -> List[Dict]:
    """Simple threat detection"""
    threats = []
    
    endpoint = log_entry.get("endpoint", "")
    raw = log_entry.get("raw", "")
    ip = log_entry.get("ip", "")
    
    # Git exposure detection
    if ".git" in endpoint.lower():
        threats.append({
            "type": "git_exposure",
            "level": "high",
            "description": "Git repository exposure attempt",
            "confidence": 0.9,
            "ip": ip,
            "endpoint": endpoint
        })
    
    # Config file access
    config_files = [".env", "config", "wp-config", "settings", ".htaccess"]
    if any(config in endpoint.lower() for config in config_files):
        threats.append({
            "type": "config_access",
            "level": "medium",
            "description": "Configuration file access attempt",
            "confidence": 0.7,
            "ip": ip,
            "endpoint": endpoint
        })
    
    # Scanner detection in user-agent (from raw)
    scanners = ["l9explore", "l9tcpid", "sqlmap", "nikto", "acunetix", "wpscan", "nmap"]
    if any(scanner in raw.lower() for scanner in scanners):
        threats.append({
            "type": "scanner",
            "level": "medium",
            "description": "Vulnerability scanner detected",
            "confidence": 0.8,
            "ip": ip
        })
    
    # SQL injection patterns
    sql_patterns = ["' or ", "' and ", "union select", "select * from", "insert into", "drop table"]
    if any(pattern in raw.lower() for pattern in sql_patterns):
        threats.append({
            "type": "sql_injection",
            "level": "high",
            "description": "SQL injection attempt",
            "confidence": 0.6,
            "ip": ip
        })
    
    # XSS patterns
    xss_patterns = ["<script", "javascript:", "onerror=", "alert("]
    if any(pattern in raw.lower() for pattern in xss_patterns):
        threats.append({
            "type": "xss",
            "level": "high",
            "description": "Cross-site scripting attempt",
            "confidence": 0.7,
            "ip": ip
        })
    
    # Directory traversal
    if "../" in endpoint or "..\\" in endpoint:
        threats.append({
            "type": "directory_traversal",
            "level": "high",
            "description": "Directory traversal attempt",
            "confidence": 0.8,
            "ip": ip,
            "endpoint": endpoint
        })
    
    return threats

# ========== API ENDPOINTS ==========

@app.get("/")
async def root():
    return {
        "message": "ForenX Sentinel Forensic Analysis Engine",
        "version": "2.0.0",
        "status": "operational",
        "endpoints": {
            "health": "/health",
            "upload": "POST /api/upload",
            "dashboard": "/api/dashboard",
            "threats": "/api/threats",
            "analytics": "/api/analytics",
            "logs": "/api/logs"
        }
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "log_count": len(log_store),
        "threat_count": len(threat_analysis)
    }

@app.post("/api/upload")
async def upload_log(file: UploadFile = File(...)):
    """Upload and analyze log file - DEBUGGED VERSION"""
    try:
        print(f"Starting upload for file: {file.filename}")
        
        # Read file content
        content = await file.read()
        print(f"File size: {len(content)} bytes")
        
        # Decode content
        try:
            text_content = content.decode('utf-8')
        except UnicodeDecodeError:
            # Try other encodings
            for encoding in ['latin-1', 'iso-8859-1', 'cp1252']:
                try:
                    text_content = content.decode(encoding)
                    break
                except:
                    continue
            else:
                text_content = content.decode('utf-8', errors='ignore')
        
        # Split into lines
        lines = text_content.splitlines()
        print(f"Total lines: {len(lines)}")
        
        # Parse logs (limit to 5000 lines for performance)
        parsed_logs = []
        threats_found = []
        
        for i, line in enumerate(lines[:5000]):
            if i % 1000 == 0 and i > 0:
                print(f"Parsed {i} lines...")
            
            if not line.strip():
                continue
                
            log_entry = parse_log_line(line)
            if log_entry:
                log_entry["id"] = len(log_store) + len(parsed_logs) + 1
                parsed_logs.append(log_entry)
                
                # Detect threats
                threats = detect_threats_simple(log_entry)
                for threat in threats:
                    threat["log_id"] = log_entry["id"]
                    threat["timestamp"] = datetime.now().isoformat()
                    threat["file"] = file.filename
                    threats_found.append(threat)
        
        # Store results
        log_store.extend(parsed_logs)
        threat_analysis.extend(threats_found)
        
        print(f"Parsed {len(parsed_logs)} logs, found {len(threats_found)} threats")
        
        return JSONResponse({
            "filename": file.filename,
            "size_bytes": len(content),
            "lines_total": len(lines),
            "lines_parsed": len(parsed_logs),
            "threats_detected": len(threats_found),
            "message": "Log file analyzed successfully",
            "sample_threats": threats_found[:3],
            "status": "success"
        })
        
    except Exception as e:
        print(f"ERROR in upload: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=500, 
            detail=f"Analysis error: {str(e)}"
        )

@app.get("/api/dashboard")
async def get_dashboard():
    """Get dashboard data"""
    try:
        # Basic counts
        total_logs = len(log_store)
        unique_ips = len(set(log.get("ip") for log in log_store if log.get("ip")))
        
        # Threat counts by level
        threat_counts = {
            "critical": sum(1 for t in threat_analysis if t.get("level") == "critical"),
            "high": sum(1 for t in threat_analysis if t.get("level") == "high"),
            "medium": sum(1 for t in threat_analysis if t.get("level") == "medium"),
            "low": sum(1 for t in threat_analysis if t.get("level") == "low"),
            "total": len(threat_analysis)
        }
        
        # Top IPs
        ip_counter = Counter(log.get("ip") for log in log_store if log.get("ip"))
        top_ips = [{"ip": ip, "count": count} for ip, count in ip_counter.most_common(10)]
        
        # Top endpoints
        endpoint_counter = Counter(log.get("endpoint") for log in log_store if log.get("endpoint"))
        top_endpoints = [{"endpoint": ep, "count": count} for ep, count in endpoint_counter.most_common(10)]
        
        # Status distribution
        status_counter = Counter(log.get("status") for log in log_store if log.get("status"))
        status_dist = {
            "2xx": sum(count for status, count in status_counter.items() if 200 <= status < 300),
            "3xx": sum(count for status, count in status_counter.items() if 300 <= status < 400),
            "4xx": sum(count for status, count in status_counter.items() if 400 <= status < 500),
            "5xx": sum(count for status, count in status_counter.items() if 500 <= status < 600),
            "details": {str(k): v for k, v in status_counter.items()}
        }
        
        # Recent threats (last 10)
        recent_threats = threat_analysis[-10:] if threat_analysis else []
        
        return {
            "summary": {
                "total_logs": total_logs,
                "unique_ips": unique_ips,
                "total_threats": threat_counts["total"],
                "critical_threats": threat_counts["critical"],
                "high_threats": threat_counts["high"],
                "medium_threats": threat_counts["medium"],
                "low_threats": threat_counts["low"],
                "last_updated": datetime.now().isoformat()
            },
            "analytics": {
                "top_ips": top_ips,
                "top_endpoints": top_endpoints,
                "status_distribution": status_dist
            },
            "threats": {
                "recent": recent_threats,
                "counts": threat_counts
            },
            "system": {
                "status": "operational",
                "version": "2.0.0",
                "memory_usage": {
                    "logs": total_logs,
                    "threats": len(threat_analysis)
                }
            }
        }
        
    except Exception as e:
        print(f"Error in dashboard: {e}")
        return {
            "summary": {
                "total_logs": 0,
                "unique_ips": 0,
                "total_threats": 0,
                "last_updated": datetime.now().isoformat()
            },
            "error": str(e)
        }

@app.get("/api/threats")
async def get_threats(
    level: Optional[str] = None,
    type: Optional[str] = None,
    limit: int = 50
):
    """Get threats with filtering"""
    try:
        filtered = threat_analysis.copy()
        
        if level:
            filtered = [t for t in filtered if t.get("level") == level]
        
        if type:
            filtered = [t for t in filtered if t.get("type") == type]
        
        return {
            "count": len(filtered),
            "threats": filtered[-limit:],
            "filters": {
                "level": level,
                "type": type
            }
        }
    except Exception as e:
        return {"error": str(e), "threats": []}

@app.get("/api/analytics")
async def get_analytics():
    """Get analytics data"""
    try:
        # IP analysis
        ip_counter = Counter(log.get("ip") for log in log_store if log.get("ip"))
        top_ips = [{"ip": ip, "count": count, "percentage": (count/len(log_store))*100 if log_store else 0}
                  for ip, count in ip_counter.most_common(20)]
        
        # Endpoint analysis
        endpoint_counter = Counter(log.get("endpoint") for log in log_store if log.get("endpoint"))
        top_endpoints = [{"endpoint": ep, "count": count} 
                        for ep, count in endpoint_counter.most_common(20)]
        
        # Method analysis
        method_counter = Counter(log.get("method", "UNKNOWN") for log in log_store)
        
        # Threat type analysis
        threat_type_counter = Counter(t.get("type", "unknown") for t in threat_analysis)
        
        return {
            "top_ips": top_ips,
            "top_endpoints": top_endpoints,
            "methods": dict(method_counter),
            "threat_types": dict(threat_type_counter),
            "total_requests": len(log_store),
            "analysis_time": datetime.now().isoformat()
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/logs")
async def get_logs(
    ip: Optional[str] = None,
    limit: int = 100
):
    """Get logs with optional IP filter"""
    try:
        filtered = log_store.copy()
        
        if ip:
            filtered = [log for log in filtered if log.get("ip") == ip]
        
        return {
            "count": len(filtered),
            "logs": filtered[-limit:],
            "filter": {"ip": ip} if ip else None
        }
    except Exception as e:
        return {"error": str(e), "logs": []}

@app.get("/api/ip/{ip_address}")
async def analyze_ip(ip_address: str):
    """Analyze specific IP address"""
    try:
        ip_logs = [log for log in log_store if log.get("ip") == ip_address]
        ip_threats = [t for t in threat_analysis if t.get("ip") == ip_address]
        
        if not ip_logs:
            return {"error": "IP not found in logs"}
        
        # Calculate risk score
        risk_score = 0
        risk_factors = []
        
        if len(ip_logs) > 100:
            risk_score += 30
            risk_factors.append(f"High volume: {len(ip_logs)} requests")
        
        if len(set(log.get("endpoint") for log in ip_logs if log.get("endpoint"))) > 20:
            risk_score += 25
            risk_factors.append("Accessed many different endpoints")
        
        if any(t.get("level") in ["high", "critical"] for t in ip_threats):
            risk_score += 45
            risk_factors.append("High/critical threats detected")
        
        risk_level = "low"
        if risk_score >= 70:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 30:
            risk_level = "medium"
        
        return {
            "ip": ip_address,
            "stats": {
                "total_requests": len(ip_logs),
                "first_seen": min(log.get("timestamp", "") for log in ip_logs) if ip_logs else "",
                "last_seen": max(log.get("timestamp", "") for log in ip_logs) if ip_logs else "",
                "threat_count": len(ip_threats)
            },
            "threats": ip_threats[-10:],
            "risk_assessment": {
                "score": risk_score,
                "level": risk_level,
                "factors": risk_factors,
                "recommendation": "Monitor activity" if risk_level in ["low", "medium"] else "Consider blocking"
            }
        }
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/clear")
async def clear_data():
    """Clear all data (for testing)"""
    global log_store, threat_analysis
    count = len(log_store) + len(threat_analysis)
    log_store = []
    threat_analysis = []
    return {"message": f"Cleared {count} records", "status": "success"}

if __name__ == "__main__":
    print("Starting ForenX Sentinel on http://0.0.0.0:8000")
    print("API Documentation: http://localhost:8000/docs")
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
