import re
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs

def parse_apache_log(log_lines: List[str], log_format: str = "combined") -> List[Dict]:
    """
    Parse Apache access logs with multiple format support.
    Supports: common, combined, vhost_combined
    """
    events = []
    
    # Define regex patterns for different formats
    patterns = {
        "common": re.compile(
            r'(?P<host>\S+) (?P<identity>\S+) (?P<user>\S+) \[(?P<timestamp>.*?)\] '
            r'"(?P<request>.*?)" (?P<status>\d+) (?P<size>\S+)'
        ),
        "combined": re.compile(
            r'(?P<host>\S+) (?P<identity>\S+) (?P<user>\S+) \[(?P<timestamp>.*?)\] '
            r'"(?P<request>.*?)" (?P<status>\d+) (?P<size>\S+) '
            r'"(?P<referrer>.*?)" "(?P<user_agent>.*?)"'
        ),
        "vhost_combined": re.compile(
            r'(?P<vhost>\S+):(?P<port>\d+) (?P<host>\S+) (?P<identity>\S+) (?P<user>\S+) '
            r'\[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d+) (?P<size>\S+) '
            r'"(?P<referrer>.*?)" "(?P<user_agent>.*?)"'
        )
    }
    
    pattern = patterns.get(log_format, patterns["combined"])
    
    for line in log_lines:
        match = pattern.search(line)
        if match:
            try:
                # Parse timestamp (Apache format: 30/Dec/2025:10:00:00 +0000)
                timestamp_str = match.group('timestamp')
                dt = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
                
                # Parse request line (e.g., "GET /api/users HTTP/1.1")
                request = match.group('request')
                method, endpoint, _ = parse_request_line(request)
                
                # Parse query parameters for payload extraction
                payload = extract_payload_from_url(endpoint)
                
                event = {
                    "timestamp": dt,
                    "source": "apache",
                    "ip": match.group('host'),
                    "method": method,
                    "endpoint": endpoint.split('?')[0] if '?' in endpoint else endpoint,
                    "status": int(match.group('status')),
                    "response_size": parse_size(match.group('size')),
                    "payload": payload,
                    "user_agent": match.group('user_agent') if 'user_agent' in match.groupdict() else None,
                    "referrer": match.group('referrer') if 'referrer' in match.groupdict() else None,
                    "raw": line.strip()
                }
                
                # Add vhost if present
                if 'vhost' in match.groupdict() and match.group('vhost'):
                    event['vhost'] = match.group('vhost')
                
                events.append(event)
                
            except Exception as e:
                print(f"Apache parse error: {e}, line: {line[:100]}")
    
    return events

def parse_request_line(request: str) -> tuple:
    """Parse HTTP request line into method, endpoint, protocol"""
    parts = request.split(' ')
    if len(parts) >= 3:
        return parts[0], parts[1], parts[2]
    elif len(parts) == 2:
        return parts[0], parts[1], 'HTTP/1.0'
    else:
        return None, request, None

def extract_payload_from_url(endpoint: str) -> Optional[str]:
    """Extract query parameters as payload for analysis"""
    if '?' not in endpoint:
        return None
    
    try:
        parsed = urlparse(endpoint)
        query_params = parse_qs(parsed.query)
        
        # Convert to string for storage
        payload_parts = []
        for key, values in query_params.items():
            for value in values:
                if len(value) < 1000:  # Limit size
                    payload_parts.append(f"{key}={value}")
        
        return '&'.join(payload_parts) if payload_parts else None
        
    except:
        return None

def parse_size(size_str: str) -> int:
    """Parse size (could be '-' for zero)"""
    if size_str == '-':
        return 0
    try:
        return int(size_str)
    except:
        return 0

# Support for error logs
def parse_apache_error_log(log_lines: List[str]) -> List[Dict]:
    """
    Parse Apache error logs for forensic analysis.
    Format: [Day Month DD HH:MM:SS.YYYY] [module:level] [pid:tid] [client IP:port] message
    """
    events = []
    pattern = re.compile(
        r'\[(?P<timestamp>.*?)\] \[(?P<module>.*?):(?P<level>.*?)\] '
        r'\[pid (?P<pid>\d+):tid (?P<tid>.*?)\] '
        r'\[client (?P<client>.*?)\] (?P<message>.*)'
    )
    
    for line in log_lines:
        match = pattern.search(line)
        if match:
            try:
                # Parse timestamp (e.g., "Mon Dec 30 10:00:00.123456 2025")
                timestamp_str = match.group('timestamp')
                dt = datetime.strptime(timestamp_str, '%a %b %d %H:%M:%S.%f %Y')
                
                # Extract IP from client field (e.g., "192.168.1.100:54321")
                client = match.group('client')
                ip = client.split(':')[0] if ':' in client else client
                
                event = {
                    "timestamp": dt,
                    "source": "apache_error",
                    "ip": ip,
                    "level": match.group('level').lower(),
                    "module": match.group('module'),
                    "pid": int(match.group('pid')),
                    "message": match.group('message'),
                    "raw": line.strip(),
                    "is_error": True
                }
                
                # Add risk score based on error level
                risk_scores = {
                    'emerg': 90, 'alert': 80, 'crit': 70,
                    'error': 60, 'warn': 40, 'notice': 20,
                    'info': 10, 'debug': 0
                }
                event['risk_score'] = risk_scores.get(event['level'], 50)
                
                events.append(event)
                
            except Exception as e:
                print(f"Apache error parse error: {e}")
    
    return events
