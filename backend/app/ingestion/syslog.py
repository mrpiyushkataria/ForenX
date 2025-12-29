import re
from datetime import datetime
from typing import List, Dict, Optional
import socket

def parse_syslog(log_lines: List[str], format: str = "rfc5424") -> List[Dict]:
    """
    Parse syslog messages (RFC 3164/RFC 5424).
    Critical for authentication logs (ssh, sudo, pam).
    """
    events = []
    
    if format == "rfc5424":
        # RFC 5424 format with structured data
        pattern = re.compile(
            r'<(?P<pri>\d+)>(?P<version>\d+) (?P<timestamp>\S+) (?P<hostname>\S+) '
            r'(?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) (?P<sd>\[.*?\])? ?(?P<message>.*)'
        )
    else:
        # RFC 3164 traditional format
        pattern = re.compile(
            r'<(?P<pri>\d+)>(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) '
            r'(?P<hostname>\S+) (?P<tag>\S+): (?P<message>.*)'
        )
    
    for line in log_lines:
        match = pattern.search(line)
        if match:
            try:
                # Parse priority (facility * 8 + severity)
                pri = int(match.group('pri'))
                facility = pri // 8
                severity = pri % 8
                
                # Parse timestamp
                timestamp_str = match.group('timestamp')
                dt = parse_syslog_timestamp(timestamp_str, format)
                
                # Extract IP from hostname if possible
                hostname = match.group('hostname')
                ip = hostname if is_ip_address(hostname) else None
                
                event = {
                    "timestamp": dt,
                    "source": "syslog",
                    "ip": ip,
                    "hostname": hostname,
                    "facility": facility,
                    "severity": severity,
                    "app": match.group('app') if format == "rfc5424" else match.group('tag'),
                    "message": match.group('message'),
                    "raw": line.strip()
                }
                
                # Parse common security events
                event.update(parse_security_events(event['message']))
                
                events.append(event)
                
            except Exception as e:
                print(f"Syslog parse error: {e}, line: {line[:100]}")
    
    return events

def parse_syslog_timestamp(timestamp_str: str, format: str) -> datetime:
    """Parse syslog timestamp"""
    try:
        if format == "rfc5424":
            # ISO 8601 format with optional fractions and timezone
            if '.' in timestamp_str:
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                return datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S%z')
        else:
            # Traditional format: "Dec 30 10:00:00"
            current_year = datetime.now().year
            dt = datetime.strptime(f"{timestamp_str} {current_year}", '%b %d %H:%M:%S %Y')
            return dt
    except:
        return datetime.now()

def is_ip_address(hostname: str) -> bool:
    """Check if string is an IP address"""
    try:
        socket.inet_pton(socket.AF_INET, hostname)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
            return True
        except socket.error:
            return False

def parse_security_events(message: str) -> Dict:
    """Parse specific security events from syslog messages"""
    result = {
        "event_type": "generic",
        "risk_score": 10,
        "details": {}
    }
    
    # SSH authentication events
    ssh_patterns = {
        "failed_password": re.compile(r'Failed password for (?P<user>\S+) from (?P<ip>\S+)'),
        "accepted_password": re.compile(r'Accepted password for (?P<user>\S+) from (?P<ip>\S+)'),
        "invalid_user": re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>\S+)'),
        "break_in_attempt": re.compile(r'POSSIBLE BREAK-IN ATTEMPT'),
        "too_many_authentication_failures": re.compile(r'Too many authentication failures')
    }
    
    for event_type, pattern in ssh_patterns.items():
        match = pattern.search(message)
        if match:
            result["event_type"] = "ssh_" + event_type
            result["details"] = match.groupdict()
            
            # Set risk scores
            if "failed" in event_type or "invalid" in event_type:
                result["risk_score"] = 60
            elif "break_in" in event_type or "too_many" in event_type:
                result["risk_score"] = 80
            elif "accepted" in event_type:
                result["risk_score"] = 20
            
            break
    
    # Sudo events
    sudo_pattern = re.compile(r'(?P<user>\S+) : (?P<tty>\S+) ; (?P<cmd>.*)')
    match = sudo_pattern.search(message)
    if match:
        result["event_type"] = "sudo_command"
        result["details"] = match.groupdict()
        result["risk_score"] = 40
    
    # PAM authentication events
    pam_patterns = {
        "session_opened": re.compile(r'session opened for user (?P<user>\S+)'),
        "session_closed": re.compile(r'session closed for user (?P<user>\S+)'),
        "authentication_failure": re.compile(r'authentication failure')
    }
    
    for event_type, pattern in pam_patterns.items():
        if pattern.search(message):
            result["event_type"] = "pam_" + event_type
            result["risk_score"] = 50 if "failure" in event_type else 20
            break
    
    return result

# Specialized parser for auth.log
def parse_auth_log(log_lines: List[str]) -> List[Dict]:
    """
    Parse Linux authentication logs (/var/log/auth.log)
    """
    events = []
    
    # Common auth.log patterns
    patterns = {
        "ssh": re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) '
            r'(?P<hostname>\S+) sshd\[(?P<pid>\d+)\]: (?P<message>.*)'
        ),
        "sudo": re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) '
            r'(?P<hostname>\S+) sudo: (?P<message>.*)'
        ),
        "pam": re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) '
            r'(?P<hostname>\S+) (?P<service>\S+): pam_(?P<message>.*)'
        )
    }
    
    for line in log_lines:
        for log_type, pattern in patterns.items():
            match = pattern.search(line)
            if match:
                try:
                    # Parse timestamp
                    timestamp_str = match.group('timestamp')
                    current_year = datetime.now().year
                    dt = datetime.strptime(f"{timestamp_str} {current_year}", '%b %d %H:%M:%S %Y')
                    
                    event = {
                        "timestamp": dt,
                        "source": "auth_log",
                        "log_type": log_type,
                        "hostname": match.group('hostname'),
                        "message": match.group('message'),
                        "raw": line.strip()
                    }
                    
                    # Add PID if present
                    if 'pid' in match.groupdict():
                        event['pid'] = int(match.group('pid'))
                    
                    # Parse security details
                    security_info = parse_security_events(event['message'])
                    event.update(security_info)
                    
                    events.append(event)
                    break
                    
                except Exception as e:
                    print(f"Auth log parse error: {e}")
    
    return events
