import re
from datetime import datetime
from typing import List, Dict

def parse_nginx_log(log_lines: List[str]) -> List[Dict]:
    """
    Parse Nginx access logs in combined format.
    Example: 127.0.0.1 - - [30/Dec/2025:10:00:00 +0000] "GET /api/users HTTP/1.1" 200 1234
    """
    events = []
    log_pattern = re.compile(
        r'(?P<ip>\S+) - - \[(?P<timestamp>.*?)\] "(?P<method>\w+) (?P<endpoint>\S+) HTTP/\d\.\d" (?P<status>\d+) (?P<size>\d+)'
    )
    
    for line in log_lines:
        match = log_pattern.search(line)
        if match:
            try:
                # Parse timestamp from Nginx format
                dt = datetime.strptime(match.group('timestamp'), '%d/%b/%Y:%H:%M:%S %z')
                
                event = {
                    "timestamp": dt,
                    "source": "nginx",
                    "ip": match.group('ip'),
                    "method": match.group('method'),
                    "endpoint": match.group('endpoint'),
                    "status": int(match.group('status')),
                    "response_size": int(match.group('size')),
                    "payload": None,  # Would extract from POST requests
                    "raw": line.strip()
                }
                events.append(event)
            except Exception as e:
                # Log parsing errors but continue processing
                print(f"Error parsing line: {line[:100]}... Error: {e}")
    
    return events
