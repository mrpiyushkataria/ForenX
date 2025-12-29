# /backend/app/ingestion/mysql.py
import re
from datetime import datetime
from typing import List, Dict

def parse_mysql_log(log_lines: List[str]) -> List[Dict]:
    """
    Parse MySQL general/slow query logs for forensic analysis.
    Critical for SQL injection detection and database correlation.
    """
    events = []
    
    # Parse MySQL general query log format
    # Example: 2025-12-30T10:00:00.123456Z     1 Connect root@localhost on 
    #          2025-12-30T10:00:01.234567Z     1 Query    SELECT * FROM users
    
    query_pattern = re.compile(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+' +
        r'(?P<thread_id>\d+)\s+' +
        r'(?P<command>\w+)\s+' +
        r'(?P<query>.*)'
    )
    
    for line in log_lines:
        if "Query" in line or "Connect" in line:
            match = query_pattern.search(line)
            if match:
                try:
                    dt = datetime.fromisoformat(match.group('timestamp').replace('Z', '+00:00'))
                    
                    event = {
                        "timestamp": dt,
                        "source": "mysql",
                        "ip": "localhost",  # Would extract from Connect statements
                        "method": "QUERY",
                        "endpoint": None,
                        "status": None,
                        "response_size": 0,
                        "payload": match.group('query'),
                        "raw": line.strip(),
                        "query_type": match.group('command'),
                        "thread_id": match.group('thread_id')
                    }
                    
                    # Flag potential SQL injection patterns
                    sql_patterns = [
                        r'(\-\-|\#)',  # Comments
                        r'(union.*select)',  # UNION injections
                        r'(sleep\(|benchmark\()',  # Time-based
                        r'(select.*from.*where.*=.*\')',  # Basic injection
                    ]
                    
                    for pattern in sql_patterns:
                        if re.search(pattern, event["payload"], re.IGNORECASE):
                            event["suspicious"] = True
                            event["risk_score"] = 70
                            break
                    
                    events.append(event)
                except Exception as e:
                    print(f"MySQL parse error: {e}")
    
    return events
