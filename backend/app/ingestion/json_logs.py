import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import re

def parse_json_logs(log_lines: List[str]) -> List[Dict]:
    """
    Parse JSON-formatted application logs.
    Supports various JSON log formats (Winston, Bunyan, Log4j JSON, etc.)
    """
    events = []
    
    for line in log_lines:
        try:
            # Try to parse as JSON
            log_data = json.loads(line.strip())
            
            # Normalize different JSON log formats
            normalized = normalize_json_log(log_data)
            
            if normalized:
                events.append(normalized)
                
        except json.JSONDecodeError:
            # Try to extract JSON from mixed-format logs
            extracted = extract_json_from_line(line)
            if extracted:
                normalized = normalize_json_log(extracted)
                if normalized:
                    events.append(normalized)
        except Exception as e:
            print(f"JSON log parse error: {e}, line: {line[:100]}")
    
    return events

def normalize_json_log(log_data: Dict[str, Any]) -> Optional[Dict]:
    """
    Normalize various JSON log formats to unified event model.
    """
    try:
        # Extract timestamp from various field names
        timestamp = extract_timestamp(log_data)
        
        # Extract log level/severity
        level = extract_log_level(log_data)
        
        # Extract message
        message = extract_message(log_data)
        
        # Extract IP address from various fields
        ip = extract_ip_address(log_data)
        
        # Extract endpoint/URL
        endpoint = extract_endpoint(log_data)
        
        # Extract method (HTTP method)
        method = extract_http_method(log_data)
        
        # Extract status code
        status = extract_status_code(log_data)
        
        # Extract response size
        response_size = extract_response_size(log_data)
        
        # Build normalized event
        event = {
            "timestamp": timestamp,
            "source": "json_log",
            "ip": ip,
            "method": method,
            "endpoint": endpoint,
            "status": status,
            "response_size": response_size,
            "payload": extract_payload(log_data),
            "raw": json.dumps(log_data),
            "log_level": level,
            "message": message
        }
        
        # Add metadata
        event.update(extract_metadata(log_data))
        
        return event
        
    except Exception as e:
        print(f"Normalization error: {e}")
        return None

def extract_timestamp(log_data: Dict) -> datetime:
    """Extract timestamp from various field names"""
    timestamp_fields = [
        'timestamp', 'time', '@timestamp', 'date', 'ts',
        'logTimestamp', 'datetime', 'createdAt'
    ]
    
    for field in timestamp_fields:
        if field in log_data:
            timestamp_str = log_data[field]
            return parse_timestamp(timestamp_str)
    
    # Default to current time
    return datetime.now()

def parse_timestamp(timestamp_str) -> datetime:
    """Parse timestamp string in various formats"""
    if isinstance(timestamp_str, (int, float)):
        # Unix timestamp (seconds or milliseconds)
        if timestamp_str > 1e10:  # Milliseconds
            return datetime.fromtimestamp(timestamp_str / 1000)
        else:  # Seconds
            return datetime.fromtimestamp(timestamp_str)
    
    # ISO format string
    if isinstance(timestamp_str, str):
        try:
            # ISO 8601
            if 'T' in timestamp_str:
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            # Common log format
            elif ' ' in timestamp_str and ':' in timestamp_str:
                for fmt in [
                    '%Y-%m-%d %H:%M:%S',
                    '%d/%b/%Y:%H:%M:%S %z',
                    '%a %b %d %H:%M:%S %Y'
                ]:
                    try:
                        return datetime.strptime(timestamp_str, fmt)
                    except:
                        continue
        except:
            pass
    
    return datetime.now()

def extract_log_level(log_data: Dict) -> str:
    """Extract log level"""
    level_fields = ['level', 'severity', 'logLevel', 'loglevel', 'pri']
    
    for field in level_fields:
        if field in log_data:
            level = str(log_data[field]).lower()
            
            # Normalize level names
            level_map = {
                'error': 'error', 'err': 'error', 'fatal': 'error',
                'warn': 'warning', 'warning': 'warning',
                'info': 'info', 'information': 'info',
                'debug': 'debug', 'verbose': 'debug',
                'trace': 'trace'
            }
            
            return level_map.get(level, level)
    
    return 'info'

def extract_message(log_data: Dict) -> str:
    """Extract log message"""
    message_fields = ['message', 'msg', 'log', 'description']
    
    for field in message_fields:
        if field in log_data:
            msg = log_data[field]
            if isinstance(msg, (str, int, float)):
                return str(msg)
    
    # Fallback to entire JSON
    return json.dumps(log_data, indent=2)[:500]

def extract_ip_address(log_data: Dict) -> Optional[str]:
    """Extract IP address from various fields"""
    ip_fields = ['ip', 'clientIp', 'remoteAddr', 'client_ip', 'source_ip']
    
    for field in ip_fields:
        if field in log_data:
            ip = str(log_data[field])
            # Validate IP format
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                return ip
    
    # Try to extract from nested fields
    if 'req' in log_data and isinstance(log_data['req'], dict):
        for field in ['ip', 'remoteAddress']:
            if field in log_data['req']:
                return str(log_data['req'][field])
    
    # Try to extract from message
    if 'message' in log_data:
        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', str(log_data['message']))
        if ip_match:
            return ip_match.group(0)
    
    return None

def extract_endpoint(log_data: Dict) -> Optional[str]:
    """Extract endpoint/URL"""
    endpoint_fields = ['endpoint', 'url', 'path', 'uri', 'resource']
    
    for field in endpoint_fields:
        if field in log_data:
            endpoint = str(log_data[field])
            # Clean up endpoint
            if endpoint.startswith('http'):
                from urllib.parse import urlparse
                parsed = urlparse(endpoint)
                endpoint = parsed.path
            return endpoint
    
    # Extract from request object
    if 'req' in log_data and isinstance(log_data['req'], dict):
        for field in ['url', 'path', 'originalUrl']:
            if field in log_data['req']:
                return str(log_data['req'][field])
    
    # Try to extract from message
    if 'message' in log_data:
        # Look for URL patterns
        url_pattern = r'(?:GET|POST|PUT|DELETE|PATCH)\s+(\S+)(?:\s+HTTP)'
        match = re.search(url_pattern, str(log_data['message']))
        if match:
            return match.group(1)
    
    return None

def extract_http_method(log_data: Dict) -> Optional[str]:
    """Extract HTTP method"""
    method_fields = ['method', 'httpMethod', 'requestMethod']
    
    for field in method_fields:
        if field in log_data:
            method = str(log_data[field]).upper()
            if method in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                return method
    
    # Extract from request object
    if 'req' in log_data and isinstance(log_data['req'], dict):
        if 'method' in log_data['req']:
            return str(log_data['req']['method']).upper()
    
    # Try to extract from message
    if 'message' in log_data:
        method_pattern = r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b'
        match = re.search(method_pattern, str(log_data['message']))
        if match:
            return match.group(1)
    
    return None

def extract_status_code(log_data: Dict) -> Optional[int]:
    """Extract HTTP status code"""
    status_fields = ['status', 'statusCode', 'code', 'httpStatus']
    
    for field in status_fields:
        if field in log_data:
            try:
                status = int(log_data[field])
                if 100 <= status <= 599:
                    return status
            except:
                pass
    
    # Extract from response object
    if 'res' in log_data and isinstance(log_data['res'], dict):
        for field in ['statusCode', 'status']:
            if field in log_data['res']:
                try:
                    return int(log_data['res'][field])
                except:
                    pass
    
    return None

def extract_response_size(log_data: Dict) -> int:
    """Extract response size in bytes"""
    size_fields = ['responseSize', 'bytes', 'contentLength', 'size']
    
    for field in size_fields:
        if field in log_data:
            try:
                return int(log_data[field])
            except:
                pass
    
    return 0

def extract_payload(log_data: Dict) -> Optional[str]:
    """Extract request payload/body"""
    payload_fields = ['payload', 'body', 'params', 'query', 'data']
    
    for field in payload_fields:
        if field in log_data:
            payload = log_data[field]
            if isinstance(payload, (str, dict, list)):
                # Convert to string, limit size
                payload_str = json.dumps(payload) if isinstance(payload, (dict, list)) else str(payload)
                return payload_str[:1000]  # Limit size
    
    return None

def extract_metadata(log_data: Dict) -> Dict:
    """Extract additional metadata"""
    metadata = {}
    
    # Common metadata fields
    meta_fields = [
        'userId', 'sessionId', 'userAgent', 'referrer',
        'duration', 'responseTime', 'tags', 'labels',
        'service', 'environment', 'host', 'app'
    ]
    
    for field in meta_fields:
        if field in log_data:
            metadata[field] = log_data[field]
    
    return metadata

def extract_json_from_line(line: str) -> Optional[Dict]:
    """
    Try to extract JSON from mixed-format log lines.
    Common pattern: [INFO] 2025-12-30T10:00:00Z {"message": "..."}
    """
    try:
        # Look for JSON object in line
        json_start = line.find('{')
        json_end = line.rfind('}')
        
        if json_start != -1 and json_end != -1 and json_end > json_start:
            json_str = line[json_start:json_end + 1]
            return json.loads(json_str)
    except:
        pass
    
    return None

# Support for structured logging formats
class StructuredLogParser:
    """Parser for specific structured logging formats"""
    
    @staticmethod
    def parse_winston_log(log_data: Dict) -> Dict:
        """Parse Winston (Node.js) log format"""
        result = {}
        
        # Winston format: { level, message, timestamp, meta }
        if 'level' in log_data:
            result['log_level'] = log_data['level']
        
        if 'message' in log_data:
            result['message'] = log_data['message']
        
        if 'timestamp' in log_data:
            result['timestamp'] = parse_timestamp(log_data['timestamp'])
        
        if 'meta' in log_data and isinstance(log_data['meta'], dict):
            # Extract HTTP request info from meta
            if 'req' in log_data['meta']:
                result.update(extract_http_info(log_data['meta']['req']))
        
        return result
    
    @staticmethod
    def parse_bunyan_log(log_data: Dict) -> Dict:
        """Parse Bunyan (Node.js) log format"""
        result = {}
        
        # Bunyan format: { v, level, name, hostname, pid, time, msg, ... }
        if 'msg' in log_data:
            result['message'] = log_data['msg']
        
        if 'level' in log_data:
            # Bunyan levels: 10=trace, 20=debug, 30=info, 40=warn, 50=error, 60=fatal
            level_map = {10: 'trace', 20: 'debug', 30: 'info', 40: 'warning', 50: 'error', 60: 'fatal'}
            result['log_level'] = level_map.get(log_data['level'], 'info')
        
        if 'time' in log_data:
            result['timestamp'] = parse_timestamp(log_data['time'])
        
        # Bunyan often includes req/res objects
        if 'req' in log_data:
            result.update(extract_http_info(log_data['req']))
        
        return result
    
    @staticmethod
    def parse_log4j_json(log_data: Dict) -> Dict:
        """Parse Log4j JSON format"""
        result = {}
        
        # Log4j JSON format: { timestamp, level, logger, message, ... }
        if 'message' in log_data:
            result['message'] = log_data['message']
        
        if 'level' in log_data:
            result['log_level'] = log_data['level'].lower()
        
        if 'timestamp' in log_data:
            result['timestamp'] = parse_timestamp(log_data['timestamp'])
        
        # Log4j often includes MDC (Mapped Diagnostic Context)
        if 'mdc' in log_data and isinstance(log_data['mdc'], dict):
            if 'ip' in log_data['mdc']:
                result['ip'] = log_data['mdc']['ip']
            if 'request' in log_data['mdc']:
                result['endpoint'] = log_data['mdc']['request']
        
        return result

def extract_http_info(req_data: Dict) -> Dict:
    """Extract HTTP information from request object"""
    result = {}
    
    if isinstance(req_data, dict):
        if 'method' in req_data:
            result['method'] = req_data['method'].upper()
        
        if 'url' in req_data:
            result['endpoint'] = req_data['url']
        
        if 'headers' in req_data and isinstance(req_data['headers'], dict):
            if 'x-forwarded-for' in req_data['headers']:
                result['ip'] = req_data['headers']['x-forwarded-for'].split(',')[0].strip()
            elif 'x-real-ip' in req_data['headers']:
                result['ip'] = req_data['headers']['x-real-ip']
        
        if 'socket' in req_data and isinstance(req_data['socket'], dict):
            if 'remoteAddress' in req_data['socket']:
                result['ip'] = req_data['socket']['remoteAddress']
    
    return result
