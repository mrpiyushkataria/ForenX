"""
Universal log parser that auto-detects log format and dispatches to appropriate parser.
"""
import re
from typing import List, Dict, Optional, Callable
from datetime import datetime

from .nginx import parse_nginx_log
from .apache import parse_apache_log, parse_apache_error_log
from .mysql import parse_mysql_log
from .syslog import parse_syslog, parse_auth_log
from .json_logs import parse_json_logs

class UniversalLogParser:
    """Auto-detects log format and parses accordingly"""
    
    # Format detection patterns
    DETECTION_PATTERNS = [
        # Nginx/Apache access logs
        (r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\[.*\].*".*".*\d{3}.*\d+', 'web_access'),
        # Apache error logs
        (r'^\[.*?\].*\[.*?:.*?\].*\[pid.*?\].*\[client.*?\].*', 'apache_error'),
        # MySQL logs
        (r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z.*\d+\s+(Query|Connect)', 'mysql'),
        # Syslog (RFC 5424)
        (r'^<\d+>\d.*', 'syslog_rfc5424'),
        # Syslog (RFC 3164)
        (r'^<\d+>.*\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}.*', 'syslog_rfc3164'),
        # Auth logs
        (r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}.*(sshd|sudo|pam).*', 'auth_log'),
        # JSON logs
        (r'^\s*\{.*\}\s*$', 'json'),
        # JSON-ish logs (starts with timestamp then JSON)
        (r'^.*?\{.*\}\s*$', 'json_mixed'),
    ]
    
    # Parser mapping
    PARSERS = {
        'web_access': parse_nginx_log,  # Default to nginx, will detect apache format
        'apache_error': parse_apache_error_log,
        'mysql': parse_mysql_log,
        'syslog_rfc5424': lambda lines: parse_syslog(lines, 'rfc5424'),
        'syslog_rfc3164': lambda lines: parse_syslog(lines, 'rfc3164'),
        'auth_log': parse_auth_log,
        'json': parse_json_logs,
        'json_mixed': parse_json_logs,
    }
    
    @classmethod
    def detect_format(cls, sample_lines: List[str]) -> Optional[str]:
        """Detect log format from sample lines"""
        if not sample_lines:
            return None
        
        # Take first 10 lines for detection
        sample = sample_lines[:10]
        
        # Count matches for each pattern
        pattern_scores = {}
        
        for line in sample:
            for pattern, format_name in cls.DETECTION_PATTERNS:
                if re.match(pattern, line):
                    pattern_scores[format_name] = pattern_scores.get(format_name, 0) + 1
        
        # Return format with highest score
        if pattern_scores:
            return max(pattern_scores.items(), key=lambda x: x[1])[0]
        
        return None
    
    @classmethod
    def detect_web_server(cls, sample_lines: List[str]) -> str:
        """Detect if web logs are from Nginx or Apache"""
        if not sample_lines:
            return 'nginx'  # Default
        
        # Check for Apache combined format (has referrer and user agent quoted strings)
        apache_pattern = r'^\S+ \S+ \S+ \[.*?\].*".*?".*\d{3}.*".*?".*".*?"'
        
        for line in sample_lines[:5]:
            if re.match(apache_pattern, line):
                # Additional check for Apache specific formats
                if 'HTTP/' in line and ('" ' in line.count('"') == 7):
                    return 'apache'
        
        return 'nginx'
    
    @classmethod
    def parse_logs(cls, log_lines: List[str], format_hint: str = None) -> List[Dict]:
        """
        Parse logs with auto-detection or format hint.
        
        Args:
            log_lines: List of log lines
            format_hint: Optional hint ('nginx', 'apache', 'mysql', 'syslog', 'json')
        
        Returns:
            List of parsed events
        """
        if format_hint:
            # Use specified parser
            return cls._parse_with_hint(log_lines, format_hint)
        else:
            # Auto-detect format
            detected_format = cls.detect_format(log_lines)
            
            if detected_format:
                parser = cls.PARSERS.get(detected_format)
                if parser:
                    return parser(log_lines)
            
            # Fallback: try all parsers
            return cls._parse_with_fallback(log_lines)
    
    @classmethod
    def _parse_with_hint(cls, log_lines: List[str], format_hint: str) -> List[Dict]:
        """Parse logs with format hint"""
        format_hint = format_hint.lower()
        
        if format_hint in ['nginx', 'apache']:
            # Detect web server type
            web_type = cls.detect_web_server(log_lines)
            if web_type == 'apache':
                return parse_apache_log(log_lines)
            else:
                return parse_nginx_log(log_lines)
        
        elif format_hint == 'mysql':
            return parse_mysql_log(log_lines)
        
        elif format_hint == 'syslog':
            # Try both syslog formats
            for syslog_format in ['rfc5424', 'rfc3164']:
                try:
                    events = parse_syslog(log_lines, syslog_format)
                    if events:
                        return events
                except:
                    continue
        
        elif format_hint == 'json':
            return parse_json_logs(log_lines)
        
        elif format_hint == 'auth':
            return parse_auth_log(log_lines)
        
        # Default to universal detection
        return cls.parse_logs(log_lines)
    
    @classmethod
    def _parse_with_fallback(cls, log_lines: List[str]) -> List[Dict]:
        """Try all parsers and return the one that produces the most events"""
        results = []
        
        # Try each parser
        for format_name, parser in cls.PARSERS.items():
            try:
                events = parser(log_lines)
                if events:
                    results.append((format_name, events, len(events)))
            except Exception as e:
                continue
        
        # Return results from parser with most events
        if results:
            results.sort(key=lambda x: x[2], reverse=True)
            return results[0][1]
        
        return []  # No parser succeeded

# Convenience function
def parse_logs_auto(log_lines: List[str], **kwargs) -> List[Dict]:
    """Convenience wrapper for universal parsing"""
    return UniversalLogParser.parse_logs(log_lines, **kwargs)
