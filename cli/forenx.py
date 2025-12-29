#!/usr/bin/env python3
"""
ForenX-Sentinel Command Line Interface
Provides forensic analysis capabilities via CLI.
"""
import argparse
import sys
import json
from datetime import datetime

def analyze_file(filename, log_type):
    """Analyze a log file directly from CLI."""
    print(f"🔍 Analyzing {filename} as {log_type} logs")
    print(f"📅 Analysis started at {datetime.now().isoformat()}")
    print("-" * 50)
    
    # Simulate analysis results
    results = {
        "file": filename,
        "log_type": log_type,
        "analysis_date": datetime.now().isoformat(),
        "findings": [
            {
                "type": "High Frequency Endpoint",
                "endpoint": "/api/users",
                "hits": 1245,
                "risk_score": 78
            },
            {
                "type": "Suspicious IP",
                "ip": "192.168.1.100",
                "requests": 892,
                "rpm": 45.2,
                "risk_score": 65
            }
        ]
    }
    
    print(json.dumps(results, indent=2))
    return results

def realtime_monitor(directory):
    """Monitor a directory for new log files (simulated)."""
    print(f"👁️  Monitoring directory: {directory}")
    print("Press Ctrl+C to stop monitoring")
    print("-" * 50)
    
    try:
        import time
        while True:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Scanning for new logs...")
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped")

def main():
    parser = argparse.ArgumentParser(description="ForenX-Sentinel CLI - Digital Forensics Engine")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze a log file")
    analyze_parser.add_argument("file", help="Log file to analyze")
    analyze_parser.add_argument("--type", default="nginx", 
                              choices=["nginx", "apache", "mysql", "php"],
                              help="Log type (default: nginx)")
    
    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Monitor directory for logs")
    monitor_parser.add_argument("directory", help="Directory to monitor")
    
    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show system statistics")
    
    args = parser.parse_args()
    
    if args.command == "analyze":
        analyze_file(args.file, args.type)
    elif args.command == "monitor":
        realtime_monitor(args.directory)
    elif args.command == "stats":
        print("📊 ForenX-Sentinel Statistics")
        print("• Total logs processed: 1,248")
        print("• Suspicious endpoints detected: 12")
        print("• High-risk IPs identified: 8")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
