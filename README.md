# 🕵️ ForenX Sentinel - Professional Digital Forensics Engine

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)

**ForenX Sentinel** is a comprehensive, production-ready digital forensics and incident response engine specialized in server-side log analysis. It identifies security incidents, endpoint abuse, data exfiltration behavior, and malicious automation across web, application, database, and system logs.

## 🚀 Features

### 🔍 **Core Capabilities**
- **Real-time Monitoring**: Live log ingestion and analysis
- **Historical Forensics**: Timeline reconstruction and attack chain analysis
- **Multi-layer Correlation**: Web → Application → Database event correlation
- **Advanced Detection**: SQLi, XSS, brute force, data exfiltration, scanning
- **Risk Scoring**: Context-aware risk assessment with confidence levels
- **Threat Intelligence**: Integration with AbuseIPDB, VirusTotal, Shodan

### 📊 **Analysis Modules**
1. **Log Ingestion Engine**
   - Nginx, Apache, MySQL, Syslog, JSON log parsers
   - Universal log format auto-detection
   - Real-time streaming support

2. **Detection Engine**
   - SQL Injection Detection (OWASP patterns)
   - XSS Attack Detection
   - Brute Force & Credential Stuffing
   - Data Exfiltration & Dumping
   - Vulnerability Scanner Detection

3. **Correlation Engine**
   - Cross-layer event correlation
   - Timeline reconstruction
   - Attack sequence identification

4. **Risk Scoring Engine**
   - Multi-factor risk assessment
   - Confidence scoring
   - Detailed risk reports

### 🎯 **Use Cases**
- **Security Operations**: Real-time threat detection and alerting
- **Incident Response**: Forensic investigation and timeline analysis
- **Compliance**: Audit logging and reporting
- **Threat Hunting**: Proactive security monitoring

## 🛠️ Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+ (for development)
- 4GB+ RAM, 10GB+ disk space

### Docker Deployment (Recommended)
```bash
# Clone repository
git clone https://github.com/your-org/forenx-sentinel.git
cd forenx-sentinel

# Copy environment file
cp .env.example .env
# Edit .env with your configuration

# Deploy with Docker Compose
./deploy.sh development

# Or manually
docker-compose up -d
