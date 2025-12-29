import requests
import json
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from functools import lru_cache
import redis
import hashlib

from app.config import settings

class ThreatIntelligenceClient:
    """Threat intelligence integration with multiple providers"""
    
    def __init__(self):
        self.cache = redis.Redis.from_url(settings.REDIS_URL)
        self.cache_ttl = 3600  # 1 hour
        
        # API endpoints
        self.providers = {
            "abuseipdb": {
                "url": "https://api.abuseipdb.com/api/v2/check",
                "headers": {"Key": settings.ABUSEIPDB_API_KEY},
                "enabled": bool(settings.ABUSEIPDB_API_KEY)
            },
            "virustotal": {
                "url": "https://www.virustotal.com/api/v3/ip_addresses",
                "headers": {"x-apikey": settings.VIRUSTOTAL_API_KEY},
                "enabled": bool(settings.VIRUSTOTAL_API_KEY)
            },
            "shodan": {
                "url": "https://api.shodan.io/shodan/host",
                "enabled": bool(settings.SHODAN_API_KEY)
            },
            "ipinfo": {
                "url": "https://ipinfo.io",
                "enabled": bool(settings.IPINFO_TOKEN)
            }
        }
    
    @lru_cache(maxsize=1000)
    def check_ip_reputation(self, ip: str) -> Dict:
        """
        Check IP reputation across multiple threat intelligence providers.
        Returns aggregated reputation score and details.
        """
        # Check cache first
        cache_key = f"threat_intel:{ip}"
        cached = self.cache.get(cache_key)
        if cached:
            return json.loads(cached)
        
        results = {
            "ip": ip,
            "reputation_score": 0.0,  # 0-100, higher is worse
            "confidence": 0.0,
            "details": {},
            "last_updated": datetime.utcnow().isoformat()
        }
        
        provider_scores = []
        provider_weights = {
            "abuseipdb": 0.4,
            "virustotal": 0.35,
            "shodan": 0.15,
            "ipinfo": 0.1
        }
        
        # Check each enabled provider
        for provider_name, provider_config in self.providers.items():
            if provider_config["enabled"]:
                try:
                    provider_result = self._check_with_provider(ip, provider_name)
                    if provider_result:
                        results["details"][provider_name] = provider_result
                        
                        # Calculate provider-specific score
                        provider_score = self._calculate_provider_score(provider_name, provider_result)
                        if provider_score is not None:
                            provider_scores.append((
                                provider_score,
                                provider_weights.get(provider_name, 0.1)
                            ))
                except Exception as e:
                    print(f"Error checking {provider_name} for {ip}: {e}")
        
        # Calculate weighted reputation score
        if provider_scores:
            total_weight = sum(weight for _, weight in provider_scores)
            weighted_score = sum(score * weight for score, weight in provider_scores)
            results["reputation_score"] = weighted_score / total_weight if total_weight > 0 else 0
        
        # Calculate confidence based on number of providers
        enabled_providers = sum(1 for p in self.providers.values() if p["enabled"])
        if enabled_providers > 0:
            results["confidence"] = len(provider_scores) / enabled_providers
        
        # Cache results
        self.cache.setex(
            cache_key,
            self.cache_ttl,
            json.dumps(results)
        )
        
        return results
    
    def _check_with_provider(self, ip: str, provider: str) -> Optional[Dict]:
        """Check IP with specific provider"""
        if provider == "abuseipdb":
            return self._check_abuseipdb(ip)
        elif provider == "virustotal":
            return self._check_virustotal(ip)
        elif provider == "shodan":
            return self._check_shodan(ip)
        elif provider == "ipinfo":
            return self._check_ipinfo(ip)
        
        return None
    
    def _check_abuseipdb(self, ip: str) -> Dict:
        """Check IP with AbuseIPDB"""
        config = self.providers["abuseipdb"]
        
        response = requests.get(
            config["url"],
            headers=config["headers"],
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt"),
                "country": data.get("countryCode"),
                "isp": data.get("isp"),
                "is_public": data.get("isPublic", False),
                "is_tor": data.get("isTor", False),
                "is_proxy": data.get("isPublic", False)
            }
        
        return {}
    
    def _check_virustotal(self, ip: str) -> Dict:
        """Check IP with VirusTotal"""
        config = self.providers["virustotal"]
        
        response = requests.get(
            f"{config['url']}/{ip}",
            headers=config["headers"],
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()["data"]
            attributes = data.get("attributes", {})
            last_analysis = attributes.get("last_analysis_stats", {})
            
            return {
                "malicious": last_analysis.get("malicious", 0),
                "suspicious": last_analysis.get("suspicious", 0),
                "harmless": last_analysis.get("harmless", 0),
                "undetected": last_analysis.get("undetected", 0),
                "asn": attributes.get("asn"),
                "country": attributes.get("country"),
                "reputation": attributes.get("reputation", 0),
                "total_engines": sum(last_analysis.values()) if last_analysis else 0
            }
        
        return {}
    
    def _check_shodan(self, ip: str) -> Dict:
        """Check IP with Shodan"""
        config = self.providers["shodan"]
        
        response = requests.get(
            f"{config['url']}/{ip}",
            params={"key": settings.SHODAN_API_KEY},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "country": data.get("country_code"),
                "last_update": data.get("last_update"),
                "tags": data.get("tags", [])
            }
        
        return {}
    
    def _check_ipinfo(self, ip: str) -> Dict:
        """Check IP with IPInfo"""
        config = self.providers["ipinfo"]
        
        response = requests.get(
            f"{config['url']}/{ip}",
            params={"token": settings.IPINFO_TOKEN},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                "hostname": data.get("hostname"),
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "loc": data.get("loc"),
                "org": data.get("org"),
                "postal": data.get("postal"),
                "timezone": data.get("timezone"),
                "asn": data.get("org", "").split()[0] if data.get("org") else None
            }
        
        return {}
    
    def _calculate_provider_score(self, provider: str, data: Dict) -> Optional[float]:
        """Calculate reputation score from provider data"""
        if provider == "abuseipdb":
            confidence = data.get("abuse_confidence", 0)
            reports = data.get("total_reports", 0)
            
            # Base score on confidence, boosted by report count
            score = confidence
            if reports >= 100:
                score += 20
            elif reports >= 50:
                score += 15
            elif reports >= 20:
                score += 10
            elif reports >= 10:
                score += 5
            
            # Boost for TOR/Proxy
            if data.get("is_tor"):
                score += 30
            if data.get("is_proxy"):
                score += 20
            
            return min(100.0, score)
        
        elif provider == "virustotal":
            malicious = data.get("malicious", 0)
            suspicious = data.get("suspicious", 0)
            total = data.get("total_engines", 0)
            
            if total > 0:
                # Weight malicious more than suspicious
                malicious_score = (malicious / total) * 100
                suspicious_score = (suspicious / total) * 50
                return min(100.0, malicious_score + suspicious_score)
            
            # Use reputation if no analysis data
            reputation = data.get("reputation", 0)
            if reputation < 0:
                return abs(reputation)  # Negative reputation is bad
            
        elif provider == "shodan":
            score = 0
            vulns = data.get("vulns", [])
            ports = data.get("ports", [])
            
            # Vulnerabilities
            if vulns:
                score += min(50, len(vulns) * 10)
            
            # Open ports (common attack vectors)
            risky_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5900, 8080}
            open_risky = len(set(ports) & risky_ports)
            score += min(30, open_risky * 5)
            
            # Tags
            tags = data.get("tags", [])
            if "honeypot" in tags:
                score += 20
            if "malware" in tags:
                score += 40
            
            return min(100.0, score)
        
        elif provider == "ipinfo":
            # IPInfo doesn't provide reputation, but we can use ASN/Org
            org = data.get("org", "").lower()
            score = 0
            
            # Known bad actors/hosting providers
            bad_keywords = [
                "bulletproof", "offshore", "vps", "vpn", "proxy",
                "tor", "anonymous", "bulletproof"
            ]
            
            for keyword in bad_keywords:
                if keyword in org:
                    score += 15
            
            return min(50.0, score)  # Lower weight for IPInfo
        
        return None
    
    def check_bulk_ips(self, ips: List[str]) -> Dict[str, Dict]:
        """Check multiple IPs efficiently"""
        results = {}
        
        for ip in ips:
            results[ip] = self.check_ip_reputation(ip)
        
        return results
    
    def get_ip_geolocation(self, ip: str) -> Dict:
        """Get geolocation information for IP"""
        cache_key = f"geolocation:{ip}"
        cached = self.cache.get(cache_key)
        
        if cached:
            return json.loads(cached)
        
        # Try multiple geolocation providers
        providers = [
            self._get_geolocation_ipinfo,
            self._get_geolocation_ipapi,
            self._get_geolocation_freegeoip
        ]
        
        for provider_func in providers:
            try:
                result = provider_func(ip)
                if result:
                    self.cache.setex(cache_key, 86400, json.dumps(result))  # 24 hours
                    return result
            except:
                continue
        
        return {}
    
    def _get_geolocation_ipinfo(self, ip: str) -> Optional[Dict]:
        """Get geolocation from IPInfo"""
        if not settings.IPINFO_TOKEN:
            return None
        
        response = requests.get(
            f"https://ipinfo.io/{ip}",
            params={"token": settings.IPINFO_TOKEN},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            loc = data.get("loc", "").split(",")
            return {
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "latitude": loc[0] if len(loc) > 0 else None,
                "longitude": loc[1] if len(loc) > 1 else None,
                "timezone": data.get("timezone"),
                "asn": data.get("org", "").split()[0] if data.get("org") else None,
                "provider": "ipinfo"
            }
        
        return None
    
    def _get_geolocation_ipapi(self, ip: str) -> Optional[Dict]:
        """Get geolocation from IP-API"""
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"},
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "city": data.get("city"),
                    "region": data.get("regionName"),
                    "country": data.get("country"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "asn": data.get("as"),
                    "isp": data.get("isp"),
                    "provider": "ip-api"
                }
        
        return None
    
    def _get_geolocation_freegeoip(self, ip: str) -> Optional[Dict]:
        """Get geolocation from freegeoip"""
        response = requests.get(
            f"https://freegeoip.app/json/{ip}",
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                "city": data.get("city"),
                "region": data.get("region_name"),
                "country": data.get("country_name"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "timezone": data.get("time_zone"),
                "provider": "freegeoip"
            }
        
        return None
    
    def check_domain_reputation(self, domain: str) -> Dict:
        """Check domain reputation"""
        cache_key = f"domain_reputation:{hashlib.md5(domain.encode()).hexdigest()}"
        cached = self.cache.get(cache_key)
        
        if cached:
            return json.loads(cached)
        
        results = {
            "domain": domain,
            "reputation_score": 0.0,
            "details": {},
            "last_updated": datetime.utcnow().isoformat()
        }
        
        # Check VirusTotal for domain
        if settings.VIRUSTOTAL_API_KEY:
            try:
                response = requests.get(
                    f"https://www.virustotal.com/api/v3/domains/{domain}",
                    headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()["data"]
                    attributes = data.get("attributes", {})
                    last_analysis = attributes.get("last_analysis_stats", {})
                    
                    results["details"]["virustotal"] = {
                        "malicious": last_analysis.get("malicious", 0),
                        "suspicious": last_analysis.get("suspicious", 0),
                        "harmless": last_analysis.get("harmless", 0),
                        "categories": attributes.get("categories", {}),
                        "last_analysis_date": attributes.get("last_analysis_date")
                    }
                    
                    # Calculate score
                    total = sum(last_analysis.values()) if last_analysis else 0
                    if total > 0:
                        malicious = last_analysis.get("malicious", 0)
                        suspicious = last_analysis.get("suspicious", 0)
                        results["reputation_score"] = (malicious / total) * 100 + (suspicious / total) * 50
            except Exception as e:
                print(f"Error checking domain {domain} with VirusTotal: {e}")
        
        # Check URLScan.io
        if settings.URLSCAN_API_KEY:
            try:
                response = requests.get(
                    f"https://urlscan.io/api/v1/search/?q=domain:{domain}",
                    headers={"API-Key": settings.URLSCAN_API_KEY},
                    timeout=10
                )
                
                if response.status_code == 200:
                    data = response.json()
                    results["details"]["urlscan"] = {
                        "total_results": data.get("total", 0),
                        "last_scan": data.get("results", [{}])[0].get("task", {}).get("time") if data.get("results") else None
                    }
            except Exception as e:
                print(f"Error checking domain {domain} with URLScan: {e}")
        
        self.cache.setex(cache_key, 3600, json.dumps(results))
        return results
    
    def get_threat_feed(self, feed_type: str = "ips") -> List[Dict]:
        """Get threat intelligence feeds"""
        cache_key = f"threat_feed:{feed_type}"
        cached = self.cache.get(cache_key)
        
        if cached:
            return json.loads(cached)
        
        feeds = []
        
        if feed_type == "ips":
            # Get known bad IPs from AbuseIPDB
            if settings.ABUSEIPDB_API_KEY:
                try:
                    response = requests.get(
                        "https://api.abuseipdb.com/api/v2/blacklist",
                        headers={"Key": settings.ABUSEIPDB_API_KEY},
                        params={"limit": 100},
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        data = response.json()["data"]
                        for item in data:
                            feeds.append({
                                "type": "ip",
                                "value": item["ipAddress"],
                                "reason": "AbuseIPDB Blacklist",
                                "confidence": item.get("abuseConfidenceScore", 0),
                                "last_reported": item.get("lastReportedAt")
                            })
                except Exception as e:
                    print(f"Error fetching AbuseIPDB feed: {e}")
        
        elif feed_type == "domains":
            # Get malicious domains from various sources
            sources = [
                "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                "https://urlhaus.abuse.ch/downloads/hostfile/"
            ]
            
            for source in sources:
                try:
                    response = requests.get(source, timeout=10)
                    if response.status_code == 200:
                        for line in response.text.split('\n'):
                            if line and not line.startswith('#'):
                                parts = line.strip().split()
                                if len(parts) >= 2:
                                    domain = parts[1]
                                    if '.' in domain:  # Simple domain check
                                        feeds.append({
                                            "type": "domain",
                                            "value": domain,
                                            "source": source,
                                            "reason": "Malicious domain list"
                                        })
                except Exception as e:
                    print(f"Error fetching domain feed from {source}: {e}")
        
        self.cache.setex(cache_key, 1800, json.dumps(feeds))  # 30 minutes cache
        return feeds

# Singleton instance
threat_intel = ThreatIntelligenceClient()
