import requests
import json
from typing import Dict, Optional
from functools import lru_cache

class GeoIPLocator:
    """Simple GeoIP location service"""
    
    def __init__(self):
        self.cache = {}
    
    @lru_cache(maxsize=1000)
    def locate(self, ip: str) -> Optional[Dict]:
        """Get geolocation for IP"""
        try:
            # Free IP geolocation service
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country"),
                        "countryCode": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "as": data.get("as")
                    }
            
            # Fallback to ipinfo
            response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                loc = data.get("loc", "").split(",")
                return {
                    "country": data.get("country"),
                    "region": data.get("region"),
                    "city": data.get("city"),
                    "lat": loc[0] if len(loc) > 0 else None,
                    "lon": loc[1] if len(loc) > 1 else None,
                    "org": data.get("org")
                }
        except Exception:
            pass
        
        return None
