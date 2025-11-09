"""
Geolocation helpers
"""
import requests, time


_IPAPI_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,timezone,message"

def geolocate_ip(ip_address: str, pause_seconds: float = 0.05):
    try:
        response = requests.get(_IPAPI_URL.format(ip=ip_address), timeout=5)
    except Exception:
        return None
    if response.status_code != 200:
        return None
    json_data = response.json()
    if json_data.get("status") == "success":
        return {
            "ip": ip_address,
            "country": json_data.get("country"),
            "country_iso": json_data.get("countryCode"),
            "city": json_data.get("city"),
            "lat": json_data.get("lat"),
            "lon": json_data.get("lon"),
            "timezone": json_data.get("timezone"),
        }
    time.sleep(pause_seconds)
    return None
