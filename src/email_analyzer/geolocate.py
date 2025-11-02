"""
Geolocation helpers
"""
import requests, time


_IPAPI_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,timezone,message"

def geolocate_ip(ip: str, pause: float = 0.05):
    try:
        r = requests.get(_IPAPI_URL.format(ip=ip), timeout=5)
    except Exception:
        return None
    if r.status_code != 200:
        return None
    j = r.json()
    if j.get("status") == "success":
        return {
            "ip": ip,
            "country": j.get("country"),
            "country_iso": j.get("countryCode"),
            "city": j.get("city"),
            "lat": j.get("lat"),
            "lon": j.get("lon"),
            "timezone": j.get("timezone"),
        }
    time.sleep(pause)
    return None
