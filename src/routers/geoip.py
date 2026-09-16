import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.parse
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from core_state import PROJECT_ROOT, verify_api_key

router = APIRouter()
logger = logging.getLogger("web_server")

CACHE_FILE = PROJECT_ROOT / "config" / "geoip_cache.json"

_GEOIP_CACHE: Dict[str, Dict[str, Any]] = {}

def _load_cache():
    global _GEOIP_CACHE
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                _GEOIP_CACHE = json.load(f)
        except Exception as e:
            logger.warning(f"Could not load GeoIP cache: {e}")
            _GEOIP_CACHE = {}

def _save_cache():
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(_GEOIP_CACHE, f, ensure_ascii=False)
    except Exception as e:
        logger.warning(f"Could not save GeoIP cache: {e}")

_load_cache()


def _lookup_maxmind(ip: str) -> Optional[Dict[str, Any]]:
    """Try lookup via local MaxMind DB if installed."""
    mmdb_paths = [
        PROJECT_ROOT / "config" / "GeoLite2-City.mmdb",
        PROJECT_ROOT / "config" / "GeoLite2-Country.mmdb",
        Path("/usr/local/share/GeoLite2/GeoLite2-City.mmdb"),
        Path("/usr/share/GeoIP/GeoLite2-City.mmdb")
    ]
    for p in mmdb_paths:
        if p.exists():
            try:
                import maxminddb
                with maxminddb.open_database(str(p)) as reader:
                    data = reader.get(ip)
                    if data:
                        return {
                            "status": "success",
                            "ip": ip,
                            "country": data.get("country", {}).get("names", {}).get("en", "Unknown"),
                            "countryCode": data.get("country", {}).get("iso_code", ""),
                            "city": data.get("city", {}).get("names", {}).get("en", "Unknown"),
                            "lat": data.get("location", {}).get("latitude", 0.0),
                            "latitude": data.get("location", {}).get("latitude", 0.0),
                            "lon": data.get("location", {}).get("longitude", 0.0),
                            "longitude": data.get("location", {}).get("longitude", 0.0),
                            "isp": data.get("traits", {}).get("isp", "Unknown"),
                            "org": data.get("traits", {}).get("organization", "Unknown")
                        }
            except Exception:
                pass
    return None


def _query_ip_api_batch(ips: List[str]) -> Dict[str, Dict[str, Any]]:
    """Batch query up to 100 IPs using ip-api.com."""
    results = {}
    if not ips:
        return results
        
    payload = [{"query": ip} for ip in ips[:100]]
    try:
        req = urllib.request.Request(
            "http://ip-api.com/batch",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "Suricata-ETPro-Manager"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for item in data:
                ip = item.get("query")
                if not ip:
                    continue
                if item.get("status") == "success":
                    res = {
                        "status": "success",
                        "ip": ip,
                        "country": item.get("country", "Unknown"),
                        "countryCode": item.get("countryCode", ""),
                        "city": item.get("city", "Unknown"),
                        "region": item.get("regionName", ""),
                        "lat": item.get("lat", 0.0),
                        "latitude": item.get("lat", 0.0),
                        "lon": item.get("lon", 0.0),
                        "longitude": item.get("lon", 0.0),
                        "isp": item.get("isp", "Unknown"),
                        "org": item.get("org", item.get("as", "Unknown")),
                        "as": item.get("as", "")
                    }
                    results[ip] = res
                    _GEOIP_CACHE[ip] = res
                else:
                    results[ip] = {"status": "fail", "message": item.get("message", "Not found"), "ip": ip}
        _save_cache()
    except Exception as e:
        logger.error(f"ip-api batch error: {e}")
    return results


@router.get("/api/geoip")
async def api_geoip(ip: str):
    """Single IP GeoIP lookup with local cache and fallback."""
    clean_ip = ip.strip()
    if not clean_ip:
        raise HTTPException(status_code=400, detail="Missing IP parameter")

    # 1. Check cache
    if clean_ip in _GEOIP_CACHE:
        return _GEOIP_CACHE[clean_ip]

    # 2. Check local mmdb
    local_data = _lookup_maxmind(clean_ip)
    if local_data:
        _GEOIP_CACHE[clean_ip] = local_data
        _save_cache()
        return local_data

    # 3. Online lookup
    batch_res = _query_ip_api_batch([clean_ip])
    if clean_ip in batch_res:
        return batch_res[clean_ip]

    return {"status": "fail", "message": "IP lookup failed", "ip": clean_ip}


class GeoIPBatchRequest(BaseModel):
    ips: List[str]


@router.post("/api/geoip/batch")
async def api_geoip_batch(req: GeoIPBatchRequest):
    """Batch GeoIP lookup for multiple IPs."""
    unique_ips = list(dict.fromkeys([ip.strip() for ip in req.ips if ip and ip.strip()]))
    
    results: Dict[str, Dict[str, Any]] = {}
    missing_ips: List[str] = []

    # Check cache and local mmdb
    for ip in unique_ips:
        if ip in _GEOIP_CACHE:
            results[ip] = _GEOIP_CACHE[ip]
        else:
            local_data = _lookup_maxmind(ip)
            if local_data:
                results[ip] = local_data
                _GEOIP_CACHE[ip] = local_data
            else:
                missing_ips.append(ip)

    # Batch query missing IPs in chunks of 50
    if missing_ips:
        for i in range(0, len(missing_ips), 50):
            chunk = missing_ips[i:i+50]
            queried = _query_ip_api_batch(chunk)
            results.update(queried)

    results_list = [v for v in results.values() if v.get("status") == "success"]

    return {
        "status": "success",
        "results": results,
        "list": results_list,
        "total": len(results_list)
    }


@router.get("/api/geoip/presets")
async def api_geoip_presets():
    """Returns sample and CTI active IPs for one-click mapping."""
    cti_file = PROJECT_ROOT / "downloads" / "cti_iocs.json"
    
    cti_ips = []
    feodo_ips = []
    
    if cti_file.exists():
        try:
            with open(cti_file, "r", encoding="utf-8") as f:
                iocs = json.load(f)
            
            for item in iocs:
                if item.get("type") == "IP" and item.get("value"):
                    val = item["value"]
                    src = item.get("source", "")
                    if src == "Feodo Tracker" and len(feodo_ips) < 20:
                        feodo_ips.append({
                            "ip": val,
                            "source": src,
                            "malware": item.get("malware_tag", "C2")
                        })
                    if len(cti_ips) < 30:
                        cti_ips.append({
                            "ip": val,
                            "source": src,
                            "malware": item.get("malware_tag", "Malware")
                        })
        except Exception as e:
            logger.warning(f"Could not load CTI samples: {e}")

    if not cti_ips:
        demo_defaults = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "185.220.101.5", "194.26.29.112", "45.154.255.80"]
        cti_ips = [{"ip": x, "source": "Demo", "malware": "Scanner"} for x in demo_defaults]

    return {
        "cti_ips": cti_ips,
        "feodo_ips": feodo_ips,
        "flow_demo": {
            "source": "140.112.1.1",
            "destinations": ["185.220.101.5", "194.26.29.112", "8.8.8.8", "1.1.1.1"]
        }
    }


