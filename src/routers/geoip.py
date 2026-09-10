import json
import logging
import math
import os
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Request, BackgroundTasks, HTTPException, Depends
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from core_state import *
import maxminddb

router = APIRouter()
logger = logging.getLogger("web_server")

@router.get("/api/geoip")
async def api_geoip(ip: str):
    if not DB_PATH.exists():
        raise HTTPException(status_code=503, detail="GeoIP database is currently downloading or missing.")
    
    try:
        import maxminddb
        with maxminddb.open_database(str(DB_PATH)) as reader:
            data = reader.get(ip)
            if not data:
                return {"status": "fail", "message": "IP not found"}
            
            return {
                "status": "success",
                "ip": ip,
                "country": data.get("country", {}).get("names", {}).get("en", "Unknown"),
                "countryCode": data.get("country", {}).get("iso_code", ""),
                "city": data.get("city", {}).get("names", {}).get("en", "Unknown"),
                "lat": data.get("location", {}).get("latitude", 0.0),
                "lon": data.get("location", {}).get("longitude", 0.0),
                "isp": data.get("traits", {}).get("isp", "Unknown"),
                "org": data.get("traits", {}).get("organization", "Unknown")
            }
    except Exception as e:
        logger.error(f"GeoIP error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

class GeoIPBatchRequest(BaseModel):
    ips: list[str]


@router.post("/api/geoip/batch")
async def api_geoip_batch(req: GeoIPBatchRequest):
    if not DB_PATH.exists():
        raise HTTPException(status_code=503, detail="GeoIP database is currently downloading or missing.")
    
    results = {}
    try:
        import maxminddb
        with maxminddb.open_database(str(DB_PATH)) as reader:
            for ip in req.ips:
                if not ip or not ip.strip():
                    continue
                ip = ip.strip()
                # Skip duplicate lookups
                if ip in results:
                    continue
                try:
                    data = reader.get(ip)
                    if data:
                        results[ip] = {
                            "status": "success",
                            "ip": ip,
                            "country": data.get("country", {}).get("names", {}).get("en", "Unknown"),
                            "countryCode": data.get("country", {}).get("iso_code", ""),
                            "city": data.get("city", {}).get("names", {}).get("en", "Unknown"),
                            "lat": data.get("location", {}).get("latitude", 0.0),
                            "lon": data.get("location", {}).get("longitude", 0.0),
                            "isp": data.get("traits", {}).get("isp", "Unknown"),
                            "org": data.get("traits", {}).get("organization", "Unknown")
                        }
                    else:
                        results[ip] = {"status": "fail", "message": "IP not found", "ip": ip}
                except Exception as e:
                    results[ip] = {"status": "fail", "message": str(e), "ip": ip}
        return results
    except Exception as e:
        logger.error(f"GeoIP batch error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


