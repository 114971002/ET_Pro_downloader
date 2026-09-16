import json
import logging
import math
import os
import sqlite3
import time
import csv
import io
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Request, BackgroundTasks, HTTPException, Depends
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from core_state import *
import maxminddb
from intel_translations import get_technique_zh_name, get_actor_zh_summary, clean_stix_text

router = APIRouter()
logger = logging.getLogger("web_server")

@router.get("/api/threat-actors")
async def api_get_threat_actors(
    request: Request,
    search: str = "",
    filter_status: str = "all",
    is_authorized: None = Depends(verify_api_key)
):
    """API to list threat actors from MITRE cache with database rules coverage."""
    project_root = PROJECT_ROOT
    try:
        from analyzer import load_intel_data
        try:
            actor_mappings, _, _ = load_intel_data()
        except Exception:
            from update_intel import DEFAULT_ACTOR_MAPPINGS as actor_mappings

        def normalize(name):
            return re.sub(r"[^a-z0-9]", "", name.lower())

        our_normalized = {}
        for group_name, aliases in actor_mappings.items():
            norm_group = normalize(group_name)
            our_normalized[norm_group] = group_name
            for alias in aliases:
                norm_alias = normalize(alias)
                our_normalized[norm_alias] = group_name

        actors = get_mitre_threat_actors(project_root)
        malpedia_actors = get_malpedia_cache(project_root)
        
        def find_malpedia_info(internal_name, aliases):
            search_names = set([normalize(n) for n in [internal_name] + list(aliases)])
            for m_key, m_val in malpedia_actors.items():
                m_names = set([normalize(m_val.get("value", ""))])
                m_names.update([normalize(s) for s in m_val.get("meta", {}).get("synonyms", [])])
                if search_names.intersection(m_names):
                    return m_val
            return None

        db_path = project_root / "config" / "deploy_rules.db"
        actor_rule_counts = {}
        actor_tech_counts = {}
        if db_path.exists():
            try:
                conn = sqlite3.connect(str(db_path))
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("PRAGMA synchronous=NORMAL;")
                cursor = conn.cursor()
                cursor.execute("SELECT threat_actor, count(*) FROM active_rules WHERE threat_actor != 'unknown' AND threat_actor != '' GROUP BY threat_actor")
                for row in cursor.fetchall():
                    actor_rule_counts[row[0]] = row[1]
                cursor.execute("SELECT threat_actor, count(DISTINCT mitre_technique_id) FROM active_rules WHERE mitre_technique_id != 'unknown' AND mitre_technique_id != '' GROUP BY threat_actor")
                for row in cursor.fetchall():
                    actor_tech_counts[row[0]] = row[1]
                conn.close()
            except Exception as ex:
                logger.warning("Failed to query DB rule counts: %s", ex)

        results = []
        search_norm = normalize(search) if search else ""
        
        # Track actors added from MITRE to avoid duplicates
        added_groups = set()

        for stix_id, a in actors.items():
            name = a["name"]
            aliases = list(a.get("aliases", []))
            
            matched_internal_group = None
            for alias in [name] + aliases:
                norm_alias = normalize(alias)
                if norm_alias in our_normalized:
                    matched_internal_group = our_normalized[norm_alias]
                    break
            
            is_monitored = matched_internal_group is not None
            
            if filter_status == "monitored" and not is_monitored:
                continue
            if filter_status == "unmonitored" and is_monitored:
                continue
                
            match_search = False
            if not search_norm:
                match_search = True
            else:
                if search_norm in normalize(name):
                    match_search = True
                for alias in aliases:
                    if search_norm in normalize(alias):
                        match_search = True
            
            if not match_search:
                continue
                
            rule_count = actor_rule_counts.get(matched_internal_group, 0) if matched_internal_group else 0
            
            # calculate ATT&CK coverage
            total_techs = max(len(a.get("techniques", [])), actor_tech_counts.get(matched_internal_group, 0) if matched_internal_group else 0)
            coverage_pct = 0
            if total_techs > 0 and rule_count > 0:
                coverage_pct = min(100, int((rule_count / (total_techs * 3)) * 100))
                
            display_name = name
            if matched_internal_group:
                added_groups.add(matched_internal_group)
                display_name = matched_internal_group
                if name not in aliases:
                    aliases.append(name)

            m_info = find_malpedia_info(display_name, aliases)
            country = ""
            if m_info:
                country = m_info.get("meta", {}).get("country", "")
                for syn in m_info.get("meta", {}).get("synonyms", []):
                    if syn and normalize(syn) not in [normalize(x) for x in aliases]:
                        aliases.append(syn)
                
            results.append({
                "id": stix_id,
                "name": display_name,
                "aliases": aliases,
                "description": a.get("description", ""),
                "country": country,
                "is_monitored": is_monitored,
                "internal_group_name": matched_internal_group,
                "rule_count": rule_count,
                "rules_count": rule_count,
                "techniques_count": total_techs,
                "attack_coverage": coverage_pct,
                "source": "MITRE ATT&CK"
            })
            
        # Add non-MITRE actors from actor_mappings
        for group_name, aliases in actor_mappings.items():
            if group_name in added_groups:
                continue
                
            is_monitored = True
            if filter_status == "unmonitored":
                continue
                
            match_search = False
            if not search_norm:
                match_search = True
            else:
                if search_norm in normalize(group_name):
                    match_search = True
                for alias in aliases:
                    if search_norm in normalize(alias):
                        match_search = True
                        
            if not match_search:
                continue
                
            rule_count = actor_rule_counts.get(group_name, 0)
            custom_id = "custom_" + normalize(group_name)
            tech_count = actor_tech_counts.get(group_name, 0)
            coverage_pct = min(100, int((rule_count / max(1, (tech_count * 3))) * 100)) if (tech_count > 0 and rule_count > 0) else 0
            
            m_info = find_malpedia_info(group_name, aliases)
            all_aliases = list(aliases)
            if m_info:
                source = "Malpedia"
                country = m_info.get("meta", {}).get("country", "")
                description = m_info.get("description", "").strip() or f"{group_name} 威脅情報由 Malpedia 威脅情報庫收錄追蹤。"
                for syn in m_info.get("meta", {}).get("synonyms", []):
                    if syn and normalize(syn) not in [normalize(x) for x in all_aliases]:
                        all_aliases.append(syn)
            else:
                source = "Proofpoint ET Pro"
                country = ""
                description = f"{group_name} 為 Proofpoint ET Pro 威脅情資庫重點監控之活動群組，特徵涵蓋 C2 通訊、惡意載荷傳遞與網路釣魚活動。"

            results.append({
                "id": custom_id,
                "name": group_name,
                "aliases": all_aliases,
                "description": description,
                "country": country,
                "is_monitored": True,
                "internal_group_name": group_name,
                "rule_count": rule_count,
                "rules_count": rule_count,
                "techniques_count": tech_count,
                "attack_coverage": coverage_pct,
                "source": source
            })
            
        # Sort by rule count descending, then by name
        results.sort(key=lambda x: (-x["rule_count"], x["name"]))
        
        return results
    except Exception as e:
        logger.error("Failed to list threat actors: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to list threat actors: {e}")


@router.get("/api/threat-actors/{actor_id}")
async def api_get_threat_actor_detail(
    actor_id: str,
    request: Request,
    is_authorized: None = Depends(verify_api_key)
):
    """API to get details of a specific threat actor, including direct and indirect rules."""
    project_root = PROJECT_ROOT
    try:
        from analyzer import load_intel_data
        try:
            actor_mappings, _, _ = load_intel_data()
        except Exception:
            from update_intel import DEFAULT_ACTOR_MAPPINGS as actor_mappings

        def normalize(name):
            return re.sub(r"[^a-z0-9]", "", name.lower())

        our_normalized = {}
        for group_name, aliases in actor_mappings.items():
            norm_group = normalize(group_name)
            our_normalized[norm_group] = group_name
            for alias in aliases:
                norm_alias = normalize(alias)
                our_normalized[norm_alias] = group_name

        actors = get_mitre_threat_actors(project_root)
        malpedia_actors = get_malpedia_cache(project_root)
        a = None
        matched_internal_group = None
        
        def find_malpedia_info(internal_name, aliases):
            search_names = set([normalize(n) for n in [internal_name] + list(aliases)])
            for m_key, m_val in malpedia_actors.items():
                m_names = set([normalize(m_val.get("value", ""))])
                m_names.update([normalize(s) for s in m_val.get("meta", {}).get("synonyms", [])])
                if search_names.intersection(m_names):
                    return m_val
            return None
        
        if actor_id.startswith("custom_"):
            norm_search = actor_id[7:]
            for group_name, aliases in actor_mappings.items():
                if normalize(group_name) == norm_search:
                    matched_internal_group = group_name
                    m_info = find_malpedia_info(group_name, aliases)
                    all_aliases = list(aliases)
                    sw = []
                    if m_info:
                        source = "Malpedia"
                        country = m_info.get("meta", {}).get("country", "")
                        desc = m_info.get("description", "").strip() or f"{group_name} is a monitored threat group cataloged in the Malpedia intelligence repository."
                        for syn in m_info.get("meta", {}).get("synonyms", []):
                            if syn and normalize(syn) not in [normalize(x) for x in all_aliases]:
                                all_aliases.append(syn)
                        sw = [f"{fam} [Malpedia]" for fam in m_info.get("families", {}).keys()]
                    else:
                        source = "Proofpoint ET Pro"
                        country = ""
                        desc = f"{group_name} is monitored by Proofpoint ET Pro threat intelligence, covering C2 communications, malicious payload delivery, and credential phishing activity."

                    a = {
                        "id": actor_id,
                        "name": group_name,
                        "aliases": all_aliases,
                        "description": desc,
                        "country": country,
                        "source": source,
                        "techniques": [],
                        "software": sw
                    }
                    break
            if not a:
                raise HTTPException(status_code=404, detail="Threat actor not found")
        else:
            if actor_id not in actors:
                raise HTTPException(status_code=404, detail="Threat actor not found")
            
            a = dict(actors[actor_id])
            a["aliases"] = list(a.get("aliases", []))
            a["software"] = list(a.get("software", []))
            a["techniques"] = list(a.get("techniques", []))
            a["source"] = "MITRE ATT&CK"
            a["country"] = ""
            
            for alias in [a["name"]] + a.get("aliases", []):
                norm_alias = normalize(alias)
                if norm_alias in our_normalized:
                    matched_internal_group = our_normalized[norm_alias]
                    break

            if matched_internal_group and matched_internal_group != a["name"]:
                if a["name"] not in a["aliases"]:
                    a["aliases"].append(a["name"])
                a["name"] = matched_internal_group

            m_info = find_malpedia_info(a["name"], a.get("aliases", []))
            if m_info:
                if m_info.get("meta", {}).get("country"):
                    a["country"] = m_info["meta"]["country"]
                m_synonyms = m_info.get("meta", {}).get("synonyms", [])
                existing_aliases = set(normalize(alias) for alias in a.get("aliases", []))
                for syn in m_synonyms:
                    if normalize(syn) not in existing_aliases:
                        a["aliases"].append(syn)
                        existing_aliases.add(normalize(syn))
                
                m_desc = m_info.get("description", "").strip()
                if m_desc and m_desc not in a.get("description", ""):
                    a["description"] = f"{a.get('description', '')}\n\n[Malpedia 補充情資] {m_desc}".strip()
                        
                m_families = m_info.get("families", {})
                for fam_name in m_families.keys():
                    sw_label = f"{fam_name} [Malpedia]"
                    if sw_label not in a["software"] and fam_name not in a["software"]:
                        a["software"].append(sw_label)

        db_path = project_root / "config" / "deploy_rules.db"
        direct_rules = []
        indirect_rules = []
        tech_coverage = {}
        known_techniques = {}
        if a.get("techniques"):
            for t in a["techniques"]:
                known_techniques[t["id"]] = t.get("name", "")
        
        extracted_software = set(a.get("software", []))
        
        if db_path.exists() and matched_internal_group:
            try:
                conn = sqlite3.connect(str(db_path))
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                # Direct rules & extract techniques and malware
                cursor.execute(
                    "SELECT sid, msg, signature_severity, classtype, content, mitre_technique_id, mitre_technique FROM active_rules WHERE threat_actor = ?", 
                    (matched_internal_group,)
                )
                for row in cursor.fetchall():
                    direct_rules.append({
                        "sid": row["sid"],
                        "msg": row["msg"],
                        "signature_severity": row["signature_severity"],
                        "classtype": row["classtype"],
                        "content": row["content"],
                        "mitre_technique_id": row["mitre_technique_id"]
                    })
                    t_id = row["mitre_technique_id"]
                    t_name = row["mitre_technique"]
                    if t_id and t_id not in ("", "unknown"):
                        if t_id not in known_techniques:
                            known_techniques[t_id] = t_name or ""
                            
                    # Extract malware/software from rules
                    msg_str = row["msg"] or ""
                    content_str = row["content"] or ""
                    for m in re.findall(r'(?:Win32|Win64|MSIL|Linux|OSX|Android)/([A-Za-z0-9_\-]+)', msg_str, re.I):
                        extracted_software.add(m.strip())
                    for mw in re.findall(r'malware_family\s+([^,;)]+)', content_str, re.I):
                        extracted_software.add(mw.strip())

                # If no specific binary malware was found (e.g. credential phishing groups like TA4903)
                if not extracted_software and any("phishing" in (r["msg"] or "").lower() or "credential" in (r.get("classtype") or "").lower() for r in direct_rules[:50]):
                    extracted_software.update([
                        "Credential Phishing Kit [憑證釣魚套件]",
                        "Quishing / QR Code Tool [QR 條碼釣魚]",
                        "BEC Domain Spoofing [商務郵件偽造]"
                    ])

                # Tech coverage & indirect rules
                if known_techniques:
                    tech_ids = list(known_techniques.keys())
                    placeholders = ",".join(["?"] * len(tech_ids))
                    
                    cursor.execute(f"""
                        SELECT mitre_technique_id, count(*) as c 
                        FROM active_rules 
                        WHERE mitre_technique_id IN ({placeholders})
                        GROUP BY mitre_technique_id
                    """, tech_ids)
                    
                    for row in cursor.fetchall():
                        tech_coverage[row["mitre_technique_id"]] = row["c"]
                        
                    # get sample of indirect rules
                    cursor.execute(f"""
                        SELECT sid, msg, signature_severity, mitre_technique_id
                        FROM active_rules 
                        WHERE mitre_technique_id IN ({placeholders})
                        AND threat_actor != ?
                        LIMIT 50
                    """, tech_ids + [matched_internal_group])
                    
                    for row in cursor.fetchall():
                        indirect_rules.append({
                            "sid": row["sid"],
                            "msg": row["msg"],
                            "signature_severity": row["signature_severity"],
                            "technique": row["mitre_technique_id"]
                        })
                        
                conn.close()
            except Exception as ex:
                logger.warning("Failed to query DB for actor details: %s", ex)
                
        # Format tech coverage with bilingual Chinese names
        techs = []
        for tid, tname in known_techniques.items():
            zh_name = get_technique_zh_name(tid)
            if zh_name and "(" in zh_name:
                full_display = zh_name
            elif zh_name and tname and zh_name != tname:
                full_display = f"{zh_name} ({tname})"
            else:
                full_display = zh_name or tname
            techs.append({
                "id": tid,
                "name": tname or zh_name,
                "name_zh": zh_name,
                "display_name": full_display,
                "rule_count": tech_coverage.get(tid, 0)
            })
        techs.sort(key=lambda x: -x["rule_count"])

        # Format bilingual descriptions
        clean_en = clean_stix_text(a.get("description", ""))
        if not clean_en or any('\u4e00' <= char <= '\u9fff' for char in clean_en[:50]):
            clean_en = f"{a['name']} is tracked by Proofpoint ET Pro and threat intelligence feeds, with specialized detection coverage across known C2 channels, payload delivery, and credential protection."

        zh_summary = get_actor_zh_summary(a["name"], a.get("aliases", []), clean_en)
        bilingual_desc = f"【繁體中文情報摘要】\n{zh_summary}\n\n【Original Intelligence (English)】\n{clean_en}"

        software_list = sorted(list(extracted_software))

        return {
            "id": a["id"],
            "name": a["name"],
            "aliases": a.get("aliases", []),
            "description": bilingual_desc,
            "description_zh": zh_summary,
            "description_en": clean_en,
            "country": a.get("country", ""),
            "source": a.get("source", "MITRE ATT&CK"),
            "software": software_list,
            "techniques": techs,
            "internal_group_name": matched_internal_group,
            "rule_count": len(direct_rules),
            "rules_count": len(direct_rules),
            "direct_rules": direct_rules,
            "indirect_rules": indirect_rules
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get threat actor details: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to get details: {e}")


@router.get("/api/cti/status")
async def api_get_cti_status(is_authorized: None = Depends(verify_api_key)):
    """API to get status of CTI feeds and blocklist rules."""
    project_root = PROJECT_ROOT
    meta_path = project_root / "downloads" / "cti_meta.json"
    
    overrides_file = project_root / "config" / "intel_overrides.json"
    enabled_feeds = {"feodo": True, "urlhaus": True, "et_compromised": True}
    if overrides_file.exists():
        try:
            with overrides_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
                enabled_feeds = data.get("cti_feeds", enabled_feeds)
        except Exception:
            pass

    status = {
        "sync_time": None,
        "last_sync": None,
        "feeds": {},
        "feed_list": [],
        "total_ip_rules": 0,
        "ip_rules": 0,
        "total_domain_rules": 0,
        "domain_rules": 0,
        "total_rules": 0
    }
    
    if meta_path.exists():
        try:
            with meta_path.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
                status.update(loaded)
        except Exception:
            pass
            
    feed_names = {
        "feodo": "Feodo Tracker",
        "urlhaus": "URLhaus",
        "et_compromised": "ET Compromised"
    }
    
    feed_list = []
    for feed_id in ["feodo", "urlhaus", "et_compromised"]:
        if "feeds" not in status:
            status["feeds"] = {}
        if feed_id not in status["feeds"]:
            status["feeds"][feed_id] = {
                "enabled": enabled_feeds.get(feed_id, True),
                "status": "pending",
                "ips_count": 0,
                "domains_count": 0
            }
        else:
            status["feeds"][feed_id]["enabled"] = enabled_feeds.get(feed_id, True)
            
        f_data = status["feeds"][feed_id]
        total_count = f_data.get("ips_count", 0) + f_data.get("domains_count", 0)
        feed_list.append({
            "id": feed_id,
            "name": feed_names.get(feed_id, feed_id),
            "enabled": f_data.get("enabled", True),
            "status": f_data.get("status", "pending"),
            "ips_count": f_data.get("ips_count", 0),
            "domains_count": f_data.get("domains_count", 0),
            "count": total_count
        })
        
    status["feed_list"] = feed_list
    status["ip_rules"] = status.get("total_ip_rules", 0)
    status["domain_rules"] = status.get("total_domain_rules", 0)
    status["total_rules"] = status.get("total_rules", 0)
    status["last_sync"] = status.get("sync_time")
            
    return status



@router.post("/api/cti/sync")
async def api_sync_cti(background_tasks: BackgroundTasks, is_authorized: None = Depends(verify_api_key)):
    """API to trigger a CTI feed sync and rebuild deploy rules in background."""
    global RUN_STATUS
    
    with RUN_LOCK:
        if RUN_STATUS["status"] == "running":
            return {"status": "already_running"}
            
    background_tasks.add_task(run_cti_pipeline_worker, PROJECT_ROOT)
    return {"status": "started"}



@router.get("/api/cti/iocs")
async def api_get_cti_iocs(
    search: str = "",
    threat_actor: str = "",
    actor: str = "",
    malware_tag: str = "",
    malware: str = "",
    source: str = "",
    type: str = "",
    start_date: str = "",
    end_date: str = "",
    page: int = 1,
    limit: int = 25,
    is_authorized: None = Depends(verify_api_key)
):
    """API to list generated IoC blocklist entries with advanced filtering."""
    project_root = PROJECT_ROOT
    registry_path = project_root / "downloads" / "cti_iocs.json"
    
    if not registry_path.exists():
        return {"total": 0, "page": page, "limit": limit, "items": [], "iocs": []}
        
    try:
        with registry_path.open("r", encoding="utf-8") as f:
            iocs = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read IOC registry: {e}")
        
    actor_filter = threat_actor or actor
    malware_filter = malware_tag or malware

    if search:
        search_lower = search.lower()
        iocs = [
            x for x in iocs 
            if search_lower in x.get("value", "").lower() 
            or search_lower in x.get("source", "").lower() 
            or search_lower in x.get("type", "").lower()
            or search_lower in x.get("threat_actor", "").lower()
            or search_lower in x.get("malware_tag", "").lower()
        ]
        
    if actor_filter:
        iocs = [x for x in iocs if x.get("threat_actor", "").lower() == actor_filter.lower()]
        
    if malware_filter:
        iocs = [x for x in iocs if x.get("malware_tag", "").lower() == malware_filter.lower()]
        
    if source:
        iocs = [x for x in iocs if x.get("source", "").lower() == source.lower()]
        
    if type:
        iocs = [x for x in iocs if x.get("type", "").lower() == type.lower()]
        
    if start_date:
        iocs = [x for x in iocs if x.get("added_date", "") >= start_date]
        
    if end_date:
        # Append T23:59:59 to end_date to include the whole day
        end_date_full = end_date if "T" in end_date else end_date + "T23:59:59"
        iocs = [x for x in iocs if x.get("added_date", "") <= end_date_full]
        
    total = len(iocs)
    start = (page - 1) * limit
    end = start + limit
    sliced = iocs[start:end]
    
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "items": sliced,
        "iocs": sliced
    }

@router.get("/api/cti/filter_options")
async def api_get_cti_filter_options(is_authorized: None = Depends(verify_api_key)):
    """API to get unique values for CTI filters."""
    project_root = PROJECT_ROOT
    registry_path = project_root / "downloads" / "cti_iocs.json"
    
    if not registry_path.exists():
        return {"threat_actors": [], "malware_tags": [], "sources": [], "types": []}
        
    try:
        with registry_path.open("r", encoding="utf-8") as f:
            iocs = json.load(f)
    except Exception as e:
        return {"threat_actors": [], "malware_tags": [], "sources": [], "types": []}
        
    actors = sorted(list(set([x.get("threat_actor", "unknown") for x in iocs])))
    tags = sorted(list(set([x.get("malware_tag", "unknown") for x in iocs])))
    sources = sorted(list(set([x.get("source", "unknown") for x in iocs])))
    types = sorted(list(set([x.get("type", "unknown") for x in iocs])))
    
    return {
        "threat_actors": actors,
        "malware_tags": tags,
        "sources": sources,
        "types": types
    }

@router.get("/api/cti/export")
async def api_export_cti_iocs(
    search: str = "",
    threat_actor: str = "",
    malware_tag: str = "",
    source: str = "",
    type: str = "",
    start_date: str = "",
    end_date: str = "",
    is_authorized: None = Depends(verify_api_key)
):
    """API to export filtered CTI blocklist entries to CSV."""
    project_root = PROJECT_ROOT
    registry_path = project_root / "downloads" / "cti_iocs.json"
    
    if not registry_path.exists():
        raise HTTPException(status_code=404, detail="CTI registry not found.")
        
    try:
        with registry_path.open("r", encoding="utf-8") as f:
            iocs = json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read IOC registry: {e}")
        
    if search:
        search_lower = search.lower()
        iocs = [x for x in iocs if search_lower in x.get("value", "").lower() or search_lower in x.get("source", "").lower() or search_lower in x.get("type", "").lower()]
        
    if threat_actor:
        iocs = [x for x in iocs if x.get("threat_actor", "") == threat_actor]
        
    if malware_tag:
        iocs = [x for x in iocs if x.get("malware_tag", "") == malware_tag]
        
    if source:
        iocs = [x for x in iocs if x.get("source", "") == source]
        
    if type:
        iocs = [x for x in iocs if x.get("type", "") == type]
        
    if start_date:
        iocs = [x for x in iocs if x.get("added_date", "") >= start_date]
        
    if end_date:
        iocs = [x for x in iocs if x.get("added_date", "") <= end_date]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Type", "Value", "Source", "Threat Actor", "Malware Tag", "Added Date"])
    
    for ioc in iocs:
        writer.writerow([
            ioc.get("type", ""),
            ioc.get("value", ""),
            ioc.get("source", ""),
            ioc.get("threat_actor", ""),
            ioc.get("malware_tag", ""),
            ioc.get("added_date", "")
        ])
        
    output.seek(0)
    
    headers = {
        'Content-Disposition': 'attachment; filename="cti_blocklist.csv"'
    }
    
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers=headers)

