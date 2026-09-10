from __future__ import annotations
import json
import logging
import math
import os
import re
import sqlite3
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import Request, BackgroundTasks, HTTPException, Depends
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parent.parent

logger = logging.getLogger("web_server")

# Global status tracking for background runner
RUN_STATUS: Dict[str, Any] = {
    "status": "idle",
    "last_run_time": None,
    "last_run_success": None,
    "last_run_error": None,
    "is_updating_rules": False
}
RUN_LOCK = threading.Lock()

# Global cache for active rules to optimize visualization dashboard loading
ACTIVE_RULES_CACHE = {
    "mtime_deploy": 0.0,
    "mtime_csv": 0.0,
    "rules": [],
    "facets": {}
}
CACHE_LOCK = threading.Lock()

_MITRE_MATRIX_CACHE = None
_MITRE_RELATIONS_CACHE = None
_MITRE_ACTORS_CACHE = None
MITRE_CACHE_LOCK = threading.Lock()

_MALPEDIA_CACHE = None
MALPEDIA_CACHE_LOCK = threading.Lock()

def get_mitre_matrix_structure(project_root: Path):
    global _MITRE_MATRIX_CACHE
    if _MITRE_MATRIX_CACHE is not None:
        return _MITRE_MATRIX_CACHE
        
    cache_path = project_root / "config" / "mitre_attack_cache.json"
    if not cache_path.exists():
        logger.warning("mitre_attack_cache.json not found, matrix structure will be empty")
        return []
        
    with MITRE_CACHE_LOCK:
        if _MITRE_MATRIX_CACHE is not None:
            return _MITRE_MATRIX_CACHE
            
        try:
            logger.info("Parsing MITRE ATT&CK cache structure...")
            with cache_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
                
            tactics = {}
            for obj in data.get("objects", []):
                if obj.get("type") == "x-mitre-tactic":
                    ext_ref = obj.get("external_references", [{}])[0]
                    t_id = ext_ref.get("external_id")
                    shortname = obj.get("x_mitre_shortname")
                    tactics[shortname] = {
                        "id": t_id,
                        "name": obj.get("name"),
                        "shortname": shortname,
                        "techniques": []
                    }
                    
            for obj in data.get("objects", []):
                if obj.get("type") == "attack-pattern":
                    if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                        continue
                    ext_ref = obj.get("external_references", [{}])[0]
                    tech_id = ext_ref.get("external_id")
                    tech_name = obj.get("name")
                    is_sub = obj.get("x_mitre_is_subtechnique", False)
                    
                    phases = obj.get("kill_chain_phases", [])
                    for phase in phases:
                        if phase.get("kill_chain_name") == "mitre-attack":
                            p_name = phase.get("phase_name")
                            if p_name in tactics:
                                tactics[p_name]["techniques"].append({
                                    "id": tech_id,
                                    "name": tech_name,
                                    "is_subtechnique": is_sub
                                })
                                
            # Sort techniques by ID
            for t in tactics.values():
                t["techniques"].sort(key=lambda x: x["id"])
                
            # Define logical order for tactics (Enterprise ATT&CK order)
            tactic_order = [
                "reconnaissance",
                "resource-development",
                "initial-access",
                "execution",
                "persistence",
                "privilege-escalation",
                "defense-evasion",
                "stealth", # TA0005 is shortname 'stealth' in STIX
                "defense-impairment",
                "credential-access",
                "discovery",
                "lateral-movement",
                "collection",
                "command-and-control",
                "exfiltration",
                "impact"
            ]
            
            ordered_list = []
            added = set()
            for name in tactic_order:
                if name in tactics and name not in added:
                    ordered_list.append(tactics[name])
                    added.add(name)
            for name, t in tactics.items():
                if name not in added:
                    ordered_list.append(t)
                    added.add(name)
                    
            _MITRE_MATRIX_CACHE = ordered_list
            logger.info("MITRE ATT&CK cache structure loaded: %d tactics", len(_MITRE_MATRIX_CACHE))
            return _MITRE_MATRIX_CACHE
        except Exception as e:
            logger.error("Failed to parse MITRE ATT&CK cache: %s", e)
            return []


def get_mitre_relations(project_root: Path):
    global _MITRE_RELATIONS_CACHE
    if _MITRE_RELATIONS_CACHE is not None:
        return _MITRE_RELATIONS_CACHE
        
    cache_path = project_root / "config" / "mitre_attack_cache.json"
    if not cache_path.exists():
        return {}
        
    with MITRE_CACHE_LOCK:
        if _MITRE_RELATIONS_CACHE is not None:
            return _MITRE_RELATIONS_CACHE
            
        try:
            logger.info("Parsing MITRE ATT&CK relationships...")
            with cache_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
                
            id_to_name = {}
            id_to_type = {}
            for obj in data.get("objects", []):
                obj_type = obj.get("type")
                if obj_type in ["intrusion-set", "malware", "tool", "attack-pattern"]:
                    id_to_name[obj.get("id")] = obj.get("name")
                    id_to_type[obj.get("id")] = obj_type
                    
            tech_stix_to_ext_id = {}
            for obj in data.get("objects", []):
                if obj.get("type") == "attack-pattern":
                    ext_ref = obj.get("external_references", [{}])[0]
                    ext_id = ext_ref.get("external_id")
                    stix_id = obj.get("id")
                    if ext_id and stix_id:
                        tech_stix_to_ext_id[stix_id] = ext_id
                        
            tech_uses = {}
            for obj in data.get("objects", []):
                if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
                    source_ref = obj.get("source_ref")
                    target_ref = obj.get("target_ref")
                    
                    if target_ref in tech_stix_to_ext_id:
                        tech_id = tech_stix_to_ext_id[target_ref]
                        source_type = id_to_type.get(source_ref)
                        source_name = id_to_name.get(source_ref)
                        
                        if tech_id and source_type and source_name:
                            if tech_id not in tech_uses:
                                tech_uses[tech_id] = {"actors": set(), "software": set()}
                            if source_type == "intrusion-set":
                                tech_uses[tech_id]["actors"].add(source_name)
                            elif source_type in ["malware", "tool"]:
                                tech_uses[tech_id]["software"].add(source_name)
                                
            # Convert sets to sorted lists for JSON serialization
            serialized_uses = {}
            for tid, val in tech_uses.items():
                serialized_uses[tid] = {
                    "actors": sorted(list(val["actors"])),
                    "software": sorted(list(val["software"]))
                }
                
            _MITRE_RELATIONS_CACHE = serialized_uses
            logger.info("MITRE ATT&CK relationships loaded: %d techniques mapped", len(_MITRE_RELATIONS_CACHE))
            return _MITRE_RELATIONS_CACHE
        except Exception as e:
            logger.error("Failed to parse MITRE ATT&CK relationships: %s", e)
            return {}


def get_mitre_threat_actors(project_root: Path):
    global _MITRE_ACTORS_CACHE
    if _MITRE_ACTORS_CACHE is not None:
        return _MITRE_ACTORS_CACHE

    cache_path = project_root / "config" / "mitre_attack_cache.json"
    if not cache_path.exists():
        return {}

    with MITRE_CACHE_LOCK:
        if _MITRE_ACTORS_CACHE is not None:
            return _MITRE_ACTORS_CACHE

        try:
            logger.info("Parsing MITRE ATT&CK threat actors...")
            with cache_path.open("r", encoding="utf-8") as f:
                data = json.load(f)

            actors = {}
            tech_map = {}
            soft_map = {}

            for obj in data.get("objects", []):
                obj_type = obj.get("type")
                if obj_type == "intrusion-set":
                    if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                        continue
                    stix_id = obj.get("id")
                    ext_refs = obj.get("external_references", [])
                    ext_id = ""
                    url = ""
                    for ref in ext_refs:
                        if ref.get("source_name") == "mitre-attack":
                            ext_id = ref.get("external_id", "")
                            url = ref.get("url", "")
                            break
                    if not ext_id and ext_refs:
                        ext_id = ext_refs[0].get("external_id", "")
                        url = ext_refs[0].get("url", "")
                    
                    actors[stix_id] = {
                        "id": stix_id,
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                        "aliases": obj.get("aliases", []),
                        "external_id": ext_id,
                        "url": url,
                        "techniques": [],
                        "software": []
                    }
                elif obj_type == "attack-pattern":
                    if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                        continue
                    stix_id = obj.get("id")
                    ext_refs = obj.get("external_references", [])
                    ext_id = ""
                    for ref in ext_refs:
                        if ref.get("source_name") == "mitre-attack":
                            ext_id = ref.get("external_id", "")
                            break
                    if not ext_id and ext_refs:
                        ext_id = ext_refs[0].get("external_id", "")
                    tech_map[stix_id] = {
                        "id": ext_id,
                        "name": obj.get("name", "")
                    }
                elif obj_type in ["malware", "tool"]:
                    if obj.get("x_mitre_deprecated") or obj.get("revoked"):
                        continue
                    stix_id = obj.get("id")
                    soft_map[stix_id] = obj.get("name", "")

            # Build relationships
            for obj in data.get("objects", []):
                if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
                    source_ref = obj.get("source_ref")
                    target_ref = obj.get("target_ref")

                    if source_ref in actors:
                        if target_ref in tech_map:
                            actors[source_ref]["techniques"].append(tech_map[target_ref])
                        elif target_ref in soft_map:
                            actors[source_ref]["software"].append(soft_map[target_ref])

            # Sort lists
            for actor in actors.values():
                actor["techniques"].sort(key=lambda x: x["id"])
                # Remove duplicate techniques just in case
                seen_techs = set()
                dedup_techs = []
                for t in actor["techniques"]:
                    if t["id"] not in seen_techs:
                        seen_techs.add(t["id"])
                        dedup_techs.append(t)
                actor["techniques"] = dedup_techs
                
                actor["software"] = sorted(list(set(actor["software"])))

            _MITRE_ACTORS_CACHE = actors
            logger.info("MITRE ATT&CK threat actors loaded: %d groups", len(_MITRE_ACTORS_CACHE))
            return _MITRE_ACTORS_CACHE
        except Exception as e:
            logger.error("Failed to parse MITRE ATT&CK threat actors: %s", e)
            return {}


def get_malpedia_cache(project_root: Path):
    global _MALPEDIA_CACHE
    if _MALPEDIA_CACHE is not None:
        return _MALPEDIA_CACHE
        
    cache_path = project_root / "config" / "malpedia_cache.json"
    if not cache_path.exists():
        return {}
        
    with MALPEDIA_CACHE_LOCK:
        if _MALPEDIA_CACHE is not None:
            return _MALPEDIA_CACHE
            
        try:
            logger.info("Parsing Malpedia threat actors cache...")
            with cache_path.open("r", encoding="utf-8") as f:
                _MALPEDIA_CACHE = json.load(f)
            logger.info("Malpedia threat actors loaded: %d groups", len(_MALPEDIA_CACHE))
            return _MALPEDIA_CACHE
        except Exception as e:
            logger.error("Failed to parse Malpedia threat actors: %s", e)
            return {}

# Load API key configuration from environment
API_KEY_ENV = os.environ.get("ETPRO_API_KEY", "").strip()

def verify_api_key(request: Request):
    if not API_KEY_ENV:
        return
    
    # Check X-API-Key header first
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        # Check query parameter
        api_key = request.query_params.get("api_key")
        
    if api_key != API_KEY_ENV:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing API Key")


def get_latest_analysis_report(project_root: Path) -> Optional[Path]:
    """Helper to locate the latest daily analysis report CSV in reports/ directory."""
    reports_dir = project_root / "reports"
    if not reports_dir.exists():
        return None
    csv_files = list(reports_dir.glob("daily_analysis_*.csv"))
    if not csv_files:
        return None
    csv_files.sort(key=lambda p: p.name)
    return csv_files[-1]


def parse_rule_metadata(raw_rule: str) -> dict:
    """Parses a raw Suricata rule to extract key metadata classification fields."""
    sid_match = re.search(r"\bsid\s*:\s*(\d+)", raw_rule, re.IGNORECASE)
    sid = sid_match.group(1) if sid_match else "unknown"
    
    msg_match = re.search(r"\bmsg\s*:\s*\"([^\"]+)\"", raw_rule, re.IGNORECASE)
    msg = msg_match.group(1) if msg_match else ""
    
    classtype_match = re.search(r"\bclasstype\s*:\s*([^;)]+)", raw_rule, re.IGNORECASE)
    classtype = classtype_match.group(1).strip() if classtype_match else "unknown"
    
    metadata_match = re.search(r"\bmetadata\s*:\s*([^;)]+)", raw_rule, re.IGNORECASE)
    affected_product = "unknown"
    attack_target = "unknown"
    confidence = "unknown"
    signature_severity = "unknown"
    cve = "unknown"
    mitre_tactic = "unknown"
    mitre_technique = "unknown"
    mitre_tactic_id = "unknown"
    mitre_technique_id = "unknown"
    
    # Try extracting CVE from references first
    cve_ref_match = re.search(r"\breference\s*:\s*cve\s*,\s*([^;)\s,]+)", raw_rule, re.IGNORECASE)
    if cve_ref_match:
        cve_val = cve_ref_match.group(1).strip()
        cve = f"CVE-{cve_val}" if not cve_val.upper().startswith("CVE-") else cve_val
    
    if metadata_match:
        meta_block = metadata_match.group(1)
        parts = meta_block.split(",")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            subparts = part.split(None, 1)
            if len(subparts) == 2:
                key, val = subparts[0].lower(), subparts[1].strip()
                if key == "affected_product":
                    affected_product = val
                elif key == "attack_target":
                    attack_target = val
                elif key == "confidence":
                    confidence = val
                elif key == "signature_severity":
                    signature_severity = val
                elif key == "cve" and cve == "unknown":
                    cve_val = val.replace("_", "-").upper()
                    cve = f"CVE-{cve_val}" if not cve_val.startswith("CVE-") else cve_val
                elif key == "mitre_tactic_name":
                    mitre_tactic = val.replace("_", " ")
                elif key == "mitre_technique_name":
                    mitre_technique = val.replace("_", " ")
                elif key == "mitre_tactic_id":
                    mitre_tactic_id = val.upper()
                elif key == "mitre_technique_id":
                    mitre_technique_id = val.upper()
                    
    return {
        "sid": sid,
        "msg": msg,
        "classtype": classtype,
        "affected_product": affected_product,
        "attack_target": attack_target,
        "confidence": confidence,
        "signature_severity": signature_severity,
        "cve": cve,
        "mitre_tactic": mitre_tactic,
        "mitre_technique": mitre_technique,
        "mitre_tactic_id": mitre_tactic_id,
        "mitre_technique_id": mitre_technique_id,
        "content": raw_rule
    }


def refresh_active_rules_cache(project_root: Path) -> None:
    """Loads and updates active rules cache from deploy.rules and daily analysis report if modified."""
    global ACTIVE_RULES_CACHE, RUN_STATUS
    deploy_path = project_root / "deploy" / "deploy.rules"
    latest_csv = get_latest_analysis_report(project_root)
    meta_file = project_root / "config" / "deploy_rules.meta.json"
    db_path = project_root / "config" / "deploy_rules.db"
    
    mtime_deploy = deploy_path.stat().st_mtime if deploy_path.exists() else 0.0
    mtime_csv = latest_csv.stat().st_mtime if latest_csv and latest_csv.exists() else 0.0
    
    with CACHE_LOCK:
        if (ACTIVE_RULES_CACHE["mtime_deploy"] == mtime_deploy and 
            ACTIVE_RULES_CACHE["mtime_csv"] == mtime_csv and 
            ACTIVE_RULES_CACHE["facets"]):
            return
            
    with RUN_LOCK:
        if RUN_STATUS.get("is_updating_rules"):
            return
            
    # Try loading from the meta file
    if db_path.exists() and meta_file.exists():
        try:
            db_ok = False
            try:
                import sqlite3
                conn_check = sqlite3.connect(str(db_path))
                cursor_check = conn_check.cursor()
                cursor_check.execute("PRAGMA table_info(active_rules)")
                columns = [row[1] for row in cursor_check.fetchall()]
                if "mitre_technique_id" in columns and "mitre_tactic_id" in columns:
                    db_ok = True
                conn_check.close()
            except Exception:
                pass

            if db_ok:
                import json
                with meta_file.open("r", encoding="utf-8") as f:
                    meta_data = json.load(f)
                    if (meta_data.get("mtime_deploy") == mtime_deploy and 
                        meta_data.get("mtime_csv") == mtime_csv and
                        "threat_actor" in meta_data.get("facets", {})):
                        import logging
                        logger = logging.getLogger("web_server")
                        logger.info("Loading active rules metadata from serialized JSON file...")
                        with CACHE_LOCK:
                            ACTIVE_RULES_CACHE["mtime_deploy"] = mtime_deploy
                            ACTIVE_RULES_CACHE["mtime_csv"] = mtime_csv
                            ACTIVE_RULES_CACHE["facets"] = meta_data["facets"]
                            ACTIVE_RULES_CACHE["rules"] = []
                        return
        except Exception as e:
            import logging
            logger = logging.getLogger("web_server")
            logger.warning("Failed to load serialized rules metadata: %s. Re-parsing...", e)

    with RUN_LOCK:
        RUN_STATUS["is_updating_rules"] = True
        
    import threading
    t = threading.Thread(target=_background_rule_update_worker, args=(project_root, mtime_deploy, mtime_csv, deploy_path, latest_csv, meta_file, db_path), daemon=True)
    t.start()


def _background_rule_update_worker(project_root: Path, mtime_deploy: float, mtime_csv: float, deploy_path: Path, latest_csv: Path, meta_file: Path, db_path: Path) -> None:
    global ACTIVE_RULES_CACHE, RUN_STATUS
    import logging
    logger = logging.getLogger("web_server")
    import sqlite3
    import json
    import re
    from pathlib import Path
    try:
        # Re-parsing from scratch
        logger.info("Starting background rule update worker... and database from raw files (90k+ entries)...")
        
        # 1. Load mappings & build fast threat actor word set and regex
        from analyzer import load_intel_data
        try:
            actor_mappings, _, _ = load_intel_data()
        except Exception as e:
            logger.warning("Failed to load intel data: %s. Using default mappings.", e)
            from update_intel import DEFAULT_ACTOR_MAPPINGS as actor_mappings

        alias_to_group = {}
        for group, aliases in actor_mappings.items():
            for alias in aliases:
                alias_to_group[alias.lower()] = group
                
        sorted_aliases = sorted(list(alias_to_group.keys()), key=len, reverse=True)
        if sorted_aliases:
            actor_regex = re.compile(rf"\b({'|'.join(re.escape(a) for a in sorted_aliases)})\b", re.IGNORECASE)
        else:
            actor_regex = None

        word_pattern = re.compile(r"[a-z0-9]+")
        alias_words = set()
        for alias in alias_to_group.keys():
            for word in word_pattern.findall(alias):
                alias_words.add(word)

        # 2. Parse CSV to a fast dictionary
        sid_to_meta = {}
        if latest_csv and latest_csv.exists():
            try:
                import csv
                with latest_csv.open("r", encoding="utf-8", errors="replace") as f:
                    reader = csv.reader(f)
                    header = next(reader)
                    sid_idx = header.index("sid")
                    msg_idx = header.index("msg")
                    class_idx = header.index("classtype")
                    file_idx = header.index("rule_file")
                    meta_idx = header.index("metadata")
                    actor_idx = header.index("threat_actor")
                    
                    for row in reader:
                        if len(row) > max(sid_idx, msg_idx, class_idx, file_idx, meta_idx, actor_idx):
                            sid = row[sid_idx].strip()
                            if not sid:
                                continue
                            
                            meta_block = row[meta_idx].strip()
                            # Parse metadata string
                            affected_product = "unknown"
                            attack_target = "unknown"
                            confidence = "unknown"
                            signature_severity = "unknown"
                            cve = "unknown"
                            mitre_tactic = "unknown"
                            mitre_technique = "unknown"
                            mitre_tactic_id = "unknown"
                            mitre_technique_id = "unknown"
                            if meta_block:
                                if meta_block.startswith("{"):
                                    try:
                                        meta_dict = json.loads(meta_block)
                                        affected_product = meta_dict.get("affected_product", "unknown")
                                        attack_target = meta_dict.get("attack_target", "unknown")
                                        confidence = meta_dict.get("confidence", "unknown")
                                        signature_severity = meta_dict.get("signature_severity", "unknown")
                                        if "cve" in meta_dict:
                                            cve_val = str(meta_dict["cve"]).replace("_", "-").upper()
                                            cve = f"CVE-{cve_val}" if not cve_val.startswith("CVE-") else cve_val
                                        if "mitre_tactic_name" in meta_dict:
                                            mitre_tactic = str(meta_dict["mitre_tactic_name"]).replace("_", " ")
                                        if "mitre_technique_name" in meta_dict:
                                            mitre_technique = str(meta_dict["mitre_technique_name"]).replace("_", " ")
                                        if "mitre_tactic_id" in meta_dict:
                                            mitre_tactic_id = str(meta_dict["mitre_tactic_id"]).upper()
                                        if "mitre_technique_id" in meta_dict:
                                            mitre_technique_id = str(meta_dict["mitre_technique_id"]).upper()
                                    except Exception:
                                        pass
                                else:
                                    parts = meta_block.split(",")
                                    for part in parts:
                                        part = part.strip()
                                        if not part:
                                            continue
                                        subparts = part.split(None, 1)
                                        if len(subparts) == 2:
                                            key, val = subparts[0].lower(), subparts[1].strip()
                                            if key == "affected_product":
                                                affected_product = val
                                            elif key == "attack_target":
                                                attack_target = val
                                            elif key == "confidence":
                                                confidence = val
                                            elif key == "signature_severity":
                                                signature_severity = val
                                            elif key == "cve":
                                                cve_val = val.replace("_", "-").upper()
                                                cve = f"CVE-{cve_val}" if not cve_val.startswith("CVE-") else cve_val
                                            elif key == "mitre_tactic_name":
                                                mitre_tactic = val.replace("_", " ")
                                            elif key == "mitre_technique_name":
                                                mitre_technique = val.replace("_", " ")
                                            elif key == "mitre_tactic_id":
                                                mitre_tactic_id = val.upper()
                                            elif key == "mitre_technique_id":
                                                mitre_technique_id = val.upper()
                                            
                            rule_file = row[file_idx].strip()
                            if rule_file and ("/" in rule_file or "\\" in rule_file):
                                rule_file = Path(rule_file).name
                            
                            threat_actor = row[actor_idx].strip()
                            if not threat_actor or threat_actor == "unknown":
                                threat_actor = ""
                                
                            sid_to_meta[sid] = {
                                "sid": sid,
                                "msg": row[msg_idx].strip(),
                                "classtype": row[class_idx].strip(),
                                "dataset": rule_file or "unknown",
                                "threat_actor": threat_actor,
                                "affected_product": affected_product,
                                "attack_target": attack_target,
                                "confidence": confidence,
                                "signature_severity": signature_severity,
                                "cve": cve,
                                "mitre_tactic": mitre_tactic,
                                "mitre_technique": mitre_technique,
                                "mitre_tactic_id": mitre_tactic_id,
                                "mitre_technique_id": mitre_technique_id
                            }
            except Exception as e:
                logger.warning("Error reading daily analysis report for cache: %s", e)

        # 3. Parse deploy.rules line by line, referencing CSV data
        facets = {
            "dataset": set(),
            "classtype": set(),
            "affected_product": set(),
            "attack_target": set(),
            "confidence": set(),
            "signature_severity": set(),
            "threat_actor": set(),
            "cve_year": set(),
            "mitre_tactic": set()
        }

        def generate_records():
            if not deploy_path.exists():
                return
            try:
                with deploy_path.open("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        clean_line = line.strip()
                        if not clean_line or clean_line.startswith("#"):
                            continue
                        if not any(clean_line.startswith(x) for x in ["alert", "pass", "drop", "reject"]):
                            continue
                            
                        # Extract SID using string find (fast)
                        sid = None
                        idx = clean_line.find("sid:")
                        if idx == -1:
                            idx = clean_line.find("SID:")
                        if idx != -1:
                            end_idx = clean_line.find(";", idx)
                            if end_idx != -1:
                                sid = "".join(c for c in clean_line[idx+4:end_idx] if c.isdigit())
                        
                        parsed = None
                        if sid and sid in sid_to_meta:
                            parsed = sid_to_meta[sid].copy()
                            parsed["content"] = clean_line
                        else:
                            parsed = parse_rule_metadata(clean_line)
                            parsed["dataset"] = "unknown"
                        
                        # Determine threat actor fallback with fast word intersection check
                        actor = parsed.get("threat_actor", "")
                        if not actor or actor == "unknown":
                            matched_actor = "unknown"
                            msg_lower = parsed["msg"].lower()
                            words = set(word_pattern.findall(msg_lower))
                            if words.intersection(alias_words):
                                if actor_regex:
                                    msg_match = actor_regex.search(parsed["msg"])
                                    if msg_match:
                                        matched_actor = alias_to_group.get(msg_match.group(1).lower(), "unknown")
                            parsed["threat_actor"] = matched_actor
                        
                        # Accumulate facets on-the-fly
                        for k in facets:
                            if k == "cve_year":
                                cve_val = parsed.get("cve", "unknown")
                                if cve_val and cve_val.startswith("CVE-"):
                                    parts = cve_val.split("-")
                                    if len(parts) >= 2 and parts[1].isdigit():
                                        facets["cve_year"].add(parts[1])
                                    else:
                                        facets["cve_year"].add("unknown")
                                else:
                                    facets["cve_year"].add("unknown")
                            else:
                                val = parsed.get(k, "unknown")
                                if val:
                                    facets[k].add(val.strip())
                                    
                        yield parsed
            except Exception as e:
                logger.error("Error parsing deploy.rules for cache: %s", e)

        # 4. Populate SQLite database using a shadow table and batching
        total_inserted = 0
        conn = None
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(db_path), isolation_level=None)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            cursor = conn.cursor()
            
            # Start explicit transaction
            conn.execute("BEGIN;")
            
            # Create shadow table
            cursor.execute("DROP TABLE IF EXISTS active_rules_temp")
            cursor.execute("""
                CREATE TABLE active_rules_temp (
                    sid TEXT PRIMARY KEY,
                    msg TEXT,
                    classtype TEXT,
                    dataset TEXT,
                    threat_actor TEXT,
                    affected_product TEXT,
                    attack_target TEXT,
                    confidence TEXT,
                    signature_severity TEXT,
                    cve TEXT,
                    mitre_tactic TEXT,
                    mitre_technique TEXT,
                    mitre_tactic_id TEXT,
                    mitre_technique_id TEXT,
                    content TEXT
                )
            """)
            
            # Batch inserts (2000 rows at a time)
            batch = []
            for r in generate_records():
                batch.append((
                    r["sid"], r["msg"], r["classtype"], r["dataset"], r["threat_actor"],
                    r["affected_product"], r["attack_target"], r["confidence"],
                    r["signature_severity"], r["cve"], r["mitre_tactic"], r["mitre_technique"],
                    r.get("mitre_tactic_id", "unknown"), r.get("mitre_technique_id", "unknown"),
                    r["content"]
                ))
                if len(batch) >= 2000:
                    cursor.executemany("INSERT OR REPLACE INTO active_rules_temp VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", batch)
                    total_inserted += len(batch)
                    batch = []
            
            if batch:
                cursor.executemany("INSERT OR REPLACE INTO active_rules_temp VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", batch)
                total_inserted += len(batch)
            
            # Drop old table and rename temp table
            cursor.execute("DROP TABLE IF EXISTS active_rules")
            cursor.execute("ALTER TABLE active_rules_temp RENAME TO active_rules")
            
            # Create indices for all query/filter columns on active_rules
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_dataset ON active_rules(dataset)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_classtype ON active_rules(classtype)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_threat_actor ON active_rules(threat_actor)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_affected_product ON active_rules(affected_product)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_attack_target ON active_rules(attack_target)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_confidence ON active_rules(confidence)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_signature_severity ON active_rules(signature_severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_cve ON active_rules(cve)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_mitre_tactic ON active_rules(mitre_tactic)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_mitre_tactic_id ON active_rules(mitre_tactic_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_rules_mitre_technique_id ON active_rules(mitre_technique_id)")
            
            # Commit the transaction!
            conn.execute("COMMIT;")
            logger.info("Saved active rules to SQLite database at %s (Atomic swap complete)", db_path)
        except Exception as e:
            if conn:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
            logger.error("Failed to populate SQLite cache database: %s", e)
        finally:
            if conn:
                conn.close()

        serialized_facets = {k: sorted(list(v)) for k, v in facets.items()}
        
        # Save metadata to disk for subsequent quick checks
        try:
            meta_file.parent.mkdir(parents=True, exist_ok=True)
            with meta_file.open("w", encoding="utf-8") as f:
                json.dump({
                    "mtime_deploy": mtime_deploy,
                    "mtime_csv": mtime_csv,
                    "facets": serialized_facets
                }, f, separators=(',', ':'), ensure_ascii=False)
            logger.info("Saved rules metadata cache to file %s", meta_file)
        except Exception as e:
            logger.warning("Failed to save rules metadata cache: %s", e)


        with CACHE_LOCK:
            ACTIVE_RULES_CACHE["mtime_deploy"] = mtime_deploy
            ACTIVE_RULES_CACHE["mtime_csv"] = mtime_csv
            ACTIVE_RULES_CACHE["facets"] = serialized_facets
            ACTIVE_RULES_CACHE["rules"] = [] # kept empty in memory
        logger.info("Active rules cache database refreshed: %d rules loaded", total_inserted)




    except Exception as e:
        logger.error("Background rule update failed: %s", e)
    finally:
        with RUN_LOCK:
            RUN_STATUS["is_updating_rules"] = False

def get_dir_size_str(path: Path) -> str:
    """Helper to calculate directory size and format it nicely."""
    if not path.exists():
        return "0 B"
    total_size = 0
    try:
        for f in path.glob("**/*"):
            if f.is_file():
                total_size += f.stat().st_size
    except Exception:
        pass
    
    # Format size nicely
    for unit in ['B', 'KB', 'MB', 'GB']:
        if total_size < 1024.0:
            return f"{total_size:.2f} {unit}"
        total_size /= 1024.0
    return f"{total_size:.2f} TB"


def parse_deployed_rules(deploy_path: Path) -> Dict[str, Any]:
    """Helper to parse active and auto-healed/user disabled rules from deploy.rules."""
    result = {
        "active_count": 0,
        "disabled_count": 0,
        "disabled_rules": []
    }
    if not deploy_path.exists() or not deploy_path.is_file():
        return result
        
    try:
        disabled_pattern = re.compile(
            r"^#\s*\[(VALIDATION FAILED|USER DISABLED) - ([^\]]+)\]\s*(.*)$", 
            re.IGNORECASE
        )
        
        with deploy_path.open("r", encoding="utf-8", errors="replace") as f:
            for idx, line in enumerate(f, start=1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                    
                match = disabled_pattern.match(clean_line)
                if match:
                    result["disabled_count"] += 1
                    status_type = match.group(1).upper()
                    raw_info = match.group(2).strip()
                    if " - " in raw_info:
                        timestamp, error_reason = raw_info.split(" - ", 1)
                        timestamp = timestamp.strip()
                        error_reason = error_reason.strip()
                    else:
                        timestamp = raw_info
                        error_reason = "Suricata validation failed" if status_type == "VALIDATION FAILED" else "User disabled"
                        
                    rule_content = match.group(3).strip()
                    # Parse SID from rule if possible
                    sid_match = re.search(r"sid:\s*(\d+)", rule_content, re.IGNORECASE)
                    sid = sid_match.group(1) if sid_match else "unknown"
                    
                    result["disabled_rules"].append({
                        "line": idx,
                        "timestamp": timestamp,
                        "sid": sid,
                        "reason": error_reason,
                        "content": rule_content
                    })
                elif not clean_line.startswith("#"):
                    # Check if it looks like a rule (e.g. starts with alert, pass, drop, reject)
                    if any(clean_line.startswith(x) for x in ["alert", "pass", "drop", "reject"]):
                        result["active_count"] += 1
    except Exception as e:
        logger.error("Error parsing deploy rules: %s", e)
        
    return result


def run_pipeline_worker(project_root: Path):
    """Background worker that runs the threat intel sync and rule downloader pipeline."""
    global RUN_STATUS
    
    with RUN_LOCK:
        if RUN_STATUS["status"] == "running":
            return
        RUN_STATUS["status"] = "running"
        RUN_STATUS["last_run_error"] = None
        RUN_STATUS["last_run_success"] = None
        
    logger.info("Web triggered pipeline thread started.")
    try:
        # Re-import within function to load properly in thread context
        from config import AppConfig
        config = AppConfig.from_env(project_root)
        config.ensure_directories()
        
        # 1. Threat Intel Sync
        if config.intel_sync_enabled:
            logger.info("Starting Threat Intel Sync in background thread...")
            try:
                from update_intel import main as sync_intel
                sync_intel(config_dir=config.project_root / "config")
                logger.info("Threat Intel Sync completed.")
            except Exception as e:
                logger.warning("Threat Intel Sync failed in background: %s", e)
                
        # 2. Run Main Download and Validation Pipeline
        logger.info("Starting rule download and validation pipeline in background thread...")
        from scheduler_entry import run_once
        run_once(config=config)
        logger.info("Rule download and validation pipeline completed successfully.")
        
        with RUN_LOCK:
            RUN_STATUS["last_run_success"] = True
    except Exception as e:
        logger.exception("Manual scheduler trigger failed in thread worker")
        with RUN_LOCK:
            RUN_STATUS["last_run_success"] = False
            RUN_STATUS["last_run_error"] = str(e)
    finally:
        with RUN_LOCK:
            RUN_STATUS["status"] = "idle"
            RUN_STATUS["last_run_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info("Web triggered pipeline thread finished.")


def run_cti_pipeline_worker(project_root: Path):
    """Worker to sync CTI feeds and trigger rule compilation, validation and reload."""
    global RUN_STATUS
    with RUN_LOCK:
        if RUN_STATUS["status"] == "running":
            return
        RUN_STATUS["status"] = "running"
        RUN_STATUS["last_run_error"] = None
        RUN_STATUS["last_run_success"] = None
        
    logger.info("Background CTI sync and rebuild started.")
    try:
        from config import AppConfig
        config = AppConfig.from_env(project_root)
        config.ensure_directories()
        
        # 1. Fetch enabled feeds config
        overrides_file = project_root / "config" / "intel_overrides.json"
        enabled_feeds = {"feodo": True, "urlhaus": True, "et_compromised": True}
        if overrides_file.exists():
            try:
                with overrides_file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    enabled_feeds = data.get("cti_feeds", enabled_feeds)
            except Exception:
                pass
                
        # 2. Run CTI Feed sync
        from cti_engine import sync_cti_feeds
        sync_cti_feeds(project_root, enabled_feeds)
        
        # 3. Run Rule compile, validation, and reload
        from scheduler_entry import run_once
        run_once(config=config)
        
        with RUN_LOCK:
            RUN_STATUS["last_run_success"] = True
    except Exception as e:
        logger.exception("Background CTI sync and rebuild failed")
        with RUN_LOCK:
            RUN_STATUS["last_run_success"] = False
            RUN_STATUS["last_run_error"] = str(e)
    finally:
        with RUN_LOCK:
            RUN_STATUS["status"] = "idle"
            RUN_STATUS["last_run_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info("Background CTI sync and rebuild finished.")


# ==========================================
# FastAPI Web Application & Routes
# ==========================================