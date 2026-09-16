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
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from pydantic import BaseModel
from core_state import *
import maxminddb

router = APIRouter()
logger = logging.getLogger("web_server")

@router.get("/api/rules/disabled")
async def api_get_disabled_rules(request: Request, is_authorized: None = Depends(verify_api_key)):
    """API to fetch disabled rules"""
    project_root = PROJECT_ROOT
    try:
        from config import AppConfig
        config = AppConfig.from_env(project_root, require_oinkcode=False)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Configuration load failed: {e}")

    deploy_path = config.deploy_target_path or (project_root / "deploy" / "deploy.rules")
    rules_stats = parse_deployed_rules(deploy_path)
    return rules_stats["disabled_rules"]



@router.get("/api/rules/active/facets")
async def api_get_active_rules_facets(request: Request, is_authorized: None = Depends(verify_api_key)):
    """API to get all unique classification values for selection dropdowns"""
    try:
        refresh_active_rules_cache(PROJECT_ROOT)
        with CACHE_LOCK:
            return ACTIVE_RULES_CACHE["facets"]
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load active rules facets: {e}")



@router.get("/api/rules/active/stats")
async def api_get_active_rules_stats(request: Request, is_authorized: None = Depends(verify_api_key)):
    """API to get active rules statistics (threat actors and severities)"""
    project_root = PROJECT_ROOT
    try:
        refresh_active_rules_cache(project_root)
        db_path = project_root / "config" / "deploy_rules.db"
        if not db_path.exists():
            return {
                "threat_actors": {},
                "severities": {},
                "mitre_tactics": {},
                "cve_years": {},
                "total_active_rules": 0
            }
        
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        cursor = conn.cursor()
        
        # Threat actors
        cursor.execute("SELECT threat_actor, count(*) FROM active_rules GROUP BY threat_actor")
        threat_counts = {row[0]: row[1] for row in cursor.fetchall()}
        
        # Severities
        cursor.execute("SELECT signature_severity, count(*) FROM active_rules GROUP BY signature_severity")
        severity_counts = {row[0]: row[1] for row in cursor.fetchall()}
        
        # MITRE Tactics
        cursor.execute("SELECT mitre_tactic, count(*) FROM active_rules GROUP BY mitre_tactic")
        tactic_counts = {row[0]: row[1] for row in cursor.fetchall()}
        
        # CVE Years
        cursor.execute("SELECT cve, count(*) FROM active_rules GROUP BY cve")
        cve_counts = {}
        for row in cursor.fetchall():
            cve_val, count = row[0], row[1]
            if cve_val and cve_val.startswith("CVE-"):
                parts = cve_val.split("-")
                if len(parts) >= 2 and parts[1].isdigit():
                    year = parts[1]
                    cve_counts[year] = cve_counts.get(year, 0) + count
                else:
                    cve_counts["unknown"] = cve_counts.get("unknown", 0) + count
            else:
                cve_counts["unknown"] = cve_counts.get("unknown", 0) + count
                
        # Total active rules
        cursor.execute("SELECT count(*) FROM active_rules")
        total_active_rules = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "threat_actors": threat_counts,
            "severities": severity_counts,
            "mitre_tactics": tactic_counts,
            "cve_years": cve_counts,
            "total_active_rules": total_active_rules
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load active rules stats: {e}")



@router.get("/api/rules/active")
async def api_get_active_rules(
    request: Request,
    page: int = 1,
    limit: int = 25,
    search: str = "",
    dataset: str = "",
    classtype: str = "",
    affected_product: str = "",
    attack_target: str = "",
    confidence: str = "",
    signature_severity: str = "",
    threat_actor: str = "",
    cve_year: str = "",
    mitre_tactic: str = "",
    mitre_technique: str = "",
    mitre_technique_id: str = "",
    cve: str = "",
    is_authorized: None = Depends(verify_api_key)
):
    """API to query and search deployed active rules (paginated using SQLite)"""
    project_root = PROJECT_ROOT
    try:
        refresh_active_rules_cache(project_root)
        db_path = project_root / "config" / "deploy_rules.db"
        if not db_path.exists():
            return {
                "total": 0,
                "page": page,
                "limit": limit,
                "total_pages": 1,
                "rules": []
            }
        
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        where_clauses = []
        params = []
        
        if search:
            where_clauses.append("(sid LIKE ? OR msg LIKE ? OR content LIKE ? OR threat_actor LIKE ? OR classtype LIKE ? OR cve LIKE ? OR mitre_tactic LIKE ? OR mitre_technique LIKE ?)")
            like_pattern = f"%{search}%"
            params.extend([like_pattern] * 8)
            
        if dataset:
            where_clauses.append("dataset = ?")
            params.append(dataset)
        if classtype:
            where_clauses.append("classtype = ?")
            params.append(classtype)
        if affected_product:
            where_clauses.append("affected_product = ?")
            params.append(affected_product)
        if attack_target:
            where_clauses.append("attack_target = ?")
            params.append(attack_target)
        if confidence:
            where_clauses.append("confidence = ?")
            params.append(confidence)
        if signature_severity:
            where_clauses.append("signature_severity = ?")
            params.append(signature_severity)
        if threat_actor:
            where_clauses.append("threat_actor = ?")
            params.append(threat_actor)
        if mitre_tactic:
            where_clauses.append("mitre_tactic = ?")
            params.append(mitre_tactic)
        if mitre_technique:
            where_clauses.append("mitre_technique = ?")
            params.append(mitre_technique)
        if mitre_technique_id:
            where_clauses.append("mitre_technique_id = ?")
            params.append(mitre_technique_id)
        if cve_year:
            if cve_year == "unknown":
                where_clauses.append("(cve IS NULL OR cve = 'unknown' OR cve NOT LIKE 'CVE-%')")
            else:
                where_clauses.append("cve LIKE ?")
                params.append(f"CVE-{cve_year}-%")
        if cve:
            where_clauses.append("cve LIKE ?")
            params.append(f"%{cve}%")
                
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)
            
        # 1. Total count
        cursor.execute(f"SELECT count(*) FROM active_rules {where_sql}", params)
        total_entries = cursor.fetchone()[0]
        
        # 2. Pagination
        total_pages = math.ceil(total_entries / limit) if limit > 0 else 1
        if page < 1:
            page = 1
        if page > total_pages and total_pages > 0:
            page = total_pages
            
        # 3. Query rows
        offset = (page - 1) * limit
        cursor.execute(f"SELECT * FROM active_rules {where_sql} LIMIT ? OFFSET ?", params + [limit, offset])
        rows = cursor.fetchall()
        
        page_rules = []
        for r in rows:
            page_rules.append({k: r[k] for k in r.keys()})
            
        conn.close()
        
        return {
            "total": total_entries,
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
            "rules": page_rules
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query active rules: {e}")


@router.get("/api/rules/detail/{sid}")
async def api_get_rule_detail(sid: str, request: Request, is_authorized: None = Depends(verify_api_key)):
    """API to get single rule detail by SID"""
    project_root = PROJECT_ROOT
    try:
        db_path = project_root / "config" / "deploy_rules.db"
        if not db_path.exists():
            raise HTTPException(status_code=404, detail="Database not found")
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM active_rules WHERE sid = ?", (str(sid),))
        row = cursor.fetchone()
        conn.close()
        if not row:
            raise HTTPException(status_code=404, detail=f"Rule with SID {sid} not found")
        return {k: row[k] for k in row.keys()}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

import io
import csv


@router.get("/api/rules/active/export")
async def api_export_active_rules(
    request: Request,
    search: str = "",
    dataset: str = "",
    classtype: str = "",
    affected_product: str = "",
    attack_target: str = "",
    confidence: str = "",
    signature_severity: str = "",
    threat_actor: str = "",
    cve_year: str = "",
    mitre_tactic: str = "",
    mitre_technique: str = "",
    mitre_technique_id: str = "",
    cve: str = "",
    is_authorized: None = Depends(verify_api_key)
):
    """API to export active rules to CSV"""
    project_root = PROJECT_ROOT
    try:
        db_path = project_root / "config" / "deploy_rules.db"
        if not db_path.exists():
            raise FileNotFoundError("SQLite rules database not found")
        
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        where_clauses = []
        params = []
        
        if search:
            where_clauses.append("(sid LIKE ? OR msg LIKE ? OR content LIKE ? OR threat_actor LIKE ? OR classtype LIKE ? OR cve LIKE ? OR mitre_tactic LIKE ? OR mitre_technique LIKE ?)")
            like_pattern = f"%{search}%"
            params.extend([like_pattern] * 8)
            
        if dataset:
            where_clauses.append("dataset = ?")
            params.append(dataset)
        if classtype:
            where_clauses.append("classtype = ?")
            params.append(classtype)
        if affected_product:
            where_clauses.append("affected_product = ?")
            params.append(affected_product)
        if attack_target:
            where_clauses.append("attack_target = ?")
            params.append(attack_target)
        if confidence:
            where_clauses.append("confidence = ?")
            params.append(confidence)
        if signature_severity:
            where_clauses.append("signature_severity = ?")
            params.append(signature_severity)
        if threat_actor:
            where_clauses.append("threat_actor = ?")
            params.append(threat_actor)
        if mitre_tactic:
            where_clauses.append("mitre_tactic = ?")
            params.append(mitre_tactic)
        if mitre_technique:
            where_clauses.append("mitre_technique = ?")
            params.append(mitre_technique)
        if mitre_technique_id:
            where_clauses.append("mitre_technique_id = ?")
            params.append(mitre_technique_id)
        if cve_year:
            if cve_year == "unknown":
                where_clauses.append("(cve IS NULL OR cve = 'unknown' OR cve NOT LIKE 'CVE-%')")
            else:
                where_clauses.append("cve LIKE ?")
                params.append(f"CVE-{cve_year}-%")
        if cve:
            where_clauses.append("cve LIKE ?")
            params.append(f"%{cve}%")
                
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)
            
        cursor.execute(f"SELECT * FROM active_rules {where_sql}", params)
        rows = cursor.fetchall()
        rows_data = [{k: row[k] for k in row.keys()} for row in rows]
        conn.close()
        
        def iter_csv():
            output = io.StringIO()
            writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
            
            headers = ["sid", "msg", "classtype", "dataset", "threat_actor", "affected_product", "attack_target", "confidence", "signature_severity", "cve", "mitre_tactic", "mitre_technique", "mitre_tactic_id", "mitre_technique_id", "content"]
            writer.writerow(headers)
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
            
            for row in rows_data:
                writer.writerow([row.get(k, "") for k in headers])
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        response = StreamingResponse(iter_csv(), media_type="text/csv")
        response.headers["Content-Disposition"] = f"attachment; filename=deployed_rules_{timestamp}.csv"
        return response
        
    except Exception as e:
        logger.error(f"Error exporting active rules: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to export active rules: {e}")


@router.get("/api/rules/active/mitre-matrix")
async def api_get_mitre_matrix(request: Request, is_authorized: None = Depends(verify_api_key)):
    """API to retrieve the MITRE ATT&CK Matrix layout, active coverages, and gap recommendations."""
    project_root = PROJECT_ROOT
    try:
        refresh_active_rules_cache(project_root)
        db_path = project_root / "config" / "deploy_rules.db"
        
        # 1. Get active rules coverage map from DB
        coverage_map = {}
        if db_path.exists():
            conn = sqlite3.connect(str(db_path))
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT mitre_technique_id, count(*) FROM active_rules WHERE mitre_technique_id != 'unknown' AND mitre_technique_id != '' GROUP BY mitre_technique_id")
                for row in cursor.fetchall():
                    coverage_map[row[0]] = row[1]
            finally:
                conn.close()
                
        # 2. Get static structures and relations (fully cached in memory)
        matrix = get_mitre_matrix_structure(project_root)
        relations_map = get_mitre_relations(project_root)
        
        # 3. Parse disabled rules to check if any gaps could be resolved by enabling them
        deploy_path = project_root / "deploy" / "deploy.rules"
        disabled_by_tech = {}
        if deploy_path.exists():
            disabled_res = parse_deployed_rules(deploy_path)
            for r in disabled_res.get("disabled_rules", []):
                meta = parse_rule_metadata(r["content"])
                t_id = meta.get("mitre_technique_id", "unknown")
                if t_id and t_id != "unknown":
                    if t_id not in disabled_by_tech:
                        disabled_by_tech[t_id] = []
                    disabled_by_tech[t_id].append(r["sid"])
                    
        # 4. Load current actor mappings & software denylist
        actor_mappings = {}
        actor_mappings_file = project_root / "config" / "actor_mappings.json"
        if actor_mappings_file.exists():
            try:
                with actor_mappings_file.open("r", encoding="utf-8") as f:
                    actor_mappings = json.load(f)
            except Exception:
                pass
                
        software_denylist = set()
        software_denylist_file = project_root / "config" / "software_denylist.json"
        if software_denylist_file.exists():
            try:
                with software_denylist_file.open("r", encoding="utf-8") as f:
                    software_denylist = set(x.lower() for x in json.load(f))
            except Exception:
                pass
                
        # Get active threat actor names & aliases
        active_actors_and_aliases = set()
        for group, aliases in actor_mappings.items():
            active_actors_and_aliases.add(group.lower())
            for alias in aliases:
                active_actors_and_aliases.add(alias.lower())
                
        # 5. Generate gap recommendations
        recommendations = []
        gaps_count = 0
        total_techniques = 0
        covered_techniques = 0
        
        # Keep track of technique IDs we have processed to avoid double counting across multiple tactics
        processed_techs = set()
        
        for tactic in matrix:
            for tech in tactic["techniques"]:
                tech_id = tech["id"]
                tech_name = tech["name"]
                
                if tech_id not in processed_techs:
                    processed_techs.add(tech_id)
                    total_techniques += 1
                    if coverage_map.get(tech_id, 0) > 0:
                        covered_techniques += 1
                
                coverage_count = coverage_map.get(tech_id, 0)
                if coverage_count == 0:
                    gaps_count += 1
                    
                    # Recommendation A: Disabled rules exist
                    disabled_sids = disabled_by_tech.get(tech_id, [])
                    if disabled_sids:
                        recommendations.append({
                            "type": "enable_rules",
                            "priority": 1,
                            "technique_id": tech_id,
                            "technique_name": tech_name,
                            "tactic_name": tactic["name"],
                            "title": f"啟用 {tech_name} ({tech_id}) 的已停用規則",
                            "description": f"檢測到有 {len(disabled_sids)} 條針對此技術的規則目前處於停用狀態（驗證失敗或手動停用）。",
                            "action_label": "前往查看停用規則",
                            "target_tab": "disabled_rules",
                            "detail": f"停用規則 SIDs: {', '.join(disabled_sids[:5])}{' ...' if len(disabled_sids) > 5 else ''}"
                        })
                        continue
                        
                    # Recommendation B: Check threat actor mapping
                    relations = relations_map.get(tech_id, {"actors": [], "software": []})
                    actors_using_it = relations["actors"]
                    software_using_it = relations["software"]
                    
                    added_rec = False
                    unmapped_actors = [a for a in actors_using_it if a.lower() not in active_actors_and_aliases]
                    if unmapped_actors:
                        recommendations.append({
                            "type": "add_actor",
                            "priority": 2,
                            "technique_id": tech_id,
                            "technique_name": tech_name,
                            "tactic_name": tactic["name"],
                            "title": f"新增威脅組織對應：{unmapped_actors[0]}",
                            "description": f"技術 {tech_name} 常被組織 {unmapped_actors[0]} 使用，但該組織未設定在您的監控列表中。",
                            "action_label": "前往設定新增組織",
                            "target_tab": "config",
                            "detail": f"建議於設定中新增威脅組織別名：{', '.join(unmapped_actors[:3])}"
                        })
                        added_rec = True
                        
                    # Recommendation C: Check software denylist
                    denylisted_software = [s for s in software_using_it if s.lower() in software_denylist]
                    if denylisted_software:
                        recommendations.append({
                            "type": "remove_denylist",
                            "priority": 2,
                            "technique_id": tech_id,
                            "technique_name": tech_name,
                            "tactic_name": tactic["name"],
                            "title": f"從黑名單中移除：{denylisted_software[0]}",
                            "description": f"技術 {tech_name} 關聯的軟體工具 {denylisted_software[0]} 目前已被列入黑名單，因而過濾了此特徵規則。",
                            "action_label": "前往設定編輯黑名單",
                            "target_tab": "config",
                            "detail": f"建議黑名單移除項目：{', '.join(denylisted_software[:3])}"
                        })
                        added_rec = True
                        
                    if not added_rec:
                        # Recommendation D: General suggestion
                        recommendations.append({
                            "type": "general",
                            "priority": 3,
                            "technique_id": tech_id,
                            "technique_name": tech_name,
                            "tactic_name": tactic["name"],
                            "title": f"引進 {tech_name} ({tech_id}) 的防禦特徵",
                            "description": f"當前部署的規則集中沒有覆蓋此防禦技術。常出現在關聯軟體：{', '.join(software_using_it[:3]) if software_using_it else '無關聯工具'}",
                            "action_label": "引進自訂規則",
                            "target_tab": "config",
                            "detail": "建議聯絡防護服務商或手動撰寫 Suricata 特徵碼以消除此防禦缺口。"
                        })
                        
        recommendations.sort(key=lambda x: x["priority"])
        
        # Calculate coverage score
        coverage_percentage = round((covered_techniques / total_techniques) * 100, 2) if total_techniques > 0 else 0.0
        
        return {
            "matrix": matrix,
            "coverage": coverage_map,
            "metrics": {
                "total_techniques": total_techniques,
                "covered_techniques": covered_techniques,
                "gaps_count": total_techniques - covered_techniques,
                "coverage_percentage": coverage_percentage
            },
            "recommendations": recommendations[:20] # Return top 20 prioritized recommendations to avoid overloading UI
        }
    except Exception as e:
        logger.error("Failed to generate MITRE matrix data: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to generate MITRE matrix data: {e}")



@router.post("/api/rules/toggle")
async def api_toggle_rule(request: Request, is_authorized: None = Depends(verify_api_key)):
    """API to toggle rule enabled/disabled status in deploy.rules"""
    try:
        payload = await request.json()
        sid = str(payload.get("sid", "")).strip()
        enabled = bool(payload.get("enabled", False))
        
        if not sid:
            raise ValueError("Missing 'sid' parameter")
        
        from config import AppConfig
        config = AppConfig.from_env(PROJECT_ROOT, require_oinkcode=False)
        deploy_path = config.deploy_target_path or (PROJECT_ROOT / "deploy" / "deploy.rules")
        
        if not deploy_path.exists():
            raise FileNotFoundError(f"Deploy rules file not found: {deploy_path}")
        
        with deploy_path.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        
        sid_pattern = re.compile(rf"\bsid\s*:\s*{re.escape(sid)}\s*;", re.IGNORECASE)
        modified = False
        
        for idx, line in enumerate(lines):
            if sid_pattern.search(line):
                if enabled:
                    if line.strip().startswith("#"):
                        new_line = re.sub(r"^#\s*\[(?:USER DISABLED|VALIDATION FAILED)[^\]]*\]\s*", "", line)
                        if new_line != line:
                            lines[idx] = new_line
                            modified = True
                else:
                    if not line.strip().startswith("#"):
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        lines[idx] = f"# [USER DISABLED - {timestamp}] {line}"
                        modified = True
                break
        
        reload_success = False
        if modified:
            with deploy_path.open("w", encoding="utf-8", newline="\n") as f:
                f.writelines(lines)
            
            with CACHE_LOCK:
                ACTIVE_RULES_CACHE["mtime_deploy"] = 0.0
                ACTIVE_RULES_CACHE["mtime_csv"] = 0.0
                ACTIVE_RULES_CACHE["rules"] = []
                ACTIVE_RULES_CACHE["facets"] = {}
            
            meta_file = PROJECT_ROOT / "config" / "deploy_rules.meta.json"
            db_file = PROJECT_ROOT / "config" / "deploy_rules.db"
            for f_to_del in [meta_file, db_file]:
                if f_to_del.exists():
                    try:
                        f_to_del.unlink()
                    except Exception as e:
                        logger.warning("Failed to delete cache file on toggle: %s", e)
            
            from deployer import trigger_suricata_reload
            reload_success = trigger_suricata_reload(config)
        
        return {
            "status": "success",
            "modified": modified,
            "reload_triggered": reload_success
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/api/deployments")
async def api_get_deployments(request: Request, is_authorized: None = Depends(verify_api_key)):
    try:
        from config import AppConfig
        config = AppConfig.from_env(PROJECT_ROOT, require_oinkcode=False)
        backups_dir = config.deploy_archive_dir
        backups = []
        if backups_dir and backups_dir.exists():
            for f in backups_dir.glob("*.rules"):
                backups.append({"filename": f.name, "size": f.stat().st_size, "mtime": f.stat().st_mtime})
        return {"status": "success", "backups": sorted(backups, key=lambda x: x["mtime"], reverse=True)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class RollbackRequest(BaseModel):
    filename: str

@router.post("/api/deployments/rollback")
async def api_rollback_deployment(req: RollbackRequest, request: Request, is_authorized: None = Depends(verify_api_key)):
    import shutil
    try:
        from config import AppConfig
        config = AppConfig.from_env(PROJECT_ROOT, require_oinkcode=False)
        backup_file = config.deploy_archive_dir / req.filename
        if not backup_file.exists():
            raise FileNotFoundError("Backup file not found")
        deploy_path = config.deploy_target_path or (PROJECT_ROOT / "deploy" / "deploy.rules")
        shutil.copy2(backup_file, deploy_path)
        
        # Trigger Suricata reload after rollback
        try:
            from deployer import trigger_suricata_reload
            trigger_suricata_reload(config)
        except Exception as reload_e:
            logger.warning(f"Reload failed after rollback: {reload_e}")
            
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/rules/transfer/latest")
async def api_get_latest_transfer_rules(request: Request, is_authorized: None = Depends(verify_api_key)):
    """API to download or view the latest generated transfer.rules file."""
    try:
        from config import AppConfig
        config = AppConfig.from_env(PROJECT_ROOT, require_oinkcode=False)
        target_dir = config.transfer_output_dir or config.output_dir
        transfer_files = sorted(
            list(target_dir.glob("*_transfer.rules")) + list(target_dir.glob("*_transfer.txt")),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        if not transfer_files:
            raise HTTPException(status_code=404, detail="No transfer rules file generated yet.")
        latest_file = transfer_files[0]
        return FileResponse(
            path=str(latest_file),
            filename=latest_file.name,
            media_type="text/plain; charset=utf-8"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
