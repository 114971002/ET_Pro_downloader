from __future__ import annotations

import csv
import json
import logging
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
import requests

logger = logging.getLogger("cti_engine")

FEEDS_CONFIG = {
    "feodo": {
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
        "name": "Feodo Tracker C2 IPs",
        "ref": "feodotracker.abuse.ch"
    },
    "urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "name": "URLhaus Malicious Domains",
        "ref": "urlhaus.abuse.ch"
    },
    "et_compromised": {
        "url": "https://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt",
        "name": "ET Open Compromised IPs",
        "ref": "rules.emergingthreats.net"
    }
}

# SID ranges: 9000000 - 9099999 for IPs, 9100000 - 9199999 for Domains
IP_SID_START = 9000000
DOMAIN_SID_START = 9100000
MAX_IOCS_PER_FEED = 1500  # Cap to prevent excessive load on Suricata and DB


def sync_cti_feeds(project_root: Path, enabled_feeds: dict[str, bool]) -> dict:
    """Downloads active feeds, parses IoCs, generates Suricata rules, and saves metadata."""
    downloads_dir = project_root / "downloads"
    downloads_dir.mkdir(parents=True, exist_ok=True)
    
    status = {
        "sync_time": datetime.now(timezone.utc).isoformat(),
        "feeds": {},
        "total_ip_rules": 0,
        "total_domain_rules": 0,
        "total_rules": 0
    }
    
    # Load historical dates
    existing_dates = {}
    registry_path = downloads_dir / "cti_iocs.json"
    if registry_path.exists():
        try:
            with registry_path.open("r", encoding="utf-8") as f:
                old_iocs = __import__("json").load(f)
                for old in old_iocs:
                    existing_dates[old["value"]] = old.get("added_date")
        except Exception:
            pass

    
    all_ips: dict[str, tuple[str, str, str]] = {}  # ip -> (source feed, threat_actor, malware_tag)
    all_domains: dict[str, tuple[str, str, str]] = {}  # domain -> (source feed, threat_actor, malware_tag)
    
    # Load actor mappings for reverse lookup
    actor_mappings_path = project_root / "config" / "actor_mappings.json"
    alias_to_actor = {}
    if actor_mappings_path.exists():
        try:
            with actor_mappings_path.open("r", encoding="utf-8") as f:
                mappings = __import__("json").load(f)
                for actor, aliases in mappings.items():
                    alias_to_actor[actor.lower()] = actor
                    for alias in aliases:
                        alias_to_actor[alias.lower()] = actor
        except Exception as e:
            logger.error("Failed to load actor mappings: %s", e)
    
    # 1. Download & Parse Feeds
    for feed_id, config in FEEDS_CONFIG.items():
        if not enabled_feeds.get(feed_id, True):
            status["feeds"][feed_id] = {"enabled": False, "status": "disabled"}
            continue
            
        logger.info("Fetching CTI feed: %s", config["name"])
        try:
            res = requests.get(config["url"], timeout=30)
            res.raise_for_status()
            content = res.text
            
            ips_count = 0
            domains_count = 0
            
            if feed_id == "feodo":
                # CSV format
                lines = content.splitlines()
                # Parse CSV rows, skipping lines starting with #
                csv_lines = [line for line in lines if line and not line.startswith("#")]
                reader = csv.reader(csv_lines)
                count = 0
                for row in reader:
                    if len(row) >= 2:
                        ip = row[1].strip()
                        malware = row[5].strip() if len(row) > 5 else ""
                        malware_tag = malware if malware else "unknown"
                        threat_actor = alias_to_actor.get(malware.lower(), "unknown")
                        # Simple IP check
                        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                            all_ips[ip] = ("Feodo Tracker", threat_actor, malware_tag)
                            ips_count += 1
                            count += 1
                            if count >= MAX_IOCS_PER_FEED:
                                break
                                
            elif feed_id == "urlhaus":
                # CSV format with tags
                lines = content.splitlines()
                csv_lines = [line for line in lines if line and not line.startswith("#")]
                reader = csv.reader(csv_lines)
                count = 0
                for row in reader:
                    if len(row) >= 3:
                        url = row[2].strip()
                        tags_raw = row[6].strip() if len(row) > 6 else ""
                        threat_actor = "unknown"
                        tags_list = [t.strip() for t in tags_raw.split(",") if t.strip()]
                        malware_tag = tags_list[0] if tags_list else "unknown"
                        for tag in tags_list:
                            if tag.lower() in alias_to_actor:
                                threat_actor = alias_to_actor[tag.lower()]
                                break
                        
                        try:
                            parsed = urllib.parse.urlparse(url)
                            host = parsed.netloc or parsed.path.split('/')[0]
                            if ":" in host:
                                host = host.split(":")[0]
                            host = host.strip()
                            if host:
                                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
                                    if host not in all_ips:
                                        all_ips[host] = ("URLhaus", threat_actor, malware_tag)
                                        ips_count += 1
                                        count += 1
                                else:
                                    if host not in all_domains:
                                        all_domains[host] = ("URLhaus", threat_actor, malware_tag)
                                        domains_count += 1
                                        count += 1
                                if count >= MAX_IOCS_PER_FEED:
                                    break
                        except Exception:
                            continue
                        
            elif feed_id == "et_compromised":
                # List of IPs
                lines = content.splitlines()
                count = 0
                for line in lines:
                    ip = line.strip()
                    if not ip or ip.startswith("#"):
                        continue
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                        all_ips[ip] = ("ET Compromised", "unknown", "unknown")
                        ips_count += 1
                        count += 1
                        if count >= MAX_IOCS_PER_FEED:
                            break
                            
            status["feeds"][feed_id] = {
                "enabled": True,
                "status": "success",
                "ips_count": ips_count,
                "domains_count": domains_count
            }
        except Exception as e:
            logger.error("Failed to sync feed %s: %s", feed_id, e)
            status["feeds"][feed_id] = {
                "enabled": True,
                "status": "failed",
                "error": str(e)
            }
            
    # 2. Generate Suricata Rules
    rules_path = downloads_dir / "cti_blocklist.rules"
    rules_generated = []
    
    # Generate IP rules (bidirectional to alert on both outgoing/incoming traffic)
    ip_sid = IP_SID_START
    for ip, (src, _, _) in sorted(all_ips.items()):
        rules_generated.append(
            f'alert ip any any <> {ip} any (msg:"CTI Blocklist: Traffic to/from Malicious IP ({src})"; '
            f'threshold:type limit, track by_src, count 1, seconds 60; '
            f'reference:url,{FEEDS_CONFIG["feodo"]["ref"]}; '
            f'metadata:status active, severity major, threat_actor CTI_Blocklist, affected_product Any, attack_target Network; '
            f'sid:{ip_sid}; rev:1;)'
        )
        ip_sid += 1
        
    # Generate Domain rules
    domain_sid = DOMAIN_SID_START
    for domain, (src, _, _) in sorted(all_domains.items()):
        rules_generated.append(
            f'alert dns $HOME_NET any -> any any (msg:"CTI Blocklist: DNS Query for Malicious Domain ({src})"; '
            f'dns.query; content:"{domain}"; nocase; '
            f'reference:url,{FEEDS_CONFIG["urlhaus"]["ref"]}; '
            f'metadata:status active, severity major, threat_actor CTI_Blocklist, affected_product Any, attack_target DNS; '
            f'sid:{domain_sid}; rev:1;)'
        )
        domain_sid += 1
        
    # Write to file
    with rules_path.open("w", encoding="utf-8", newline="\n") as f:
        f.write("# Generated CTI Blocklist Rules - Do Not Edit Manually\n")
        for rule in rules_generated:
            f.write(rule + "\n")
            
    status["total_ip_rules"] = len(all_ips)
    status["total_domain_rules"] = len(all_domains)
    status["total_rules"] = len(rules_generated)
    
    # Save metadata JSON
    meta_path = downloads_dir / "cti_meta.json"
    with meta_path.open("w", encoding="utf-8") as f:
        json.dump(status, f, indent=2)
        
    # Save a detailed IOC registry JSON for fast API lookups
    ioc_registry = []
    for idx, (ip, (src, actor, tag)) in enumerate(sorted(all_ips.items())):
        ioc_registry.append({
            "type": "IP",
            "value": ip,
            "source": src,
            "threat_actor": actor,
            "malware_tag": tag,
            "sid": IP_SID_START + idx,
            "added_date": existing_dates.get(ip) or status["sync_time"]
        })
    for idx, (domain, (src, actor, tag)) in enumerate(sorted(all_domains.items())):
        ioc_registry.append({
            "type": "Domain",
            "value": domain,
            "source": src,
            "threat_actor": actor,
            "malware_tag": tag,
            "sid": DOMAIN_SID_START + idx,
            "added_date": existing_dates.get(domain) or status["sync_time"]
        })
        
    registry_path = downloads_dir / "cti_iocs.json"
    with registry_path.open("w", encoding="utf-8") as f:
        json.dump(ioc_registry, f, separators=(',', ':'))
        
    logger.info("CTI feeds sync complete. Generated %d rules.", len(rules_generated))
    return status
