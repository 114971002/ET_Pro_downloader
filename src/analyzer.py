from __future__ import annotations

import csv
import io
import json
import logging
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional


CSV_FIELDS = [
    "date",
    "sid",
    "rev",
    "msg",
    "classtype",
    "priority",
    "protocol",
    "source",
    "destination",
    "rule_file",
    "metadata",
    "references",
    "threat_actor",
    "candidate_actor",
    "actor_code",
    "actor_evidence",
    "actor_keyword",
    "actor_confidence",
    "raw_rule",
]

RULE_ACTIONS = {"alert", "drop", "reject", "pass"}


@dataclass(frozen=True)
class AnalysisResult:
    report_path: Path
    total_rules: int
    records: List[Dict[str, str]]


logger = logging.getLogger("analyzer")


def analyze_archive(archive_path: Path, report_path: Path, date_stamp: str) -> AnalysisResult:
    actor_mappings, canonical_codes, base_denylist = load_intel_data()
    active_denylist = base_denylist.copy()
    keyword_patterns = get_keyword_patterns(actor_mappings)
    new_malware_families = set()

    # Build protected threat actor aliases set for the poisoning prevention guardrail
    actor_aliases = {alias.lower() for aliases in actor_mappings.values() for alias in aliases}
    actor_aliases.update(name.lower() for name in actor_mappings.keys())

    records = list(iter_rule_records(
        archive_path,
        date_stamp,
        actor_mappings,
        canonical_codes,
        active_denylist,
        keyword_patterns,
        new_malware_families,
        actor_aliases
    ))

    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(records)

    # Persist newly learned malware families
    if new_malware_families:
        config_dir = Path(__file__).resolve().parent.parent / "config"
        dynamic_malware_file = config_dir / "dynamic_malware_list.json"
        existing_dynamic = set()
        if dynamic_malware_file.exists():
            try:
                with dynamic_malware_file.open("r", encoding="utf-8") as f:
                    existing_dynamic.update(json.load(f))
            except Exception:
                pass
        existing_dynamic.update(new_malware_families)
        try:
            config_dir.mkdir(parents=True, exist_ok=True)
            with dynamic_malware_file.open("w", encoding="utf-8") as f:
                json.dump(sorted(list(existing_dynamic)), f, indent=4, ensure_ascii=False)
            logger.info("Persisted %d newly learned malware families to %s", len(new_malware_families), dynamic_malware_file)
        except Exception:
            pass

    return AnalysisResult(
        report_path=report_path,
        total_rules=len(records),
        records=records,
    )


def learn_malware_from_rule(
    raw_rule: str,
    active_denylist: set[str],
    new_malware_families: set[str],
    actor_aliases: Optional[set[str]] = None
) -> None:
    if not hasattr(learn_malware_from_rule, "logged_poison"):
        learn_malware_from_rule.logged_poison = set()
        
    # Look for metadata block(s)
    matches = re.findall(r"\bmetadata\s*:\s*([^;)]+)", raw_rule, re.IGNORECASE)
    for meta_block in matches:
        # Search for malware_family tag
        mw_matches = re.finditer(r"\bmalware_family\s+([^,;]+)", meta_block, re.IGNORECASE)
        for mw_m in mw_matches:
            mw_name = mw_m.group(1).strip()
            if mw_name:
                mw_lower = mw_name.lower()
                # Skip if the malware family is a registered threat actor or alias to prevent denylist poisoning
                if actor_aliases and mw_lower in actor_aliases:
                    if mw_lower not in learn_malware_from_rule.logged_poison:
                        logger.debug("Prevented poisoning of software denylist: '%s' is a registered threat actor/alias", mw_name)
                        learn_malware_from_rule.logged_poison.add(mw_lower)
                    continue
                if mw_lower not in active_denylist:
                    active_denylist.add(mw_lower)
                    new_malware_families.add(mw_lower)


def iter_rule_records(
    archive_path: Path,
    date_stamp: str,
    actor_mappings: Optional[dict[str, list[str]]] = None,
    canonical_codes: Optional[dict[str, str]] = None,
    active_denylist: Optional[set[str]] = None,
    keyword_patterns: Optional[dict[str, list[tuple[str, re.Pattern]]]] = None,
    new_malware_families: Optional[set[str]] = None,
    actor_aliases: Optional[set[str]] = None
) -> Iterable[Dict[str, str]]:
    if actor_mappings is None or canonical_codes is None or active_denylist is None or keyword_patterns is None:
        am, cc, dl = load_intel_data()
        actor_mappings = actor_mappings if actor_mappings is not None else am
        canonical_codes = canonical_codes if canonical_codes is not None else cc
        active_denylist = active_denylist if active_denylist is not None else dl.copy()
        keyword_patterns = keyword_patterns if keyword_patterns is not None else get_keyword_patterns(actor_mappings)
    
    if actor_aliases is None:
        actor_aliases = {alias.lower() for aliases in actor_mappings.values() for alias in aliases}
        actor_aliases.update(name.lower() for name in actor_mappings.keys())
    
    if new_malware_families is None:
        new_malware_families = set()

    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile() or not member.name.lower().endswith(".rules"):
                continue

            extracted = archive.extractfile(member)
            if extracted is None:
                continue

            text_stream = io.TextIOWrapper(extracted, encoding="utf-8", errors="replace")
            for raw_line in text_stream:
                raw_rule = raw_line.strip()
                if not is_enabled_rule(raw_rule):
                    continue
                
                # Dynamically learn malware_family from metadata
                learn_malware_from_rule(raw_rule, active_denylist, new_malware_families, actor_aliases)

                yield parse_rule(
                    raw_rule,
                    member.name,
                    date_stamp,
                    actor_mappings=actor_mappings,
                    canonical_codes=canonical_codes,
                    active_denylist=active_denylist,
                    keyword_patterns=keyword_patterns
                )


def is_enabled_rule(raw_rule: str) -> bool:
    if not raw_rule or raw_rule.startswith("#"):
        return False
    first_word = raw_rule.split(maxsplit=1)[0].lower()
    return first_word in RULE_ACTIONS and "(" in raw_rule and ")" in raw_rule


DEFAULT_ACTOR_MAPPINGS_FILE = Path(__file__).resolve().parent / "default_actor_mappings.json"
try:
    with DEFAULT_ACTOR_MAPPINGS_FILE.open("r", encoding="utf-8") as _f:
        DEFAULT_ACTOR_MAPPINGS = json.load(_f)
except Exception:
    DEFAULT_ACTOR_MAPPINGS = {
        "Lazarus / Hidden Cobra": ["lazarus", "hidden cobra", "andariel", "bluenoroff", "apt38", "apt-38", "hidden-cobra"],
        "APT28 / Fancy Bear": ["fancy bear", "fancybear", "sednit", "sofacy", "apt28", "apt-28"],
        "APT29 / Cozy Bear": ["cozy bear", "cozybear", "nobelium", "apt29", "apt-29"],
        "Winnti / APT41": ["winnti", "apt41", "apt-41", "double dragon", "wicked panda", "barium"],
        "Gamaredon": ["gamaredon", "primitive bear"],
        "Kimsuky": ["kimsuky", "velvet cholima", "black banshee"],
    }


DEFAULT_CANONICAL_ACTOR_CODES = {
    "APT28 / Fancy Bear": "APT28",
    "APT29 / Cozy Bear": "APT29",
    "Winnti / APT41": "APT41",
    "APT34 / OilRig": "APT34",
    "Carbanak / Anunak": "FIN7",
    "APT35 / Charming Kitten": "APT35",
    "Sandworm": "APT44",
    "Transparent Tribe / APT36": "APT36",
    "APT33": "APT33",
    "APT32 / OceanLotus": "APT32",
    "LuckyMouse": "APT27",
    "APT1 / CommentCrew": "APT1",
}

DEFAULT_SOFTWARE_DENYLIST = {
    "gravityrat",
    "bisonal",
    "babyshark",
    "quasar",
    "cobalt strike",
    "cobaltstrike",
    "royalapt",
    "royal apt",
}


def load_intel_data() -> tuple[dict[str, list[str]], dict[str, str], set[str]]:
    config_dir = Path(__file__).resolve().parent.parent / "config"
    actor_mappings_file = config_dir / "actor_mappings.json"
    software_denylist_file = config_dir / "software_denylist.json"
    dynamic_malware_file = config_dir / "dynamic_malware_list.json"

    actor_mappings = DEFAULT_ACTOR_MAPPINGS
    if actor_mappings_file.exists():
        try:
            with actor_mappings_file.open("r", encoding="utf-8") as f:
                actor_mappings = json.load(f)
        except Exception:
            pass

    canonical_codes = {}
    for group_name in actor_mappings:
        if group_name in DEFAULT_CANONICAL_ACTOR_CODES:
            canonical_codes[group_name] = DEFAULT_CANONICAL_ACTOR_CODES[group_name]
        else:
            aliases = actor_mappings[group_name]
            for alias in aliases:
                norm = alias.upper().replace(" ", "").replace("-", "")
                if RE_APT.match(norm) or RE_TA.match(norm) or RE_UNC.match(norm) or RE_FIN.match(norm):
                    canonical_codes[group_name] = norm
                    break

    software_denylist = set(DEFAULT_SOFTWARE_DENYLIST)
    if software_denylist_file.exists():
        try:
            with software_denylist_file.open("r", encoding="utf-8") as f:
                loaded_denylist = json.load(f)
                software_denylist.update(x.lower() for x in loaded_denylist)
        except Exception:
            pass

    # Build actor aliases set to identify poisoned items
    actor_aliases = {alias.lower() for aliases in actor_mappings.values() for alias in aliases}
    actor_aliases.update(name.lower() for name in actor_mappings.keys())

    dynamic_list_cleaned = []
    if dynamic_malware_file.exists():
        try:
            with dynamic_malware_file.open("r", encoding="utf-8") as f:
                dynamic_list = json.load(f)
            
            needs_write_back = False
            for item in dynamic_list:
                item_lower = item.lower()
                if item_lower in actor_aliases:
                    needs_write_back = True
                    logger.warning("Cleaning up poisoned item '%s' from dynamic malware list (it is a threat actor/alias)", item)
                else:
                    dynamic_list_cleaned.append(item)
            
            if needs_write_back:
                try:
                    with dynamic_malware_file.open("w", encoding="utf-8") as f:
                        json.dump(sorted(dynamic_list_cleaned), f, indent=4, ensure_ascii=False)
                except Exception as we:
                    logger.warning("Could not write back cleaned dynamic malware list: %s", we)
        except Exception:
            pass

    software_denylist.update(x.lower() for x in dynamic_list_cleaned)

    return actor_mappings, canonical_codes, software_denylist


def get_keyword_patterns(actor_mappings: dict[str, list[str]]) -> dict[str, list[tuple[str, re.Pattern]]]:
    return {
        group: [(kw, re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE)) for kw in keywords]
        for group, keywords in actor_mappings.items()
    }


def is_denylisted(val: str, software_denylist: set[str]) -> bool:
    val_lower = val.lower()
    for item in software_denylist:
        if item in val_lower:
            start_idx = val_lower.find(item)
            while start_idx != -1:
                end_idx = start_idx + len(item)
                # Check left boundary: must not be preceded by alphanumeric/underscore
                left_ok = True
                if start_idx > 0:
                    left_char = val_lower[start_idx - 1]
                    if left_char.isalnum() or left_char == '_':
                        left_ok = False
                # Check right boundary: must not be followed by alphanumeric/underscore
                right_ok = True
                if end_idx < len(val_lower):
                    right_char = val_lower[end_idx]
                    if right_char.isalnum() or right_char == '_':
                        right_ok = False
                if left_ok and right_ok:
                    return True
                start_idx = val_lower.find(item, start_idx + 1)
    return False


def is_context_qualified(source_text: str, start: int, end: int, keyword: str, raw_rule: str) -> bool:
    kw_lower = keyword.lower()
    if kw_lower not in {"reaper", "inception", "hades", "platinum"}:
        return True

    if kw_lower == "reaper":
        raw_rule_lower = raw_rule.lower()
        if "scarcruft" in raw_rule_lower or "apt-37" in raw_rule_lower or "apt37" in raw_rule_lower:
            return True

    window_back = source_text[max(0, start - 20) : start].lower()
    window_ahead = source_text[end : min(len(source_text), end + 20)].lower()

    security_kws = ["group", "actor", "apt", "campaign", "threat"]
    if any(sec_kw in window_back for sec_kw in security_kws):
        return True
    if any(sec_kw in window_ahead for sec_kw in security_kws):
        return True

    return False


RE_APT = re.compile(r"\bapt\s*\d+\b|\bapt-\d+\b|\bapt-c-\d+\b", re.IGNORECASE)
RE_TA = re.compile(r"\bta\d{3,}\b", re.IGNORECASE)
RE_TA_MITRE = re.compile(r"^ta00\d{2}$", re.IGNORECASE)
RE_UNC = re.compile(r"\bunc\d+\b", re.IGNORECASE)
RE_FIN = re.compile(r"\bfin\d+\b", re.IGNORECASE)


def normalize_code(code_str: str) -> str:
    c = code_str.upper().replace(" ", "")
    if c.startswith("APT-C-"):
        return c
    else:
        return c.replace("-", "")


def get_actor_for_code_or_keyword(val: str, actor_mappings: dict[str, list[str]]) -> str:
    val_lower = val.lower()
    for actor_name, aliases in actor_mappings.items():
        if val_lower in aliases:
            return actor_name
    return ""


def get_remaining_rule_text(raw_rule: str) -> str:
    # Strip msg
    text = re.sub(r'\bmsg\s*:\s*"[^"\\]*(?:\\.[^"\\]*)*"\s*;?', '', raw_rule, flags=re.IGNORECASE)
    # Strip metadata
    text = re.sub(r'\bmetadata\s*:[^;)]+;?', '', text, flags=re.IGNORECASE)
    # Strip reference(s)
    text = re.sub(r'\breference\s*:[^;)]+;?', '', text, flags=re.IGNORECASE)
    return text


def extract_actor_data(
    raw_rule: str,
    actor_mappings: Optional[dict[str, list[str]]] = None,
    canonical_codes: Optional[dict[str, str]] = None,
    active_denylist: Optional[set[str]] = None,
    keyword_patterns: Optional[dict[str, list[tuple[str, re.Pattern]]]] = None
) -> Dict[str, str]:
    if actor_mappings is None or canonical_codes is None or active_denylist is None or keyword_patterns is None:
        am, cc, dl = load_intel_data()
        actor_mappings = actor_mappings if actor_mappings is not None else am
        canonical_codes = canonical_codes if canonical_codes is not None else cc
        active_denylist = active_denylist if active_denylist is not None else dl
        keyword_patterns = keyword_patterns if keyword_patterns is not None else get_keyword_patterns(actor_mappings)

    header, _, options_text = raw_rule.partition("(")
    options = options_text.rsplit(")", 1)[0] if ")" in options_text else options_text
    
    msg_text = find_quoted_option(options, "msg")
    
    metadata_parts = re.findall(r"(?:^|;)\s*metadata\s*:\s*([^;]+)", options)
    metadata_text = " ".join(metadata_parts)
    
    reference_parts = re.findall(r"(?:^|;)\s*reference\s*:\s*([^;]+)", options)
    references_text = " ".join(reference_parts)
    
    remaining_text = get_remaining_rule_text(raw_rule)
    
    sources = {
        "msg": msg_text,
        "metadata": metadata_text,
        "references": references_text,
        "raw_rule": remaining_text,
    }
    
    actor_matches = {}
    
    def add_match(actor_name: str, code: Optional[str], keyword: str, source: str):
        if is_denylisted(actor_name, active_denylist) or (code and is_denylisted(code, active_denylist)) or is_denylisted(keyword, active_denylist):
            return
        if actor_name not in actor_matches:
            actor_matches[actor_name] = {
                "codes": set(),
                "keywords": set(),
                "sources": set()
            }
        if code:
            actor_matches[actor_name]["codes"].add(code)
        if keyword:
            actor_matches[actor_name]["keywords"].add(keyword)
        actor_matches[actor_name]["sources"].add(source)

    for source_name, source_text in sources.items():
        if not source_text:
            continue
        
        # APT codes
        for m in RE_APT.finditer(source_text):
            val = m.group(0)
            norm_code = normalize_code(val)
            mapped_actor = get_actor_for_code_or_keyword(val, actor_mappings) or get_actor_for_code_or_keyword(norm_code, actor_mappings)
            if mapped_actor:
                add_match(mapped_actor, norm_code, val, source_name)
            else:
                add_match(norm_code, norm_code, val, source_name)
                
        # TA codes
        for m in RE_TA.finditer(source_text):
            val = m.group(0)
            if RE_TA_MITRE.match(val):
                continue
            
            # CISA advisory filter
            start, end = m.span()
            is_cisa = False
            for cisa_m in re.finditer(r"\bta\d{2}-\d{3}[a-zA-Z]?\b", source_text, re.IGNORECASE):
                c_start, c_end = cisa_m.span()
                if not (end <= c_start or start >= c_end):
                    is_cisa = True
                    break
            if is_cisa:
                continue

            norm_code = normalize_code(val)
            mapped_actor = get_actor_for_code_or_keyword(val, actor_mappings) or get_actor_for_code_or_keyword(norm_code, actor_mappings)
            if mapped_actor:
                add_match(mapped_actor, norm_code, val, source_name)
            else:
                add_match(norm_code, norm_code, val, source_name)
                
        # UNC codes
        for m in RE_UNC.finditer(source_text):
            val = m.group(0)
            norm_code = normalize_code(val)
            mapped_actor = get_actor_for_code_or_keyword(val, actor_mappings) or get_actor_for_code_or_keyword(norm_code, actor_mappings)
            if mapped_actor:
                add_match(mapped_actor, norm_code, val, source_name)
            else:
                add_match(norm_code, norm_code, val, source_name)
                
        # FIN codes
        for m in RE_FIN.finditer(source_text):
            val = m.group(0)
            norm_code = normalize_code(val)
            mapped_actor = get_actor_for_code_or_keyword(val, actor_mappings) or get_actor_for_code_or_keyword(norm_code, actor_mappings)
            if mapped_actor:
                add_match(mapped_actor, norm_code, val, source_name)
            else:
                add_match(norm_code, norm_code, val, source_name)

    lower_sources = {k: v.lower() for k, v in sources.items() if v}
    
    for source_name, lower_text in lower_sources.items():
        source_text = sources[source_name]
        for actor_name, patterns in keyword_patterns.items():
            for kw, pattern in patterns:
                if kw.lower() not in lower_text:
                    continue
                for match in pattern.finditer(source_text):
                    val = match.group(0)
                    start, end = match.span()
                    if not is_context_qualified(source_text, start, end, val, raw_rule):
                        continue
                    canon_code = canonical_codes.get(actor_name)
                    add_match(actor_name, canon_code, val, source_name)

    sorted_actors = sorted(actor_matches.keys())
    
    threat_actor_list = []
    actor_code_list = []
    actor_evidence_list = []
    actor_keyword_list = []
    actor_confidence_list = []
    
    candidate_actor_list = []
    
    for actor in sorted_actors:
        data = actor_matches[actor]
        
        if "msg" in data["sources"] or "metadata" in data["sources"]:
            confidence = "high"
        elif "raw_rule" in data["sources"]:
            confidence = "medium"
        else:
            confidence = "low"
            
        if confidence in ("high", "medium"):
            codes = sorted(list(data["codes"]))
            code_str = ",".join(codes) if codes else "-"
            
            srcs = sorted(list(data["sources"]))
            evidence_str = ",".join(srcs) if srcs else "-"
            
            # Deduplicate keywords case-insensitively
            seen_kws = set()
            kws_unique = []
            for k in sorted(list(data["keywords"])):
                k_low = k.lower()
                if k_low not in seen_kws:
                    seen_kws.add(k_low)
                    kws_unique.append(k)
            keyword_str = ",".join(kws_unique) if kws_unique else "-"
            
            threat_actor_list.append(actor)
            actor_code_list.append(code_str)
            actor_evidence_list.append(evidence_str)
            actor_keyword_list.append(keyword_str)
            actor_confidence_list.append(confidence)
        else:
            candidate_actor_list.append(actor)

    res = {}
    if threat_actor_list:
        res["threat_actor"] = "; ".join(threat_actor_list)
        res["actor_code"] = "; ".join(actor_code_list)
        res["actor_evidence"] = "; ".join(actor_evidence_list)
        res["actor_keyword"] = "; ".join(actor_keyword_list)
        res["actor_confidence"] = "; ".join(actor_confidence_list)
    else:
        res["threat_actor"] = "unknown"
        res["actor_code"] = "-"
        res["actor_evidence"] = "-"
        res["actor_keyword"] = "-"
        res["actor_confidence"] = "-"
        
    if candidate_actor_list:
        res["candidate_actor"] = "; ".join(candidate_actor_list)
    else:
        res["candidate_actor"] = "unknown"
        
    return res


def parse_rule(
    raw_rule: str,
    rule_file: str,
    date_stamp: str,
    actor_mappings: Optional[dict[str, list[str]]] = None,
    canonical_codes: Optional[dict[str, str]] = None,
    active_denylist: Optional[set[str]] = None,
    keyword_patterns: Optional[dict[str, list[tuple[str, re.Pattern]]]] = None
) -> Dict[str, str]:
    if actor_mappings is None or canonical_codes is None or active_denylist is None or keyword_patterns is None:
        am, cc, dl = load_intel_data()
        actor_mappings = actor_mappings if actor_mappings is not None else am
        canonical_codes = canonical_codes if canonical_codes is not None else cc
        active_denylist = active_denylist if active_denylist is not None else dl
        keyword_patterns = keyword_patterns if keyword_patterns is not None else get_keyword_patterns(actor_mappings)

    header, _, options_text = raw_rule.partition("(")
    header_parts = header.split()

    protocol = header_parts[1] if len(header_parts) > 1 else ""
    source = " ".join(header_parts[2:4]) if len(header_parts) > 3 else ""
    destination = " ".join(header_parts[5:7]) if len(header_parts) > 6 else ""
    options = options_text.rsplit(")", 1)[0] if ")" in options_text else options_text

    actor_data = extract_actor_data(
        raw_rule,
        actor_mappings=actor_mappings,
        canonical_codes=canonical_codes,
        active_denylist=active_denylist,
        keyword_patterns=keyword_patterns
    )

    return {
        "date": date_stamp,
        "sid": find_option(options, "sid"),
        "rev": find_option(options, "rev"),
        "msg": find_quoted_option(options, "msg"),
        "classtype": find_option(options, "classtype"),
        "priority": find_option(options, "priority"),
        "protocol": protocol,
        "source": source,
        "destination": destination,
        "rule_file": rule_file,
        "metadata": find_metadata_json(options),
        "references": find_references_json(options),
        "threat_actor": actor_data["threat_actor"],
        "candidate_actor": actor_data["candidate_actor"],
        "actor_code": actor_data["actor_code"],
        "actor_evidence": actor_data["actor_evidence"],
        "actor_keyword": actor_data["actor_keyword"],
        "actor_confidence": actor_data["actor_confidence"],
        "raw_rule": raw_rule,
    }


def find_option(options: str, name: str) -> str:
    match = re.search(rf"(?:^|;)\s*{re.escape(name)}\s*:\s*([^;]+)", options)
    return match.group(1).strip() if match else ""


def find_quoted_option(options: str, name: str) -> str:
    match = re.search(rf'(?:^|;)\s*{re.escape(name)}\s*:\s*"((?:\\.|[^"\\])*)"', options)
    if not match:
        return find_option(options, name)
    return unescape_suricata_string(match.group(1))


def unescape_suricata_string(value: str) -> str:
    return value.replace(r"\"", '"').replace(r"\\", "\\")


def find_metadata_json(options: str) -> str:
    matches = re.findall(r"(?:^|;)\s*metadata\s*:\s*([^;]+)", options)
    metadata_dict = {}
    for match in matches:
        pairs = match.split(",")
        for pair in pairs:
            pair = pair.strip()
            if not pair:
                continue
            parts = pair.split(maxsplit=1)
            if len(parts) == 2:
                key, val = parts
                metadata_dict[key.strip()] = val.strip()
            elif len(parts) == 1:
                metadata_dict[parts[0].strip()] = ""
    return json.dumps(metadata_dict) if metadata_dict else "{}"


def find_references_json(options: str) -> str:
    matches = re.findall(r"(?:^|;)\s*reference\s*:\s*([^,;]+)\s*,\s*([^;]+)", options)
    ref_list = [{"type": t.strip(), "value": v.strip()} for t, v in matches]
    return json.dumps(ref_list) if ref_list else "[]"

