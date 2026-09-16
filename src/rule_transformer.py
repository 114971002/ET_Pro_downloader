from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Precompiled regex pattern to match 'sid:<digits>;'
# Uses word boundary \b to avoid matching within identifiers
SID_PATTERN = re.compile(r"(\bsid:\s*\d+\s*;)", re.IGNORECASE)


def transform_rule_line(line: str) -> str:
    """
    Transforms a single Suricata rule line:
    1. Replaces all occurrences of '$HOME_NET' with '$TWNIC_NETS'.
    2. Inserts 'gid: 70; ' right before 'sid:' if 'gid:' is not already present.
    """
    # 1. Replace $HOME_NET with $TWNIC_NETS
    if "$HOME_NET" in line:
        line = line.replace("$HOME_NET", "$TWNIC_NETS")

    # 2. Insert 'gid: 70; ' before 'sid:'
    # Check if 'sid:' exists and 'gid:' is not already present in the rule
    if "sid:" in line and "gid:" not in line:
        line = SID_PATTERN.sub(r"gid: 70; \1", line, count=1)

    return line


def transform_rules_for_transfer(
    source_path: Path,
    output_path: Path,
    custom_logger: Optional[logging.Logger] = None,
) -> Dict[str, Any]:
    """
    Reads rules from source_path, transforms them, and writes to output_path.
    Streams line-by-line to avoid high memory usage on large rule sets.
    """
    log = custom_logger or logger
    source_path = Path(source_path)
    output_path = Path(output_path)

    if not source_path.exists():
        raise FileNotFoundError(f"Source rules file not found: {source_path}")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_output = output_path.with_suffix(".tmp")

    total_lines = 0
    transformed_sid_count = 0
    home_net_replacements = 0

    log.info("Starting rule transformation for transfer from %s -> %s", source_path, output_path)

    with source_path.open("r", encoding="utf-8", errors="replace") as infile, \
         temp_output.open("w", encoding="utf-8", newline="\n") as outfile:

        for line in infile:
            total_lines += 1
            if "$HOME_NET" in line:
                home_net_replacements += line.count("$HOME_NET")
            
            transformed = transform_rule_line(line)
            if "gid: 70;" in transformed and "gid: 70;" not in line:
                transformed_sid_count += 1

            outfile.write(transformed)

    # Atomic rename/replace
    temp_output.replace(output_path)

    log.info(
        "Transfer rules successfully generated at %s: total_lines=%d, gid_added=%d, home_net_replaced=%d",
        output_path,
        total_lines,
        transformed_sid_count,
        home_net_replacements,
    )

    return {
        "output_path": output_path,
        "total_lines": total_lines,
        "gid_added": transformed_sid_count,
        "home_net_replaced": home_net_replacements,
    }
