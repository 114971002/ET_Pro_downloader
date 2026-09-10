from __future__ import annotations

import io
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import re


@dataclass(frozen=True)
class RuleExportResult:
    output_path: Path
    rule_count: int


def export_uncommented_rules(archive_path: Path, output_path: Path) -> RuleExportResult:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rule_count = 0

    with output_path.open("w", encoding="utf-8", newline="\n") as output:
        # 1. Export ET Pro rules
        for rule_line in iter_uncommented_rule_lines(archive_path):
            output.write(rule_line + "\n")
            rule_count += 1

        # 2. Append CTI blocklist rules if they exist
        cti_rules_path = archive_path.parent / "cti_blocklist.rules"
        if cti_rules_path.exists():
            try:
                with cti_rules_path.open("r", encoding="utf-8") as cti_file:
                    for line in cti_file:
                        line_stripped = line.strip()
                        if line_stripped and not line_stripped.startswith("#"):
                            output.write(line_stripped + "\n")
                            rule_count += 1
            except Exception:
                pass

    return RuleExportResult(output_path=output_path, rule_count=rule_count)


def iter_uncommented_rule_lines(archive_path: Path) -> Iterable[str]:
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile() or not member.name.lower().endswith(".rules"):
                continue

            extracted = archive.extractfile(member)
            if extracted is None:
                continue

            text_stream = io.TextIOWrapper(extracted, encoding="utf-8", errors="replace")
            ruleset_name = Path(member.name).name
            for raw_line in text_stream:
                line = raw_line.strip()
                if line and not line.lstrip().startswith("#"):
                    match = re.search(r'metadata:([^;]+);', line)
                    if match:
                        original = match.group(1)
                        new_meta = f"metadata:{original}, source ETPro, ruleset {ruleset_name};"
                        line = line[:match.start()] + new_meta + line[match.end():]
                    else:
                        if line.endswith(')'):
                            new_meta = f" metadata:source ETPro, ruleset {ruleset_name};"
                            line = line[:-1] + new_meta + ")"
                    yield line

