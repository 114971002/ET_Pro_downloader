from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set


@dataclass(frozen=True)
class FilterCriteria:
    classtypes: Set[str] = field(default_factory=set)
    priorities: Set[str] = field(default_factory=set)
    sids: Set[str] = field(default_factory=set)
    message_keywords: Sequence[str] = field(default_factory=tuple)

    @property
    def is_empty(self) -> bool:
        return not (
            self.classtypes
            or self.priorities
            or self.sids
            or self.message_keywords
        )


@dataclass(frozen=True)
class FilterResult:
    selected_records: List[Dict[str, str]]
    reason: str


def select_rules(
    records: Iterable[Dict[str, str]],
    criteria: Optional[FilterCriteria] = None,
) -> FilterResult:
    criteria = criteria or FilterCriteria()
    if criteria.is_empty:
        return FilterResult(
            selected_records=[],
            reason="No filter criteria configured yet.",
        )

    selected: List[Dict[str, str]] = []
    for record in records:
        if matches_criteria(record, criteria):
            selected.append(record)

    return FilterResult(
        selected_records=selected,
        reason="Rules selected by configured criteria.",
    )


def matches_criteria(record: Dict[str, str], criteria: FilterCriteria) -> bool:
    if criteria.classtypes and record.get("classtype", "") not in criteria.classtypes:
        return False
    if criteria.priorities and record.get("priority", "") not in criteria.priorities:
        return False
    if criteria.sids and record.get("sid", "") not in criteria.sids:
        return False
    if criteria.message_keywords:
        message = record.get("msg", "").lower()
        if not any(keyword.lower() in message for keyword in criteria.message_keywords):
            return False
    return True


def write_selected_rules_file(
    result: FilterResult,
    output_path: Path,
    date_stamp: str,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as output:
        output.write(f"# Generated date: {date_stamp}\n")
        output.write(f"# {result.reason}\n")
        output.write(f"# Selected rules: {len(result.selected_records)}\n")
        for record in result.selected_records:
            raw_rule = record.get("raw_rule", "").strip()
            if raw_rule:
                output.write(raw_rule + "\n")
    return output_path

