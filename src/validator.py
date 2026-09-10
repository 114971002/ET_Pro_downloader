from __future__ import annotations

import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import List


class ValidationError(RuntimeError):
    """Raised when a downloaded archive is not usable."""


@dataclass(frozen=True)
class ValidationResult:
    path: Path
    is_valid: bool
    rule_files: List[str]
    errors: List[str]


def validate_archive(path: Path) -> ValidationResult:
    errors: List[str] = []
    rule_files: List[str] = []

    if not path.exists():
        errors.append("Downloaded file does not exist.")
        return ValidationResult(path=path, is_valid=False, rule_files=rule_files, errors=errors)

    if not path.is_file():
        errors.append("Downloaded path is not a file.")
        return ValidationResult(path=path, is_valid=False, rule_files=rule_files, errors=errors)

    if path.stat().st_size <= 0:
        errors.append("Downloaded file is empty.")
        return ValidationResult(path=path, is_valid=False, rule_files=rule_files, errors=errors)

    try:
        with tarfile.open(path, mode="r:gz") as archive:
            for member in archive.getmembers():
                if member.isfile() and member.name.lower().endswith(".rules"):
                    rule_files.append(member.name)
    except (tarfile.TarError, OSError) as exc:
        errors.append(f"Archive cannot be opened as .tar.gz: {exc}")

    if not rule_files:
        errors.append("Archive does not contain any .rules files.")

    return ValidationResult(
        path=path,
        is_valid=not errors,
        rule_files=rule_files,
        errors=errors,
    )


def raise_if_invalid(result: ValidationResult) -> None:
    if not result.is_valid:
        raise ValidationError("; ".join(result.errors))

