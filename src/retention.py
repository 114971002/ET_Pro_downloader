from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, Optional

from config import taipei_now


@dataclass(frozen=True)
class CleanupResult:
    deleted_downloads: int
    deleted_reports: int
    deleted_deploy_archives: int = 0
    deleted_transfer_files: int = 0


def cleanup_old_files(
    downloads_dir: Path,
    reports_dir: Path,
    now: Optional[datetime],
    download_retention_days: int,
    report_retention_days: int,
    deploy_archive_dir: Optional[Path] = None,
    deploy_archive_retention_days: int = 30,
    transfer_output_dir: Optional[Path] = None,
    transfer_retention_days: int = 30,
    logger: Optional[logging.Logger] = None,
) -> CleanupResult:
    logger = logger or logging.getLogger(__name__)
    current_date = taipei_now(now).date()
    download_cutoff = current_date - timedelta(days=download_retention_days)
    report_cutoff = current_date - timedelta(days=report_retention_days)

    deleted_downloads = delete_older_than(
        files=downloads_dir.glob("*.tar.gz"),
        cutoff_date=download_cutoff,
        logger=logger,
    )
    deleted_reports = delete_older_than(
        files=reports_dir.glob("*.csv"),
        cutoff_date=report_cutoff,
        logger=logger,
    )

    deleted_deploy_archives = 0
    if deploy_archive_dir is not None and deploy_archive_dir.exists():
        deploy_archive_cutoff = current_date - timedelta(days=deploy_archive_retention_days)
        deleted_deploy_archives = delete_older_than(
            files=deploy_archive_dir.glob("*.rules"),
            cutoff_date=deploy_archive_cutoff,
            logger=logger,
        )

    deleted_transfer_files = 0
    if transfer_output_dir is not None and transfer_output_dir.exists():
        transfer_cutoff = current_date - timedelta(days=transfer_retention_days)
        transfer_files = list(transfer_output_dir.glob("*_transfer.rules")) + list(transfer_output_dir.glob("*_transfer.txt"))
        deleted_transfer_files = delete_older_than(
            files=transfer_files,
            cutoff_date=transfer_cutoff,
            logger=logger,
        )

    return CleanupResult(
        deleted_downloads=deleted_downloads,
        deleted_reports=deleted_reports,
        deleted_deploy_archives=deleted_deploy_archives,
        deleted_transfer_files=deleted_transfer_files,
    )


def delete_older_than(
    files: Iterable[Path],
    cutoff_date,
    logger: logging.Logger,
) -> int:
    deleted_count = 0
    for file_path in files:
        file_date = date_from_filename(file_path.name)
        if file_date is None or file_date >= cutoff_date:
            continue

        try:
            file_path.unlink()
            deleted_count += 1
            logger.info("Deleted expired file: %s", file_path)
        except OSError as exc:
            logger.warning("Failed to delete expired file %s: %s", file_path, exc)

    return deleted_count


def date_from_filename(filename: str):
    match = re.search(r"(\d{8})", filename)
    if match is None:
        return None

    try:
        return datetime.strptime(match.group(1), "%Y%m%d").date()
    except ValueError:
        return None

