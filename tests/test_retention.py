from __future__ import annotations

import logging
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
import sys

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from retention import cleanup_old_files


LOGGER = logging.getLogger("test_retention")
LOGGER.addHandler(logging.NullHandler())
LOGGER.propagate = False


class RetentionTests(unittest.TestCase):
    def test_cleanup_keeps_only_configured_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            downloads = root / "downloads"
            reports = root / "reports"
            downloads.mkdir()
            reports.mkdir()

            old_download = downloads / "20260414_etpro.rules.tar.gz"
            kept_download = downloads / "20260415_etpro.rules.tar.gz"
            old_report = reports / "daily_analysis_20260213.csv"
            kept_report = reports / "daily_analysis_20260214.csv"
            for path in (old_download, kept_download, old_report, kept_report):
                path.write_text("x", encoding="utf-8")

            result = cleanup_old_files(
                downloads_dir=downloads,
                reports_dir=reports,
                now=datetime(2026, 5, 15),
                download_retention_days=30,
                report_retention_days=90,
                logger=LOGGER,
            )

            self.assertEqual(result.deleted_downloads, 1)
            self.assertEqual(result.deleted_reports, 1)
            self.assertFalse(old_download.exists())
            self.assertTrue(kept_download.exists())
            self.assertFalse(old_report.exists())
            self.assertTrue(kept_report.exists())

    def test_cleanup_deploy_archives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            downloads = root / "downloads"
            reports = root / "reports"
            archive = root / "deploy_archive"
            downloads.mkdir()
            reports.mkdir()
            archive.mkdir()

            old_archive = archive / "20260414_deploy.rules"
            kept_archive = archive / "20260415_deploy.rules"
            random_file = archive / "some_random_file.txt"
            
            for path in (old_archive, kept_archive, random_file):
                path.write_text("rules data", encoding="utf-8")

            result = cleanup_old_files(
                downloads_dir=downloads,
                reports_dir=reports,
                now=datetime(2026, 5, 15),
                download_retention_days=30,
                report_retention_days=90,
                deploy_archive_dir=archive,
                deploy_archive_retention_days=30,
                logger=LOGGER,
            )

            self.assertEqual(result.deleted_deploy_archives, 1)
            self.assertFalse(old_archive.exists())
            self.assertTrue(kept_archive.exists())
            self.assertTrue(random_file.exists())


if __name__ == "__main__":
    unittest.main()
