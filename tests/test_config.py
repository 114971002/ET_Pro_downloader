from __future__ import annotations

import tempfile
import unittest
from datetime import datetime
from pathlib import Path
import sys

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from config import AppConfig, ConfigError


class ConfigTests(unittest.TestCase):
    def test_loads_required_env_and_builds_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig.from_env(
                project_root=Path(tmp),
                env={"ETPRO_OINKCODE": "abcdef123456"},
            )
            now = datetime(2026, 5, 15, 0, 0, 0)

            self.assertEqual(config.suricata_version, "8.0")
            self.assertEqual(config.retry_count, 10)
            self.assertEqual(config.max_attempts, 11)
            self.assertFalse(config.force_download)
            self.assertEqual(
                config.download_path(now).name,
                "20260515_etpro.rules.tar.gz",
            )
            self.assertIn("/abcdef123456/suricata-8.0/", config.download_url)
            self.assertNotIn("abcdef123456", config.masked_download_url)
            self.assertEqual(config.deploy_target_path, Path(tmp).resolve() / "deploy" / "deploy.rules")
            self.assertEqual(config.deploy_archive_dir, Path(tmp).resolve() / "deploy" / "archive")
            self.assertEqual(config.staged_deploy_rules_path(), Path(tmp).resolve() / "output" / "deploy.rules")
            self.assertEqual(config.previous_date_stamp(now), "20260514")
            
            # Validation configs default values
            self.assertTrue(config.suricata_validation_enabled)
            self.assertTrue(config.intel_sync_enabled)
            self.assertEqual(config.suricata_exe_path, Path(r"C:\Program Files\Suricata\suricata.exe"))
            self.assertEqual(config.suricata_yaml_path, Path(r"C:\Program Files\Suricata\suricata.yaml"))
            self.assertEqual(config.npcap_dir_path, Path(r"C:\Windows\System32\Npcap"))

    def test_missing_oinkcode_raises_config_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ConfigError):
                AppConfig.from_env(project_root=Path(tmp), env={})

    def test_relative_deploy_target_is_project_relative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig.from_env(
                project_root=Path(tmp),
                env={
                    "ETPRO_OINKCODE": "abcdef123456",
                    "ETPRO_DEPLOY_TARGET_PATH": "deploy\\selected.rules",
                },
            )

            self.assertEqual(
                config.deploy_target_path,
                Path(tmp).resolve() / "deploy" / "selected.rules",
            )

    def test_custom_suricata_validation_configs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig.from_env(
                project_root=Path(tmp),
                env={
                    "ETPRO_OINKCODE": "abcdef123456",
                    "ETPRO_SURICATA_VALIDATION_ENABLED": "false",
                    "ETPRO_SURICATA_EXE": "C:\\custom\\suricata.exe",
                    "ETPRO_SURICATA_YAML": "C:\\custom\\suricata.yaml",
                    "ETPRO_NPCAP_DIR": "C:\\custom\\npcap",
                    "ETPRO_SURICATA_VERSION": "9.9",
                    "ETPRO_FORCE_DOWNLOAD": "true",
                    "ETPRO_INTEL_SYNC_ENABLED": "false",
                },
            )

            self.assertFalse(config.suricata_validation_enabled)
            self.assertFalse(config.intel_sync_enabled)
            self.assertEqual(config.suricata_exe_path, Path("C:\\custom\\suricata.exe"))
            self.assertEqual(config.suricata_yaml_path, Path("C:\\custom\\suricata.yaml"))
            self.assertEqual(config.npcap_dir_path, Path("C:\\custom\\npcap"))
            self.assertEqual(config.suricata_version, "9.9")
            self.assertTrue(config.force_download)

    def test_deploy_archive_and_retention_configs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            # Case 1: Custom absolute path and valid retention days
            config1 = AppConfig.from_env(
                project_root=Path(tmp),
                env={
                    "ETPRO_OINKCODE": "abcdef123456",
                    "ETPRO_DEPLOY_ARCHIVE_PATH": "T:\\etpro_deploy_archive",
                    "ETPRO_DEPLOY_ARCHIVE_RETENTION_DAYS": "45",
                },
            )
            self.assertEqual(config1.deploy_archive_dir, Path("T:\\etpro_deploy_archive"))
            self.assertEqual(config1.deploy_archive_retention_days, 45)

            # Case 2: Custom relative path and invalid retention days (should fallback to 30)
            config2 = AppConfig.from_env(
                project_root=Path(tmp),
                env={
                    "ETPRO_OINKCODE": "abcdef123456",
                    "ETPRO_DEPLOY_ARCHIVE_PATH": "custom_archive",
                    "ETPRO_DEPLOY_ARCHIVE_RETENTION_DAYS": "invalid",
                },
            )
            self.assertEqual(config2.deploy_archive_dir, Path(tmp).resolve() / "custom_archive")
            self.assertEqual(config2.deploy_archive_retention_days, 30)


if __name__ == "__main__":
    unittest.main()
