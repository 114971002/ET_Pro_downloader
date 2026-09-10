from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
import sys

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from config import AppConfig
from scheduler_entry import run_once
from suricata_validator import RuleValidationError
from unittest.mock import patch, MagicMock


SAMPLE_RULE = (
    'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 '
    '(msg:"Pipeline test rule"; classtype:trojan-activity; sid:3001; rev:1; priority:1;)'
)


class FakeResponse:
    status_code = 200

    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def iter_content(self, chunk_size: int):
        for index in range(0, len(self.payload), chunk_size):
            yield self.payload[index : index + chunk_size]

    def close(self) -> None:
        pass


class FakeSession:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.calls = 0

    def get(self, url, stream, timeout):
        self.calls += 1
        return self.response


def make_tar_payload() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        data = (SAMPLE_RULE + "\n# disabled rule\n").encode("utf-8")
        info = tarfile.TarInfo(name="rules/emerging-test.rules")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


class SchedulerEntryTests(unittest.TestCase):
    def test_run_once_pipeline_without_external_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = AppConfig.from_env(
                project_root=Path(tmp),
                env={
                    "ETPRO_OINKCODE": "abcdef123456",
                    "ETPRO_SURICATA_VALIDATION_ENABLED": "false",
                },
            )
            session = FakeSession(FakeResponse(make_tar_payload()))

            result = run_once(
                config=config,
                now=datetime(2026, 5, 15),
                session=session,
                sleep=lambda _: None,
            )

            self.assertEqual(session.calls, 1)
            self.assertTrue(result.download_path.exists())
            self.assertTrue(result.report_path.exists())
            self.assertTrue(result.deploy_rules_path.exists())
            self.assertEqual(result.deploy_rules_path, Path(tmp) / "deploy" / "deploy.rules")
            self.assertEqual(result.total_rules, 1)
            self.assertEqual(result.deploy_rule_count, 1)
            self.assertTrue(result.deployed)
            self.assertEqual(result.archived_deploy_rules_path, None)
            self.assertEqual(result.deleted_downloads, 0)
            self.assertEqual(result.deleted_reports, 0)
            self.assertEqual(result.deleted_deploy_archives, 0)
            self.assertIn("Pipeline test rule", result.report_path.read_text(encoding="utf-8"))
            self.assertIn("Pipeline test rule", result.deploy_rules_path.read_text(encoding="utf-8"))
            self.assertNotIn("disabled rule", result.deploy_rules_path.read_text(encoding="utf-8"))

    def test_run_once_archives_existing_deploy_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = AppConfig.from_env(
                project_root=root,
                env={
                    "ETPRO_OINKCODE": "abcdef123456",
                    "ETPRO_SURICATA_VALIDATION_ENABLED": "false",
                },
            )
            config.ensure_directories()
            existing_deploy = root / "deploy" / "deploy.rules"
            existing_deploy.write_text("old deploy\n", encoding="utf-8")
            session = FakeSession(FakeResponse(make_tar_payload()))

            result = run_once(
                config=config,
                now=datetime(2026, 5, 15),
                session=session,
                sleep=lambda _: None,
            )

            archived_path = root / "deploy" / "archive" / "20260514_deploy.rules"
            self.assertEqual(result.archived_deploy_rules_path, archived_path)
            self.assertEqual(archived_path.read_text(encoding="utf-8"), "old deploy\n")
            self.assertIn("Pipeline test rule", existing_deploy.read_text(encoding="utf-8"))

    def test_run_once_resolves_archive_conflict_with_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = AppConfig.from_env(
                project_root=root,
                env={
                    "ETPRO_OINKCODE": "abcdef123456",
                    "ETPRO_SURICATA_VALIDATION_ENABLED": "false",
                },
            )
            config.ensure_directories()
            existing_deploy = root / "deploy" / "deploy.rules"
            archive_path = root / "deploy" / "archive" / "20260514_deploy.rules"
            existing_deploy.write_text("old deploy\n", encoding="utf-8")
            archive_path.write_text("already archived\n", encoding="utf-8")
            session = FakeSession(FakeResponse(make_tar_payload()))

            result = run_once(
                config=config,
                now=datetime(2026, 5, 15),
                session=session,
                sleep=lambda _: None,
            )

            expected_archive = root / "deploy" / "archive" / "20260514_1_deploy.rules"
            self.assertEqual(result.archived_deploy_rules_path, expected_archive)
            self.assertEqual(expected_archive.read_text(encoding="utf-8"), "old deploy\n")
            self.assertIn("Pipeline test rule", existing_deploy.read_text(encoding="utf-8"))

    @patch("scheduler_entry.validate_rules_file")
    def test_run_once_validator_success(self, mock_validate: unittest.mock.MagicMock) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = AppConfig.from_env(
                project_root=root,
                env={
                    "ETPRO_OINKCODE": "abcdef123456",
                    "ETPRO_SURICATA_VALIDATION_ENABLED": "true",
                },
            )
            session = FakeSession(FakeResponse(make_tar_payload()))

            result = run_once(
                config=config,
                now=datetime(2026, 5, 15),
                session=session,
                sleep=lambda _: None,
            )

            mock_validate.assert_called_once()
            self.assertTrue(result.deployed)

    @patch("scheduler_entry.validate_rules_file")
    def test_run_once_validator_failure(self, mock_validate: unittest.mock.MagicMock) -> None:
        mock_validate.side_effect = RuleValidationError("Validation simulated failure")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = AppConfig.from_env(
                project_root=root,
                env={
                    "ETPRO_OINKCODE": "abcdef123456",
                    "ETPRO_SURICATA_VALIDATION_ENABLED": "true",
                },
            )
            config.ensure_directories()
            existing_deploy = root / "deploy" / "deploy.rules"
            existing_deploy.write_text("old valid rules\n", encoding="utf-8")
            session = FakeSession(FakeResponse(make_tar_payload()))

            with self.assertRaises(RuleValidationError):
                run_once(
                    config=config,
                    now=datetime(2026, 5, 15),
                    session=session,
                    sleep=lambda _: None,
                )

            mock_validate.assert_called_once()
            # Ensure the old rules are untouched (rollback / abort deploy)
            self.assertEqual(existing_deploy.read_text(encoding="utf-8"), "old valid rules\n")
            # Ensure no archive was created
            archive_files = list(config.deploy_archive_dir.glob("*"))
            self.assertEqual(len(archive_files), 0)

    @patch("scheduler_entry.validate_rules_file")
    def test_run_once_validator_healing(self, mock_validate: unittest.mock.MagicMock) -> None:
        calls = []
        def side_effect(*args, **kwargs):
            calls.append(True)
            if len(calls) == 1:
                # First call fails on line 1 of deploy.rules
                raise RuleValidationError("simulated error", stdout="", stderr="deploy.rules at line 1")
            # Second call succeeds
            return

        mock_validate.side_effect = side_effect
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = AppConfig.from_env(
                project_root=root,
                env={
                    "ETPRO_OINKCODE": "abcdef123456",
                    "ETPRO_SURICATA_VALIDATION_ENABLED": "true",
                },
            )
            session = FakeSession(FakeResponse(make_tar_payload()))

            result = run_once(
                config=config,
                now=datetime(2026, 5, 15),
                session=session,
                sleep=lambda _: None,
            )

            # validate_rules_file should be called twice
            self.assertEqual(len(calls), 2)
            self.assertTrue(result.deployed)

            # Check that the debug log files were created in logs/failed_rules/run_*
            failed_rules_dir = root / "logs" / "failed_rules"
            self.assertTrue(failed_rules_dir.exists())
            run_dirs = list(failed_rules_dir.glob("run_*"))
            self.assertEqual(len(run_dirs), 1)
            run_dir = run_dirs[0]

            self.assertTrue((run_dir / "round1_failed_rules.rules").exists())
            self.assertTrue((run_dir / "round1_suricata_error.log").exists())

            # Read the failed rules debug file
            failed_rules_content = (run_dir / "round1_failed_rules.rules").read_text(encoding="utf-8")
            self.assertIn("Line 1:", failed_rules_content)

            # Check that the deployed rule file actually had the rule on line 1 commented out
            deployed_rules_content = result.deploy_rules_path.read_text(encoding="utf-8")
            self.assertIn("# [VALIDATION FAILED -", deployed_rules_content)

    def test_run_once_cleans_expired_deploy_archives(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = AppConfig.from_env(
                project_root=root,
                env={
                    "ETPRO_OINKCODE": "abcdef123456",
                    "ETPRO_SURICATA_VALIDATION_ENABLED": "false",
                    "ETPRO_DEPLOY_ARCHIVE_RETENTION_DAYS": "30",
                },
            )
            config.ensure_directories()
            
            # Create old and new archives in config.deploy_archive_dir
            old_archive = config.deploy_archive_dir / "20260414_deploy.rules"
            new_archive = config.deploy_archive_dir / "20260514_deploy.rules"
            old_archive.write_text("old archive rules", encoding="utf-8")
            new_archive.write_text("new archive rules", encoding="utf-8")
            
            session = FakeSession(FakeResponse(make_tar_payload()))

            result = run_once(
                config=config,
                now=datetime(2026, 5, 15),
                session=session,
                sleep=lambda _: None,
            )

            self.assertEqual(result.deleted_deploy_archives, 1)
            self.assertFalse(old_archive.exists())
            self.assertTrue(new_archive.exists())

    @patch("scheduler_entry.run_once")
    @patch("scheduler_entry.AppConfig.from_env")
    @patch("update_intel.main")
    def test_main_runs_intel_sync_when_enabled(
        self, mock_sync: unittest.mock.MagicMock, mock_from_env: unittest.mock.MagicMock, mock_run_once: unittest.mock.MagicMock
    ) -> None:
        from scheduler_entry import main as scheduler_main
        
        # Configure mock AppConfig
        mock_config = MagicMock()
        mock_config.intel_sync_enabled = True
        mock_config.project_root = Path("C:\\dummy_root")
        mock_from_env.return_value = mock_config
        
        # Run main
        exit_code = scheduler_main()
        
        self.assertEqual(exit_code, 0)
        mock_sync.assert_called_once_with(config_dir=Path("C:\\dummy_root\\config"))
        mock_run_once.assert_called_once_with(config=mock_config)

    @patch("scheduler_entry.run_once")
    @patch("scheduler_entry.AppConfig.from_env")
    @patch("update_intel.main")
    def test_main_skips_intel_sync_when_disabled(
        self, mock_sync: unittest.mock.MagicMock, mock_from_env: unittest.mock.MagicMock, mock_run_once: unittest.mock.MagicMock
    ) -> None:
        from scheduler_entry import main as scheduler_main
        
        # Configure mock AppConfig
        mock_config = MagicMock()
        mock_config.intel_sync_enabled = False
        mock_config.project_root = Path("C:\\dummy_root")
        mock_from_env.return_value = mock_config
        
        # Run main
        exit_code = scheduler_main()
        
        self.assertEqual(exit_code, 0)
        mock_sync.assert_not_called()
        mock_run_once.assert_called_once_with(config=mock_config)


if __name__ == "__main__":
    unittest.main()
