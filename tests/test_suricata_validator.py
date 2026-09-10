from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from config import AppConfig
from suricata_validator import RuleValidationError, validate_rules_file


class SuricataValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = AppConfig.from_env(
            project_root=Path("C:\\dummy_root"),
            env={
                "ETPRO_OINKCODE": "abcdef123456",
                "ETPRO_SURICATA_VALIDATION_ENABLED": "true",
                "ETPRO_SURICATA_EXE": "C:\\dummy_root\\suricata.exe",
                "ETPRO_SURICATA_YAML": "C:\\dummy_root\\suricata.yaml",
                "ETPRO_NPCAP_DIR": "C:\\dummy_root\\npcap",
            },
        )
        self.rules_path = Path("C:\\dummy_root\\output\\deploy.rules")

    def test_validation_disabled(self) -> None:
        disabled_config = AppConfig.from_env(
            project_root=Path("C:\\dummy_root"),
            env={
                "ETPRO_OINKCODE": "abcdef123456",
                "ETPRO_SURICATA_VALIDATION_ENABLED": "false",
            },
        )
        # Should return immediately without checking path existence
        validate_rules_file(self.rules_path, disabled_config)

    @patch.object(Path, "exists", autospec=True)
    def test_missing_suricata_exe_raises_error(self, mock_exists: MagicMock) -> None:
        # Rules file exists, but exe does not
        def exists_side_effect(path_obj):
            if str(path_obj) == str(self.config.suricata_exe_path):
                return False
            return True
        
        mock_exists.side_effect = exists_side_effect
        
        with self.assertRaises(RuleValidationError) as ctx:
            validate_rules_file(self.rules_path, self.config)
        self.assertIn("executable not found", str(ctx.exception).lower())

    @patch.object(Path, "exists", autospec=True)
    def test_missing_suricata_yaml_raises_error(self, mock_exists: MagicMock) -> None:
        # Rules file and exe exist, but yaml does not
        def exists_side_effect(path_obj):
            if str(path_obj) == str(self.config.suricata_yaml_path):
                return False
            return True
        
        mock_exists.side_effect = exists_side_effect
        
        with self.assertRaises(RuleValidationError) as ctx:
            validate_rules_file(self.rules_path, self.config)
        self.assertIn("config yaml not found", str(ctx.exception).lower())

    @patch.object(Path, "exists")
    @patch("subprocess.run")
    def test_validation_success(self, mock_run: MagicMock, mock_exists: MagicMock) -> None:
        mock_exists.return_value = True
        
        # Mock subprocess run to return success
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="i: suricata: Configuration successfully loaded.",
            stderr="",
        )
        
        validate_rules_file(self.rules_path, self.config)
        
        # Verify it was called with Npcap path in PATH env
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args[1]
        env = call_kwargs.get("env", {})
        self.assertIn("C:\\dummy_root\\npcap", env.get("PATH", ""))

    @patch.object(Path, "exists")
    @patch("subprocess.run")
    def test_validation_failure(self, mock_run: MagicMock, mock_exists: MagicMock) -> None:
        mock_exists.return_value = True
        
        # Mock subprocess run to return failure
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="E: detect-parse: no rule options.",
            stderr="E: detect: error parsing signature from file deploy.rules at line 1",
        )
        
        with self.assertRaises(RuleValidationError) as ctx:
            validate_rules_file(self.rules_path, self.config)
            
        self.assertIn("no rule options", str(ctx.exception))
        self.assertIn("error parsing signature", str(ctx.exception))
        self.assertEqual(ctx.exception.stdout, "E: detect-parse: no rule options.")
        self.assertEqual(ctx.exception.stderr, "E: detect: error parsing signature from file deploy.rules at line 1")

    @patch.object(Path, "exists")
    @patch("subprocess.run")
    def test_validation_timeout(self, mock_run: MagicMock, mock_exists: MagicMock) -> None:
        mock_exists.return_value = True
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=[], timeout=120)
        
        with self.assertRaises(RuleValidationError) as ctx:
            validate_rules_file(self.rules_path, self.config)
            
        self.assertIn("timed out", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
