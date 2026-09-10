from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import sys

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from deployer import DeploymentError, deploy_rules_file
from filter_engine import FilterCriteria, select_rules, write_selected_rules_file


class FilterDeployerTests(unittest.TestCase):
    def test_empty_filter_selects_nothing(self) -> None:
        records = [
            {"sid": "1", "raw_rule": "alert tcp any any -> any any (sid:1;)"},
        ]

        result = select_rules(records)

        self.assertEqual(result.selected_records, [])
        self.assertIn("No filter criteria", result.reason)

    def test_filter_by_sid_and_write_rules_file(self) -> None:
        records = [
            {"sid": "1", "raw_rule": "alert tcp any any -> any any (sid:1;)"},
            {"sid": "2", "raw_rule": "alert tcp any any -> any any (sid:2;)"},
        ]

        result = select_rules(records, FilterCriteria(sids={"2"}))

        with tempfile.TemporaryDirectory() as tmp:
            output_path = Path(tmp) / "selected.rules"
            write_selected_rules_file(result, output_path, "20260515")

            text = output_path.read_text(encoding="utf-8")
            self.assertIn("Selected rules: 1", text)
            self.assertIn("sid:2", text)
            self.assertNotIn("sid:1", text)

    def test_deploy_skips_without_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "selected.rules"
            source.write_text("# empty\n", encoding="utf-8")

            result = deploy_rules_file(source, None)

            self.assertFalse(result.deployed)
            self.assertIsNone(result.target_path)

    def test_deploy_moves_file_to_target_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "selected.rules"
            target_dir = Path(tmp) / "deploy"
            target_dir.mkdir()
            source.write_text("alert tcp any any -> any any (sid:1;)\n", encoding="utf-8")

            result = deploy_rules_file(source, target_dir)

            self.assertTrue(result.deployed)
            self.assertEqual((target_dir / "selected.rules").read_text(encoding="utf-8"), "alert tcp any any -> any any (sid:1;)\n")
            self.assertFalse(source.exists())

    def test_deploy_archives_existing_target_before_move(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "selected.rules"
            target = Path(tmp) / "deployed.rules"
            archive_dir = Path(tmp) / "archive"
            source.write_text("new\n", encoding="utf-8")
            target.write_text("existing\n", encoding="utf-8")

            result = deploy_rules_file(
                source,
                target,
                archive_dir=archive_dir,
                archive_date_stamp="20260514",
            )

            self.assertTrue(result.deployed)
            self.assertEqual(target.read_text(encoding="utf-8"), "new\n")
            self.assertEqual((archive_dir / "20260514_deployed.rules").read_text(encoding="utf-8"), "existing\n")
            self.assertFalse(source.exists())

    def test_deploy_resolves_archive_name_collision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "selected.rules"
            target = Path(tmp) / "deployed.rules"
            archive_dir = Path(tmp) / "archive"
            archive_dir.mkdir()
            source.write_text("new\n", encoding="utf-8")
            target.write_text("existing\n", encoding="utf-8")
            (archive_dir / "20260514_deployed.rules").write_text("already archived 1\n", encoding="utf-8")

            result = deploy_rules_file(
                source,
                target,
                archive_dir=archive_dir,
                archive_date_stamp="20260514",
            )

            self.assertTrue(result.deployed)
            self.assertEqual(target.read_text(encoding="utf-8"), "new\n")
            self.assertEqual((archive_dir / "20260514_deployed.rules").read_text(encoding="utf-8"), "already archived 1\n")
            self.assertEqual((archive_dir / "20260514_1_deployed.rules").read_text(encoding="utf-8"), "existing\n")
            self.assertFalse(source.exists())


if __name__ == "__main__":
    unittest.main()
