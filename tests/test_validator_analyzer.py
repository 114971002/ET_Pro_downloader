from __future__ import annotations

import csv
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
import sys

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from analyzer import analyze_archive
from rule_exporter import export_uncommented_rules
from validator import validate_archive


SAMPLE_RULE = (
    'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 '
    '(msg:"Test ET Pro rule"; classtype:trojan-activity; sid:1001; rev:2; priority:1;)'
)


def make_tar_gz(path: Path, files) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in files.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


class ValidatorAnalyzerTests(unittest.TestCase):
    def test_validate_archive_accepts_tar_with_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "rules.tar.gz"
            make_tar_gz(archive_path, {"rules/emerging.rules": SAMPLE_RULE})

            result = validate_archive(archive_path)

            self.assertTrue(result.is_valid)
            self.assertEqual(result.rule_files, ["rules/emerging.rules"])

    def test_validate_archive_rejects_tar_without_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "rules.tar.gz"
            make_tar_gz(archive_path, {"README.txt": "hello"})

            result = validate_archive(archive_path)

            self.assertFalse(result.is_valid)
            self.assertIn("Archive does not contain any .rules files.", result.errors)

    def test_analyze_archive_writes_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "rules.tar.gz"
            report_path = Path(tmp) / "report.csv"
            make_tar_gz(
                archive_path,
                {
                    "rules/emerging.rules": SAMPLE_RULE + "\n# disabled comment\n",
                },
            )

            result = analyze_archive(archive_path, report_path, "20260515")

            self.assertEqual(result.total_rules, 1)
            with report_path.open("r", encoding="utf-8", newline="") as input_file:
                rows = list(csv.DictReader(input_file))

            self.assertEqual(rows[0]["date"], "20260515")
            self.assertEqual(rows[0]["sid"], "1001")
            self.assertEqual(rows[0]["rev"], "2")
            self.assertEqual(rows[0]["msg"], "Test ET Pro rule")
            self.assertEqual(rows[0]["classtype"], "trojan-activity")
            self.assertEqual(rows[0]["priority"], "1")
            self.assertEqual(rows[0]["protocol"], "tcp")
            self.assertEqual(rows[0]["metadata"], "{}")
            self.assertEqual(rows[0]["references"], "[]")
            self.assertEqual(rows[0]["threat_actor"], "unknown")
            self.assertEqual(rows[0]["candidate_actor"], "unknown")
            self.assertEqual(rows[0]["actor_code"], "-")
            self.assertEqual(rows[0]["actor_evidence"], "-")
            self.assertEqual(rows[0]["actor_keyword"], "-")
            self.assertEqual(rows[0]["actor_confidence"], "-")

    def test_analyze_archive_metadata_and_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "rules.tar.gz"
            report_path = Path(tmp) / "report.csv"
            rule_with_meta = (
                'alert tcp any any -> any any '
                '(msg:"Metadata and Reference test rule"; '
                'metadata:affected_product IIS, attack_target Web_Server, created_at 2026_05_22; '
                'reference:cve,2026-9999; reference:url,example.com/exploit; '
                'sid:1003; rev:1;)'
            )
            make_tar_gz(
                archive_path,
                {
                    "rules/emerging.rules": rule_with_meta,
                },
            )

            result = analyze_archive(archive_path, report_path, "20260522")

            self.assertEqual(result.total_rules, 1)
            with report_path.open("r", encoding="utf-8", newline="") as input_file:
                rows = list(csv.DictReader(input_file))

            self.assertEqual(rows[0]["sid"], "1003")
            
            # Check metadata parsing
            meta = json.loads(rows[0]["metadata"])
            self.assertEqual(meta.get("affected_product"), "IIS")
            self.assertEqual(meta.get("attack_target"), "Web_Server")
            self.assertEqual(meta.get("created_at"), "2026_05_22")

            # Check references parsing
            refs = json.loads(rows[0]["references"])
            self.assertEqual(len(refs), 2)
            self.assertEqual(refs[0]["type"], "cve")
            self.assertEqual(refs[0]["value"], "2026-9999")
            self.assertEqual(refs[1]["type"], "url")
            self.assertEqual(refs[1]["value"], "example.com/exploit")

    def test_analyze_archive_threat_actor_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "rules.tar.gz"
            report_path = Path(tmp) / "report.csv"
            
            # Rule 1: No threat actor (has general Proofpoint metadata tag)
            rule_no_actor = (
                'alert tcp any any -> any any '
                '(msg:"Generic Rule"; '
                'metadata:tag Description_Generated_By_Proofpoint_Nexus; '
                'sid:2001; rev:1;)'
            )
            # Rule 2: Single threat actor via tag/metadata and malware_family
            rule_single_actor = (
                'alert tcp any any -> any any '
                '(msg:"TA399 ClickFix payload"; '
                'metadata:malware_family TinyTick, tag TA399; '
                'sid:2002; rev:1;)'
            )
            # Rule 3: Multiple threat actors
            rule_multi_actor = (
                'alert tcp any any -> any any '
                '(msg:"Lazarus activity targeting SideWinder"; '
                'metadata:tag Sidewinder; '
                'sid:2003; rev:1;)'
            )
            # Rule 4: MITRE Tactic ID only (should be ignored)
            rule_mitre_only = (
                'alert tcp any any -> any any '
                '(msg:"Rule with MITRE ID"; '
                'metadata:mitre_tactic_id TA0011; '
                'sid:2004; rev:1;)'
            )
            
            make_tar_gz(
                archive_path,
                {
                    "rules/test.rules": "\n".join([rule_no_actor, rule_single_actor, rule_multi_actor, rule_mitre_only]),
                },
            )

            result = analyze_archive(archive_path, report_path, "20260522")
            self.assertEqual(result.total_rules, 4)

            with report_path.open("r", encoding="utf-8", newline="") as input_file:
                rows = list(csv.DictReader(input_file))

            # Row 0: No threat actor
            self.assertEqual(rows[0]["sid"], "2001")
            self.assertEqual(rows[0]["threat_actor"], "unknown")
            self.assertEqual(rows[0]["candidate_actor"], "unknown")
            self.assertEqual(rows[0]["actor_code"], "-")
            self.assertEqual(rows[0]["actor_evidence"], "-")
            self.assertEqual(rows[0]["actor_keyword"], "-")
            self.assertEqual(rows[0]["actor_confidence"], "-")

            # Row 1: Single threat actor (TA399 is mapped specifically, not collapsed to TA groups)
            self.assertEqual(rows[1]["sid"], "2002")
            self.assertEqual(rows[1]["threat_actor"], "TA399")
            self.assertEqual(rows[1]["candidate_actor"], "unknown")
            self.assertEqual(rows[1]["actor_code"], "TA399")
            self.assertEqual(rows[1]["actor_evidence"], "metadata,msg")
            self.assertEqual(rows[1]["actor_keyword"], "TA399")
            self.assertEqual(rows[1]["actor_confidence"], "high")

            # Row 2: Multiple threat actors
            self.assertEqual(rows[2]["sid"], "2003")
            self.assertEqual(rows[2]["threat_actor"], "Lazarus / Hidden Cobra; SideWinder")
            self.assertEqual(rows[2]["candidate_actor"], "unknown")
            self.assertEqual(rows[2]["actor_code"], "APT38; -")
            self.assertEqual(rows[2]["actor_evidence"], "msg; metadata,msg")
            self.assertEqual(rows[2]["actor_keyword"], "Lazarus; SideWinder")
            self.assertEqual(rows[2]["actor_confidence"], "high; high")

            # Row 3: MITRE Tactic ID only (TA0011 is ignored)
            self.assertEqual(rows[3]["sid"], "2004")
            self.assertEqual(rows[3]["threat_actor"], "unknown")
            self.assertEqual(rows[3]["candidate_actor"], "unknown")
            self.assertEqual(rows[3]["actor_code"], "-")
            self.assertEqual(rows[3]["actor_evidence"], "-")
            self.assertEqual(rows[3]["actor_keyword"], "-")
            self.assertEqual(rows[3]["actor_confidence"], "-")

    def test_analyze_archive_threat_actor_confidence_tiers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "rules.tar.gz"
            report_path = Path(tmp) / "report.csv"
            
            # Rule 1: Reference-only match -> low confidence
            rule_ref_only = (
                'alert tcp any any -> any any '
                '(msg:"SimpleHelp Remote Access Software Activity"; '
                'reference:url,deepinstinct.com/blog/muddywater-attack; '
                'sid:3001; rev:1;)'
            )
            # Rule 2: Content-only match (raw_rule) -> medium confidence
            rule_content_only = (
                'alert tcp any any -> any any '
                '(msg:"Checking inbound PowerShell"; '
                'content:"oilrig"; '
                'sid:3002; rev:1;)'
            )
            
            make_tar_gz(
                archive_path,
                {
                    "rules/test.rules": "\n".join([rule_ref_only, rule_content_only]),
                },
            )

            analyze_archive(archive_path, report_path, "20260522")

            with report_path.open("r", encoding="utf-8", newline="") as input_file:
                rows = list(csv.DictReader(input_file))

            # Row 0: MuddyWater from references only -> low confidence (placed in candidate_actor)
            self.assertEqual(rows[0]["sid"], "3001")
            self.assertEqual(rows[0]["threat_actor"], "unknown")
            self.assertEqual(rows[0]["candidate_actor"], "MuddyWater")
            self.assertEqual(rows[0]["actor_code"], "-")
            self.assertEqual(rows[0]["actor_evidence"], "-")
            self.assertEqual(rows[0]["actor_keyword"], "-")
            self.assertEqual(rows[0]["actor_confidence"], "-")

            # Row 1: OilRig from content option -> medium confidence (placed in threat_actor)
            self.assertEqual(rows[1]["sid"], "3002")
            self.assertEqual(rows[1]["threat_actor"], "APT34 / OilRig")
            self.assertEqual(rows[1]["candidate_actor"], "unknown")
            self.assertEqual(rows[1]["actor_code"], "APT34")
            self.assertEqual(rows[1]["actor_evidence"], "raw_rule")
            self.assertEqual(rows[1]["actor_keyword"], "oilrig")
            self.assertEqual(rows[1]["actor_confidence"], "medium")

    def test_strict_categorization_engine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "rules.tar.gz"
            report_path = Path(tmp) / "report.csv"
            
            # Rule 1: CISA advisory format TA17-318A or TA18-106A (should be ignored)
            rule_cisa = (
                'alert tcp any any -> any any '
                '(msg:"CISA Alert test"; '
                'reference:url,us-cert.gov/ncas/alerts/TA17-318A; '
                'sid:4001; rev:1;)'
            )
            # Rule 2: Context sensitive "reaper" without security keyword -> unknown
            rule_reaper_no_context = (
                'alert tcp any any -> any any '
                '(msg:"The reaper process has started"; '
                'sid:4002; rev:1;)'
            )
            # Rule 3: Context sensitive "reaper" with security keyword -> ScarCruft
            rule_reaper_with_context = (
                'alert tcp any any -> any any '
                '(msg:"Reaper Group activity detected"; '
                'sid:4003; rev:1;)'
            )
            # Rule 4: Context sensitive "reaper" with synonym scarcruft -> ScarCruft
            rule_reaper_synonym = (
                'alert tcp any any -> any any '
                '(msg:"The reaper synonym scarcruft rules"; '
                'sid:4004; rev:1;)'
            )
            # Rule 5: Software denylist: "Bisonal" and "BabyShark" should be ignored
            rule_denylisted = (
                'alert tcp any any -> any any '
                '(msg:"Bisonal RAT and BabyShark malware family"; '
                'metadata:malware_family Bisonal; '
                'sid:4005; rev:1;)'
            )
            # Rule 6: Context sensitive "hades" with "apt" -> Hades
            rule_hades = (
                'alert tcp any any -> any any '
                '(msg:"hades apt rules"; '
                'sid:4006; rev:1;)'
            )

            make_tar_gz(
                archive_path,
                {
                    "rules/test.rules": "\n".join([
                        rule_cisa, rule_reaper_no_context, rule_reaper_with_context,
                        rule_reaper_synonym, rule_denylisted, rule_hades
                    ]),
                },
            )

            analyze_archive(archive_path, report_path, "20260522")

            with report_path.open("r", encoding="utf-8", newline="") as input_file:
                rows = list(csv.DictReader(input_file))

            # Row 0: CISA Advisory ignored
            self.assertEqual(rows[0]["sid"], "4001")
            self.assertEqual(rows[0]["threat_actor"], "unknown")
            self.assertEqual(rows[0]["candidate_actor"], "unknown")

            # Row 1: reaper without context -> unknown
            self.assertEqual(rows[1]["sid"], "4002")
            self.assertEqual(rows[1]["threat_actor"], "unknown")
            self.assertEqual(rows[1]["candidate_actor"], "unknown")

            # Row 2: reaper with context -> ScarCruft
            self.assertEqual(rows[2]["sid"], "4003")
            self.assertEqual(rows[2]["threat_actor"], "ScarCruft")
            self.assertEqual(rows[2]["actor_confidence"], "high")

            # Row 3: reaper with scarcruft in rule -> ScarCruft
            self.assertEqual(rows[3]["sid"], "4004")
            self.assertEqual(rows[3]["threat_actor"], "ScarCruft")
            self.assertEqual(rows[3]["actor_confidence"], "high")

            # Row 4: Bisonal/BabyShark denylisted -> unknown
            self.assertEqual(rows[4]["sid"], "4005")
            self.assertEqual(rows[4]["threat_actor"], "unknown")
            self.assertEqual(rows[4]["candidate_actor"], "unknown")

            # Row 5: hades with apt -> Hades
            self.assertEqual(rows[5]["sid"], "4006")
            self.assertEqual(rows[5]["threat_actor"], "Hades")

    def test_export_uncommented_rules_writes_deploy_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "rules.tar.gz"
            output_path = Path(tmp) / "deploy.rules"
            second_rule = "drop tcp any any -> any any (msg:\"Second\"; sid:1002; rev:1;)"
            make_tar_gz(
                archive_path,
                {
                    "rules/emerging.rules": SAMPLE_RULE + "\n# disabled comment\n\n" + second_rule + "\n",
                },
            )

            result = export_uncommented_rules(archive_path, output_path)

            self.assertEqual(result.rule_count, 2)
            text = output_path.read_text(encoding="utf-8")
            self.assertIn(SAMPLE_RULE, text)
            self.assertIn(second_rule, text)
            self.assertNotIn("disabled comment", text)

    def test_dynamic_self_learning_malware_denylist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "rules.tar.gz"
            report_path = Path(tmp) / "report.csv"
            
            rule = (
                'alert tcp any any -> any any '
                '(msg:"SuperDuperMalware activity"; '
                'metadata:malware_family SuperDuperMalware; '
                'sid:5001; rev:1;)'
            )
            make_tar_gz(
                archive_path,
                {
                    "rules/test.rules": rule,
                },
            )

            analyze_archive(archive_path, report_path, "20260522")

            with report_path.open("r", encoding="utf-8", newline="") as input_file:
                rows = list(csv.DictReader(input_file))

            self.assertEqual(rows[0]["sid"], "5001")
            self.assertEqual(rows[0]["threat_actor"], "unknown")
            self.assertEqual(rows[0]["candidate_actor"], "unknown")
            
            # Verify it was saved to the config
            config_dir = Path(__file__).resolve().parents[1] / "config"
            dynamic_malware_file = config_dir / "dynamic_malware_list.json"
            self.assertTrue(dynamic_malware_file.exists())
            
            with dynamic_malware_file.open("r", encoding="utf-8") as f:
                dynamic_list = json.load(f)
            self.assertIn("superdupermalware", dynamic_list)
            
            try:
                dynamic_malware_file.unlink()
            except Exception:
                pass

    def test_self_learning_poisoning_prevention(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "rules.tar.gz"
            report_path = Path(tmp) / "report.csv"
            
            # Rule 1: A rule trying to poison 'Lazarus' (registered threat actor)
            rule_poison = (
                'alert tcp any any -> any any '
                '(msg:"Poison rule"; '
                'metadata:malware_family Lazarus; '
                'sid:6001; rev:1;)'
            )
            
            # Rule 2: A subsequent rule matching Lazarus via msg
            rule_match = (
                'alert tcp any any -> any any '
                '(msg:"Lazarus activity"; '
                'sid:6002; rev:1;)'
            )
            
            make_tar_gz(
                archive_path,
                {
                    "rules/test.rules": "\n".join([rule_poison, rule_match]),
                },
            )

            analyze_archive(archive_path, report_path, "20260522")

            with report_path.open("r", encoding="utf-8", newline="") as input_file:
                rows = list(csv.DictReader(input_file))

            config_dir = Path(__file__).resolve().parents[1] / "config"
            dynamic_malware_file = config_dir / "dynamic_malware_list.json"
            
            # Lazarus should not be added to dynamic malware list JSON
            if dynamic_malware_file.exists():
                with dynamic_malware_file.open("r", encoding="utf-8") as f:
                    dynamic_list = json.load(f)
                self.assertNotIn("lazarus", dynamic_list)
                
            # Row 1 (rule_match) should still successfully classify Lazarus
            self.assertEqual(rows[1]["sid"], "6002")
            self.assertEqual(rows[1]["threat_actor"], "Lazarus / Hidden Cobra")

    def test_dynamic_malware_list_self_healing(self) -> None:
        config_dir = Path(__file__).resolve().parents[1] / "config"
        dynamic_malware_file = config_dir / "dynamic_malware_list.json"
        
        # Backup existing
        backup_data = None
        if dynamic_malware_file.exists():
            try:
                backup_data = dynamic_malware_file.read_text(encoding="utf-8")
            except Exception:
                pass
            
        try:
            # Write a poisoned list containing a generic malware and a threat actor name
            poisoned_data = ["somegenericmalware", "Lazarus"]
            with dynamic_malware_file.open("w", encoding="utf-8") as f:
                json.dump(poisoned_data, f)
                
            from analyzer import load_intel_data
            actor_mappings, canonical_codes, software_denylist = load_intel_data()
            
            # Check that lazarus was filtered out, but generic malware remains
            self.assertNotIn("lazarus", software_denylist)
            self.assertIn("somegenericmalware", software_denylist)
            
            # Check that the file itself was automatically self-healed and cleaned
            with dynamic_malware_file.open("r", encoding="utf-8") as f:
                cleaned_list = json.load(f)
            self.assertNotIn("lazarus", cleaned_list)
            self.assertIn("somegenericmalware", cleaned_list)
        finally:
            # Restore backup
            if backup_data is not None:
                dynamic_malware_file.write_text(backup_data, encoding="utf-8")
            elif dynamic_malware_file.exists():
                try:
                    dynamic_malware_file.unlink()
                except Exception:
                    pass

    def test_mitre_sync_cache_fallback(self) -> None:
        from unittest.mock import patch
        import update_intel
        
        config_dir = Path(__file__).resolve().parents[1] / "config"
        cache_file = config_dir / "mitre_attack_cache.json"
        actor_mappings_file = config_dir / "actor_mappings.json"
        software_denylist_file = config_dir / "software_denylist.json"
        
        # Backup existing
        backup_cache = cache_file.read_text(encoding="utf-8") if cache_file.exists() else None
        backup_mappings = actor_mappings_file.read_text(encoding="utf-8") if actor_mappings_file.exists() else None
        backup_denylist = software_denylist_file.read_text(encoding="utf-8") if software_denylist_file.exists() else None
        
        try:
            # Write mock cache content
            mock_mitre_data = {
                "objects": [
                    {
                        "type": "intrusion-set",
                        "name": "Mock Threat Group",
                        "aliases": ["mock_alias"]
                    },
                    {
                        "type": "malware",
                        "name": "Mock Malware"
                    }
                ]
            }
            with cache_file.open("w", encoding="utf-8") as f:
                json.dump(mock_mitre_data, f)
                
            # Mock fetch_mitre_data to raise exception and trigger offline cache loader
            with patch("update_intel.fetch_mitre_data", side_effect=Exception("Simulated network failure")):
                update_intel.main()
                
            # Verify mappings and software denylist were successfully populated from the cache
            with actor_mappings_file.open("r", encoding="utf-8") as f:
                mappings = json.load(f)
            self.assertIn("Mock Threat Group", mappings)
            self.assertIn("mock_alias", mappings["Mock Threat Group"])
            
            with software_denylist_file.open("r", encoding="utf-8") as f:
                denylist = json.load(f)
            self.assertIn("mock malware", denylist)
        finally:
            # Restore backups
            for file_path, backup_content in [
                (cache_file, backup_cache),
                (actor_mappings_file, backup_mappings),
                (software_denylist_file, backup_denylist)
            ]:
                if backup_content is not None:
                    file_path.write_text(backup_content, encoding="utf-8")
                elif file_path.exists():
                    try:
                        file_path.unlink()
                    except Exception:
                        pass




if __name__ == "__main__":
    unittest.main()
