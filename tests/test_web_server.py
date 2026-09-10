from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path
import requests

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from web_server import start_server


class WebServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory()
        cls.project_root = Path(cls.tmp_dir.name)
        
        # Create necessary directories
        (cls.project_root / "config").mkdir(parents=True, exist_ok=True)
        (cls.project_root / "logs").mkdir(parents=True, exist_ok=True)
        (cls.project_root / "deploy").mkdir(parents=True, exist_ok=True)
        (cls.project_root / "downloads").mkdir(parents=True, exist_ok=True)
        (cls.project_root / "reports").mkdir(parents=True, exist_ok=True)
        
        # Write dummy configs
        cls.overrides_file = cls.project_root / "config" / "intel_overrides.json"
        with cls.overrides_file.open("w", encoding="utf-8") as f:
            json.dump({"actor_mappings": {"Lazarus": ["hidden cobra"]}, "software_denylist": ["cobaltstrike"]}, f)
            
        # Write mock MITRE ATT&CK cache JSON
        cls.mitre_cache_file = cls.project_root / "config" / "mitre_attack_cache.json"
        mitre_dummy = {
            "objects": [
                {
                    "type": "x-mitre-tactic",
                    "name": "Initial Access",
                    "x_mitre_shortname": "initial-access",
                    "external_references": [{"external_id": "TA0001"}]
                },
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--1",
                    "name": "Exploit Public-Facing Application",
                    "x_mitre_is_subtechnique": False,
                    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
                    "external_references": [{"external_id": "T1190"}]
                },
                {
                    "type": "intrusion-set",
                    "id": "intrusion-set--1",
                    "name": "Lazarus Group"
                },
                {
                    "type": "relationship",
                    "relationship_type": "uses",
                    "source_ref": "intrusion-set--1",
                    "target_ref": "attack-pattern--1"
                }
            ]
        }
        with cls.mitre_cache_file.open("w", encoding="utf-8") as f:
            json.dump(mitre_dummy, f)
            
        # Write mock rules file
        cls.deploy_rules = cls.project_root / "deploy" / "deploy.rules"
        cls.deploy_rules.write_text(
            "alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:\"Test active\"; metadata:affected_product IIS, attack_target Web_Server, confidence high, signature_severity Major, cve 2026_3001, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application; classtype:attempted-user; sid:3001;)\n"
            "# [VALIDATION FAILED - 2026-05-22 12:00:00] alert tcp any any -> any any (msg:\"Test disabled\"; metadata:mitre_tactic_id TA0001, mitre_technique_id T1190; sid:3002;)\n"
            "# [VALIDATION FAILED - 2026-05-22 12:05:00 - E: invalid keyword 'abc'] alert tcp any any -> any any (msg:\"Test disabled 2\"; sid:3003;)\n",
            encoding="utf-8"
        )
        
        # Write mock daily analysis CSV report
        cls.report_csv = cls.project_root / "reports" / "daily_analysis_20260522.csv"
        cls.report_csv.write_text(
            "date,sid,rev,msg,classtype,priority,protocol,source,destination,rule_file,metadata,references,threat_actor,candidate_actor,actor_code,actor_evidence,actor_keyword,actor_confidence,raw_rule\n"
            "20260522,3001,1,Test active,attempted-user,1,tcp,$EXTERNAL_NET,$HOME_NET,emerging-web.rules,\"affected_product IIS, attack_target Web_Server, confidence high, signature_severity Major, cve 2026_3001, mitre_tactic_id TA0001, mitre_tactic_name Initial_Access, mitre_technique_id T1190, mitre_technique_name Exploit_Public_Facing_Application\",[],unknown,unknown,-,-,-,-,\"alert tcp ...\"\n",
            encoding="utf-8"
        )
        
        # Write mock logs
        cls.log_file = cls.project_root / "logs" / "download.log"
        cls.log_file.write_text("INFO - Starting job\nINFO - Completed job\n", encoding="utf-8")
        
        # Setup environment variables so AppConfig doesn't throw on missing ETPRO_OINKCODE
        cls.env_patcher = unittest.mock.patch.dict("os.environ", {"ETPRO_OINKCODE": "test_oinkcode"})
        cls.env_patcher.start()
        
        # Start server on dynamic port
        cls.server = start_server(host="127.0.0.1", port=0, project_root=cls.project_root)
        cls.server_port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        
        # Wait a brief moment for the server to start
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.env_patcher.stop()
        cls.tmp_dir.cleanup()

    def test_get_root_serves_html(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/"
        response = requests.get(url, timeout=5)
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers.get("Content-Type", ""))
        self.assertIn("ET Pro 自動下載器", response.text)

    def test_get_status_endpoint(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/status"
        response = requests.get(url, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "idle")
        self.assertEqual(data["total_rules"], 1)
        self.assertEqual(data["disabled_rules_count"], 2)
        self.assertTrue(data["oinkcode_configured"])

    def test_get_config_endpoint(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/config"
        response = requests.get(url, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("Lazarus", data["actor_mappings"])
        self.assertIn("cobaltstrike", data["software_denylist"])

    def test_post_config_endpoint_success(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/config"
        payload = {
            "actor_mappings": {
                "Lazarus": ["hidden cobra", "andariel"],
                "APT28": ["fancy bear"]
            },
            "software_denylist": ["cobaltstrike", "quasar"]
        }
        response = requests.post(url, json=payload, timeout=5)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "success")
        
        # Verify it was written to file
        with self.overrides_file.open("r", encoding="utf-8") as f:
            saved_data = json.load(f)
        self.assertIn("andariel", saved_data["actor_mappings"]["Lazarus"])
        self.assertIn("quasar", saved_data["software_denylist"])

    def test_post_config_endpoint_validation_error(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/config"
        payload = {"invalid_keys": True}
        response = requests.post(url, json=payload, timeout=5)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["status"], "error")

    def test_get_logs_endpoint(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/logs"
        response = requests.get(url, timeout=5)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Starting job", response.text)

    def test_get_disabled_rules_endpoint(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/rules/disabled"
        response = requests.get(url, timeout=5)
        self.assertEqual(response.status_code, 200)
        rules = response.json()
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["sid"], "3002")
        self.assertEqual(rules[0]["timestamp"], "2026-05-22 12:00:00")
        self.assertEqual(rules[0]["reason"], "Suricata validation failed")
        
        self.assertEqual(rules[1]["sid"], "3003")
        self.assertEqual(rules[1]["timestamp"], "2026-05-22 12:05:00")
        self.assertEqual(rules[1]["reason"], "E: invalid keyword 'abc'")

    def test_get_active_rules_endpoint_and_facets(self) -> None:
        # 1. Test facets endpoint
        facets_url = f"http://127.0.0.1:{self.server_port}/api/rules/active/facets"
        facets_res = requests.get(facets_url, timeout=5)
        self.assertEqual(facets_res.status_code, 200)
        facets = facets_res.json()
        self.assertIn("emerging-web.rules", facets["dataset"])
        self.assertIn("attempted-user", facets["classtype"])
        self.assertIn("IIS", facets["affected_product"])
        self.assertIn("Web_Server", facets["attack_target"])
        self.assertIn("high", facets["confidence"])
        self.assertIn("Major", facets["signature_severity"])

        # 2. Test active rules paginated endpoint without filter
        rules_url = f"http://127.0.0.1:{self.server_port}/api/rules/active?page=1&limit=10"
        rules_res = requests.get(rules_url, timeout=5)
        self.assertEqual(rules_res.status_code, 200)
        data = rules_res.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["page"], 1)
        self.assertEqual(len(data["rules"]), 1)
        rule = data["rules"][0]
        self.assertEqual(rule["sid"], "3001")
        self.assertEqual(rule["dataset"], "emerging-web.rules")
        self.assertEqual(rule["affected_product"], "IIS")
        self.assertEqual(rule["attack_target"], "Web_Server")

        # 3. Test active rules paginated endpoint with filter matching
        filtered_url = f"http://127.0.0.1:{self.server_port}/api/rules/active?affected_product=IIS"
        filtered_res = requests.get(filtered_url, timeout=5)
        self.assertEqual(filtered_res.status_code, 200)
        filtered_data = filtered_res.json()
        self.assertEqual(filtered_data["total"], 1)

        # 4. Test active rules paginated endpoint with filter NOT matching
        mismatch_url = f"http://127.0.0.1:{self.server_port}/api/rules/active?affected_product=Apache"
        mismatch_res = requests.get(mismatch_url, timeout=5)
        self.assertEqual(mismatch_res.status_code, 200)
        mismatch_data = mismatch_res.json()
        self.assertEqual(mismatch_data["total"], 0)

    def test_trigger_pipeline(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/trigger"
        # Mock the run_pipeline_worker to prevent running the actual network downloader during test
        with unittest.mock.patch("web_server.run_pipeline_worker") as mock_worker:
            response = requests.post(url, timeout=5)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["status"], "started")
            # The background worker thread should be spawned, calling run_pipeline_worker
            time.sleep(0.1)
            mock_worker.assert_called_once()

    def test_get_active_rules_stats(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/rules/active/stats"
        response = requests.get(url, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("threat_actors", data)
        self.assertIn("severities", data)
        self.assertIn("mitre_tactics", data)
        self.assertIn("cve_years", data)
        self.assertEqual(data["total_active_rules"], 1)
        self.assertEqual(data["severities"].get("Major", 0), 1)

    def test_sse_stream_endpoint(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/stream"
        # We can read a small chunk of the stream to verify SSE works
        with requests.get(url, stream=True, timeout=5) as response:
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.headers.get("Content-Type", "").startswith("text/event-stream"))
            
            # Read the first event
            lines = []
            for line in response.iter_lines():
                if line:
                    lines.append(line.decode("utf-8"))
                if len(lines) >= 2:
                    break
            
            # The first event should be 'connected'
            self.assertTrue(any("event: connected" in l or "Welcome to ETPro" in l for l in lines))

    def test_api_key_authorization(self) -> None:
        import web_server
        
        # Save original API_KEY_ENV
        orig_key = web_server.API_KEY_ENV
        try:
            # Set a test API key
            web_server.API_KEY_ENV = "supersecretkey"
            
            # 1. Test request without key (should fail with 401)
            url = f"http://127.0.0.1:{self.server_port}/api/status"
            response = requests.get(url, timeout=5)
            self.assertEqual(response.status_code, 401)
            
            # 2. Test request with wrong key (should fail with 401)
            response = requests.get(url, headers={"X-API-Key": "wrongkey"}, timeout=5)
            self.assertEqual(response.status_code, 401)
            
            # 3. Test request with correct key in header (should succeed with 200)
            response = requests.get(url, headers={"X-API-Key": "supersecretkey"}, timeout=5)
            self.assertEqual(response.status_code, 200)
            
            # 4. Test request with correct key in query parameter (should succeed with 200)
            response = requests.get(f"{url}?api_key=supersecretkey", timeout=5)
            self.assertEqual(response.status_code, 200)
            
        finally:
            # Restore original API_KEY_ENV
            web_server.API_KEY_ENV = orig_key

    def test_toggle_rule_status(self) -> None:
        original_content = self.deploy_rules.read_text(encoding="utf-8")
        try:
            url = f"http://127.0.0.1:{self.server_port}/api/rules/toggle"
            payload = {"sid": "3001", "enabled": False}
            
            with unittest.mock.patch("deployer.trigger_suricata_reload", return_value=True) as mock_reload:
                res = requests.post(url, json=payload, timeout=5)
                self.assertEqual(res.status_code, 200)
                self.assertTrue(res.json()["modified"])
                mock_reload.assert_called_once()
                
                content = self.deploy_rules.read_text(encoding="utf-8")
                self.assertIn("# [USER DISABLED", content)
                
                # Toggle it back to enabled
                payload_enable = {"sid": "3001", "enabled": True}
                res_enable = requests.post(url, json=payload_enable, timeout=5)
                self.assertEqual(res_enable.status_code, 200)
                self.assertTrue(res_enable.json()["modified"])
                
                content_restored = self.deploy_rules.read_text(encoding="utf-8")
                self.assertNotIn("# [USER DISABLED", content_restored)
                self.assertTrue(content_restored.startswith("alert tcp"))
        finally:
            self.deploy_rules.write_text(original_content, encoding="utf-8")

    def test_sqlite_wal_and_atomic_swap(self) -> None:
        import sqlite3
        db_path = self.project_root / "config" / "deploy_rules.db"
        self.assertTrue(db_path.exists())
        
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Check journal mode
        cursor.execute("PRAGMA journal_mode")
        journal_mode = cursor.fetchone()[0]
        self.assertEqual(journal_mode.lower(), "wal")
        
        # Check active_rules table exists and has rows
        cursor.execute("SELECT count(*) FROM active_rules")
        count = cursor.fetchone()[0]
        self.assertGreaterEqual(count, 1)
        
        # Check that shadow table active_rules_temp is cleaned up
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='active_rules_temp'")
        temp_table = cursor.fetchone()
        self.assertIsNone(temp_table)
        
        conn.close()

    def test_cve_filtering(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/rules/active?cve=2026-3001"
        response = requests.get(url, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["rules"][0]["sid"], "3001")
        self.assertEqual(data["rules"][0]["cve"], "CVE-2026-3001")

        # Test filter mismatch
        mismatch_url = f"http://127.0.0.1:{self.server_port}/api/rules/active?cve=CVE-2025-0000"
        mismatch_res = requests.get(mismatch_url, timeout=5)
        self.assertEqual(mismatch_res.status_code, 200)
        self.assertEqual(mismatch_res.json()["total"], 0)

    def test_get_deployments(self) -> None:
        archive_dir = self.project_root / "deploy" / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)
        archive_file = archive_dir / "20260522_1_deploy.rules"
        archive_file.write_text("alert tcp ...", encoding="utf-8")

        url = f"http://127.0.0.1:{self.server_port}/api/deployments"
        response = requests.get(url, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreaterEqual(len(data), 1)
        self.assertEqual(data[0]["filename"], "20260522_1_deploy.rules")
        self.assertEqual(data[0]["date"], "20260522")
        self.assertEqual(data[0]["version"], "1")

    def test_rollback_deployment(self) -> None:
        original_content = self.deploy_rules.read_text(encoding="utf-8")
        try:
            archive_dir = self.project_root / "deploy" / "archive"
            archive_dir.mkdir(parents=True, exist_ok=True)
            archive_file = archive_dir / "20260522_2_deploy.rules"
            archive_file.write_text("alert tcp any any -> any 80 (msg:\"Test rollback rules\"; sid:9999;)", encoding="utf-8")

            url = f"http://127.0.0.1:{self.server_port}/api/deployments/rollback"
            payload = {"filename": "20260522_2_deploy.rules"}
            
            with unittest.mock.patch("deployer.trigger_suricata_reload", return_value=True) as mock_reload:
                response = requests.post(url, json=payload, timeout=5)
                self.assertEqual(response.status_code, 200)
                data = response.json()
                self.assertEqual(data["status"], "success")
                self.assertEqual(data["filename"], "20260522_2_deploy.rules")
                self.assertTrue(data["reload_triggered"])
                mock_reload.assert_called_once()

                active_rules = self.project_root / "deploy" / "deploy.rules"
                self.assertIn("sid:9999", active_rules.read_text(encoding="utf-8"))
        finally:
            self.deploy_rules.write_text(original_content, encoding="utf-8")
            # Query rules to recreate deploy_rules.db cache
            requests.get(f"http://127.0.0.1:{self.server_port}/api/rules/active?page=1&limit=10", timeout=5)

    def test_system_health(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/system/health"
        response = requests.get(url, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("suricata_running", data)
        self.assertIn("disk_usage", data)
        self.assertIn("downloads_dir_size", data)
        self.assertIn("status", data)

    def test_mitre_matrix_endpoint(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/rules/active/mitre-matrix"
        response = requests.get(url, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertIn("matrix", data)
        self.assertIn("coverage", data)
        self.assertIn("metrics", data)
        self.assertIn("recommendations", data)
        
        # Test matrix structure contains our mock tactic and technique
        matrix = data["matrix"]
        self.assertGreaterEqual(len(matrix), 1)
        self.assertEqual(matrix[0]["id"], "TA0001")
        self.assertEqual(matrix[0]["techniques"][0]["id"], "T1190")
        
        # Test active rule coverage count
        self.assertEqual(data["coverage"].get("T1190"), 1)
        
        # Test metrics calculation
        self.assertEqual(data["metrics"]["total_techniques"], 1)
        self.assertEqual(data["metrics"]["covered_techniques"], 1)
        self.assertEqual(data["metrics"]["gaps_count"], 0)
        self.assertEqual(data["metrics"]["coverage_percentage"], 100.0)

    def test_get_active_rules_by_mitre_technique_id(self) -> None:
        # Test matching technique filter
        url = f"http://127.0.0.1:{self.server_port}/api/rules/active?mitre_technique_id=T1190"
        response = requests.get(url, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["rules"][0]["sid"], "3001")

        # Test mismatching technique filter
        url_mismatch = f"http://127.0.0.1:{self.server_port}/api/rules/active?mitre_technique_id=T9999"
        response_mismatch = requests.get(url_mismatch, timeout=5)
        self.assertEqual(response_mismatch.status_code, 200)
        self.assertEqual(response_mismatch.json()["total"], 0)

    def test_get_threat_actors(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/threat-actors"
        response = requests.get(url, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertGreaterEqual(len(data), 1)
        lazarus_group = next((x for x in data if "Lazarus" in x["name"]), None)
        self.assertIsNotNone(lazarus_group)
        self.assertEqual(lazarus_group["is_monitored"], True)
        self.assertEqual(lazarus_group["matched_group"], "Lazarus / Hidden Cobra")
        self.assertEqual(lazarus_group["techniques_count"], 1)

    def test_get_threat_actor_detail(self) -> None:
        url = f"http://127.0.0.1:{self.server_port}/api/threat-actors/intrusion-set--1"
        response = requests.get(url, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data["id"], "intrusion-set--1")
        self.assertEqual(data["name"], "Lazarus Group")
        self.assertEqual(data["is_monitored"], True)
        self.assertEqual(data["matched_group"], "Lazarus / Hidden Cobra")
        self.assertEqual(len(data["techniques"]), 1)
        self.assertEqual(data["techniques"][0]["id"], "T1190")
        self.assertEqual(data["techniques"][0]["active_rules_count"], 1)
        self.assertEqual(data["indirect_rules_count"], 1)

    def test_cti_status_and_iocs(self) -> None:
        # Test initial status (no meta file exists)
        url_status = f"http://127.0.0.1:{self.server_port}/api/cti/status"
        response = requests.get(url_status, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("feeds", data)
        self.assertEqual(data["feeds"]["feodo"]["enabled"], True)
        self.assertEqual(data["feeds"]["feodo"]["status"], "pending")

        # Create mock metadata and ioc registry files
        downloads_dir = self.project_root / "downloads"
        downloads_dir.mkdir(parents=True, exist_ok=True)
        
        mock_meta = {
            "sync_time": "2026-05-28T06:00:00Z",
            "feeds": {
                "feodo": {"enabled": True, "status": "success", "ips_count": 2, "domains_count": 0},
                "urlhaus": {"enabled": True, "status": "success", "ips_count": 0, "domains_count": 1},
                "et_compromised": {"enabled": False, "status": "disabled"}
            },
            "total_ip_rules": 2,
            "total_domain_rules": 1,
            "total_rules": 3
        }
        with (downloads_dir / "cti_meta.json").open("w", encoding="utf-8") as f:
            json.dump(mock_meta, f)
            
        mock_iocs = [
            {"type": "IP", "value": "1.2.3.4", "source": "Feodo Tracker", "sid": 9000000, "added_date": "2026-05-28T06:00:00Z"},
            {"type": "IP", "value": "5.6.7.8", "source": "Feodo Tracker", "sid": 9000001, "added_date": "2026-05-28T06:00:00Z"},
            {"type": "Domain", "value": "malicious.local", "source": "URLhaus", "sid": 9100000, "added_date": "2026-05-28T06:00:00Z"}
        ]
        with (downloads_dir / "cti_iocs.json").open("w", encoding="utf-8") as f:
            json.dump(mock_iocs, f)
            
        # Test status with meta file
        # Update overrides to disable et_compromised
        with self.overrides_file.open("w", encoding="utf-8") as f:
            json.dump({
                "actor_mappings": {"Lazarus": ["hidden cobra"]},
                "software_denylist": ["cobaltstrike"],
                "cti_feeds": {"feodo": True, "urlhaus": True, "et_compromised": False}
            }, f)

        response = requests.get(url_status, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total_rules"], 3)
        self.assertEqual(data["feeds"]["feodo"]["status"], "success")
        self.assertEqual(data["feeds"]["et_compromised"]["enabled"], False)
        
        # Test IOC list endpoint
        url_iocs = f"http://127.0.0.1:{self.server_port}/api/cti/iocs?page=1&limit=2"
        response = requests.get(url_iocs, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total"], 3)
        self.assertEqual(len(data["items"]), 2)
        self.assertEqual(data["items"][0]["value"], "1.2.3.4")
        
        # Test IOC list search
        url_search = f"http://127.0.0.1:{self.server_port}/api/cti/iocs?search=malicious"
        response = requests.get(url_search, timeout=5)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["value"], "malicious.local")

    def test_cti_sync_endpoint(self) -> None:
        import cti_engine
        import scheduler_entry
        
        # Patch sync functions globally at module level to prevent network calls and suricata dry-run
        original_sync = cti_engine.sync_cti_feeds
        original_run_once = scheduler_entry.run_once
        
        cti_engine.sync_cti_feeds = lambda *args, **kwargs: {"total_rules": 0}
        scheduler_entry.run_once = lambda *args, **kwargs: None
        
        try:
            url_sync = f"http://127.0.0.1:{self.server_port}/api/cti/sync"
            response = requests.post(url_sync, timeout=5)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["status"], "started")
            
            # Wait for background task to invoke the mocked function
            time.sleep(0.5)
        finally:
            cti_engine.sync_cti_feeds = original_sync
            scheduler_entry.run_once = original_run_once


if __name__ == "__main__":
    unittest.main()

