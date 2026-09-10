from __future__ import annotations

import json
import sys
import unittest
import unittest.mock
from pathlib import Path
import tempfile

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

import cti_engine


class CtiEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.project_root = Path(self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    @unittest.mock.patch("cti_engine.requests.get")
    def test_sync_cti_feeds_success(self, mock_get) -> None:
        # Mock responses for all three feeds
        feodo_csv = (
            "# Feodo Tracker Blocklist\n"
            "# Header info\n"
            "Firstseen,DstIP,DstPort,Lastseen,Malware\n"
            "2026-05-28 00:00:00,10.0.0.1,443,2026-05-28 01:00:00,CobaltStrike\n"
            "2026-05-28 00:00:00,10.0.0.2,80,2026-05-28 01:00:00,Feodo\n"
        )
        
        urlhaus_text = (
            "# URLhaus malicious URLs\n"
            "http://malicious-domain.com/path1\n"
            "https://192.168.1.100:8080/malware\n"
        )
        
        et_ips = (
            "# ET Open Compromised IPs\n"
            "172.16.5.5\n"
            "172.16.5.6\n"
        )

        def mock_get_impl(url, **kwargs):
            r = unittest.mock.Mock()
            r.raise_for_status = lambda: None
            if "feodotracker" in url:
                r.text = feodo_csv
            elif "urlhaus" in url:
                r.text = urlhaus_text
            elif "compromised-ips" in url:
                r.text = et_ips
            else:
                r.text = ""
            return r

        mock_get.side_effect = mock_get_impl

        # Run sync with all feeds enabled
        enabled_feeds = {"feodo": True, "urlhaus": True, "et_compromised": True}
        status = cti_engine.sync_cti_feeds(self.project_root, enabled_feeds)

        # Assert status
        self.assertEqual(status["total_ip_rules"], 5)  # 10.0.0.1, 10.0.0.2, 192.168.1.100, 172.16.5.5, 172.16.5.6
        self.assertEqual(status["total_domain_rules"], 1)  # malicious-domain.com
        self.assertEqual(status["total_rules"], 6)
        self.assertEqual(status["feeds"]["feodo"]["status"], "success")
        self.assertEqual(status["feeds"]["urlhaus"]["status"], "success")
        self.assertEqual(status["feeds"]["et_compromised"]["status"], "success")

        # Verify output files exist
        downloads_dir = self.project_root / "downloads"
        self.assertTrue((downloads_dir / "cti_blocklist.rules").exists())
        self.assertTrue((downloads_dir / "cti_meta.json").exists())
        self.assertTrue((downloads_dir / "cti_iocs.json").exists())

        # Inspect generated rules
        rules_content = (downloads_dir / "cti_blocklist.rules").read_text(encoding="utf-8")
        lines = [line.strip() for line in rules_content.splitlines() if line.strip() and not line.startswith("#")]
        
        # We expect 6 rules: 5 IP drops + 1 DNS drop
        self.assertEqual(len(lines), 6)
        
        # Test IP alert syntax (should contain bidirectional <> and IP value)
        self.assertIn('alert ip any any <> 10.0.0.1 any (msg:"CTI Blocklist: Traffic to/from Malicious IP (Feodo Tracker)"', rules_content)
        self.assertIn('sid:9000000;', rules_content)
        
        # Test DNS alert syntax (should contain dns.query, home_net, content and Domain value)
        self.assertIn('alert dns $HOME_NET any -> any any (msg:"CTI Blocklist: DNS Query for Malicious Domain (URLhaus)"', rules_content)
        self.assertIn('dns.query; content:"malicious-domain.com"; nocase;', rules_content)
        self.assertIn('sid:9100000;', rules_content)

        # Inspect CTI IOCs registry
        iocs_content = json.loads((downloads_dir / "cti_iocs.json").read_text(encoding="utf-8"))
        self.assertEqual(len(iocs_content), 6)
        
        # Verify specific entries
        self.assertEqual(iocs_content[0]["type"], "IP")
        self.assertEqual(iocs_content[0]["value"], "10.0.0.1")
        self.assertEqual(iocs_content[0]["source"], "Feodo Tracker")
        self.assertEqual(iocs_content[0]["sid"], 9000000)

        self.assertEqual(iocs_content[5]["type"], "Domain")
        self.assertEqual(iocs_content[5]["value"], "malicious-domain.com")
        self.assertEqual(iocs_content[5]["source"], "URLhaus")
        self.assertEqual(iocs_content[5]["sid"], 9100000)

    @unittest.mock.patch("cti_engine.requests.get")
    def test_sync_cti_feeds_disabled(self, mock_get) -> None:
        # Run sync with feodo and et_compromised disabled
        enabled_feeds = {"feodo": False, "urlhaus": True, "et_compromised": False}
        
        urlhaus_text = (
            "http://another-malicious.com/\n"
        )
        r = unittest.mock.Mock()
        r.raise_for_status = lambda: None
        r.text = urlhaus_text
        mock_get.return_value = r

        status = cti_engine.sync_cti_feeds(self.project_root, enabled_feeds)

        self.assertEqual(status["total_ip_rules"], 0)
        self.assertEqual(status["total_domain_rules"], 1)
        self.assertEqual(status["feeds"]["feodo"]["enabled"], False)
        self.assertEqual(status["feeds"]["feodo"]["status"], "disabled")
        self.assertEqual(status["feeds"]["urlhaus"]["enabled"], True)
        self.assertEqual(status["feeds"]["urlhaus"]["status"], "success")
        self.assertEqual(status["feeds"]["et_compromised"]["enabled"], False)


if __name__ == "__main__":
    unittest.main()
