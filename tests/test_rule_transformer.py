import sys
import tempfile
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_DIR))

from rule_transformer import transform_rule_line, transform_rules_for_transfer


class RuleTransformerTests(unittest.TestCase):

    def test_transform_home_net_to_twnic_nets(self):
        line = 'alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"Test HTTP"; sid:1000001; rev:1;)'
        result = transform_rule_line(line)
        self.assertNotIn("$HOME_NET", result)
        self.assertIn("$TWNIC_NETS", result)
        self.assertIn("gid: 70; sid:1000001;", result)

    def test_multiple_home_net_replacements(self):
        line = 'alert ip $HOME_NET any -> $HOME_NET any (msg:"Internal"; sid:1000002; rev:1;)'
        result = transform_rule_line(line)
        self.assertEqual(result.count("$HOME_NET"), 0)
        self.assertEqual(result.count("$TWNIC_NETS"), 2)
        self.assertIn("gid: 70; sid:1000002;", result)

    def test_insert_gid_before_sid(self):
        line = 'alert udp any any -> any 53 (msg:"DNS query"; classtype:bad-traffic; sid:1000003; rev:2;)'
        result = transform_rule_line(line)
        self.assertIn("; gid: 70; sid:1000003;", result)

    def test_do_not_duplicate_gid_if_already_present(self):
        line = 'alert tcp any any -> any any (msg:"Has GID"; gid:1; sid:1000004; rev:1;)'
        result = transform_rule_line(line)
        self.assertNotIn("gid: 70;", result)
        self.assertIn("gid:1; sid:1000004;", result)

    def test_commented_rule_transformation(self):
        line = '# [AUTO-HEALED] alert tcp $HOME_NET any -> any any (msg:"Disabled"; sid:1000005; rev:1;)'
        result = transform_rule_line(line)
        self.assertIn("$TWNIC_NETS", result)
        self.assertNotIn("$HOME_NET", result)
        self.assertIn("gid: 70; sid:1000005;", result)

    def test_full_file_transformation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            source_file = tmp_path / "deploy.rules"
            output_file = tmp_path / "transfer.txt"

            rules_content = [
                '# Comment line without sid\n',
                'alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"Rule 1"; sid:2000001; rev:1;)\n',
                'alert udp $HOME_NET any -> $HOME_NET 53 (msg:"Rule 2"; sid:2000002; rev:1;)\n',
                'alert ip any any -> any any (msg:"Rule 3 without home_net"; sid:2000003; rev:1;)\n',
            ]
            source_file.write_text("".join(rules_content), encoding="utf-8")

            stats = transform_rules_for_transfer(source_file, output_file)
            self.assertTrue(output_file.exists())
            self.assertEqual(stats["total_lines"], 4)
            self.assertEqual(stats["gid_added"], 3)
            self.assertEqual(stats["home_net_replaced"], 3)

            output_lines = output_file.read_text(encoding="utf-8").splitlines()
            self.assertEqual(output_lines[0], '# Comment line without sid')
            self.assertIn("$TWNIC_NETS 443", output_lines[1])
            self.assertIn("gid: 70; sid:2000001;", output_lines[1])
            self.assertIn("gid: 70; sid:2000002;", output_lines[2])
            self.assertIn("gid: 70; sid:2000003;", output_lines[3])


if __name__ == "__main__":
    unittest.main()
