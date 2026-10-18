#!/usr/bin/env python3
"""NAN-3342: network fixtures must expose names for their known IANA ids.

Run with Vector on PATH. Covers the live Sysmon protocol=tcp shape and the
other parsers that previously emitted only connection_info.protocol_num.
"""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
PARSERS = (
    "crowdstrike_falcon", "defender_edr", "limacharlie", "linux_auditd",
    "sophos", "sysmon_linux_xml", "sysmon_xml", "windows_sysmon",
)
NAMES = {1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 41: "ipv6", 47: "gre",
         50: "esp", 51: "ah", 58: "icmpv6", 89: "ospf", 132: "sctp"}


class ProtocolNames(unittest.TestCase):
    def test_network_fixtures_have_protocol_names(self):
        checked = 0
        for name in PARSERS:
            parser = yaml.safe_load((ROOT / "parsers-ocsf" / name / "parser.yaml").read_text())
            samples = [s for s in parser["samples"] if s.get("expect", {}).get("class_uid") == 4001]
            self.assertTrue(samples, name)
            with tempfile.TemporaryDirectory() as directory:
                program = Path(directory) / "parser.vrl"
                program.write_text(parser["parser_vrl"])
                for sample in samples:
                    with self.subTest(parser=name, index=parser["samples"].index(sample)):
                        event = Path(directory) / "input.json"
                        event.write_text(json.dumps({"message": sample["raw"]}))
                        result = subprocess.run(
                            ["vector", "vrl", "--input", str(event), "--program", str(program), "--print-object"],
                            capture_output=True, text=True, timeout=30,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        output = json.loads(result.stdout)
                        connection = output.get("connection_info", {})
                        number = connection.get("protocol_num")
                        if number in NAMES:
                            self.assertEqual(connection.get("protocol_name"), NAMES[number])
                            checked += 1
        self.assertGreaterEqual(checked, len(PARSERS))


if __name__ == "__main__":
    unittest.main()
