#!/usr/bin/env python3
"""Rule 5 (canonical OCSF 1.9 paths) and inline-sample feeding regression checks."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ocsf_event_checks import envelope_problems, inline_events, noncanonical_paths  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ROOT / "scripts" / "ocsf_event_checks.py"


class Rule5Tests(unittest.TestCase):
    def test_canonical_paths_the_old_promoted_list_missed_are_clean(self):
        # NAN-3689: these were reported as "silently unqueryable" against the
        # retired gen1 promoted-column list; the lean lake serves them all.
        event = {
            "class_uid": 3002,
            "device": {"ip": "10.0.0.5", "uid": "dev-1"},
            "actor": {"user": {"email_addr": "a@example.com"}},
            "user": {"email_addr": "b@example.com"},
            "src_endpoint": {"location": {"city": "Ottawa"}, "isp": "x"},
        }
        self.assertEqual(noncanonical_paths(event, 3002), [])

    def test_network_endpoint_and_process_leaves(self):
        network = {"dst_endpoint": {"svc_name": "https", "zone": "dmz", "interface_name": "eth0"}}
        self.assertEqual(noncanonical_paths(network, 4001), [])
        process = {
            "process": {"integrity": "Medium", "working_directory": "C:\\\\",
                        "parent_process": {"parent_process": {"cmd_line": "x"}}},
            "actor": {"process": {"user": {"name": "CORP\\\\bsmith"}}},
        }
        self.assertEqual(noncanonical_paths(process, 1007), [])
        # `process` is not an attribute of Network Activity.
        self.assertEqual(noncanonical_paths(process, 4001)[0], "process.integrity")

    def test_arrays_of_objects_walk_each_item(self):
        event = {
            "evidences": [{"dst_endpoint": {"ip": "1.2.3.4"}}, {"process": {"cmd_line": "x", "nope": 1}}],
        }
        self.assertEqual(noncanonical_paths(event, 2004), ["evidences.process.nope"])
        hashes = {"process": {"file": {"hashes": [{"algorithm_id": 3, "value": "ab"}]}}}
        self.assertEqual(noncanonical_paths(hashes, 1007), [])

    def test_non_canonical_paths_are_reported(self):
        event = {"src_endpoint": {"ip": "1.1.1.1", "made_up": "x"}, "vendor_blob": {"a": {"b": 1}}}
        self.assertEqual(
            noncanonical_paths(event, 4001), ["src_endpoint.made_up", "vendor_blob.a.b"]
        )

    def test_unmapped_and_free_form_values_are_exempt(self):
        event = {
            "unmapped": {"anything": {"goes": 1}},
            "enrichments": [{"name": "x", "value": "y", "data": {"producer": {"keys": 1}}}],
        }
        self.assertEqual(noncanonical_paths(event, 4001), [])


class InlineSampleFeedTests(unittest.TestCase):
    """What validate-ocsf.sh runs each inline sample on (parsers#99)."""

    def feed(self, samples):
        """The events extract-inline writes, read back through `wrap`."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "parser.yaml").write_text(yaml.safe_dump({"name": "t", "samples": samples}))
            rc = subprocess.run([sys.executable, str(CHECKS), "extract-inline", str(tmp / "parser.yaml"), str(tmp / "out")],
                                capture_output=True, text=True)
            if rc.returncode != 0:
                return rc.returncode, rc.stderr
            events = []
            for f in sorted((tmp / "out").glob("*.json")):
                out = subprocess.run([sys.executable, str(CHECKS), "wrap", str(f)], capture_output=True, text=True, check=True)
                events.append(json.loads(out.stdout))
            return 0, events

    def test_a_json_line_with_its_own_message_is_fed_as_the_line(self):
        line = '{"timestamp":"2026-11-24T01:02:03Z","message":{"inner":"x"},"host":"h"}'
        rc, events = self.feed([{"raw": line}, {"raw": '{"message":"text","k":1}'}, {"raw": "plain text"}])
        self.assertEqual(rc, 0, events)
        self.assertEqual(events, [{"message": line}, {"message": '{"message":"text","k":1}'}, {"message": "plain text"}])

    def test_an_envelope_sample_is_fed_as_the_event(self):
        # The non-string `.message` branches (null, number, pre-decoded object)
        # are reachable only through this gate; they must stay fed as events.
        rc, events = self.feed([{"raw": '{"message":null}', "envelope": True},
                                {"raw": '{"message":{"id":115}}', "envelope": True},
                                {"raw": '{"message":7}', "envelope": True},
                                {"raw": '{"message":7}', "envelope": False}])
        self.assertEqual(rc, 0, events)
        self.assertEqual(events, [{"message": None}, {"message": {"id": 115}}, {"message": 7}, {"message": '{"message":7}'}])

    def test_an_unmarked_bare_non_string_message_is_refused_not_fed_as_a_line(self):
        rc, err = self.feed([{"raw": '{"message":null}'}])
        self.assertEqual(rc, 2, err)
        self.assertIn("envelope: true", err)
        self.assertEqual(envelope_problems([{"raw": '{"message":"text"}'}, {"raw": '{"message":1,"k":2}'}]), [])

    def test_a_malformed_envelope_sample_fails_with_exit_2(self):
        rc, err = self.feed([{"raw": "plain text", "envelope": True}])
        self.assertEqual(rc, 2, err)

    def test_every_parser_states_its_envelope_samples(self):
        # The tree: no bare non-string `message` sample is left ambiguous, and
        # every envelope sample really reaches the parser with that `.message`.
        envelopes = 0
        for path in sorted((ROOT / "parsers-ocsf").glob("*/parser.yaml")) + sorted((ROOT / "enrichments").glob("**/parser.yaml")):
            samples = (yaml.safe_load(path.read_text()) or {}).get("samples") or []
            self.assertEqual(envelope_problems(samples), [], path)
            for index, event in inline_events(samples):
                if isinstance(samples[index], dict) and samples[index].get("envelope") is True:
                    envelopes += 1
                    self.assertNotIsInstance(event["message"], str, f"{path} sample {index}")
        self.assertGreaterEqual(envelopes, 10)


if __name__ == "__main__":
    unittest.main()
