#!/usr/bin/env python3
"""Rule 5 (canonical OCSF 1.9 paths) regression checks."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ocsf_event_checks import noncanonical_paths  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
