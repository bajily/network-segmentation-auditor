import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

import security_tool as tool

NOW = datetime(2026, 10, 13, 12, tzinfo=timezone.utc)


class ReportingTests(unittest.TestCase):
    def test_demo_generates_explainable_findings(self):
        results = tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)
        self.assertTrue(results)
        self.assertTrue(all(item['remediation'] and item['evidence'] for item in results))

    def test_fingerprints_are_deterministic(self):
        self.assertEqual(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW),
                         tool.audit(copy.deepcopy(tool.DEMO), {}, NOW))

    def test_active_and_expired_suppressions(self):
        rows = tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)
        item = {'fingerprint': rows[0]['fingerprint'], 'reason': 'Synthetic exception review',
                'expires': '2027-01-01T00:00:00Z'}
        self.assertEqual(len(tool.build_report(rows, [item], NOW)['suppressed']), 1)
        item['expires'] = '2026-01-01T00:00:00Z'
        self.assertEqual(len(tool.build_report(rows, [item], NOW)['suppressed']), 0)

    def test_invalid_exception_and_input(self):
        with self.assertRaises(ValueError):
            tool.build_report([], [{'fingerprint': 'x', 'reason': '', 'expires': 'bad'}], NOW)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            tool.audit({}, {}, NOW)
        duplicate = {'fingerprint': 'same', 'reason': 'Synthetic test exception', 'expires': '2027-01-01T00:00:00Z'}
        with self.assertRaises(ValueError):
            tool.build_report([], [duplicate, duplicate], NOW)

    def test_json_ambiguity_rejected(self):
        for content in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}']:
            with self.assertRaises(ValueError):
                tool.decode_json(content)

    def test_sarif_contains_rules_and_stable_fingerprints(self):
        report = tool.build_report(tool.audit(copy.deepcopy(tool.DEMO), {}, NOW), now=NOW)
        result = tool.sarif(report)
        self.assertEqual(result['version'], '2.1.0')
        self.assertEqual(len(result['runs'][0]['results']), len(report['findings']))
        self.assertTrue(all(x['partialFingerprints'] for x in result['runs'][0]['results']))

    def test_cli_demo_and_missing_input(self):
        script = Path(__file__).with_name('security_tool.py')
        result = subprocess.run([sys.executable, str(script), '--demo', '--now', NOW.isoformat()],
                                capture_output=True, text=True)
        self.assertIn(result.returncode, [0, 1], result.stderr)
        self.assertEqual(json.loads(result.stdout)['tool'], tool.TOOL)
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)

class NetworkTests(unittest.TestCase):
    def test_mixed_family_flow_rejected(self):
        data = copy.deepcopy(tool.DEMO)
        data['flows'][0]['destination'] = '2001:db8::1'
        with self.assertRaises(ValueError):
            tool.audit(data, {}, NOW)

    def test_first_matching_deny_wins(self):
        data = copy.deepcopy(tool.DEMO)
        data['rules'].reverse()
        rules = tool.compile_rules(data)
        self.assertEqual(tool.flow_decision(rules, data['flows'][0]), ('deny', 'deny-admin'))

    def test_implicit_default_deny(self):
        data = copy.deepcopy(tool.DEMO)
        data['rules'] = []
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_covered_rule_detected(self):
        self.assertIn('NET-SHADOWED-RULE', {x['rule'] for x in tool.audit(copy.deepcopy(tool.DEMO), {}, NOW)})

    def test_ranges_merge_and_boundaries(self):
        self.assertEqual(tool.port_ranges([22, [20, 21], [23, 30]]), [(20, 30)])
        with self.assertRaises(ValueError):
            tool.port_ranges([[40, 20]])

    def test_ipv6(self):
        data = {'rules': [{'id': 'v6', 'source': '::/0', 'destination': '2001:db8::/32', 'protocol': 'tcp', 'ports': [22], 'action': 'deny'}],
                'flows': [{'id': 'flow', 'source': '2001:db8:1::1', 'destination': '2001:db8:2::1', 'protocol': 'tcp', 'port': 22, 'expected': 'deny'}]}
        self.assertEqual(tool.audit(data, {}, NOW), [])

    def test_partial_overlap_not_fully_shadowed(self):
        data = copy.deepcopy(tool.DEMO)
        data['rules'][0]['ports'] = [443]
        self.assertNotIn('NET-SHADOWED-RULE', {x['rule'] for x in tool.audit(data, {}, NOW)})

    def test_mixed_families_rejected(self):
        data = copy.deepcopy(tool.DEMO)
        data['rules'][0]['destination'] = '::/0'
        with self.assertRaises(ValueError):
            tool.audit(data, {}, NOW)


if __name__ == "__main__":
    unittest.main()
