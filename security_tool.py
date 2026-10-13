"""Shared validation, findings, suppressions and reporting for defensive tools."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO 8601 string with a timezone")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamps require a timezone")
    return result.astimezone(timezone.utc)


def object_value(value, label="input"):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def records(data, key, required=()):
    object_value(data)
    rows = data.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"{key} must be an array")
    for index, row in enumerate(rows):
        object_value(row, f"{key}[{index}]")
        if any(field not in row for field in required):
            raise ValueError(f"{key}[{index}] is missing required fields: {', '.join(required)}")
    return rows


def text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def boolean(value, label):
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def number(value, label, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number")
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{label} is outside the permitted range")
    return value


def string_list(value, label):
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label} must be an array of non-empty strings")
    return value


def setting(policy, key, default, minimum=0, maximum=None):
    return number(policy.get(key, default), f"policy.{key}", minimum, maximum)


def finding(rule, severity, resource, title, evidence, remediation, **extra):
    if severity not in SEVERITIES:
        raise ValueError("unknown finding severity")
    resource = str(resource)
    stable = json.dumps([TOOL, rule, resource, extra.get("subject", "")], ensure_ascii=False)
    result = {"rule": rule, "severity": severity, "resource": resource,
              "title": title, "evidence": evidence, "remediation": remediation,
              "fingerprint": hashlib.sha256(stable.encode()).hexdigest()[:24]}
    result.update(extra)
    return result


def unique_rows(rows, key):
    result = {}
    for row in rows:
        identifier = text(row[key], key)
        if identifier in result:
            raise ValueError(f"duplicate {key} in inventory")
        result[identifier] = row
    return result


def decode_json(content):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("JSON contains a duplicate key")
            result[key] = value
        return result
    return json.loads(content, object_pairs_hook=reject_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON number")))


def load_json(path):
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("JSON input exceeds the 10 MiB limit")
    return decode_json(path.read_text(encoding="utf-8-sig"))


def build_report(findings, suppressions=(), now=None):
    now = now or datetime.now(timezone.utc)
    active, suppressed = [], []
    fingerprints = set()
    for suppression in suppressions:
        object_value(suppression, "suppression")
        text(suppression.get("fingerprint"), "suppression fingerprint")
        text(suppression.get("reason"), "suppression reason")
        timestamp(suppression.get("expires"))
        if suppression["fingerprint"] in fingerprints:
            raise ValueError("duplicate suppression fingerprint")
        fingerprints.add(suppression["fingerprint"])
    known = {item["fingerprint"]: item for item in suppressions
             if timestamp(item["expires"]) > now}
    for item in findings:
        if item["fingerprint"] in known:
            suppressed.append({**item, "suppression_reason": known[item["fingerprint"]]["reason"]})
        else:
            active.append(item)
    active.sort(key=lambda item: (-SEVERITIES[item["severity"]], item["resource"], item["rule"], item["fingerprint"]))
    return {"tool": TOOL, "version": VERSION, "generated_at": now.isoformat(),
            "summary": dict(Counter(item["severity"] for item in active)),
            "findings": active, "suppressed": suppressed}


def sarif(report):
    rules = {item["rule"]: item["title"] for item in report["findings"]}
    results = []
    for item in report["findings"]:
        results.append({"ruleId": item["rule"],
                        "level": "error" if SEVERITIES[item["severity"]] >= 3 else "warning" if SEVERITIES[item["severity"]] >= 1 else "note",
                        "message": {"text": item["title"] + ". " + item["remediation"]},
                        "locations": [{"logicalLocations": [{"name": item["resource"]}]}],
                        "partialFingerprints": {"securityToolFingerprint/v1": item["fingerprint"]},
                        "properties": {"severity": item["severity"], "evidence": item["evidence"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": TOOL, "version": VERSION,
                       "rules": [{"id": key, "shortDescription": {"text": title}} for key, title in sorted(rules.items())]}},
                       "results": results}]}


def markdown(report):
    def escape(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    lines = [f"# {TOOL} report", "", f"Version: {VERSION}. Findings: {len(report['findings'])}.", "",
             "| Severity | Resource | Finding | Recommended action |", "|---|---|---|---|"]
    for item in report["findings"]:
        lines.append("| " + " | ".join(escape(item[key]) for key in ("severity", "resource", "title", "remediation")) + " |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("input", nargs="?", type=Path, help="JSON inventory, event export or tool configuration")
    parser.add_argument("--demo", action="store_true", help="run the embedded synthetic example")
    parser.add_argument("--policy", type=Path, help="JSON object overriding documented defaults")
    parser.add_argument("--suppressions", type=Path, help="JSON array: fingerprint, reason, expires")
    parser.add_argument("--format", choices=["json", "sarif", "markdown"], default="json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=list(SEVERITIES), default="high")
    parser.add_argument("--now", help="timezone-aware ISO timestamp for reproducible reviews")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if args.demo == bool(args.input):
        parser.error("provide exactly one of input or --demo")
    try:
        now = timestamp(args.now) if args.now else datetime.now(timezone.utc)
        data = object_value(json.loads(json.dumps(DEMO)) if args.demo else load_json(args.input))
        policy = object_value(load_json(args.policy), "policy") if args.policy else {}
        suppressions = load_json(args.suppressions) if args.suppressions else []
        if not isinstance(suppressions, list):
            raise ValueError("suppressions must be an array")
        report = build_report(audit(data, policy, now), suppressions, now)
        content = markdown(report) if args.format == "markdown" else json.dumps(sarif(report) if args.format == "sarif" else report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            # Exclusive creation keeps earlier evidence from being overwritten.
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(content)
        else:
            print(content, end="")
        return int(any(SEVERITIES[item["severity"]] >= SEVERITIES[args.fail_on] for item in report["findings"]))
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        parser.exit(2, f"error: {type(exc).__name__}: {exc}\n")
import ipaddress

TOOL = "network-segmentation-auditor"
DESCRIPTION = "Evaluate ordered firewall rules, segmentation test flows and fully shadowed rules."
DEMO = {"rules": [{"id": "wide-admin", "source": "0.0.0.0/0", "destination": "10.0.0.0/8",
                   "protocol": "tcp", "ports": [[1, 65535]], "action": "allow"},
                  {"id": "deny-admin", "source": "0.0.0.0/0", "destination": "10.0.0.0/8",
                   "protocol": "tcp", "ports": [22], "action": "deny"}],
        "flows": [{"id": "public-to-admin", "source": "192.0.2.20", "destination": "10.1.0.10",
                   "protocol": "tcp", "port": 22, "expected": "deny"}]}


def port_ranges(values):
    if not isinstance(values, list) or not values:
        raise ValueError("ports must be a non-empty array of ports or inclusive ranges")
    result = []
    for value in values:
        pair = [value, value] if isinstance(value, int) and not isinstance(value, bool) else value
        if not isinstance(pair, list) or len(pair) != 2:
            raise ValueError("invalid port range")
        low, high = pair
        if any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in pair) or low > high:
            raise ValueError("ports must be ordered integers in 1..65535")
        result.append((low, high))
    merged = []
    for low, high in sorted(result):
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(high, merged[-1][1]))
        else:
            merged.append((low, high))
    return merged


def compile_rules(data):
    rules = list(unique_rows(records(data, "rules", ("id", "source", "destination", "protocol", "ports", "action")), "id").values())
    for rule in rules:
        if rule["protocol"] not in {"tcp", "udp", "any"} or rule["action"] not in {"allow", "deny"}:
            raise ValueError("unsupported protocol or action")
        rule["source_net"] = ipaddress.ip_network(rule["source"], strict=False)
        rule["destination_net"] = ipaddress.ip_network(rule["destination"], strict=False)
        if rule["source_net"].version != rule["destination_net"].version:
            raise ValueError("source and destination networks must use the same IP family")
        rule["ranges"] = port_ranges(rule["ports"])
    return rules


def flow_decision(rules, flow):
    source, destination = ipaddress.ip_address(flow["source"]), ipaddress.ip_address(flow["destination"])
    if source.version != destination.version:
        raise ValueError("flow source and destination must use the same IP family")
    port = number(flow["port"], "flow.port", 1, 65535)
    if not isinstance(port, int) or flow["protocol"] not in {"tcp", "udp"}:
        raise ValueError("flow requires an integer port and tcp or udp protocol")
    for rule in rules:
        if source in rule["source_net"] and destination in rule["destination_net"] and rule["protocol"] in {flow["protocol"], "any"}:
            if any(low <= port <= high for low, high in rule["ranges"]):
                return rule["action"], rule["id"]
    return "deny", "implicit-default-deny"


def covers(previous, current):
    if previous["source_net"].version != current["source_net"].version:
        return False
    return (current["source_net"].subnet_of(previous["source_net"]) and
            current["destination_net"].subnet_of(previous["destination_net"]) and
            previous["protocol"] in {current["protocol"], "any"} and
            all(any(plow <= low and high <= phigh for plow, phigh in previous["ranges"]) for low, high in current["ranges"]))


def audit(data, policy, now):
    rules = compile_rules(json.loads(json.dumps(data)))
    flows = unique_rows(records(data, "flows", ("id", "source", "destination", "protocol", "port", "expected")), "id")
    admin_ports = policy.get("administrative_ports", [22, 3389, 5985, 5986])
    if not isinstance(admin_ports, list) or any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in admin_ports):
        raise ValueError("administrative_ports must be an array of valid integer ports")
    result = []
    for index, rule in enumerate(rules):
        earlier = next((previous for previous in rules[:index] if covers(previous, rule)), None)
        if earlier:
            result.append(finding("NET-SHADOWED-RULE", "medium", rule["id"], "Rule is fully covered by an earlier rule",
                                  {"earlier_rule": earlier["id"], "earlier_action": earlier["action"]},
                                  "Review ordering and remove or relocate unreachable rules."))
        exposed = [port for port in admin_ports if any(low <= port <= high for low, high in rule["ranges"])]
        if not earlier and rule["action"] == "allow" and rule["source_net"].prefixlen == 0 and exposed:
            result.append(finding("NET-PUBLIC-ADMIN", "high", rule["id"], "Catch-all source can reach administrative ports",
                                  {"ports": exposed, "destination": rule["destination"]},
                                  "Constrain source networks and administrative access paths; validate earlier partial denies."))
    for identifier, flow in flows.items():
        if flow["expected"] not in {"allow", "deny"}:
            raise ValueError("flow.expected must be allow or deny")
        decision, matched = flow_decision(rules, flow)
        if decision != flow["expected"]:
            result.append(finding("NET-SEGMENTATION-MISMATCH", "high" if decision == "allow" else "low", identifier,
                                  "Firewall decision differs from the segmentation test", {"expected": flow["expected"], "actual": decision, "matched_rule": matched},
                                  "Review the intended segmentation boundary and the first matching rule."))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
