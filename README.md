# Network Segmentation Auditor

Firewall rule analysis with first-match decisions, IPv4/IPv6 segmentation tests, administrative-port exposure and fully shadowed rule detection.

Test a proposed ordered firewall policy against explicit expected traffic decisions.

**Python 3.11+ · Standard library · JSON, SARIF 2.1.0 and Markdown reports · MIT license**

## Quick start

```bash
git clone https://github.com/bajily/network-segmentation-auditor.git
cd network-segmentation-auditor
python security_tool.py --demo --now 2026-10-13T12:00:00Z
python -m unittest discover -v
```

The synthetic example intentionally contains risky conditions. Exit status `1` means a finding met the configured threshold; it is not a crash.

```bash
python security_tool.py example.json --format sarif --output findings.sarif
python security_tool.py example.json --format markdown --output review.md --fail-on critical
python security_tool.py example.json --policy policy.json --suppressions exceptions.json
```

## How the review works

Test a proposed ordered firewall policy against explicit expected traffic decisions.

Implemented rule families: `NET-PUBLIC-ADMIN`, `NET-SEGMENTATION-MISMATCH`, `NET-SHADOWED-RULE`.

Each finding includes a rule ID, severity, resource, evidence, a recommended review action and a stable fingerprint. Reports sort findings by severity and resource. No automatic enforcement is performed.

## Input contract

The example below is the minimal supported export structure. Required fields are validated; malformed or ambiguous inputs cause exit status 2.



```json
{
  "rules": [
    {
      "id": "wide-admin",
      "source": "0.0.0.0/0",
      "destination": "10.0.0.0/8",
      "protocol": "tcp",
      "ports": [
        [
          1,
          65535
        ]
      ],
      "action": "allow"
    },
    {
      "id": "deny-admin",
      "source": "0.0.0.0/0",
      "destination": "10.0.0.0/8",
      "protocol": "tcp",
      "ports": [
        22
      ],
      "action": "deny"
    }
  ],
  "flows": [
    {
      "id": "public-to-admin",
      "source": "192.0.2.20",
      "destination": "10.1.0.10",
      "protocol": "tcp",
      "port": 22,
      "expected": "deny"
    }
  ]
}
```

Identifiers in examples are synthetic. Adapt exports to this exact shape instead of assuming provider APIs use identical field names.

## Policy and integration

Policy defaults and the input fields are documented below and in the audit function. Review thresholds before operational use.

```json
{
  "administrative_ports": [
    22,
    3389,
    5985,
    5986
  ]
}
```

The empty object selects defaults. Every input file is limited to 10 MiB. Duplicate JSON keys and non-finite numbers are rejected. Timestamps require explicit timezones. `--now` makes time-dependent reviews reproducible.

Exit statuses: `0` means no active finding meets `--fail-on`; `1` means the threshold is met; `2` means invalid input or an operational error. Output files are created exclusively and existing evidence is not overwritten. A clean report does not establish that a system is secure.

## Reviewed exceptions

Use a finding's exact fingerprint, an explanation and an expiration date:

```json
[
  {"fingerprint": "COPY-A-FINDING-FINGERPRINT", "reason": "Approved temporary exception; ticket SEC-123", "expires": "2027-01-01T00:00:00Z"}
]
```

Expired exceptions stop suppressing findings. Suppressed findings remain in JSON evidence. Keep exception review separate from code changes.

## Validation and deployment limits

Unit tests exercise the detector, clean inputs, boundary conditions, report generation, input failures and exception expiry. GitHub Actions runs the suite on Python 3.11 and 3.14.

The model is an ordered stateless ACL with implicit default deny. It does not simulate NAT, stateful sessions, routing, vendor object groups or multiple-device paths. Public-admin findings are rule candidates; earlier partial denies must be reviewed.

Version 0.1.0 is an initial implementation for controlled evaluation. Establish a company-specific baseline, test representative sanitized exports, review false positives and perform an independent security review before relying on it operationally. These projects have no measured production performance or effectiveness claims.

## Security and contributions

Keep secrets, private inventories, real email, signing keys and sensitive logs out of public issues and repositories. Publish only synthetic or sanitized fixtures. Findings and generated reports can contain private asset identifiers; protect them as internal security records.

For a suspected vulnerability, use GitHub private reporting if available. Otherwise describe the issue without secrets or sensitive exploit details. Include a reproducible synthetic test with focused changes, and run the test suite before proposing a contribution.

## بالعربية

أداة دفاعية لتحليل الأدلة الأمنية وإنتاج نتائج قابلة للمراجعة مع قواعد واضحة واختبارات. تعمل على مدخلات موثقة وتدعم ضبط السياسات والاستثناءات المؤقتة. يلزم تقييمها على بيئة الشركة قبل الاعتماد التشغيلي؛ لا تقدّم ضمانًا شاملًا لحماية الأنظمة.
