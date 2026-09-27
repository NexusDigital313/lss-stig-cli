#!/usr/bin/env python3
"""Convert a DISA STIG XCCDF (manual) benchmark into an lss-stig catalog.

The catalog is the single source of truth for rule metadata — IDs, severity,
titles, check/fix text, CCIs. Control implementations only carry logic and
look everything else up here, so a new STIG release is a re-import plus a
diff review, not a rewrite.

Usage:
    python3 tools/import_xccdf.py U_CAN_Ubuntu_24-04_LTS_V1R6_Manual-xccdf.xml \
        lss_stig/benchmarks/ubuntu2404_v1r6.json
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

NS = {
    "x": "http://checklists.nist.gov/xccdf/1.1",
    "dc": "http://purl.org/dc/elements/1.1/",
}

# Pseudo-XML tags DISA embeds (escaped) inside each Rule <description>.
_DESC_TAGS = {
    "VulnDiscussion": "discussion",
    "FalsePositives": "false_positives",
    "FalseNegatives": "false_negatives",
    "Documentable": "documentable",
    "Mitigations": "mitigations",
    "SeverityOverrideGuidance": "security_override_guidance",
    "PotentialImpacts": "potential_impacts",
    "ThirdPartyTools": "third_party_tools",
    "MitigationControl": "mitigation_control",
    "Responsibility": "responsibility",
    "IAControls": "ia_controls",
}


def _text(el) -> str:
    return (el.text or "") if el is not None else ""


def _parse_description(raw: str) -> dict[str, str]:
    out = {v: "" for v in _DESC_TAGS.values()}
    for tag, key in _DESC_TAGS.items():
        m = re.search(rf"<{tag}>(.*?)</{tag}>", raw, re.S)
        if m:
            out[key] = m.group(1).strip()
    return out


def convert(xccdf_path: Path) -> dict:
    root = ET.parse(xccdf_path).getroot()

    release_info = ""
    for pt in root.findall("x:plain-text", NS):
        if pt.get("id") == "release-info":
            release_info = _text(pt)
    status = root.find("x:status", NS)

    rules = []
    for group in root.findall("x:Group", NS):
        rule = group.find("x:Rule", NS)
        check = rule.find("x:check", NS)
        ccref = check.find("x:check-content-ref", NS) if check is not None else None
        target = rule.find("x:reference/dc:identifier", NS)
        entry = {
            "group_id": group.get("id"),
            "group_title": _text(group.find("x:title", NS)),
            "rule_id_src": rule.get("id"),
            "rule_version": _text(rule.find("x:version", NS)),
            "rule_title": _text(rule.find("x:title", NS)),
            "severity": rule.get("severity"),
            "weight": rule.get("weight", "10.0"),
            "check_content": _text(check.find("x:check-content", NS)) if check is not None else "",
            "check_content_ref": {
                "href": ccref.get("href", "") if ccref is not None else "",
                "name": ccref.get("name", "M") if ccref is not None else "M",
            },
            "fix_text": _text(rule.find("x:fixtext", NS)),
            "ccis": [_text(i) for i in rule.findall("x:ident", NS) if "cci" in (i.get("system") or "")],
            "legacy_ids": [_text(i) for i in rule.findall("x:ident", NS) if "legacy" in (i.get("system") or "")],
            "reference_identifier": _text(target),
        }
        entry.update(_parse_description(_text(rule.find("x:description", NS))))
        rules.append(entry)

    return {
        "stig_id": root.get("id"),
        "stig_name": _text(root.find("x:title", NS)),
        "version": _text(root.find("x:version", NS)),
        "release_info": release_info,
        "status_date": status.get("date") if status is not None else "",
        "source_sha256": hashlib.sha256(xccdf_path.read_bytes()).hexdigest(),
        "rules": rules,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    data = convert(Path(argv[1]))
    Path(argv[2]).write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n")
    sev = {}
    for r in data["rules"]:
        sev[r["severity"]] = sev.get(r["severity"], 0) + 1
    print(f"{data['stig_name']} — {data['release_info']}: {len(data['rules'])} rules {sev}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
