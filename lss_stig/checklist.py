"""CKLB export — the STIG Viewer 3 checklist format.

Every rule in the benchmark is written, not just the automated ones, so the
file drops straight into STIG Viewer / eMASS workflows as a complete
checklist: automated rules carry a status and the evidence we collected in
finding_details; the rest arrive as not_reviewed for the assessor.
"""

from __future__ import annotations

import json
import socket
import uuid
from pathlib import Path

from lss_stig import __version__
from lss_stig.lib.registry import Benchmark

CKLB_STATUS = {
    "pass": "not_a_finding",
    "fail": "open",
    "manual": "open",
    "review": "not_reviewed",
    "na": "not_applicable",
    "unimpl": "not_reviewed",
}

_RULE_TEXT_FIELDS = (
    "group_title", "rule_version", "rule_title", "severity", "weight", "fix_text",
    "check_content", "discussion", "false_positives", "false_negatives", "documentable",
    "mitigations", "potential_impacts", "third_party_tools", "mitigation_control",
    "responsibility", "security_override_guidance", "ia_controls",
)


def _default_iface() -> str | None:
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if len(f) > 1 and f[1] == "00000000":
                return f[0]
    except OSError:
        pass
    return None


def target_data() -> dict:
    host = socket.gethostname()
    ip = mac = ""
    try:
        # UDP connect sends nothing; it just picks the outbound interface.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ip = s.getsockname()[0]
    except OSError:
        pass
    iface = _default_iface()
    if iface:
        try:
            mac = Path(f"/sys/class/net/{iface}/address").read_text().strip().upper()
        except OSError:
            pass
    return {
        "target_type": "Computing",
        "host_name": host,
        "ip_address": ip,
        "mac_address": mac,
        "fqdn": socket.getfqdn(),
        "comments": "",
        "role": "None",
        "is_web_database": False,
        "technology_area": "",
        "web_db_site": "",
        "web_db_instance": "",
        "classification": None,
    }


def build(bench: Benchmark, results: dict[str, dict], target: dict | None = None,
          title: str | None = None) -> dict:
    """results: {vuln_id: {"status", "detail", "evidence"}} (missing → not reviewed)."""
    stig_uuid = str(uuid.uuid4())
    rules = []
    for rule in bench.rules:
        raw = rule.raw
        res = results.get(rule.vuln_id, {"status": "unimpl"})
        status = res.get("status", "unimpl")
        details = res.get("detail", "")
        if res.get("evidence"):
            details = (details + "\n\n" if details else "") + res["evidence"]
        comment = (f"lss-stig {__version__}: not automated — assess manually"
                   if status == "unimpl" else
                   f"lss-stig {__version__}: automated check ({status})")
        entry = {
            "uuid": str(uuid.uuid4()),
            "stig_uuid": stig_uuid,
            "target_key": None,
            "stig_ref": None,
            "group_id": rule.vuln_id,
            "group_id_src": rule.vuln_id,
            "rule_id": rule.rule_id.removesuffix("_rule"),
            "rule_id_src": rule.rule_id,
            "classification": "UNCLASSIFIED",
            "check_content_ref": raw.get("check_content_ref", {"href": "", "name": "M"}),
            "legacy_ids": raw.get("legacy_ids", []),
            "ccis": raw.get("ccis", []),
            "group_tree": [{"id": rule.vuln_id, "title": raw.get("group_title", ""),
                            "description": "<GroupDescription></GroupDescription>"}],
            "reference_identifier": raw.get("reference_identifier", ""),
            "status": CKLB_STATUS.get(status, "not_reviewed"),
            "overrides": {},
            "comments": comment,
            "finding_details": details,
        }
        for k in _RULE_TEXT_FIELDS:
            entry[k] = raw.get(k, "")
        rules.append(entry)

    return {
        "title": title or f"{bench.label} — {socket.gethostname()}",
        "id": str(uuid.uuid4()),
        "stigs": [{
            "stig_name": bench.stig_name,
            "display_name": bench.stig_name.replace(" Security Technical Implementation Guide", ""),
            "stig_id": bench.stig_id,
            "release_info": bench.release_info,
            "version": bench.version,
            "uuid": stig_uuid,
            "reference_identifier": bench.rules[0].raw.get("reference_identifier", "") if bench.rules else "",
            "size": len(rules),
            "rules": rules,
        }],
        "active": False,
        "mode": 1,
        "has_path": True,
        "target_data": target if target is not None else target_data(),
        "cklb_version": "1.0",
    }


def write(data: dict, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    return path
