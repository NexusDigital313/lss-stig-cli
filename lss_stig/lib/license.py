"""License gate for `harden --confirm`.

Everything read-only stays free: audit, the CKLB checklist, list, site,
`harden --dry-run`. Rollback is never gated either: a customer whose license
lapsed must still be able to undo what the tool did to their host.

A license is an Ed25519-signed file issued by the vendor
(`lss-stig license install FILE`), verified locally with no network at all,
because STIG'd hosts are often air-gapped. It can be bound to specific hosts
(`lss-stig license id` prints the ID to send) and can carry an expiry date.

This is an honest gate for paying customers, not DRM: the source is readable.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import socket
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from lss_stig import _edition
from lss_stig.lib import ed25519

# Vendor's offline-license verification key (Ed25519, raw 32 bytes, hex).
# The matching private key never enters this repository.
OFFLINE_PUBLIC_KEY = bytes.fromhex("ce4c16a0929aa5d4f5823e556a8202c0c5c5103606ff1b35fbe6902dbb5de46a")

CONF_DIR = Path("/etc/lss-stig")
OFFLINE_PATH = CONF_DIR / "license.lic"

_BEGIN, _SIG, _END = "-----BEGIN LSS-STIG LICENSE-----", "-----SIGNATURE-----", "-----END LSS-STIG LICENSE-----"


@dataclass
class LicenseStatus:
    valid: bool
    detail: str = ""
    licensee: str = ""
    tier: str = ""
    source: str = ""        # owner | offline-file
    expires: str = ""


def owner_build() -> bool:
    return _edition.EDITION == "owner"


# ---- host identity (for host-bound offline licenses) -------------------------

def host_id() -> str:
    """Stable, non-reversible ID of this host, derived from /etc/machine-id."""
    try:
        mid = Path("/etc/machine-id").read_text().strip()
    except OSError:
        mid = ""
    if not mid:
        mid = socket.gethostname()
    h = hashlib.sha256(f"lss-stig:{mid}".encode()).hexdigest()[:16].upper()
    return "-".join(h[i:i + 4] for i in range(0, 16, 4))


# ---- offline license files ---------------------------------------------------

def encode_offline(payload: dict, signature: bytes) -> str:
    body = base64.b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).decode()
    wrap = lambda s: "\n".join(s[i:i + 64] for i in range(0, len(s), 64))
    return f"{_BEGIN}\n{wrap(body)}\n{_SIG}\n{wrap(base64.b64encode(signature).decode())}\n{_END}\n"


def signing_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def parse_offline(text: str) -> tuple[dict | None, str]:
    """(payload, '') for an authentic license, else (None, why)."""
    m = re.search(re.escape(_BEGIN) + r"(.*?)" + re.escape(_SIG) + r"(.*?)" + re.escape(_END), text, re.S)
    if not m:
        return None, "not an lss-stig license file"
    try:
        raw = base64.b64decode("".join(m.group(1).split()), validate=True)
        sig = base64.b64decode("".join(m.group(2).split()), validate=True)
        payload = json.loads(raw)
    except (binascii.Error, ValueError):
        return None, "license file is damaged"
    except RecursionError:
        return None, "license file is damaged"
    if not isinstance(payload, dict) or not ed25519.verify(OFFLINE_PUBLIC_KEY, signing_bytes(payload), sig):
        return None, "license signature is not valid"
    return payload, ""


def _offline_status(payload: dict, today: date | None = None) -> LicenseStatus:
    today = today or date.today()
    who, tier = str(payload.get("licensee", "")), str(payload.get("tier", ""))
    if payload.get("product") != "lss-stig":
        return LicenseStatus(False, "license is for a different product")
    exp = payload.get("expires") or ""
    if exp:
        try:
            if date.fromisoformat(exp) < today:
                return LicenseStatus(False, f"license expired on {exp}", licensee=who, tier=tier, expires=exp)
        except ValueError:
            return LicenseStatus(False, "license has an unreadable expiry date")
    hosts = payload.get("hosts") or []
    if hosts and host_id() not in hosts:
        return LicenseStatus(False, f"license is not issued for this host (host ID {host_id()})", licensee=who, tier=tier)
    return LicenseStatus(True, "license valid", licensee=who, tier=tier, source="offline-file", expires=exp)


def install_offline(text: str) -> LicenseStatus:
    payload, why = parse_offline(text)
    if payload is None:
        return LicenseStatus(False, why)
    st = _offline_status(payload)
    if st.valid:
        _write(OFFLINE_PATH, text if text.endswith("\n") else text + "\n")
    return st


def remove() -> LicenseStatus:
    if not OFFLINE_PATH.exists():
        return LicenseStatus(False, "no license on this host")
    OFFLINE_PATH.unlink()
    return LicenseStatus(True, "removed the license file from this host")


# ---- the gate ----------------------------------------------------------------

def check() -> LicenseStatus:
    if owner_build():
        return LicenseStatus(True, "owner build — license gate disabled", source="owner")
    if not OFFLINE_PATH.exists():
        return LicenseStatus(False, "no license on this host")
    try:
        text = OFFLINE_PATH.read_text(errors="replace")
    except OSError as exc:
        return LicenseStatus(False, f"cannot read {OFFLINE_PATH}: {exc.strerror}")
    payload, why = parse_offline(text)
    if payload is None:
        return LicenseStatus(False, why)
    return _offline_status(payload)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)
