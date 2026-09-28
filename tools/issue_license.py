#!/usr/bin/env python3
"""Vendor tool: issue offline lss-stig license files.

  # once — creates the signing key; keep it offline and backed up
  tools/issue_license.py keygen --out ~/lss-stig-signing.key

  # per customer
  tools/issue_license.py issue --key ~/lss-stig-signing.key \\
      --licensee "Example Program Office" --tier Enclave \\
      --host 1A2B-3C4D-5E6F-7A8B --host ... --expires 2027-09-30 \\
      --out example.lic

Hosts come from `lss-stig license id` on each customer machine. Omit --host
for a site license that is valid on any host; omit --expires for perpetual.
The public half of the key must match OFFLINE_PUBLIC_KEY in
lss_stig/lib/license.py (`keygen` prints it).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import uuid
from datetime import date, datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lss_stig.lib import ed25519  # noqa: E402


def keygen(out: Path) -> int:
    if out.exists():
        print(f"refusing to overwrite {out}", file=sys.stderr)
        return 1
    secret = os.urandom(32)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secret.hex() + "\n")
    print(f"signing key written to {out} (mode 0600) — keep it off shared machines")
    print(f"OFFLINE_PUBLIC_KEY = {ed25519.public_key(secret).hex()}")
    return 0


def issue(a) -> int:
    from lss_stig.lib import license  # only here: keygen must run before a key is set

    secret = bytes.fromhex(Path(a.key).read_text().strip())
    if ed25519.public_key(secret) != license.OFFLINE_PUBLIC_KEY:
        print("this signing key does not match OFFLINE_PUBLIC_KEY in lss_stig/lib/license.py", file=sys.stderr)
        return 1
    for h in a.host or []:
        if not re.fullmatch(r"[0-9A-F]{4}(-[0-9A-F]{4}){3}", h):
            print(f"bad host ID {h!r} (expected XXXX-XXXX-XXXX-XXXX from `lss-stig license id`)", file=sys.stderr)
            return 2
    if a.expires:
        date.fromisoformat(a.expires)
    payload = {
        "product": "lss-stig",
        "id": str(uuid.uuid4()),
        "licensee": a.licensee,
        "tier": a.tier,
        "hosts": sorted(set(a.host or [])),
        "expires": a.expires or "",
        "issued": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }
    text = license.encode_offline(payload, ed25519.sign(secret, license.signing_bytes(payload)))
    assert license.parse_offline(text)[0] == payload
    Path(a.out).write_text(text)
    scope = f"{len(payload['hosts'])} host(s)" if payload["hosts"] else "any host"
    print(f"{a.out}: {a.licensee} · {a.tier} · {scope} · expires {a.expires or 'never'} · id {payload['id']}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--out", required=True, type=Path)
    i = sub.add_parser("issue")
    i.add_argument("--key", required=True)
    i.add_argument("--licensee", required=True)
    i.add_argument("--tier", default="Enclave")
    i.add_argument("--host", action="append")
    i.add_argument("--expires")
    i.add_argument("--out", required=True)
    a = p.parse_args()
    return keygen(a.out) if a.cmd == "keygen" else issue(a)


if __name__ == "__main__":
    sys.exit(main())
