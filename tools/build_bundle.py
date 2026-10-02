#!/usr/bin/env python3
"""Build the offline release artifacts for air-gapped hosts.

  tools/build_bundle.py                 # dist/: .deb, .pyz, SHA256SUMS
  tools/build_bundle.py --owner         # dist/owner/: unlicensed build for the
                                        # copyright holder's own test media

Artifacts:
  lss-stig_<ver>_all.deb   Debian/Ubuntu package: /usr/bin/lss-stig, code in
                           /usr/lib/lss-stig. Depends only on python3.
  lss-stig-<ver>.pyz       Single file; run with `sudo python3 lss-stig-<ver>.pyz`.
  SHA256SUMS               Checksums, for verifying the copy on the far side.

An owner build has the license gate off. Its file names and banner say
UNLICENSED; never publish one.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lss_stig import __version__  # noqa: E402

# Runs as root: -E ignores PYTHON* variables, -s skips user site-packages,
# -B keeps .pyc files out of the package directory so dpkg removes it cleanly.
WRAPPER = """#!/bin/sh
exec /usr/bin/python3 -E -s -B -c '
import sys
sys.path.insert(0, "/usr/lib/lss-stig")
sys.argv[0] = "lss-stig"
from lss_stig.cli import main
main()
' "$@"
"""

CONTROL = """Package: lss-stig
Version: {version}
Architecture: all
Maintainer: {maintainer}
Depends: python3 (>= 3.10)
Section: admin
Priority: optional
Description: audit, harden and roll back hosts against DISA STIGs
 LSS STIG audits a host against the DISA STIG for its distribution,
 applies the automatic fixes it can make safely, journals every change
 so it can be rolled back, and writes STIG Viewer (CKLB) checklists.
 Standard library only, for air-gapped hosts.
"""


def _stage_package(dest: Path, owner: bool) -> None:
    shutil.copytree(ROOT / "lss_stig", dest / "lss_stig",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    if owner:
        (dest / "lss_stig" / "_edition.py").write_text(
            '# Owner build: license gate off. Never publish.\nEDITION = "owner"\n')


def _maintainer() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10: no tomllib; read the authors line directly
        m = re.search(r'authors\s*=\s*\[\s*\{\s*name\s*=\s*"([^"]+)"\s*,\s*email\s*=\s*"([^"]+)"', text)
        return f"{m.group(1)} <{m.group(2)}>"
    author = tomllib.loads(text)["project"]["authors"][0]
    return f"{author['name']} <{author['email']}>"


def build_pyz(out: Path, owner: bool, name: str) -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        _stage_package(Path(tmp), owner)
        target = out / f"{name}-{__version__}.pyz"
        zipapp.create_archive(tmp, target, interpreter="/usr/bin/env python3",
                              main="lss_stig.cli:main", compressed=True)
    return target


def build_deb(out: Path, owner: bool, name: str) -> Path:
    version = f"{__version__}+owner" if owner else __version__
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "pkg"
        lib = root / "usr/lib/lss-stig"
        lib.mkdir(parents=True)
        _stage_package(lib, owner)
        (root / "usr/bin").mkdir(parents=True)
        (root / "usr/bin/lss-stig").write_text(WRAPPER)
        doc = root / "usr/share/doc/lss-stig"
        doc.mkdir(parents=True)
        shutil.copy(ROOT / "LICENSE", doc / "copyright")
        shutil.copy(ROOT / "README.md", doc / "README.md")
        if (ROOT / "CHANGELOG.md").exists():
            shutil.copy(ROOT / "CHANGELOG.md", doc / "CHANGELOG.md")
        for p in root.rglob("*"):
            os.chmod(p, 0o755 if p.is_dir() else 0o644)
        os.chmod(root / "usr/bin/lss-stig", 0o755)

        sums = []
        for p in sorted(x for x in root.rglob("*") if x.is_file()):
            sums.append(f"{hashlib.md5(p.read_bytes()).hexdigest()}  {p.relative_to(root)}\n")
        debian = root / "DEBIAN"
        debian.mkdir(mode=0o755)
        (debian / "control").write_text(CONTROL.format(version=version, maintainer=_maintainer()))
        (debian / "md5sums").write_text("".join(sums))
        for p in debian.iterdir():
            os.chmod(p, 0o644)

        target = out / f"{name}_{version}_all.deb"
        subprocess.run(["dpkg-deb", "--root-owner-group", "-Zxz", "--build", str(root), str(target)],
                       check=True, stdout=subprocess.DEVNULL)
    return target


def write_sums(out: Path, files: list[Path]) -> Path:
    lines = [f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n" for f in files]
    target = out / "SHA256SUMS"
    target.write_text("".join(lines))
    return target


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--owner", action="store_true", help="unlicensed build for your own test media")
    p.add_argument("--out", type=Path, help="output directory (default: dist/, or dist/owner/ with --owner)")
    p.add_argument("--no-deb", action="store_true", help="skip the .deb (no dpkg-deb on this machine)")
    a = p.parse_args()

    out = a.out or (ROOT / "dist" / ("owner" if a.owner else ""))
    out.mkdir(parents=True, exist_ok=True)
    name = "lss-stig-OWNER-UNLICENSED" if a.owner else "lss-stig"
    built = [build_pyz(out, a.owner, name)]
    if not a.no_deb:
        if not shutil.which("dpkg-deb"):
            print("dpkg-deb not found; use --no-deb or build on Debian/Ubuntu", file=sys.stderr)
            return 1
        built.append(build_deb(out, a.owner, name))
    built.append(write_sums(out, built))
    for f in built:
        print(f"{f}  ({f.stat().st_size // 1024} KiB)")
    if a.owner:
        print("OWNER BUILD: license gate is off. Keep it on your own media; never publish it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
