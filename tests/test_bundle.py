import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("build_bundle", ROOT / "tools" / "build_bundle.py")
bb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bb)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_pyz(self, pyz, *args):
        return subprocess.run([sys.executable, str(pyz), *args], capture_output=True, text=True, timeout=120)

    def test_pyz_runs_and_reads_benchmark_from_zip(self):
        pyz = bb.build_pyz(self.out, False, "lss-stig")
        self.assertIn(bb.__version__, self.run_pyz(pyz, "--version").stdout)
        r = self.run_pyz(pyz, "list", "--cat", "I")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("194 rules", r.stdout)

    def test_owner_build_is_marked_and_ungated(self):
        pyz = bb.build_pyz(self.out, True, "lss-stig-OWNER-UNLICENSED")
        code = ("import sys; sys.path.insert(0, sys.argv[1]); "
                "from lss_stig import _edition; from lss_stig.lib import license; "
                "print(_edition.EDITION, license.check().valid)")
        r = subprocess.run([sys.executable, "-c", code, str(pyz)], capture_output=True, text=True)
        self.assertEqual(r.stdout.split(), ["owner", "True"], r.stderr)

    def test_release_build_keeps_gate(self):
        pyz = bb.build_pyz(self.out, False, "lss-stig")
        code = "import sys; sys.path.insert(0, sys.argv[1]); from lss_stig import _edition; print(_edition.EDITION)"
        r = subprocess.run([sys.executable, "-c", code, str(pyz)], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "commercial")

    @unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb not installed")
    def test_deb_layout(self):
        deb = bb.build_deb(self.out, False, "lss-stig")
        listing = subprocess.run(["dpkg-deb", "-c", str(deb)], capture_output=True, text=True).stdout
        self.assertRegex(listing, r"-rwxr-xr-x root/root .* \./usr/bin/lss-stig")
        self.assertIn("./usr/lib/lss-stig/lss_stig/benchmarks/ubuntu2404_v1r6.json", listing)
        self.assertNotIn("__pycache__", listing)
        info = subprocess.run(["dpkg-deb", "-f", str(deb), "Package", "Version", "Depends"],
                              capture_output=True, text=True).stdout
        self.assertIn("Package: lss-stig", info)
        self.assertIn(f"Version: {bb.__version__}", info)


if __name__ == "__main__":
    unittest.main()
