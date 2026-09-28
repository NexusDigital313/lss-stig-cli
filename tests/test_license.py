import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest import mock

from lss_stig import _edition
from lss_stig.lib import ed25519, license

SECRET = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_vector_1(self):
        sig = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
               "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertEqual(ed25519.public_key(SECRET), PUBLIC)
        self.assertEqual(ed25519.sign(SECRET, b"").hex(), sig)
        self.assertTrue(ed25519.verify(PUBLIC, b"", bytes.fromhex(sig)))
        self.assertFalse(ed25519.verify(PUBLIC, b"x", bytes.fromhex(sig)))

    def test_shipped_key_is_a_valid_point(self):
        self.assertEqual(len(license.OFFLINE_PUBLIC_KEY), 32)
        self.assertIsNotNone(ed25519._decompress(license.OFFLINE_PUBLIC_KEY))


def make(payload, secret=SECRET):
    return license.encode_offline(payload, ed25519.sign(secret, license.signing_bytes(payload)))


BASE = {"product": "lss-stig", "id": "x", "licensee": "Example PMO", "tier": "Enclave",
        "hosts": [], "expires": "", "issued": "2026-09-28"}


class Isolated(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.patches = [
            mock.patch.object(license, "OFFLINE_PUBLIC_KEY", PUBLIC),
            mock.patch.object(license, "CONF_DIR", d),
            mock.patch.object(license, "OFFLINE_PATH", d / "license.lic"),
            mock.patch.object(_edition, "EDITION", "commercial"),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()


class OfflineTests(Isolated):
    def test_valid_site_license(self):
        st = license.install_offline(make(BASE))
        self.assertTrue(st.valid, st.detail)
        self.assertTrue(license.OFFLINE_PATH.exists())
        self.assertEqual(license.OFFLINE_PATH.stat().st_mode & 0o777, 0o600)
        self.assertEqual(license.check().source, "offline-file")

    def test_tampered_payload_rejected(self):
        text = make(BASE)
        forged = make({**BASE, "licensee": "Mallory"}, secret=bytes(32))
        self.assertFalse(license.install_offline(forged).valid)
        body = text.replace(text.split("\n")[1], text.split("\n")[1][:-4] + "AAAA")
        self.assertFalse(license.install_offline(body).valid)
        self.assertFalse(license.OFFLINE_PATH.exists())

    def test_expiry_host_binding_and_product(self):
        self.assertIn("expired", license.install_offline(make({**BASE, "expires": "2020-01-01"})).detail)
        self.assertIn("not issued for this host",
                      license.install_offline(make({**BASE, "hosts": ["0000-0000-0000-0000"]})).detail)
        self.assertTrue(license.install_offline(make({**BASE, "hosts": [license.host_id()]})).valid)
        self.assertIn("different product", license.install_offline(make({**BASE, "product": "lss"})).detail)

    def test_expiry_is_inclusive(self):
        payload, _ = license.parse_offline(make({**BASE, "expires": "2027-01-01"}))
        self.assertTrue(license._offline_status(payload, date(2027, 1, 1)).valid)
        self.assertFalse(license._offline_status(payload, date(2027, 1, 2)).valid)

    def test_garbage(self):
        self.assertFalse(license.install_offline("hello").valid)
        self.assertFalse(license.install_offline(license._BEGIN + "!!" + license._SIG + "!!" + license._END).valid)


class GateTests(Isolated):
    def test_no_license(self):
        self.assertFalse(license.check().valid)

    def test_remove(self):
        self.assertFalse(license.remove().valid)
        license.install_offline(make(BASE))
        self.assertTrue(license.remove().valid)
        self.assertFalse(license.OFFLINE_PATH.exists())
        self.assertFalse(license.check().valid)

    def test_installed_file_that_went_bad(self):
        license.install_offline(make({**BASE, "expires": "2099-01-01"}))
        with mock.patch.object(license, "OFFLINE_PUBLIC_KEY", ed25519.public_key(bytes(32))):
            self.assertIn("signature", license.check().detail)

    def test_owner_build(self):
        with mock.patch.object(_edition, "EDITION", "owner"):
            self.assertEqual(license.check().source, "owner")

    def test_harden_confirm_gated_dry_run_free(self):
        from lss_stig import cli
        with mock.patch("os.geteuid", return_value=0), \
             mock.patch("lss_stig.benchmarks.for_host", return_value="ubuntu2404_v1r6"), \
             mock.patch("lss_stig.harden.run_harden", return_value=0) as run, \
             mock.patch.object(cli, "_survive_disconnect"), \
             mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit) as e:
                cli.main(["harden", "--confirm"])
            self.assertEqual(e.exception.code, 3)
            run.assert_not_called()
            with self.assertRaises(SystemExit) as e:
                cli.main(["harden", "--dry-run"])
            self.assertEqual(e.exception.code, 0)
            run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
