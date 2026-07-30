import io
import json
import os
import sys
import tempfile
import types
import unittest
import zipfile

from flask import Flask, request


def install_pwnagotchi_stubs():
    pwnagotchi = types.ModuleType("pwnagotchi")
    plugins = types.ModuleType("pwnagotchi.plugins")
    plugins.Plugin = object
    fonts = types.ModuleType("pwnagotchi.ui.fonts")
    fonts.Bold = object()
    fonts.Medium = object()
    components = types.ModuleType("pwnagotchi.ui.components")
    components.LabeledValue = object
    view = types.ModuleType("pwnagotchi.ui.view")
    view.BLACK = 0

    sys.modules["pwnagotchi"] = pwnagotchi
    sys.modules["pwnagotchi.plugins"] = plugins
    sys.modules["pwnagotchi.ui"] = types.ModuleType("pwnagotchi.ui")
    sys.modules["pwnagotchi.ui.fonts"] = fonts
    sys.modules["pwnagotchi.ui.components"] = components
    sys.modules["pwnagotchi.ui.view"] = view


install_pwnagotchi_stubs()

from A_pwmenu import A_pwmenu


class BackupTests(unittest.TestCase):
    """Portable unencrypted backup and restore coverage."""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.app = Flask(__name__)
        self.plugin = A_pwmenu()
        self.plugin.options = {
            "backup_max_bytes": 4 * 1024 * 1024,
        }
        root = self.tempdir.name
        handshakes = os.path.join(root, "handshakes")
        os.makedirs(handshakes)
        self.plugin.handshake_dirs = [handshakes]
        self.plugin.config_path = os.path.join(root, "config.toml")
        self.plugin.data_file = os.path.join(root, "state.json")
        self.plugin.ohc_export_file = os.path.join(root, "ohc-export.json")
        self.plugin.potfile_ohc = os.path.join(root, "ohc.potfile")
        self.plugin.potfile_handshake_lab = os.path.join(
            root, "lab.potfile"
        )
        self.plugin.potfile_manual = os.path.join(root, "manual.potfile")
        self.files = {
            self.plugin.config_path: b"[main]\nname='pwmenu'\n",
            self.plugin.data_file: json.dumps({
                "locations": {"capture.pcap": {"lat": 1, "lon": 2}}
            }).encode(),
            self.plugin.ohc_export_file: b'{"tasks":[]}',
            self.plugin.potfile_ohc: b"ohc-result\n",
            self.plugin.potfile_handshake_lab: b"lab-result\n",
            self.plugin.potfile_manual: b"manual-result\n",
            os.path.join(
                handshakes, "wpa-sec.cracked.potfile"
            ): b"wpa-result\n",
            os.path.join(
                handshakes, "capture.pcap.gps.json"
            ): b'{"lat":1,"lon":2}',
            os.path.join(
                handshakes, "capture.pcap"
            ): b"pcap-data",
        }
        for path, content in self.files.items():
            with open(path, "wb") as handle:
                handle.write(content)

    def test_backup_contains_a_versioned_manifest_and_expected_data(self):
        archive, count = self.plugin._build_backup_archive()
        self.assertGreaterEqual(count, 8)
        with zipfile.ZipFile(io.BytesIO(archive), "r") as backup:
            manifest = json.loads(backup.read("manifest.json"))
            self.assertEqual(
                manifest["format"], "newfpv-pwmenu-backup-v1"
            )
            names = {entry["name"] for entry in manifest["files"]}
            self.assertIn("config/config.toml", names)
            self.assertIn("state/a_pwmenu_data.json", names)
            self.assertIn(
                "locations/0/capture.pcap.gps.json", names
            )
            self.assertIn("captures/0/capture.pcap", names)
            self.assertEqual(
                backup.read("data/captures/0/capture.pcap"),
                b"pcap-data",
            )
            self.assertEqual(
                backup.read("data/credentials/manual.potfile"),
                b"manual-result\n",
            )

    def test_restore_verifies_archive_and_atomically_restores_files(self):
        archive, _ = self.plugin._build_backup_archive()
        for path in self.files:
            with open(path, "wb") as handle:
                handle.write(b"changed")

        with self.app.test_request_context(
            "/plugins/A_pwmenu/backup-restore",
            method="POST",
            data={
                "file": (
                    io.BytesIO(archive),
                    "backup.pwmenu-backup",
                ),
            },
        ):
            ok, message = self.plugin._restore_backup(request)

        self.assertTrue(ok, message)
        for path, expected in self.files.items():
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), expected)
        self.assertTrue(
            os.path.isfile(self.plugin.config_path + ".pwmenu-restore.bak")
        )


if __name__ == "__main__":
    unittest.main()
