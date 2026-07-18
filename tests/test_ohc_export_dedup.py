import json
import os
import sys
import tempfile
import types
import unittest


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


class OhcExportDedupTests(unittest.TestCase):
    def setUp(self):
        self.plugin = A_pwmenu()
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.plugin.ohc_export_file = os.path.join(
            self.tempdir.name,
            ".a_pwmenu_ohc_export.json",
        )

    def test_task_and_hash_match(self):
        task = "Example WiFi<br><span class=\"muted\">aa:bb:cc:dd:ee:ff</span>"
        identity, bssid = self.plugin._ohc_export_task_identity(task)
        hash_line = "WPA*02*00*aabbccddeeff*bbbbbbbbbbbb*4578616d706c652057694669"

        self.assertEqual(identity, "aa:bb:cc:dd:ee:ff|Example WiFi")
        self.assertEqual(bssid, "aa:bb:cc:dd:ee:ff")
        self.assertTrue(
            self.plugin._ohc_hash_in_export(hash_line, {identity}, {bssid})
        )

    def test_bssid_match_is_conservative_across_essid_changes(self):
        identity = "aa:bb:cc:dd:ee:ff|Old name"
        hash_line = "WPA*01*00*aabbccddeeff*bbbbbbbbbbbb*4e6577206e616d65"

        self.assertTrue(
            self.plugin._ohc_hash_in_export(
                hash_line,
                {identity},
                {"aa:bb:cc:dd:ee:ff"},
            )
        )

    def test_unrelated_bssid_is_not_suppressed(self):
        hash_line = "WPA*02*00*111111111111*bbbbbbbbbbbb*4578616d706c65"

        self.assertFalse(
            self.plugin._ohc_hash_in_export(
                hash_line,
                {"aa:bb:cc:dd:ee:ff|Example"},
                {"aa:bb:cc:dd:ee:ff"},
            )
        )

    def test_snapshot_excludes_passwords_and_round_trips(self):
        tasks = [
            {
                "task": "Example<br>aa:bb:cc:dd:ee:ff",
                "status": "FOUND",
                "password": "must-not-be-stored",
            },
            {
                "task": "Example<br>aa:bb:cc:dd:ee:ff",
                "status": "NOTFOUND",
                "password": "",
            },
        ]

        count = self.plugin._store_ohc_export_snapshot(tasks, "tasks.csv")
        identities, bssids, info = self.plugin._load_ohc_export_snapshot()

        self.assertEqual(count, 1)
        self.assertEqual(info["tasks"], 1)
        self.assertEqual(info["source"], "tasks.csv")
        self.assertEqual(bssids, {"aa:bb:cc:dd:ee:ff"})
        self.assertIn("aa:bb:cc:dd:ee:ff|Example", identities)
        with open(self.plugin.ohc_export_file, "r", encoding="utf-8") as handle:
            serialized = handle.read()
        self.assertNotIn("must-not-be-stored", serialized)
        self.assertEqual(json.loads(serialized)["version"], 1)

    def test_invalid_upload_does_not_replace_valid_snapshot(self):
        valid = [{"task": "Example<br>aa:bb:cc:dd:ee:ff"}]
        self.assertEqual(
            self.plugin._store_ohc_export_snapshot(valid, "valid.csv"),
            1,
        )
        with open(self.plugin.ohc_export_file, "rb") as handle:
            before = handle.read()

        self.assertEqual(
            self.plugin._store_ohc_export_snapshot([], "invalid.csv"),
            0,
        )
        with open(self.plugin.ohc_export_file, "rb") as handle:
            after = handle.read()
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
