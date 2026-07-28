import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock


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
        self.plugin.data_file = os.path.join(
            self.tempdir.name,
            ".a_pwmenu_data.json",
        )
        self.plugin.options = {}
        self.plugin.data = {
            "ohc_files": {},
            "ohc_hash_files": {},
            "ohc_found_files": {},
            "ohc_pending_files": {},
            "ohc_file_signatures": {},
            "ohc_reported": [],
            "ohc_reported_hashes": [],
        }

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

    def test_imported_export_stops_capture_before_queue(self):
        path = os.path.join(self.tempdir.name, "Example_aabbccddeeff.pcap")
        with open(path, "wb") as handle:
            handle.write(b"pcap")
        self.plugin._store_ohc_export_snapshot(
            [{"task": "Example<br>aa:bb:cc:dd:ee:ff"}],
            "tasks.csv",
        )

        with (
            mock.patch.object(self.plugin, "_candidate_ohc_paths", return_value=[path]),
            mock.patch.object(self.plugin, "_best_capture_paths_by_ap", return_value=[path]),
            mock.patch.object(
                self.plugin,
                "_capture_export_network",
                return_value=("Example", "aabbccddeeff"),
            ),
        ):
            queued = self.plugin._queue_ohc_files(force=True)

        self.assertEqual(queued, 0)
        self.assertEqual(self.plugin.data["ohc_pending_files"], {})
        self.assertEqual(
            self.plugin.data["ohc_files"][os.path.basename(path)]["status"],
            "already_reported",
        )

    def test_local_reported_hash_stops_same_bssid_before_queue(self):
        path = os.path.join(self.tempdir.name, "Renamed_aabbccddeeff.pcap")
        with open(path, "wb") as handle:
            handle.write(b"pcap")
        self.plugin.data["ohc_reported_hashes"] = [
            "WPA*02*00*aabbccddeeff*bbbbbbbbbbbb*4f6c64206e616d65"
        ]

        with (
            mock.patch.object(self.plugin, "_candidate_ohc_paths", return_value=[path]),
            mock.patch.object(self.plugin, "_best_capture_paths_by_ap", return_value=[path]),
            mock.patch.object(
                self.plugin,
                "_capture_export_network",
                return_value=("Renamed", "aabbccddeeff"),
            ),
        ):
            queued = self.plugin._queue_ohc_files(force=True)

        self.assertEqual(queued, 0)
        self.assertEqual(self.plugin.data["ohc_pending_files"], {})

    def test_vless_config_is_disabled_when_url_is_empty(self):
        self.plugin.options = {"ohc_vless_url": ""}
        self.assertIsNone(self.plugin._ohc_vless_config())

    def test_vless_reality_url_builds_loopback_http_proxy(self):
        self.plugin.options = {
            "ohc_vless_url": (
                "vless://11111111-2222-3333-4444-555555555555@vpn.example:443"
                "?encryption=none&flow=xtls-rprx-vision&type=tcp"
                "&security=reality&sni=www.example.com&fp=chrome"
                "&pbk=public-key&sid=a916&spx=%2F"
            ),
            "ohc_proxy_port": 10809,
        }

        config = self.plugin._ohc_vless_config()

        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
        self.assertEqual(config["inbounds"][0]["protocol"], "http")
        self.assertEqual(config["outbounds"][0]["protocol"], "vless")
        self.assertEqual(
            config["outbounds"][0]["streamSettings"]["security"],
            "reality",
        )

    def test_vless_flow_can_override_incorrect_shared_link(self):
        self.plugin.options = {
            "ohc_vless_url": (
                "vless://11111111-2222-3333-4444-555555555555@vpn.example:443"
                "?encryption=none&flow=xtls-rprx-vision-udp443&type=tcp"
                "&security=reality&sni=www.example.com&fp=chrome"
                "&pbk=public-key&sid=a916&spx=%2F"
            ),
            "ohc_vless_flow": "",
        }

        config = self.plugin._ohc_vless_config()

        self.assertEqual(config["outbounds"][0]["settings"]["flow"], "")


if __name__ == "__main__":
    unittest.main()
