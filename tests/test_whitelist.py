import os
import sys
import tempfile
import types
import unittest

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


class WhitelistTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.config_path = os.path.join(self.tempdir.name, "config.toml")
        with open(self.config_path, "w", encoding="utf-8") as handle:
            handle.write('main.name = "test-unit"\nmain.whitelist = ["Home"]\n')

        self.plugin = A_pwmenu()
        self.plugin.config_path = self.config_path
        self.plugin._agent = types.SimpleNamespace(
            _config={"main": {"whitelist": ["Home"]}}
        )

    def test_add_and_remove_update_config_backup_and_runtime(self):
        changed, _ = self.plugin._add_to_whitelist("Cafe WiFi")

        self.assertTrue(changed)
        self.assertEqual(self.plugin._get_whitelist(), ["Cafe WiFi", "Home"])
        self.assertEqual(
            self.plugin._agent._config["main"]["whitelist"],
            ["Cafe WiFi", "Home"],
        )
        self.assertTrue(os.path.isfile(self.config_path + ".pwmenu-whitelist.bak"))

        changed, _ = self.plugin._remove_from_whitelist("Home")

        self.assertTrue(changed)
        self.assertEqual(self.plugin._get_whitelist(), ["Cafe WiFi"])
        self.assertEqual(
            self.plugin._agent._config["main"]["whitelist"],
            ["Cafe WiFi"],
        )

    def test_duplicate_and_control_characters_are_rejected(self):
        changed, message = self.plugin._add_to_whitelist("Home")
        self.assertFalse(changed)
        self.assertIn("already", message)

        changed, message = self.plugin._add_to_whitelist("bad\nnetwork")
        self.assertFalse(changed)
        self.assertIn("unsupported", message)

    def test_bssid_resolves_exact_ssid_and_replaces_sanitized_alias(self):
        with open(self.config_path, "w", encoding="utf-8") as handle:
            handle.write('main.name = "test-unit"\nmain.whitelist = ["TPLink8241"]\n')
        self.plugin._agent._config["main"]["whitelist"] = ["TPLink8241"]
        self.plugin._get_cracked_data = lambda: {
            ("bssid", "aabbccddeeff", "secret123"): {
                "essid": "TP-Link_8241",
                "bssid": "aabbccddeeff",
                "password": "secret123",
            }
        }

        changed, message = self.plugin._add_to_whitelist(
            "TPLink8241",
            "aa:bb:cc:dd:ee:ff",
        )

        self.assertTrue(changed)
        self.assertIn("TP-Link_8241", message)
        self.assertEqual(self.plugin._get_whitelist(), ["TP-Link_8241"])

    def test_whitelist_alias_migration_is_conservative_and_deduplicates(self):
        with open(self.config_path, "w", encoding="utf-8") as handle:
            handle.write(
                'main.name = "test-unit"\n'
                'main.whitelist = ["TPLink8241", "TP-Link_8241", "Dolphin"]\n'
            )
        self.plugin._agent._config["main"]["whitelist"] = [
            "TPLink8241", "TP-Link_8241", "Dolphin",
        ]
        self.plugin._get_cracked_data = lambda: {
            ("bssid", "aabbccddeeff", "secret123"): {
                "essid": "TP-Link_8241",
                "bssid": "aabbccddeeff",
                "password": "secret123",
            }
        }

        repaired = self.plugin._repair_whitelist_aliases()

        self.assertGreaterEqual(repaired, 1)
        self.assertEqual(self.plugin._get_whitelist(), ["Dolphin", "TP-Link_8241"])

    def test_whitelist_alias_migration_uses_password_free_ohc_snapshot(self):
        with open(self.config_path, "w", encoding="utf-8") as handle:
            handle.write(
                'main.name = "test-unit"\n'
                'main.whitelist = ["POB45114", "Dolphin"]\n'
            )
        self.plugin._agent._config["main"]["whitelist"] = ["POB45114", "Dolphin"]
        self.plugin._get_cracked_data = lambda: {}
        self.plugin._load_ohc_export_snapshot = lambda: (
            {"aa:bb:cc:dd:ee:ff|POB45-114"},
            {"aa:bb:cc:dd:ee:ff"},
            {"tasks": 1},
        )

        repaired = self.plugin._repair_whitelist_aliases()

        self.assertEqual(repaired, 1)
        self.assertEqual(self.plugin._get_whitelist(), ["Dolphin", "POB45-114"])

    def test_group_whitelist_adds_only_excellent_quality_networks(self):
        groups = [
            {"essid": "Home", "files": [{"quality": {"grade": "Excellent"}}]},
            {"essid": "Cafe", "files": [{"quality": {"grade": "Excellent"}}]},
            {
                "essid": "Office",
                "files": [
                    {"quality": {"grade": "Partial"}},
                    {"quality": {"grade": "Excellent"}},
                ],
            },
            {"essid": "UsableOnly", "files": [{"quality": {"grade": "Usable"}}]},
        ]

        changed, message = self.plugin._add_excellent_to_whitelist(
            ["Home", "Cafe", "Office", "UsableOnly", "Unknown"],
            groups=groups,
        )

        self.assertTrue(changed)
        self.assertEqual(self.plugin._get_whitelist(), ["Cafe", "Home", "Office"])
        self.assertIn("Added 2", message)
        self.assertIn("1 already whitelisted", message)
        self.assertIn("2 skipped", message)

    def test_group_whitelist_reports_when_no_excellent_network_is_new(self):
        changed, message = self.plugin._add_excellent_to_whitelist(
            ["Home", "UsableOnly"],
            groups=[
                {"essid": "Home", "files": [{"quality": {"grade": "Excellent"}}]},
                {"essid": "UsableOnly", "files": [{"quality": {"grade": "Usable"}}]},
            ],
        )

        self.assertFalse(changed)
        self.assertEqual(self.plugin._get_whitelist(), ["Home"])
        self.assertIn("No new Excellent-quality networks", message)
        self.assertIn("1 already whitelisted", message)
        self.assertIn("1 skipped", message)

    def test_async_whitelist_response_is_compact_json(self):
        app = Flask(__name__)
        with app.test_request_context(
            "/plugins/A_pwmenu/whitelist-add",
            method="POST",
            headers={"X-PWMenu-Async": "1"},
        ):
            response = self.plugin._whitelist_action_response(
                request,
                True,
                "Added Cafe",
                "map",
            )

        self.assertEqual(response.mimetype, "application/json")
        self.assertEqual(response.get_json()["message"], "Added Cafe")
        self.assertEqual(response.get_json()["whitelist"], ["Home"])
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_async_map_action_response_is_compact_json(self):
        app = Flask(__name__)
        with app.test_request_context(headers={"X-PWMenu-Async": "1"}):
            response = self.plugin._action_response(
                request,
                "Upload started",
                False,
                "map",
            )

        self.assertEqual(response.mimetype, "application/json")
        self.assertEqual(response.get_json(), {"ok": True, "message": "Upload started"})
        self.assertEqual(response.headers["Cache-Control"], "no-store")


if __name__ == "__main__":
    unittest.main()
