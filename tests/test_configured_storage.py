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


class Agent:
    def __init__(self, config):
        self._config = config

    def config(self):
        return self._config


class ConfiguredStorageTests(unittest.TestCase):
    def disabled_options(self):
        return {
            "module_web_enabled": False,
            "module_gps_enabled": False,
            "module_ohc_enabled": False,
            "module_wpa_sec_enabled": False,
            "module_quality_enabled": False,
            "module_quickdic_enabled": False,
            "pwndroid_ws_enabled": False,
            "ohc_enabled": False,
            "ohc_auto_upload": False,
            "quality_auto_scan": False,
        }

    def test_storage_waits_for_agent_and_uses_bettercap_handshakes(self):
        with tempfile.TemporaryDirectory() as root:
            configured = os.path.join(root, "captures")
            plugin = A_pwmenu()
            plugin.options = self.disabled_options()
            plugin.config_path = os.path.join(root, "config.toml")

            plugin.on_loaded()

            self.assertFalse(plugin.ready)
            self.assertFalse(plugin.storage_ready)
            self.assertEqual(plugin.handshake_dirs, [])
            self.assertEqual(plugin.data_file, "")

            plugin.on_ready(Agent({
                "bettercap": {"handshakes": configured}
            }))

            resolved = os.path.realpath(configured)
            self.assertTrue(plugin.ready)
            self.assertTrue(plugin.storage_ready)
            self.assertEqual(plugin.storage_dir, resolved)
            self.assertEqual(plugin.handshake_dirs, [resolved])
            self.assertEqual(
                plugin.data_file,
                os.path.join(resolved, ".a_pwmenu_data.json"),
            )
            self.assertEqual(
                plugin.potfile_ohc,
                os.path.join(
                    resolved,
                    "onlinehashcrack.cracked.potfile",
                ),
            )
            self.assertTrue(os.path.isfile(plugin.potfile_ohc))
            self.assertTrue(os.path.isfile(plugin.potfile_handshake_lab))
            self.assertTrue(os.path.isfile(plugin.potfile_manual))

    def test_agent_private_config_is_supported_when_method_is_unavailable(self):
        plugin = A_pwmenu()
        agent = types.SimpleNamespace(
            _config={"bettercap": {"handshakes": "/configured/captures"}}
        )

        config = plugin._active_agent_config(agent)

        self.assertEqual(
            config["bettercap"]["handshakes"],
            "/configured/captures",
        )

    def test_missing_setting_uses_dynamic_home_fallback(self):
        plugin = A_pwmenu()
        with mock.patch("A_pwmenu.os.path.expanduser") as expanduser:
            expanduser.side_effect = lambda value: (
                "/runtime-user" if value == "~" else value
            )
            directory, source = plugin._configured_handshake_directory(
                Agent({})
            )

        self.assertEqual(
            directory,
            os.path.realpath("/runtime-user/handshakes"),
        )
        self.assertEqual(source, "user-home compatibility fallback")

    def test_filesystem_root_is_rejected(self):
        plugin = A_pwmenu()
        with self.assertRaisesRegex(ValueError, "filesystem root"):
            plugin._configured_handshake_directory(
                Agent({"bettercap": {"handshakes": os.path.abspath(os.sep)}})
            )

    def test_legacy_dynamic_home_state_is_migrated_without_data_loss(self):
        with tempfile.TemporaryDirectory() as root:
            legacy_home = os.path.join(root, "legacy-home")
            legacy = os.path.join(legacy_home, "handshakes")
            configured = os.path.join(root, "configured")
            os.makedirs(legacy)
            with open(
                os.path.join(legacy, "manual.potfile"),
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write(
                    "AA:BB:CC:DD:EE:FF:AA:BB:CC:DD:EE:FF:"
                    "Lab:verified-pass\n"
                )
            os.makedirs(configured)
            with open(
                os.path.join(configured, ".a_pwmenu_data.json"),
                "w",
                encoding="utf-8",
            ) as handle:
                json.dump({
                    "xp": 7,
                    "locations": {
                        "configured.pcap": {"lat": 1.0, "lng": 2.0}
                    },
                    "action_history": [{"ts": 1, "title": "configured"}],
                }, handle)
            with open(
                os.path.join(legacy, ".a_pwmenu_data.json"),
                "w",
                encoding="utf-8",
            ) as handle:
                json.dump({
                    "xp": 42,
                    "locations": {
                        "legacy.pcap": {"lat": 3.0, "lng": 4.0}
                    },
                    "action_history": [{"ts": 2, "title": "legacy"}],
                }, handle)

            plugin = A_pwmenu()
            with mock.patch("A_pwmenu.os.path.expanduser") as expanduser:
                expanduser.side_effect = lambda value: (
                    legacy_home if value == "~" else value
                )
                plugin._configure_storage_paths(Agent({
                    "bettercap": {"handshakes": configured}
                }))
                migrated = plugin._migrate_legacy_storage()

            self.assertEqual(migrated, 2)
            with open(
                plugin.potfile_manual,
                "r",
                encoding="utf-8",
            ) as handle:
                self.assertIn("verified-pass", handle.read())
            with open(plugin.data_file, "r", encoding="utf-8") as handle:
                state = json.load(handle)
            self.assertEqual(state["xp"], 42)
            self.assertIn("configured.pcap", state["locations"])
            self.assertIn("legacy.pcap", state["locations"])
            self.assertEqual(len(state["action_history"]), 2)
            self.assertTrue(os.path.isfile(plugin.data_file + ".bak"))
            self.assertTrue(os.path.isfile(
                plugin.data_file + ".pre-config-path-migration"
            ))

    def test_legacy_ohc_snapshot_is_merged(self):
        with tempfile.TemporaryDirectory() as root:
            legacy_home = os.path.join(root, "legacy-home")
            legacy = os.path.join(legacy_home, "handshakes")
            configured = os.path.join(root, "configured")
            os.makedirs(legacy)
            os.makedirs(configured)
            with open(
                os.path.join(legacy, ".a_pwmenu_ohc_export.json"),
                "w",
                encoding="utf-8",
            ) as handle:
                json.dump({
                    "identities": ["aa:bb:cc:dd:ee:ff|Legacy"],
                    "bssids": ["aa:bb:cc:dd:ee:ff"],
                    "imported_at": 20,
                }, handle)
            with open(
                os.path.join(configured, ".a_pwmenu_ohc_export.json"),
                "w",
                encoding="utf-8",
            ) as handle:
                json.dump({
                    "identities": ["11:22:33:44:55:66|Configured"],
                    "bssids": ["11:22:33:44:55:66"],
                    "imported_at": 10,
                }, handle)

            plugin = A_pwmenu()
            with mock.patch("A_pwmenu.os.path.expanduser") as expanduser:
                expanduser.side_effect = lambda value: (
                    legacy_home if value == "~" else value
                )
                plugin._configure_storage_paths(Agent({
                    "bettercap": {"handshakes": configured}
                }))
                plugin._migrate_legacy_storage()

            identities, bssids, info = plugin._load_ohc_export_snapshot()
            self.assertEqual(len(identities), 2)
            self.assertEqual(len(bssids), 2)
            self.assertEqual(info["imported_at"], 20)

    def test_legacy_storage_is_discovered_from_system_account_homes(self):
        with tempfile.TemporaryDirectory() as root:
            runtime_home = os.path.join(root, "runtime")
            other_home = os.path.join(root, "other-account")
            configured = os.path.join(root, "configured")
            legacy = os.path.join(other_home, "handshakes")
            os.makedirs(runtime_home)
            os.makedirs(legacy)
            os.makedirs(configured)
            with open(
                os.path.join(legacy, ".a_pwmenu_data.json"),
                "w",
                encoding="utf-8",
            ) as handle:
                json.dump({"xp": 99}, handle)

            plugin = A_pwmenu()
            plugin.storage_dir = os.path.realpath(configured)
            fake_pwd = types.SimpleNamespace(
                getpwall=lambda: [
                    types.SimpleNamespace(pw_dir=other_home),
                    types.SimpleNamespace(pw_dir=configured),
                ]
            )
            with (
                mock.patch.dict(sys.modules, {"pwd": fake_pwd}),
                mock.patch(
                    "A_pwmenu.os.path.expanduser",
                    return_value=runtime_home,
                ),
            ):
                directories = plugin._legacy_storage_directories()

            self.assertEqual(directories, [os.path.realpath(legacy)])

    def test_migration_marker_prevents_old_state_from_reapplying(self):
        with tempfile.TemporaryDirectory() as root:
            legacy_home = os.path.join(root, "legacy-home")
            legacy = os.path.join(legacy_home, "handshakes")
            configured = os.path.join(root, "configured")
            os.makedirs(legacy)
            with open(
                os.path.join(legacy, ".a_pwmenu_data.json"),
                "w",
                encoding="utf-8",
            ) as handle:
                json.dump({"xp": 42}, handle)

            plugin = A_pwmenu()
            plugin._configure_storage_paths(Agent({
                "bettercap": {"handshakes": configured}
            }))
            with mock.patch.object(
                plugin,
                "_legacy_storage_directories",
                return_value=[legacy],
            ):
                self.assertEqual(plugin._migrate_legacy_storage(), 1)
                with open(
                    plugin.data_file,
                    "w",
                    encoding="utf-8",
                ) as handle:
                    json.dump({"xp": 100}, handle)
                self.assertEqual(plugin._migrate_legacy_storage(), 0)

            with open(plugin.data_file, "r", encoding="utf-8") as handle:
                self.assertEqual(json.load(handle)["xp"], 100)
            self.assertTrue(os.path.isfile(
                plugin._legacy_migration_marker(legacy)
            ))

    def test_newer_configured_scalar_wins_during_first_merge(self):
        with tempfile.TemporaryDirectory() as root:
            legacy = os.path.join(root, "legacy")
            configured = os.path.join(root, "configured")
            os.makedirs(legacy)
            os.makedirs(configured)
            legacy_state = os.path.join(legacy, ".a_pwmenu_data.json")
            configured_state = os.path.join(
                configured,
                ".a_pwmenu_data.json",
            )
            with open(legacy_state, "w", encoding="utf-8") as handle:
                json.dump({"xp": 42, "locations": {"old": {}}}, handle)
            with open(configured_state, "w", encoding="utf-8") as handle:
                json.dump({"xp": 100, "locations": {"new": {}}}, handle)
            os.utime(legacy_state, (10, 10))
            os.utime(configured_state, (20, 20))

            plugin = A_pwmenu()
            plugin._configure_storage_paths(Agent({
                "bettercap": {"handshakes": configured}
            }))
            self.assertTrue(plugin._migrate_legacy_state(legacy))

            with open(plugin.data_file, "r", encoding="utf-8") as handle:
                state = json.load(handle)
            self.assertEqual(state["xp"], 100)
            self.assertEqual(set(state["locations"]), {"old", "new"})


if __name__ == "__main__":
    unittest.main()
