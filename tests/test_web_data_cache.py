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


class WebDataCacheTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.plugin = A_pwmenu()
        self.plugin.options = {
            "timezone": 0,
            "module_quality_enabled": False,
            # Tests exercise exact external-file detection. Production defaults
            # to a 30-second metadata verification window.
            "web_inventory_cache_seconds": 0,
            "web_credential_cache_seconds": 0,
        }
        self.plugin.handshake_dirs = [self.tempdir.name]
        self.plugin.potfile_ohc = os.path.join(
            self.tempdir.name, "onlinehashcrack.cracked.potfile"
        )
        self.plugin.potfile_handshake_lab = os.path.join(
            self.tempdir.name, "handshake-lab.cracked.potfile"
        )
        self.plugin.potfile_manual = os.path.join(
            self.tempdir.name, "manual.potfile"
        )
        self.plugin.data_file = os.path.join(
            self.tempdir.name, ".a_pwmenu_data.json"
        )
        self.plugin.data = {
            "xp": 0,
            "badges": [],
            "history_cracked": 0,
            "history_captured": 0,
            "seen_files": {},
            "locations": {},
            "ohc_files": {},
            "capture_quality": {},
        }

    def test_credentials_are_parsed_once_until_a_source_changes(self):
        with open(self.plugin.potfile_ohc, "w", encoding="utf-8") as handle:
            handle.write(
                "aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:"
                "Cafe:password123\n"
            )

        with mock.patch.object(
            self.plugin,
            "_load_cracked_data",
            wraps=self.plugin._load_cracked_data,
        ) as loader:
            first = self.plugin._get_cracked_data()
            second = self.plugin._get_cracked_data()
            self.assertIs(first, second)
            self.assertEqual(loader.call_count, 1)

            with open(
                self.plugin.potfile_ohc, "a", encoding="utf-8"
            ) as handle:
                handle.write(
                    "00:11:22:33:44:55:66:77:88:99:aa:bb:"
                    "Office:anotherpass\n"
                )

            third = self.plugin._get_cracked_data()
            self.assertEqual(loader.call_count, 2)
            self.assertEqual(len(third), 2)

    def test_page_model_is_reused_and_explicitly_invalidated(self):
        groups = [{
            "is_cracked": False,
            "files": [],
            "lat": None,
            "lon": None,
        }]
        achievements = {
            "level": 1,
            "xp": 0,
            "next_xp": 1000,
            "rank": "Script Kiddie",
            "lvl_percent": 0,
            "badges": [],
        }
        with (
            mock.patch.object(
                self.plugin, "_capture_source_revision", return_value="captures"
            ),
            mock.patch.object(
                self.plugin, "_credential_source_revision", return_value="credentials"
            ),
            mock.patch.object(
                self.plugin, "_get_cracked_data", return_value={}
            ) as cracked,
            mock.patch.object(
                self.plugin, "_scan_and_group_files", return_value=groups
            ) as scan,
            mock.patch.object(
                self.plugin, "_build_map_points", return_value=[]
            ),
            mock.patch.object(
                self.plugin, "_build_no_gps_networks", return_value=[]
            ),
            mock.patch.object(
                self.plugin, "_potfile_health", return_value={"ok": True}
            ),
            mock.patch.object(
                self.plugin,
                "_capture_cleanup_report",
                return_value={"count": 0},
            ),
            mock.patch.object(
                self.plugin,
                "_update_achievements",
                return_value=achievements,
            ),
        ):
            first = self.plugin._web_page_model()
            second = self.plugin._web_page_model()

            self.assertIs(first, second)
            self.assertEqual(scan.call_count, 1)
            self.assertEqual(cracked.call_count, 1)

            self.plugin._invalidate_web_data_cache()
            third = self.plugin._web_page_model()

            self.assertIsNot(first, third)
            self.assertEqual(scan.call_count, 2)
            self.assertEqual(cracked.call_count, 2)

    def test_state_save_invalidates_the_page_model(self):
        self.plugin.web_data_cache_key = ("old",)
        self.plugin.web_data_cache = {"old": True}

        self.plugin._save_data()

        self.assertIsNone(self.plugin.web_data_cache_key)
        self.assertIsNone(self.plugin.web_data_cache)
        self.assertEqual(self.plugin.web_data_cache_revision, 1)

    def test_capture_revision_tracks_pcap_and_gps_sidecar(self):
        empty_revision = self.plugin._capture_source_revision()
        capture = os.path.join(
            self.tempdir.name, "Cafe_aabbccddeeff.pcap"
        )
        with open(capture, "wb") as handle:
            handle.write(b"pcap")
        capture_revision = self.plugin._capture_source_revision()

        with open(
            os.path.splitext(capture)[0] + ".gps.json",
            "w",
            encoding="utf-8",
        ) as handle:
            handle.write('{"Latitude":53.9,"Longitude":27.56}')
        sidecar_revision = self.plugin._capture_source_revision()

        self.assertNotEqual(empty_revision, capture_revision)
        self.assertNotEqual(capture_revision, sidecar_revision)

    def test_web_scan_never_waits_for_a_gpsd_socket(self):
        with mock.patch.object(
            self.plugin, "_fresh_live_gps", return_value=None
        ) as gps:
            self.plugin._scan_and_group_files({})

        gps.assert_called_once_with(poll_gpsd=False)

    def test_health_panel_only_reports_actionable_failures(self):
        self.plugin.loaded_at = 0
        self.plugin.options.update({
            "module_gps_enabled": True,
            "health_gps_grace_seconds": 0,
            "health_queue_stuck_seconds": 300,
            "health_disk_warning_percent": 10,
        })
        self.plugin.data["ohc_pending_files"] = {
            "capture.pcap": {
                "queued_at": int(__import__("time").time()) - 600
            }
        }
        disk = types.SimpleNamespace(
            total=1000, used=500, free=500
        )
        with mock.patch(
            "A_pwmenu.shutil.disk_usage", return_value=disk
        ):
            issues = self.plugin._health_issues(
                {"label": "PwnDroid", "state": "reconnecting"},
                {"pending": 1, "uploading": False, "retry_in": 0},
                {"pending": 1},
            )

        kinds = {issue["kind"] for issue in issues}
        self.assertEqual(kinds, {"gps", "ohc", "wpa"})

        self.plugin.data["ohc_pending_files"] = {}
        with mock.patch(
            "A_pwmenu.shutil.disk_usage", return_value=disk
        ):
            issues = self.plugin._health_issues(
                {"label": "PwnDroid", "state": "connected"},
                {"pending": 0, "uploading": False, "retry_in": 0},
                {"pending": 0},
            )
        self.assertEqual(issues, [])


if __name__ == "__main__":
    unittest.main()
