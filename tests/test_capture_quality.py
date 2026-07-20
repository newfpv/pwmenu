import glob
import os
import sys
import tempfile
import time
import types
import unittest

from flask import Flask, render_template_string


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


class CaptureQualityTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.plugin = A_pwmenu()
        self.plugin.options = {"auto_replace_unusable": True}
        self.plugin.handshake_dirs = [self.tempdir.name]
        self.plugin.data_file = os.path.join(self.tempdir.name, ".state.json")
        self.plugin.data = {
            "seen_files": {},
            "locations": {},
            "ohc_files": {},
            "ohc_found_files": {},
            "ohc_pending_files": {},
            "ohc_file_signatures": {},
            "ohc_hash_files": {},
            "capture_quality": {},
            "replacement_history": [],
            "capture_cleanup_history": [],
        }

    def test_quality_grades_follow_hcx_metrics(self):
        excellent_report = "\n".join(
            [
                "EAPOL messages (total)...................: 15",
                "EAPOL pairs (best).......................: 1",
                "EAPOL M32E2 (authorized).................: 1",
            ]
        )
        usable_report = "EAPOL messages (total)...................: 6"
        partial_report = "\n".join(
            [
                "EAPOL messages (total)...................: 1",
                "EAPOL M1 messages (total)................: 1",
            ]
        )

        excellent = self.plugin._classify_capture_quality(excellent_report, ["hash"], 100)
        usable = self.plugin._classify_capture_quality(usable_report, ["hash"], 100)
        partial = self.plugin._classify_capture_quality(partial_report, [], 100)
        unusable = self.plugin._classify_capture_quality("", [], 24)

        self.assertEqual(excellent["grade"], "Excellent")
        self.assertEqual(usable["grade"], "Usable")
        self.assertEqual(partial["grade"], "Partial")
        self.assertEqual(unusable["grade"], "Unusable")

    def test_empty_cleanup_requires_current_report_token(self):
        empty_path = os.path.join(self.tempdir.name, "Empty_aabbccddeeff.pcap")
        with open(empty_path, "wb") as handle:
            handle.write(b"\xd4\xc3\xb2\xa1" + (b"\x00" * 20))

        report = self.plugin._capture_cleanup_report()
        self.assertEqual(report["count"], 1)

        deleted, total, _ = self.plugin._clean_capture_candidates("0" * 64)
        self.assertEqual((deleted, total), (0, 1))
        self.assertTrue(os.path.exists(empty_path))

        deleted, total, _ = self.plugin._clean_capture_candidates(report["token"])
        self.assertEqual((deleted, total), (1, 1))
        self.assertFalse(os.path.exists(empty_path))

    def test_later_usable_capture_archives_weak_capture_for_same_bssid(self):
        old_path = os.path.join(self.tempdir.name, "Old_aabbccddeeff.pcap")
        new_path = os.path.join(self.tempdir.name, "New_aabbccddeeff.pcap")
        with open(old_path, "wb") as handle:
            handle.write(b"x" * 128)
        with open(new_path, "wb") as handle:
            handle.write(b"y" * 256)
        now = time.time()
        os.utime(old_path, (now - 30, now - 30))
        os.utime(new_path, (now, now))
        self.plugin.data["capture_quality"] = {
            os.path.basename(old_path): {
                "grade": "Partial",
                "rank": 1,
                "hashes": 0,
                "signature": self.plugin._ohc_file_signature(old_path),
            },
            os.path.basename(new_path): {
                "grade": "Usable",
                "rank": 2,
                "hashes": 1,
                "signature": self.plugin._ohc_file_signature(new_path),
            },
        }

        replaced = self.plugin._replace_weaker_captures("New", "aabbccddeeff")

        self.assertEqual(replaced, 1)
        self.assertFalse(os.path.exists(old_path))
        self.assertTrue(os.path.exists(new_path))
        self.assertEqual(len(glob.glob(old_path + ".replaced-*")), 1)

    def test_empty_capture_is_never_auto_replaced(self):
        old_path = os.path.join(self.tempdir.name, "Old_aabbccddeeff.pcap")
        new_path = os.path.join(self.tempdir.name, "New_aabbccddeeff.pcap")
        with open(old_path, "wb") as handle:
            handle.write(b"\xd4\xc3\xb2\xa1" + (b"\x00" * 20))
        with open(new_path, "wb") as handle:
            handle.write(b"y" * 256)
        now = time.time()
        os.utime(old_path, (now - 30, now - 30))
        os.utime(new_path, (now, now))
        self.plugin.data["capture_quality"] = {
            os.path.basename(old_path): {
                "grade": "Unusable",
                "rank": 0,
                "hashes": 0,
                "signature": self.plugin._ohc_file_signature(old_path),
            },
            os.path.basename(new_path): {
                "grade": "Usable",
                "rank": 2,
                "hashes": 1,
                "signature": self.plugin._ohc_file_signature(new_path),
            },
        }

        replaced = self.plugin._replace_weaker_captures("New", "aabbccddeeff")

        self.assertEqual(replaced, 0)
        self.assertTrue(os.path.exists(old_path))

    def test_web_template_renders_quality_cleanup_and_branding(self):
        app = Flask(__name__)
        with app.test_request_context("/plugins/A_pwmenu/"):
            page = render_template_string(
                self.plugin._get_html(),
                groups=[],
                cracked={},
                notif=None,
                ntype=None,
                tab="other",
                stats={
                    "cracked": 0,
                    "total": 0,
                    "percent": 0,
                    "files": 0,
                    "level": 1,
                    "xp": 0,
                    "next_xp": 1000,
                    "rank": "Script Kiddie",
                    "lvl_percent": 0,
                    "gps_points": 0,
                    "cracked_gps": 0,
                    "no_gps": 0,
                },
                ach=[],
                token="test-token",
                show_wpa=False,
                map_points=[],
                gps_status={
                    "label": "GPS",
                    "state": "offline",
                    "lat": None,
                    "lon": None,
                    "accuracy": 0,
                    "age": 0,
                    "detail": "",
                },
                no_gps_networks=[],
                ohc_status={"pending": 0, "retry_in": 0},
                pot_health={
                    "ok": True,
                    "credentials": 0,
                    "bytes": 0,
                    "duplicates": 0,
                    "invalid": 0,
                    "nul_bytes": 0,
                },
                cleanup_report={
                    "count": 0,
                    "empty_count": 0,
                    "unusable_count": 0,
                    "display_files": [],
                    "more": 0,
                    "token": "0" * 64,
                },
                whitelist=[],
            )

        self.assertIn("function qualityStatusBlock", page)
        self.assertIn("Capture Cleanup", page)
        self.assertIn("Made by", page)
        self.assertIn("function loadYandexMaps", page)
        self.assertNotIn('<script src="https://api-maps.yandex.ru', page)


if __name__ == "__main__":
    unittest.main()
