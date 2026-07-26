import glob
import csv
import io
import os
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

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
        self.plugin.potfile_ohc = os.path.join(self.tempdir.name, "ohc.potfile")
        self.plugin.potfile_handshake_lab = os.path.join(self.tempdir.name, "handshake-lab.potfile")
        self.plugin.potfile_manual = os.path.join(self.tempdir.name, "manual.potfile")
        self.plugin.ohc_export_file = os.path.join(self.tempdir.name, ".ohc-export.json")
        self.plugin.data_file = os.path.join(self.tempdir.name, ".state.json")
        self.plugin.data = {
            "xp": 0,
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

    def test_bssid_only_capture_filename_preserves_ap_identity(self):
        self.assertEqual(
            self.plugin._handshake_identity("d0f3f54ab694.pcap"),
            ("d0f3f54ab694", "d0f3f54ab694"),
        )

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

    def test_uncracked_export_matches_exact_bssid_not_only_essid(self):
        known_path = os.path.join(self.tempdir.name, "Shared_aaaaaaaaaaaa.pcap")
        unknown_path = os.path.join(self.tempdir.name, "Shared_bbbbbbbbbbbb.pcap")
        with open(known_path, "wb") as handle:
            handle.write(b"known")
        with open(unknown_path, "wb") as handle:
            handle.write(b"unknown")

        with open(self.plugin.potfile_ohc, "w", encoding="utf-8") as handle:
            handle.write("aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:Shared_Network:secret123\n")
        self.plugin._capture_is_crackable = lambda path: True
        self.plugin._verify_capture_passwords = (
            lambda path, essid, bssid, passwords, revision:
            (path == known_path, False)
        )

        selected = [name for _, name in self.plugin._uncracked_export_files()]

        self.assertNotIn("Shared_aaaaaaaaaaaa.pcap", selected)
        self.assertIn("Shared_bbbbbbbbbbbb.pcap", selected)

    def test_uncracked_export_keeps_name_only_capture_when_known_record_has_bssid(self):
        capture_path = os.path.join(self.tempdir.name, "Shared_Network.pcap")
        with open(capture_path, "wb") as handle:
            handle.write(b"unknown-ap")
        with open(self.plugin.potfile_ohc, "w", encoding="utf-8") as handle:
            handle.write("aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:Shared_Network:secret123\n")
        self.plugin._capture_is_crackable = lambda path: True

        selected = [name for _, name in self.plugin._uncracked_export_files()]

        self.assertIn("Shared_Network.pcap", selected)

    def test_handshake_lab_import_preserves_source_and_matches_sanitized_capture(self):
        self.plugin._store_ohc_export_snapshot(
            [{"task": "OHC Network<br>11:22:33:44:55:66"}],
            "OnlineHashCrack_tasks.csv",
        )
        output = io.StringIO(newline="")
        writer = csv.DictWriter(
            output,
            fieldnames=[
                "datetime", "task", "algorithm", "status", "password", "note",
                "source", "format_version", "essid", "bssid",
            ],
        )
        writer.writeheader()
        writer.writerow({
            "datetime": "2026-07-25 12:00:00 UTC",
            "task": "TP-Link_8241-Guest<br><span class=\"small\">aa:bb:cc:dd:ee:ff</span>",
            "algorithm": "WPA(2)",
            "status": "FOUND",
            "password": "secret123",
            "note": "Exported by Handshake Lab / Hashcat Web UI",
            "source": "Handshake Lab / Hashcat Web UI",
            "format_version": "newfpv-handshake-lab-results-v1",
            "essid": "TP-Link_8241-Guest",
            "bssid": "aa:bb:cc:dd:ee:ff",
        })

        first = self.plugin._process_import(output.getvalue(), "recovered.csv")
        second = self.plugin._process_import(output.getvalue(), "recovered.csv")

        self.assertEqual(first["added"], 1)
        self.assertEqual(first["source"], "Handshake Lab")
        self.assertEqual(second["added"], 0)
        self.assertEqual(second["already"], 1)
        _, snapshot_bssids, snapshot_info = self.plugin._load_ohc_export_snapshot()
        self.assertEqual(snapshot_info["source"], "OnlineHashCrack_tasks.csv")
        self.assertEqual(snapshot_bssids, {"11:22:33:44:55:66"})

        capture_path = os.path.join(self.tempdir.name, "TPLink8241Guest_aabbccddeeff.pcap")
        with open(capture_path, "wb") as handle:
            handle.write(b"capture")
        self.plugin.data["capture_quality"][os.path.basename(capture_path)] = {
            "grade": "Usable",
            "rank": 2,
            "hashes": 1,
            "signature": self.plugin._ohc_file_signature(capture_path),
        }
        self.plugin._verify_capture_passwords = (
            lambda path, essid, bssid, passwords, revision: (True, False)
        )

        cracked = self.plugin._get_cracked_data()
        groups = self.plugin._scan_and_group_files(cracked)
        selected = [name for _, name in self.plugin._uncracked_export_files()]

        self.assertEqual(len(cracked), 1)
        record = next(iter(cracked.values()))
        self.assertEqual(record["essid"], "TP-Link_8241-Guest")
        self.assertEqual(record["bssid"], "aabbccddeeff")
        self.assertEqual(record["source"], "Handshake Lab")
        self.assertEqual(len(groups), 1)
        self.assertTrue(groups[0]["is_cracked"])
        self.assertEqual(groups[0]["essid"], "TP-Link_8241-Guest")
        self.assertNotIn(os.path.basename(capture_path), selected)
        self.assertEqual(self.plugin._candidate_ohc_paths(), [])

        self.plugin.data["ohc_pending_files"][capture_path] = {
            "signature": self.plugin._ohc_file_signature(capture_path),
            "queued_at": int(time.time()),
        }
        self.assertEqual(self.plugin._pending_ohc_paths(), [])
        self.assertEqual(
            self.plugin.data["ohc_files"][os.path.basename(capture_path)]["status"],
            "local_cracked",
        )

    def test_uncracked_export_excludes_known_bssid_without_reverification(self):
        capture_path = os.path.join(
            self.tempdir.name, "ChangedNetwork_aaaaaaaaaaaa.pcap"
        )
        with open(capture_path, "wb") as handle:
            handle.write(b"new-password-handshake")
        with open(self.plugin.potfile_ohc, "w", encoding="utf-8") as handle:
            handle.write(
                "aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:aa:"
                "ChangedNetwork:old-password\n"
            )
        self.plugin.data["capture_quality"][os.path.basename(capture_path)] = {
            "grade": "Usable",
            "rank": 2,
            "hashes": 1,
            "signature": self.plugin._ohc_file_signature(capture_path),
        }
        self.plugin._verify_capture_passwords = mock.Mock(
            side_effect=AssertionError("known APs must not be re-exported")
        )

        selected = [name for _, name in self.plugin._uncracked_export_files()]

        self.assertEqual(selected, [])
        self.plugin._verify_capture_passwords.assert_not_called()

    def test_uncracked_export_uses_analyzed_bssid_for_legacy_filename(self):
        capture_path = os.path.join(self.tempdir.name, "aabbccddeeff.pcap")
        with open(capture_path, "wb") as handle:
            handle.write(b"legacy-name")
        with open(self.plugin.potfile_handshake_lab, "w", encoding="utf-8") as handle:
            handle.write(
                "aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:"
                "Exact_Network:secret123\n"
            )
        self.plugin.data["capture_quality"][os.path.basename(capture_path)] = {
            "grade": "Usable",
            "rank": 2,
            "hashes": 1,
            "essid": "Exact_Network",
            "bssid": "aabbccddeeff",
            "signature": self.plugin._ohc_file_signature(capture_path),
        }

        selected = self.plugin._uncracked_export_files()

        self.assertEqual(selected, [])

    def test_uncracked_export_excludes_capture_without_usable_hash(self):
        capture_path = os.path.join(
            self.tempdir.name, "Broken_dddddddddddd.pcap"
        )
        with open(capture_path, "wb") as handle:
            handle.write(b"not-crackable")
        self.plugin.data["capture_quality"][os.path.basename(capture_path)] = {
            "grade": "Unusable",
            "rank": 0,
            "hashes": 0,
            "signature": self.plugin._ohc_file_signature(capture_path),
        }

        self.assertEqual(self.plugin._uncracked_export_files(), [])

    def test_aircrack_verification_is_cached_without_password_material(self):
        capture_path = os.path.join(
            self.tempdir.name, "Verified_aabbccddeeff.pcap"
        )
        with open(capture_path, "wb") as handle:
            handle.write(b"capture")
        result = types.SimpleNamespace(
            returncode=0,
            stdout="KEY FOUND! [ hidden-secret ]",
            stderr="",
        )
        with mock.patch("A_pwmenu.shutil.which", return_value="/usr/bin/aircrack-ng"), \
             mock.patch("A_pwmenu.subprocess.run", return_value=result) as run:
            verified, changed = self.plugin._verify_capture_passwords(
                capture_path,
                "Verified",
                "aabbccddeeff",
                ["hidden-secret"],
                "credential-revision",
            )
            cached, cached_changed = self.plugin._verify_capture_passwords(
                capture_path,
                "Verified",
                "aabbccddeeff",
                ["hidden-secret"],
                "credential-revision",
            )

        self.assertTrue(verified)
        self.assertTrue(changed)
        self.assertTrue(cached)
        self.assertFalse(cached_changed)
        run.assert_called_once()
        command = run.call_args.args[0]
        self.assertIn("aa:bb:cc:dd:ee:ff", command)
        self.assertNotIn("hidden-secret", command)
        serialized = str(self.plugin.data["capture_password_checks"])
        self.assertNotIn("hidden-secret", serialized)

    def test_integrated_password_display_uses_latest_enabled_source(self):
        with open(self.plugin.potfile_manual, "w", encoding="utf-8") as handle:
            handle.write(
                "aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:"
                "Manual_Network:manual-pass\n"
            )
        quickdic = os.path.join(
            self.tempdir.name, "Quick_Network_aabbccddeeff.pcap.cracked"
        )
        with open(quickdic, "w", encoding="utf-8") as handle:
            handle.write("quick-pass")
        now = time.time()
        os.utime(self.plugin.potfile_manual, (now - 10, now - 10))
        os.utime(quickdic, (now, now))
        self.plugin.options.update({
            "display_password_wpa_sec": False,
            "display_password_ohc": False,
            "display_password_handshake_lab": False,
            "display_password_manual": True,
            "display_password_quickdic": True,
            "display_password_max_length": 80,
        })

        self.assertEqual(
            self.plugin._display_password_text(),
            "Quick_Network:quick-pass",
        )

    def test_integrated_quickdic_skips_scan_when_known_key_verifies(self):
        capture_path = os.path.join(
            self.tempdir.name, "Known_aabbccddeeff.pcap"
        )
        with open(capture_path, "wb") as handle:
            handle.write(b"capture")
        with open(self.plugin.potfile_manual, "w", encoding="utf-8") as handle:
            handle.write(
                "aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:Known:known-pass\n"
            )
        self.plugin._verify_capture_passwords = (
            lambda path, essid, bssid, passwords, revision: (True, False)
        )
        agent = types.SimpleNamespace(view=lambda: None)
        with mock.patch("A_pwmenu.shutil.which", return_value="/usr/bin/aircrack-ng"), \
             mock.patch("A_pwmenu.subprocess.run") as run:
            result = self.plugin._run_quickdic(
                agent,
                capture_path,
                {"bssid": "aa:bb:cc:dd:ee:ff"},
            )

        self.assertTrue(result)
        run.assert_not_called()

    def test_integrated_quickdic_recovers_sidecar_display_and_event(self):
        capture_path = os.path.join(
            self.tempdir.name, "Fresh_aabbccddeeff.pcap"
        )
        with open(capture_path, "wb") as handle:
            handle.write(b"capture")
        wordlist_dir = os.path.join(self.tempdir.name, "wordlists")
        os.makedirs(wordlist_dir)
        with open(os.path.join(wordlist_dir, "quick.txt"), "w", encoding="utf-8") as handle:
            handle.write("fresh-pass\n")
        self.plugin.options.update({
            "quickdic_wordlist_folder": wordlist_dir,
            "quickdic_update_display": True,
            "quickdic_telegram_enabled": False,
        })

        class View:
            def __init__(self):
                self.values = {}
                self.updated = False
            def set(self, key, value):
                self.values[key] = value
            def update(self, force=False):
                self.updated = force

        view = View()
        agent = types.SimpleNamespace(view=lambda: view)

        def aircrack(command, **kwargs):
            output_path = command[command.index("-l") + 1]
            with open(output_path, "w", encoding="utf-8") as handle:
                handle.write("fresh-pass")
            return types.SimpleNamespace(
                returncode=0,
                stdout="KEY FOUND! [ fresh-pass ]",
                stderr="",
            )

        with mock.patch("A_pwmenu.shutil.which", return_value="/usr/bin/aircrack-ng"), \
             mock.patch("A_pwmenu.subprocess.run", side_effect=aircrack), \
             mock.patch("A_pwmenu.plugins.on", create=True) as event:
            result = self.plugin._run_quickdic(
                agent,
                capture_path,
                {"bssid": "aa:bb:cc:dd:ee:ff"},
            )

        self.assertTrue(result)
        with open(capture_path + ".cracked", encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "fresh-pass")
        self.assertIn("fresh-pass", view.values["status"])
        self.assertTrue(view.updated)
        event.assert_called_once()

    def test_uncracked_export_keeps_best_duplicate_capture(self):
        second_dir = tempfile.TemporaryDirectory()
        self.addCleanup(second_dir.cleanup)
        self.plugin.handshake_dirs = [self.tempdir.name, second_dir.name]
        self.plugin.potfile_ohc = os.path.join(self.tempdir.name, "ohc.potfile")
        self.plugin.potfile_manual = os.path.join(self.tempdir.name, "manual.potfile")

        filename = "Field_cccccccccccc.pcap"
        weak_path = os.path.join(self.tempdir.name, filename)
        excellent_path = os.path.join(second_dir.name, filename)
        with open(weak_path, "wb") as handle:
            handle.write(b"weak")
        with open(excellent_path, "wb") as handle:
            handle.write(b"excellent")
        self.plugin.data["capture_quality"] = {
            filename: {
                "grade": "Excellent",
                "rank": 3,
                "hashes": 1,
                "authorized": 1,
                "signature": self.plugin._ohc_file_signature(excellent_path),
            }
        }

        selected = self.plugin._uncracked_export_files()

        self.assertEqual([(excellent_path, filename)], selected)

    def test_uncracked_export_keeps_best_differently_named_capture_per_bssid(self):
        weak_path = os.path.join(self.tempdir.name, "OldName_aabbccddeeff.pcap")
        excellent_path = os.path.join(self.tempdir.name, "NewName_aabbccddeeff.pcap")
        with open(weak_path, "wb") as handle:
            handle.write(b"weak")
        with open(excellent_path, "wb") as handle:
            handle.write(b"excellent")
        self.plugin.data["capture_quality"] = {
            os.path.basename(weak_path): {
                "grade": "Partial", "rank": 1, "hashes": 1,
                "essid": "Exact-Name", "bssid": "aabbccddeeff",
                "signature": self.plugin._ohc_file_signature(weak_path),
            },
            os.path.basename(excellent_path): {
                "grade": "Excellent", "rank": 3, "hashes": 1, "authorized": 1,
                "essid": "Exact-Name", "bssid": "aabbccddeeff",
                "signature": self.plugin._ohc_file_signature(excellent_path),
            },
        }

        selected = self.plugin._uncracked_export_files()

        self.assertEqual(
            [(excellent_path, os.path.basename(excellent_path))],
            selected,
        )

    def test_ohc_keeps_best_capture_per_bssid(self):
        weak_path = os.path.join(self.tempdir.name, "Old_aabbccddeeff.pcap")
        best_path = os.path.join(self.tempdir.name, "New_aabbccddeeff.pcap")
        for path in (weak_path, best_path):
            with open(path, "wb") as handle:
                handle.write(b"capture")
        self.plugin.data["capture_quality"] = {
            os.path.basename(weak_path): {
                "rank": 1,
                "hashes": 1,
                "signature": self.plugin._ohc_file_signature(weak_path),
            },
            os.path.basename(best_path): {
                "rank": 3,
                "hashes": 2,
                "signature": self.plugin._ohc_file_signature(best_path),
            },
        }

        selected = self.plugin._best_capture_paths_by_ap([weak_path, best_path])

        self.assertEqual(selected, [best_path])

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
        self.assertIn("Download All Uncracked APs", page)
        self.assertIn("Made by", page)
        self.assertIn("function loadYandexMaps", page)
        self.assertIn("function whitelistAction", page)
        self.assertIn("function whitelistExcellentGroup", page)
        self.assertIn("const whitelistedNetworks = new Set", page)
        self.assertIn("async function postAsync", page)
        self.assertIn("async function updateWhitelistAsync", page)
        self.assertIn("async function runMapAction", page)
        self.assertIn("runMapAction('ohc-upload-cluster'", page)
        self.assertIn("runMapAction('wpa-sec-upload-cluster'", page)
        self.assertNotIn('<script src="https://api-maps.yandex.ru', page)


if __name__ == "__main__":
    unittest.main()
