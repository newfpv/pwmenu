import os
import sys
import tempfile
import threading
import time
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


class ActivityAndConflictTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.plugin = A_pwmenu()
        self.plugin.options = {
            "timezone": 0,
            "activity_history_max": 50,
            "activity_history_hours": 24,
        }
        self.plugin.data_file = os.path.join(
            self.tempdir.name, "state.json"
        )
        self.plugin.data = {
            "action_history": [],
            "locations": {},
            "capture_quality": {},
        }

    def test_activity_history_is_bounded_deduplicated_and_time_limited(self):
        self.assertTrue(
            self.plugin._record_action(
                "system",
                "Ready",
                dedupe_key="ready",
                dedupe_window=60,
            )
        )
        self.assertFalse(
            self.plugin._record_action(
                "system",
                "Ready again",
                dedupe_key="ready",
                dedupe_window=60,
            )
        )
        self.plugin._record_action("capture", "Capture one")
        self.plugin._record_action("cloud", "Cloud sync")

        page = self.plugin._activity_history_page()
        self.assertEqual(page["total"], 3)
        self.assertEqual(len(page["items"]), 3)
        self.assertFalse(page["hasMore"])
        self.assertNotIn("key", page["items"][0])

        self.plugin.data["action_history"].append({
            "ts": int(time.time()) - (25 * 3600),
            "kind": "system",
            "title": "Expired",
        })
        page = self.plugin._activity_history_page()
        self.assertEqual(page["total"], 3)
        self.assertNotIn(
            "Expired",
            {item["title"] for item in page["items"]},
        )

    def test_conflict_center_finds_all_supported_conflict_types(self):
        groups = [{
            "essid": "Cafe",
            "bssid": "aabbccddeeff",
            "files": [
                {"filename": "weak.pcap", "essid": "Cafe"},
                {"filename": "best.pcap", "essid": "Cafe-5G"},
            ],
            "best_file": {"filename": "best.pcap"},
        }]
        cracked = {
            ("one",): {
                "essid": "Cafe",
                "bssid": "aabbccddeeff",
                "password": "first-pass",
            },
            ("two",): {
                "essid": "Cafe-5G",
                "bssid": "aabbccddeeff",
                "password": "second-pass",
            },
            ("name",): {
                "essid": "Legacy",
                "bssid": "",
                "password": "legacy-pass",
            },
        }

        conflicts = self.plugin._build_conflicts(groups, cracked)
        kinds = {item["kind"] for item in conflicts}

        self.assertEqual(
            kinds,
            {"duplicate", "identity", "password", "name-only"},
        )
        password_conflict = next(
            item for item in conflicts
            if item["kind"] == "password"
        )
        self.assertNotIn("first-pass", password_conflict["detail"])
        self.assertNotIn("second-pass", password_conflict["detail"])

    def test_punctuation_aliases_and_unique_zero_bssid_are_auto_reconciled(self):
        groups = [{
            "essid": "TP-Link_8241",
            "bssid": "d84732388241",
            "files": [{
                "filename": "TP-Link_8241_d84732388241.pcap",
                "essid": "TP-Link_8241",
            }],
            "best_file": {
                "filename": "TP-Link_8241_d84732388241.pcap"
            },
        }]
        cracked = {
            ("alias",): {
                "essid": "TPLink8241",
                "bssid": "d84732388241",
                "password": "correct-pass",
            },
            ("legacy",): {
                "essid": "TP-Link_8241",
                "bssid": "00:00:00:00:00:00",
                "password": "correct-pass",
            },
        }

        conflicts = self.plugin._build_conflicts(groups, cracked)

        self.assertNotIn(
            "identity",
            {item["kind"] for item in conflicts},
        )
        self.assertNotIn(
            "password",
            {item["kind"] for item in conflicts},
        )
        self.assertNotIn(
            "name-only",
            {item["kind"] for item in conflicts},
        )

    def test_password_repair_keeps_only_one_locally_verified_candidate(self):
        self.plugin.potfile_manual = os.path.join(
            self.tempdir.name,
            "manual.potfile",
        )
        self.plugin.potfile_ohc = os.path.join(
            self.tempdir.name,
            "ohc.potfile",
        )
        self.plugin.potfile_handshake_lab = os.path.join(
            self.tempdir.name,
            "lab.potfile",
        )
        bssid = "AA:BB:CC:DD:EE:FF"
        records = {
            ("valid",): {
                "essid": "Lab",
                "bssid": bssid,
                "password": "valid-pass",
            },
            ("invalid",): {
                "essid": "Lab",
                "bssid": bssid,
                "password": "wrong-pass",
            },
        }
        with (
            mock.patch.object(
                self.plugin,
                "_get_cracked_data",
                return_value=records,
            ),
            mock.patch.object(
                self.plugin,
                "_verify_manual_password",
                side_effect=[
                    (True, "verified"),
                    (False, "Password does not match"),
                ],
            ),
            mock.patch.object(self.plugin, "_delete_password") as delete,
            mock.patch.object(self.plugin, "_record_action"),
        ):
            ok, message = self.plugin._repair_password_conflict(bssid)

        self.assertTrue(ok, message)
        delete.assert_called_once_with(
            "",
            "wrong-pass",
            bssid="aabbccddeeff",
        )
        rejection = self.plugin._credential_rejection_key(
            bssid,
            "wrong-pass",
        )
        self.assertIn(
            rejection,
            self.plugin.data["credential_rejections"],
        )

    def test_password_repair_changes_nothing_when_any_candidate_is_inconclusive(self):
        bssid = "AA:BB:CC:DD:EE:FF"
        records = {
            ("valid",): {
                "essid": "Lab",
                "bssid": bssid,
                "password": "valid-pass",
            },
            ("unknown",): {
                "essid": "Lab",
                "bssid": bssid,
                "password": "unknown-pass",
            },
        }
        with (
            mock.patch.object(
                self.plugin,
                "_get_cracked_data",
                return_value=records,
            ),
            mock.patch.object(
                self.plugin,
                "_verify_manual_password",
                side_effect=[
                    (True, "verified"),
                    (
                        False,
                        "Password cannot be verified because this capture "
                        "contains no usable hash",
                    ),
                ],
            ),
            mock.patch.object(self.plugin, "_delete_password") as delete,
        ):
            ok, message = self.plugin._repair_password_conflict(bssid)

        self.assertFalse(ok)
        self.assertIn("could not be checked conclusively", message)
        delete.assert_not_called()
        self.assertNotIn(
            "credential_rejections",
            self.plugin.data,
        )

    def test_password_repair_runs_in_background_and_exposes_progress(self):
        started = threading.Event()
        release = threading.Event()

        def repair(_bssid, progress=None):
            progress(1, 2, "Checking local candidate 1 of 2...")
            started.set()
            release.wait(2)
            return True, "Conflict repaired"

        with mock.patch.object(
            self.plugin,
            "_repair_password_conflict",
            side_effect=repair,
        ):
            ok, payload = self.plugin._start_password_conflict_repair(
                "AA:BB:CC:DD:EE:FF"
            )
            self.assertTrue(ok)
            self.assertEqual(payload["status"], "running")
            self.assertTrue(started.wait(1))
            with self.plugin.conflict_repair_lock:
                running = dict(
                    self.plugin.conflict_repair_jobs["aabbccddeeff"]
                )
            self.assertEqual(running["current"], 1)
            self.assertEqual(running["total"], 2)
            release.set()
            for _ in range(100):
                with self.plugin.conflict_repair_lock:
                    status = self.plugin.conflict_repair_jobs[
                        "aabbccddeeff"
                    ]["status"]
                if status == "done":
                    break
                time.sleep(0.01)
            self.assertEqual(status, "done")

    def test_individual_download_resolves_to_best_capture(self):
        weak = os.path.join(self.tempdir.name, "weak.pcap")
        best = os.path.join(self.tempdir.name, "best.pcap")
        for path in (weak, best):
            with open(path, "wb") as handle:
                handle.write(os.path.basename(path).encode())
        self.plugin.handshake_dirs = [self.tempdir.name]

        with (
            mock.patch.object(
                self.plugin,
                "_best_capture_for_path",
                return_value=best,
            ),
            mock.patch(
                "A_pwmenu.send_file",
                return_value="response",
            ) as sender,
        ):
            response = self.plugin._serve_file("weak.pcap")

        self.assertEqual(response, "response")
        sender.assert_called_once()
        self.assertEqual(sender.call_args.args[0], best)
        self.assertEqual(
            sender.call_args.kwargs["download_name"], "best.pcap"
        )


if __name__ == "__main__":
    unittest.main()
