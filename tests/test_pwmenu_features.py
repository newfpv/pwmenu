import hashlib
import hmac
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

from flask import Flask


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


class PWMenuFeatureTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.plugin = A_pwmenu()
        self.plugin.options = {
            "timezone": 0,
            "module_wpa_sec_enabled": True,
            "wpa_sec_key": "test-key",
            "wpa_sec_api_url": "https://wpa-sec.example",
        }
        self.plugin.handshake_dirs = [self.tempdir.name]
        self.plugin.potfile_ohc = os.path.join(self.tempdir.name, "ohc.potfile")
        self.plugin.potfile_handshake_lab = os.path.join(
            self.tempdir.name, "handshake-lab.potfile"
        )
        self.plugin.potfile_manual = os.path.join(
            self.tempdir.name, "manual.potfile"
        )
        self.plugin.data_file = os.path.join(self.tempdir.name, ".state.json")
        self.plugin.data = {
            "xp": 0,
            "capture_quality": {},
            "capture_password_checks": {},
            "locations": {},
            "wpa_files": {},
            "wpa_networks": {},
            "wpa_last_download": 0,
        }

    def test_manual_password_is_saved_only_after_aircrack_verification(self):
        capture = os.path.join(
            self.tempdir.name, "Cafe_aabbccddeeff.pcap"
        )
        with open(capture, "wb") as handle:
            handle.write(b"capture")

        with (
            mock.patch.object(
                self.plugin, "_matching_capture_paths", return_value=[capture]
            ),
            mock.patch.object(
                self.plugin,
                "_run_aircrack_password_check",
                return_value=(True, True, "KEY FOUND"),
            ),
        ):
            ok, message = self.plugin._add_manual_password(
                "Cafe", "aa:bb:cc:dd:ee:ff", "pass:word"
            )

        self.assertTrue(ok)
        self.assertIn("verified", message)
        with open(self.plugin.potfile_manual, encoding="utf-8") as handle:
            self.assertIn("Cafe:pass:word", handle.read())

    def test_manual_password_rejection_does_not_create_potfile(self):
        with mock.patch.object(
            self.plugin,
            "_matching_capture_paths",
            return_value=[],
        ):
            ok, message = self.plugin._add_manual_password(
                "Cafe", "aa:bb:cc:dd:ee:ff", "wrongpass"
            )

        self.assertFalse(ok)
        self.assertIn("No matching capture", message)
        self.assertFalse(os.path.exists(self.plugin.potfile_manual))

    def test_manual_password_falls_back_to_hcxtools_for_pmkid(self):
        capture = os.path.join(
            self.tempdir.name, "Cafe_aabbccddeeff.pcap"
        )
        with open(capture, "wb") as handle:
            handle.write(b"pmkid capture")

        with (
            mock.patch.object(
                self.plugin, "_matching_capture_paths", return_value=[capture]
            ),
            mock.patch.object(
                self.plugin,
                "_run_aircrack_password_check",
                return_value=(False, False, "no EAPOL data"),
            ),
            mock.patch.object(
                self.plugin,
                "_run_hcxpmk_password_check",
                return_value=(True, True, "PMKID confirmed"),
            ) as hcx_check,
        ):
            ok, message = self.plugin._add_manual_password(
                "Cafe", "aa:bb:cc:dd:ee:ff", "correcthorse"
            )

        self.assertTrue(ok)
        self.assertIn("verified", message)
        hcx_check.assert_called_once_with(
            capture,
            "Cafe",
            "aabbccddeeff",
            ["correcthorse"],
        )

    def test_manual_password_explains_when_capture_has_no_hash(self):
        capture = os.path.join(
            self.tempdir.name, "Cafe_aabbccddeeff.pcap"
        )
        with open(capture, "wb") as handle:
            handle.write(b"incomplete capture")

        with (
            mock.patch.object(
                self.plugin, "_matching_capture_paths", return_value=[capture]
            ),
            mock.patch.object(
                self.plugin,
                "_run_aircrack_password_check",
                return_value=(False, False, "Packets contained no EAPOL data"),
            ),
            mock.patch.object(
                self.plugin,
                "_run_hcxpmk_password_check",
                return_value=(
                    False,
                    False,
                    "No matching PMKID/EAPOL hash was extracted",
                ),
            ),
        ):
            verified, message = self.plugin._verify_manual_password(
                "Cafe",
                "aabbccddeeff",
                "correcthorse",
            )

        self.assertFalse(verified)
        self.assertEqual(
            message,
            "Password cannot be verified because this capture contains no "
            "usable WPA/PMKID hash. Recapture the access point",
        )

    def test_pmkid_verification_is_local_and_password_not_in_subprocess(self):
        capture = os.path.join(
            self.tempdir.name, "Cafe_aabbccddeeff.pcap"
        )
        with open(capture, "wb") as handle:
            handle.write(b"pmkid capture")

        tool_calls = []
        ap_mac = bytes.fromhex("aabbccddeeff")
        station_mac = bytes.fromhex("112233445566")
        essid_bytes = b"Cafe"
        pmk = hashlib.pbkdf2_hmac(
            "sha1",
            b"correcthorse",
            essid_bytes,
            4096,
            dklen=32,
        )
        pmkid = hmac.new(
            pmk,
            b"PMK Name" + ap_mac + station_mac,
            hashlib.sha1,
        ).digest()[:16].hex()
        hash_line = (
            f"WPA*01*{pmkid}*"
            "aabbccddeeff*112233445566*43616665"
        )

        def run_tool(args, **kwargs):
            tool_calls.append((args, kwargs))
            with open(args[2], "w", encoding="utf-8") as handle:
                handle.write(hash_line + "\n")
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        with (
            mock.patch(
                "A_pwmenu.shutil.which",
                side_effect=lambda name: f"/fake/{name}",
            ),
            mock.patch("A_pwmenu.subprocess.run", side_effect=run_tool),
        ):
            verified, conclusive, _ = self.plugin._run_hcxpmk_password_check(
                capture,
                "Cafe",
                "aa:bb:cc:dd:ee:ff",
                ["correcthorse"],
            )

        self.assertTrue(verified)
        self.assertTrue(conclusive)
        self.assertEqual(len(tool_calls), 1)
        argv, call_options = tool_calls[0]
        self.assertNotIn("correcthorse", argv)
        self.assertNotIn("input", call_options)
        self.assertFalse(
            self.plugin._verify_pmkid_hash_password(
                hash_line, "definitelywrong"
            )
        )

    def test_capture_map_location_is_persisted_for_exact_handshake(self):
        filename = "Cafe_aabbccddeeff.pcap"
        capture = os.path.join(self.tempdir.name, filename)
        with open(capture, "wb") as handle:
            handle.write(b"capture")

        ok, message, point_id = self.plugin._set_capture_map_location(
            filename, "53.9", "27.56"
        )

        self.assertTrue(ok)
        self.assertIn(filename, message)
        self.assertEqual(filename, point_id)
        location = self.plugin.data["locations"][filename]
        self.assertEqual(53.9, location["lat"])
        self.assertEqual(27.56, location["lon"])
        self.assertEqual("manual-map", location["source"])
        resolved, changed = self.plugin._location_for_file(
            filename,
            capture,
            "Cafe",
            "aabbccddeeff",
            os.path.getmtime(capture),
            "today",
        )
        self.assertFalse(changed)
        self.assertEqual(53.9, resolved["lat"])

    def test_single_map_point_does_not_duplicate_member_payload(self):
        points = self.plugin._build_map_points([
            {
                "essid": "Cafe",
                "is_cracked": False,
                "files": [{
                    "filename": "Cafe_aabbccddeeff.pcap",
                    "bssid": "aa:bb:cc:dd:ee:ff",
                    "lat": 53.9,
                    "lon": 27.56,
                    "gps_source": "manual-map",
                    "quality": {},
                }],
            }
        ])

        self.assertEqual(len(points), 1)
        self.assertEqual(points[0]["source"], "manual-map")
        self.assertEqual(points[0]["members"], [])
        self.assertEqual(points[0]["history"], [])

    def test_capture_map_location_rejects_invalid_target_or_coordinates(self):
        filename = "Cafe_aabbccddeeff.pcap"
        capture = os.path.join(self.tempdir.name, filename)
        with open(capture, "wb") as handle:
            handle.write(b"capture")

        ok, message, _ = self.plugin._set_capture_map_location(
            "../Cafe.pcap", "53.9", "27.56"
        )
        self.assertFalse(ok)
        self.assertIn("not found", message)

        ok, message, _ = self.plugin._set_capture_map_location(
            filename, "120", "27.56"
        )
        self.assertFalse(ok)
        self.assertIn("Latitude", message)

        ok, message, _ = self.plugin._set_capture_map_location(
            filename, "undefined", "27.56"
        )
        self.assertFalse(ok)
        self.assertEqual("Map coordinates are invalid", message)

    def test_password_txt_is_utf8_tsv_and_preserves_colons(self):
        with open(self.plugin.potfile_manual, "w", encoding="utf-8") as handle:
            handle.write(
                "aa:bb:cc:dd:ee:ff:aa:bb:cc:dd:ee:ff:Cafe:pass:word\n"
            )
        app = Flask(__name__)
        with app.test_request_context("/plugins/A_pwmenu/export-passwords"):
            response = self.plugin._serve_password_list()
            response.direct_passthrough = False
            payload = response.get_data()

        self.assertTrue(payload.startswith(b"\xef\xbb\xbf"))
        text = payload.decode("utf-8-sig")
        self.assertTrue(text.startswith("ESSID\tBSSID\tPASSWORD\tSOURCE\r\n"))
        self.assertIn("Cafe\tAA:BB:CC:DD:EE:FF\tpass:word\tManual", text)

    def test_single_ohc_action_reports_why_nothing_was_queued(self):
        request = types.SimpleNamespace(
            form={"filenames": "Partial_aabbccddeeff.pcap"}
        )
        with (
            mock.patch.object(
                self.plugin,
                "_queue_ohc_files",
                return_value=0,
            ),
            mock.patch.object(
                self.plugin,
                "_ohc_file_record",
                return_value={
                    "status": "invalid",
                    "message": "No usable WPA or PMKID hash found",
                },
            ),
        ):
            message, is_error = self.plugin._handle_ohc_cluster_upload(
                request
            )

        self.assertTrue(is_error)
        self.assertEqual(
            message,
            "Nothing queued: No usable WPA or PMKID hash found",
        )

    def test_wpa_upload_uses_service_cookie(self):
        capture = os.path.join(
            self.tempdir.name, "Cafe_aabbccddeeff.pcap"
        )
        with open(capture, "wb") as handle:
            handle.write(b"capture")
        response = mock.Mock(status_code=200, text="accepted")

        with mock.patch("A_pwmenu.requests.post", return_value=response) as post:
            message, is_error = self.plugin._upload_path_to_wpa(
                capture, "secret"
            )

        self.assertFalse(is_error)
        self.assertEqual("Uploaded successfully", message)
        kwargs = post.call_args.kwargs
        self.assertEqual({"key": "secret"}, kwargs["cookies"])
        self.assertNotIn("params", kwargs)

    def test_wpa_queue_does_not_resubmit_known_bssid(self):
        capture = os.path.join(
            self.tempdir.name, "Cafe_aabbccddeeff.pcap"
        )
        with open(capture, "wb") as handle:
            handle.write(b"capture")
        self.plugin.data["wpa_networks"] = {
            "bssid:aabbccddeeff": {"status": "submitted"}
        }

        queued = self.plugin._queue_wpa_files(
            [os.path.basename(capture)], force=False
        )

        self.assertEqual(0, queued)
        self.assertEqual({}, self.plugin.wpa_pending_files)

    def test_wpa_results_download_is_owned_by_pwmenu(self):
        response = mock.Mock(
            content=(
                b"aa:bb:cc:dd:ee:ff:00:00:00:00:00:00:"
                b"Cafe:password123\n"
            )
        )
        response.raise_for_status.return_value = None

        with mock.patch("A_pwmenu.requests.get", return_value=response) as get:
            message, is_error = self.plugin._download_wpa_results("secret")

        self.assertFalse(is_error)
        self.assertIn("results downloaded", message)
        target = os.path.join(
            self.tempdir.name, "wpa-sec.cracked.potfile"
        )
        self.assertTrue(os.path.isfile(target))
        self.assertGreater(self.plugin.data["wpa_last_download"], 0)
        self.assertEqual({"key": "secret"}, get.call_args.kwargs["cookies"])

    def test_wpa_compact_potfile_preserves_bssid_and_password_colons(self):
        target = os.path.join(
            self.tempdir.name, "wpa-sec.cracked.potfile"
        )
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(
                "aabbccddeeff:112233445566:Cafe_Network:pass:word\n"
            )

        cracked = self.plugin._get_cracked_data()

        self.assertEqual(len(cracked), 1)
        record = next(iter(cracked.values()))
        self.assertEqual(record["essid"], "Cafe_Network")
        self.assertEqual(record["bssid"], "aabbccddeeff")
        self.assertEqual(record["password"], "pass:word")
        self.assertEqual(record["source"], "WPA-Sec")

    def test_wpa_compact_potfile_keeps_same_name_on_distinct_bssids(self):
        target = os.path.join(
            self.tempdir.name, "wpa-sec.cracked.potfile"
        )
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(
                "aabbccddeeff:112233445566:Shared:password123\n"
                "ffeeddccbbaa:665544332211:Shared:password123\n"
            )

        cracked = self.plugin._get_cracked_data()

        self.assertEqual(len(cracked), 2)
        self.assertEqual(
            {record["bssid"] for record in cracked.values()},
            {"aabbccddeeff", "ffeeddccbbaa"},
        )

    def test_wpa_compact_and_colon_formats_merge_by_exact_bssid(self):
        target = os.path.join(
            self.tempdir.name, "wpa-sec.cracked.potfile"
        )
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(
                "aabbccddeeff:112233445566:Cafe:password123\n"
            )
        with open(self.plugin.potfile_ohc, "w", encoding="utf-8") as handle:
            handle.write(
                "aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:"
                "Cafe:password123\n"
            )

        cracked = self.plugin._get_cracked_data()

        self.assertEqual(len(cracked), 1)
        record = next(iter(cracked.values()))
        self.assertEqual(record["bssid"], "aabbccddeeff")
        self.assertEqual(record["sources"], ["WPA-Sec", "OHC"])


if __name__ == "__main__":
    unittest.main()
