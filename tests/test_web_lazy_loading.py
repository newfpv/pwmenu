import gzip
import json
import sys
import types
import unittest
from unittest import mock

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


class WebLazyLoadingTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.plugin = A_pwmenu()
        self.plugin.ready = True
        self.plugin.options = {
            "module_web_enabled": True,
            "web_background_preload": True,
        }

    def test_large_page_assets_are_split_and_browser_cacheable(self):
        resources = self.plugin._web_resources()

        self.assertLess(len(resources["page"]), 50000)
        self.assertGreater(len(resources["app.css"]), 50000)
        self.assertGreater(len(resources["app.js"]), 50000)
        self.assertIn("assets/app.css", resources["page"])
        self.assertIn("assets/app.js", resources["page"])
        self.assertRegex(
            resources["page"], r"assets/app\.js\?h=[0-9a-f]{12}"
        )
        self.assertNotIn("__PWMENU_JS_REV__", resources["page"])
        self.assertNotIn("__PWMENU_ICON_REV__", resources["app.js"])
        self.assertIn("async function loadTab", resources["app.js"])
        self.assertIn("scheduleBackgroundPreload", resources["app.js"])
        self.assertIn("seedCardPlaceholders", resources["app.js"])
        self.assertIn("scheduleTabBackfill", resources["app.js"])
        self.assertIn("pwmenu-card-arrival", resources["app.js"])
        self.assertIn("hydrateTabDetails", resources["app.js"])
        self.assertNotIn("{{ map_points|tojson }}", resources["app.js"])
        self.assertIn(
            ".conflict-list,.activity-history-list,.whitelist-compact-list",
            resources["app.css"],
        )
        self.assertIn("max-height:305px", resources["app.css"])
        self.assertIn(".map-toast { position:fixed", resources["app.css"])
        self.assertIn("compact-card-heading", resources["page"])
        self.assertIn('id="whitelistTotal"', resources["page"])
        self.assertIn("whitelist-compact-list", resources["page"])
        self.assertNotIn("whitelist-more", resources["page"])
        self.assertNotIn(
            "function toggleWhitelistOverflow", resources["app.js"]
        )
        self.assertNotIn("whitelist-overflow", resources["page"])
        self.assertNotIn("Show more", resources["page"])
        self.assertIn(
            "const total = document.getElementById('whitelistTotal')",
            resources["app.js"],
        )
        self.assertIn("function copyConflictCenter", resources["app.js"])
        self.assertIn(
            "async function copyAllActivityHistory",
            resources["app.js"],
        )
        self.assertNotIn("loadMoreActivityHistory", resources["app.js"])
        self.assertNotIn("Load older activity", resources["page"])
        self.assertIn(
            "async function repairPasswordConflict",
            resources["app.js"],
        )
        self.assertIn("button.textContent = 'Checking...'", resources["app.js"])
        self.assertIn(
            "api/repair-password-conflict/",
            resources["app.js"],
        )
        self.assertEqual(resources["page"].count('id="mapToast"'), 1)
        self.assertIn(
            "function toggleIdentityAchievements", resources["app.js"]
        )
        self.assertIn(
            "foreground ? foregroundBatchSize : backgroundBatchSize",
            resources["app.js"],
        )
        self.assertIn(
            "async function hydratePendingTabDetails",
            resources["app.js"],
        )
        self.assertIn(
            "if(!state.hasMore) hydratePendingTabDetails(tabName)",
            resources["app.js"],
        )
        self.assertIn(
            "const queue = ['handshakes', 'map', 'cracked', 'other']",
            resources["app.js"],
        )
        self.assertIn("loadYandexMaps();", resources["app.js"])
        self.assertIn("Results &amp; transfer", resources["page"])
        action_labels = [
            "Export passwords",
            "Download all PCAPs",
            "Download Uncracked",
            "Download backup",
            ">Import<",
            "Sync device time",
        ]
        positions = [resources["page"].index(label) for label in action_labels]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("Restore backup", resources["page"])
        self.assertIn(".pwmenu-backup", resources["page"])
        self.assertNotIn("OHC Password Storage", resources["page"])
        self.assertNotIn(">Copy all<", resources["page"])
        self.assertIn(
            "#v-other>.activity-card{grid-column:1/-1;order:7}",
            resources["app.css"],
        )
        self.assertIn(
            "#v-other>.conflict-card{grid-column:1/-1;order:8}",
            resources["app.css"],
        )

        with self.app.test_request_context(
            "/plugins/A_pwmenu/assets/app.js",
            headers={"Accept-Encoding": "gzip"},
        ):
            response = self.plugin._serve_web_asset("app.js", request)
            etag = response.headers["ETag"]
            self.assertEqual(response.headers["Content-Encoding"], "gzip")
            self.assertIn("immutable", response.headers["Cache-Control"])
            self.assertEqual(
                gzip.decompress(response.get_data()).decode("utf-8"),
                resources["app.js"],
            )

        with self.app.test_request_context(
            "/plugins/A_pwmenu/assets/app.js",
            headers={"If-None-Match": etag},
        ):
            response = self.plugin._serve_web_asset("app.js", request)
            self.assertEqual(response.status_code, 304)

    def test_snapshot_is_split_into_shell_tabs_and_on_demand_details(self):
        rendered = """
        before
        <!-- PWMENU_TAB_CRACKED_START -->
        <!-- PWMENU_CARD_CRACKED_1_START -->
        <article data-t="Cafe Alpha">cracked
        <!-- PWMENU_DETAIL_CRACKED_1_START -->secret<!-- PWMENU_DETAIL_CRACKED_1_END -->
        </article>
        <!-- PWMENU_CARD_CRACKED_1_END -->
        <!-- PWMENU_TAB_CRACKED_END -->
        <!-- PWMENU_TAB_HANDSHAKES_START -->
        <!-- PWMENU_CARD_HANDSHAKES_2_START -->
        <article data-t="Cafe Beta">handshakes
        <!-- PWMENU_DETAIL_HANDSHAKE_2_START -->captures<!-- PWMENU_DETAIL_HANDSHAKE_2_END -->
        </article>
        <!-- PWMENU_CARD_HANDSHAKES_2_END -->
        <!-- PWMENU_TAB_HANDSHAKES_END -->
        <!-- PWMENU_TAB_MAP_START -->map<!-- PWMENU_TAB_MAP_END -->
        <!-- PWMENU_TAB_OTHER_START -->other<!-- PWMENU_TAB_OTHER_END -->
        after
        """

        shell, fragments, details, paged_tabs = (
            self.plugin._snapshot_sections(rendered)
        )

        self.assertIn("pwmenu-tab-skeleton", shell)
        self.assertIn("pwmenu-map-loading", shell)
        self.assertIn("Loading map...", shell)
        self.assertNotIn("secret", shell)
        self.assertNotIn("captures", fragments["handshakes"])
        self.assertEqual(details["cracked"]["1"], "secret")
        self.assertEqual(details["handshake"]["2"], "captures")
        self.assertEqual(len(paged_tabs["cracked"]["cards"]), 1)
        self.assertEqual(
            paged_tabs["cracked"]["cards"][0]["search"], "cafe alpha"
        )

    def test_tab_and_detail_routes_return_snapshot_fragments(self):
        snapshot = {
            "id": "snapshot-1",
            "fragments": {
                "cracked": "<article>Cracked</article>",
                "handshakes": "<article>Handshakes</article>",
                "map": "<article>Map</article>",
                "other": "<article>Other</article>",
            },
            "details": {
                "cracked": {"1": "<div>Password</div>"},
                "handshake": {},
            },
            "map_points": [{"id": "one"}],
            "no_gps_networks": [],
            "gps_status": {"state": "online"},
        }
        with mock.patch.object(
            self.plugin, "_page_snapshot", return_value=snapshot
        ):
            with self.app.test_request_context(
                "/plugins/A_pwmenu/api/tab/map"
            ):
                response = self.plugin.on_webhook("api/tab/map", request)
                payload = json.loads(response.get_data(as_text=True))
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["snapshotId"], "snapshot-1")
                self.assertEqual(payload["mapPoints"], [{"id": "one"}])

            with self.app.test_request_context(
                "/plugins/A_pwmenu/api/detail/cracked/1?snapshot=snapshot-1"
            ):
                response = self.plugin.on_webhook(
                    "api/detail/cracked/1", request
                )
                payload = json.loads(response.get_data(as_text=True))
                self.assertEqual(payload["html"], "<div>Password</div>")

            with self.app.test_request_context(
                "/plugins/A_pwmenu/api/details/cracked?snapshot=snapshot-1"
            ):
                response = self.plugin.on_webhook(
                    "api/details/cracked", request
                )
                payload = json.loads(response.get_data(as_text=True))
                self.assertEqual(
                    payload["details"], {"1": "<div>Password</div>"}
                )

            with self.app.test_request_context(
                "/plugins/A_pwmenu/api/detail/cracked/1?snapshot=old"
            ):
                response = self.plugin.on_webhook(
                    "api/detail/cracked/1", request
                )
                self.assertEqual(response.status_code, 409)

    def test_network_tabs_are_paginated_and_search_server_side(self):
        cards = [
            {
                "id": str(index),
                "html": f"<article>Network {index}</article>",
                "search": (
                    f"network {index} "
                    + ("office" if index % 2 == 0 else "home")
                ),
            }
            for index in range(1, 26)
        ]
        snapshot = {
            "id": "page-snapshot",
            "fragments": {
                "cracked": "full",
                "handshakes": "",
                "map": "",
                "other": "",
            },
            "paged_tabs": {
                "cracked": {
                    "cards": cards,
                    "tail": "<footer>End</footer>",
                }
            },
            "details": {"cracked": {}, "handshake": {}},
            "map_points": [],
            "no_gps_networks": [],
            "gps_status": {},
        }
        with mock.patch.object(
            self.plugin, "_page_snapshot", return_value=snapshot
        ):
            with self.app.test_request_context(
                "/plugins/A_pwmenu/api/tab/cracked?page=1&limit=10"
            ):
                payload = json.loads(
                    self.plugin._tab_fragment_response(
                        "cracked", request
                    ).get_data(as_text=True)
                )
                self.assertEqual(payload["total"], 25)
                self.assertEqual(len(payload["detailIds"]), 10)
                self.assertTrue(payload["hasMore"])
                self.assertNotIn("<footer>End</footer>", payload["html"])

            with self.app.test_request_context(
                "/plugins/A_pwmenu/api/tab/cracked?page=2&limit=10&q=office"
            ):
                payload = json.loads(
                    self.plugin._tab_fragment_response(
                        "cracked", request
                    ).get_data(as_text=True)
                )
                self.assertEqual(payload["total"], 12)
                self.assertEqual(len(payload["detailIds"]), 2)
                self.assertFalse(payload["hasMore"])
                self.assertIn("<footer>End</footer>", payload["html"])

            with self.app.test_request_context(
                "/plugins/A_pwmenu/api/tab/cracked"
                "?offset=10&limit=5&snapshot=page-snapshot"
            ):
                payload = json.loads(
                    self.plugin._tab_fragment_response(
                        "cracked", request
                    ).get_data(as_text=True)
                )
                self.assertEqual(payload["offset"], 10)
                self.assertEqual(payload["nextOffset"], 15)
                self.assertEqual(
                    payload["detailIds"],
                    ["11", "12", "13", "14", "15"],
                )

    def test_historical_snapshot_keeps_background_pages_stable(self):
        old = {"id": "old", "created_at": 1}
        current = {"id": "current", "created_at": 2}
        self.plugin.web_snapshot_cache = current
        self.plugin.web_snapshot_history = {"old": old}

        with self.app.test_request_context(
            "/plugins/A_pwmenu/api/tab/cracked?snapshot=old"
        ):
            self.assertIs(
                self.plugin._snapshot_for_request(request), old
            )


if __name__ == "__main__":
    unittest.main()
