import gzip
import sys
import types
import unittest

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


class WebTransportTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.plugin = A_pwmenu()
        self.html = "<!doctype html><title>PWMenu</title>" + ("capture-data;" * 2000)

    def test_large_html_is_gzipped_when_browser_accepts_it(self):
        with self.app.test_request_context(
            "/plugins/A_pwmenu/",
            headers={"Accept-Encoding": "gzip, deflate"},
        ):
            response = self.plugin._html_response(self.html)

        self.assertEqual(response.headers["Content-Encoding"], "gzip")
        self.assertEqual(response.headers["Vary"], "Accept-Encoding")
        self.assertEqual(gzip.decompress(response.get_data()).decode("utf-8"), self.html)
        self.assertLess(len(response.get_data()), len(self.html.encode("utf-8")) // 4)

    def test_identity_response_remains_plain_utf8_html(self):
        with self.app.test_request_context(
            "/plugins/A_pwmenu/",
            headers={"Accept-Encoding": "identity"},
        ):
            response = self.plugin._html_response(self.html)

        self.assertNotIn("Content-Encoding", response.headers)
        self.assertEqual(response.mimetype, "text/html")
        self.assertEqual(response.get_data().decode("utf-8"), self.html)


if __name__ == "__main__":
    unittest.main()
