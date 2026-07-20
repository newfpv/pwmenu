import os
import sys
import tempfile
import types
import unittest


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


if __name__ == "__main__":
    unittest.main()
