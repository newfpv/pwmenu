import sys
import threading
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


class OhcWorkerSerializationTests(unittest.TestCase):
    def test_concurrent_starts_create_one_worker(self):
        plugin = A_pwmenu()
        plugin.options = {}
        plugin._pending_ohc_paths = lambda: ["capture.pcap"]
        plugin._ohc_retry_at = lambda: 0
        release_worker = threading.Event()
        started_workers = []

        def worker(_filenames):
            started_workers.append(threading.current_thread())
            release_worker.wait(2)

        plugin._ohc_upload_worker = worker
        callers = [
            threading.Thread(target=plugin._start_ohc_upload_thread)
            for _ in range(20)
        ]
        for caller in callers:
            caller.start()
        for caller in callers:
            caller.join()

        self.assertEqual(len(started_workers), 1)
        release_worker.set()
        plugin.ohc_upload_thread.join(2)


if __name__ == "__main__":
    unittest.main()
