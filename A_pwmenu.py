import os
import logging
import glob
import json
import csv
import copy
import io
import datetime
import re
import zipfile
import subprocess
import requests
import socket
import time
import threading
import asyncio
import email.utils
import html
import shutil
import tempfile
import pwnagotchi.plugins as plugins
import pwnagotchi.ui.fonts as fonts
from flask import render_template_string, send_file, make_response
from pwnagotchi.ui.components import LabeledValue
from pwnagotchi.ui.view import BLACK

try:
    import websockets
except ImportError:
    websockets = None

try:
    from flask_wtf.csrf import generate_csrf
except ImportError:
    generate_csrf = None

def get_local_time(timestamp, tz_offset):
    dt = datetime.datetime.utcfromtimestamp(timestamp)
    local_dt = dt + datetime.timedelta(hours=tz_offset)
    return local_dt.strftime('%Y-%m-%d %H:%M')

logging.info("[A_pwmenu] Module init.")

class A_pwmenu(plugins.Plugin):
    __author__ = 'NewFPV'
    __version__ = '1.1.3'
    __license__ = 'GPL3'
    __description__ = 'Ultimate Password Manager'

    def __init__(self):
        self.ready = False
        self.handshake_dirs = ['/root/handshakes/', '/home/pi/handshakes/']
        self.potfile_ohc = '/root/handshakes/onlinehashcrack.cracked.potfile'
        self.potfile_manual = '/root/handshakes/manual.potfile'
        self.data_file = '/root/handshakes/.a_pwmenu_data.json'
        self.last_sync = 0
        self.data_lock = threading.RLock()
        self.save_lock = threading.Lock()
        self.time_sync_lock = threading.Lock()
        self.wpa_upload_lock = threading.Lock()
        self.wpa_upload_thread = None
        self.wpa_last_result = ''
        self.gps_indicator_name = 'pwmenu_gps'
        self.pwndroid_running = False
        self.pwndroid_thread = None
        self.pwndroid_coordinates = {}
        self.pwndroid_ws_state = 'stopped'
        self.pwndroid_ws_uri = ''
        self.pwndroid_ws_error_uri = ''
        self.pwndroid_ws_error = ''
        self.gps_lock = threading.RLock()
        self.gpsd_cached_location = None
        self.gpsd_last_poll = 0
        self.ohc_uploading = False
        self.ohc_upload_lock = threading.Lock()
        self.ohc_upload_thread = None
        self.ohc_upload_faces = ('0__1', '1__0', '0__0', '1__1')
        self.ohc_upload_face = '0__0'
        self.ohc_display_faces = None
        self.ohc_display_status = ''
        self.ohc_display_result_until = 0
        self.ohc_progress_current = 0
        self.ohc_progress_total = 0
        self.ohc_progress_name = ''
        self.ohc_found_notice = ''
        self.ohc_found_notice_checked = 0
        self.ohc_last_result = ''
        self.ohc_scheduler_running = False
        self.ohc_scheduler_thread = None
        self.ohc_scheduler_wakeup = threading.Event()

    def on_loaded(self):
        logging.info("[A_pwmenu] Loaded.")
        self._ensure_file(self.potfile_ohc)
        self._ensure_file(self.potfile_manual)
        self._load_data()
        self.options.setdefault('time_sync_interval', 1800)
        self.options.setdefault('phone_gps_enabled', True)
        self.options.setdefault('phone_gps_max_age', 600)
        self.options.setdefault('gps_assign_window', 180)
        self.options.setdefault('gps_stale_seconds', 180)
        self.options.setdefault('gpsd_enabled', True)
        self.options.setdefault('gpsd_host', '127.0.0.1')
        self.options.setdefault('gpsd_port', 2947)
        self.options.setdefault('gpsd_poll_interval', 10)
        self.options.setdefault('pwndroid_ws_enabled', True)
        self.options.setdefault('pwndroid_gateway', '')
        self.options.setdefault('pwndroid_extra_gateways', '')
        self.options.setdefault('pwndroid_mac', '')
        self.options.setdefault('pwndroid_port', 8080)
        self.options.setdefault('ohc_enabled', True)
        self.options.setdefault('ohc_api_key', '')
        self.options.setdefault('ohc_auto_upload', True)
        self.options.setdefault('ohc_sync_interval', 3600)
        self.options.setdefault('ohc_receive_email', 'yes')
        self.options.setdefault('import_max_bytes', 2097152)
        self.options.setdefault('archive_memory_limit', 2097152)
        self.options.setdefault('hcxpcapngtool_timeout', 90)
        self.options.setdefault('ohc_retry_poll_interval', 60)
        self.options.setdefault('ohc_reconcile_on_start', False)
        self._start_pwndroid_ws()
        self.ready = True
        if self._option_bool('ohc_auto_upload', True):
            reconcile = self._option_bool('ohc_reconcile_on_start', False)
            if reconcile:
                with self.data_lock:
                    self.data['ohc_reconcile_requested'] = True
            self._queue_ohc_files(force=reconcile)
        self._start_ohc_scheduler()

    def on_ui_setup(self, ui):
        with ui._lock:
            ui.add_element(self.gps_indicator_name, LabeledValue(
                color=BLACK,
                label='G',
                value='-',
                position=(ui.width() / 2 - 38, 0),
                label_font=fonts.Bold,
                text_font=fonts.Medium
            ))

    def on_ui_update(self, ui):
        if not self.ready:
            return
        try:
            ui.set(self.gps_indicator_name, 'C' if self._fresh_live_gps() else '-')
        except Exception as e:
            logging.debug(f"[A_pwmenu] GPS indicator update failed: {e}")
        if self.ohc_uploading:
            idx = int(time.time()) % len(self.ohc_upload_faces)
            self.ohc_upload_face = self.ohc_upload_faces[idx]
            try:
                faces = self._ohc_display_face_values()
                ui.set('face', faces[idx % len(faces)])
                name = self.ohc_progress_name or 'handshakes'
                if self.ohc_progress_total > 1:
                    ui.set('status', f"OHC uploading {name} {self.ohc_progress_current}/{self.ohc_progress_total}"[:64])
                else:
                    ui.set('status', f"OHC uploading {name}"[:64])
            except Exception as e:
                logging.debug(f"[A_pwmenu] OHC display update failed: {e}")
        elif self.ohc_display_status and time.time() < self.ohc_display_result_until:
            try:
                ui.set('status', self.ohc_display_status[:32])
            except Exception as e:
                logging.debug(f"[A_pwmenu] OHC display result failed: {e}")
        else:
            try:
                if time.time() - self.ohc_found_notice_checked > 30:
                    self.ohc_found_notice = self._ohc_pending_found_notice()
                    self.ohc_found_notice_checked = time.time()
                if self.ohc_found_notice:
                    ui.set('status', self.ohc_found_notice[:64])
            except Exception as e:
                logging.debug(f"[A_pwmenu] OHC found notice failed: {e}")

        try:
            interval = int(self.options.get('time_sync_interval', 1800))
        except (TypeError, ValueError):
            interval = 1800

        if time.time() - self.last_sync > interval:
            self._start_time_sync_thread()

    def on_unload(self, ui):
        self.pwndroid_running = False
        self.ohc_scheduler_running = False
        self.ohc_scheduler_wakeup.set()
        try:
            with ui._lock:
                ui.remove_element(self.gps_indicator_name)
        except Exception:
            pass

    def on_internet_available(self, agent):
        if self.ready and self._option_bool('ohc_auto_upload', True):
            self._queue_ohc_files(force=False)
            self._start_ohc_upload_thread()

    def on_handshake(self, agent, filename, access_point, client_station):
        loc = self._fresh_live_gps()
        if loc:
            try:
                now = time.time()
                gps_age = abs(now - loc.get('ts', now))
                gps_filename = filename.replace(".pcap", ".gps.json")
                with open(gps_filename, "w+t") as fp:
                    json.dump({
                        'Latitude': loc.get('lat'),
                        'Longitude': loc.get('lon'),
                        'Altitude': loc.get('altitude', 0),
                        'Speed': loc.get('speed', 0),
                        'Accuracy': loc.get('accuracy', 0),
                        'Bearing': loc.get('bearing', 0),
                        'Timestamp': loc.get('ts', now),
                        'CaptureTimestamp': now,
                        'GPSAge': gps_age,
                        'GPSStale': gps_age > self._option_int('gps_stale_seconds', 180),
                        'Source': loc.get('source', 'gps')
                    }, fp)
                logging.info(f"[A_pwmenu] Saved PwnDroid GPS to {gps_filename}")
            except Exception as e:
                logging.error(f"[A_pwmenu] Could not save PwnDroid GPS: {e}")
        if self._option_bool('ohc_auto_upload', True):
            self._queue_ohc_files([os.path.basename(filename)], force=False)
            self._start_ohc_upload_thread()

    def on_webhook(self, path, request):
        if not self.ready:
            return "Loading..."
        if path is None:
            path = '/'

        try:
            if request.method == 'POST':
                if path == 'delete-password':
                    essid = request.form.get('essid')
                    pwd = request.form.get('password')
                    source = request.form.get('source')
                    if self._delete_password(essid, pwd, source):
                        return self._render_page(notification="Password deleted", notif_type="success")
                    else:
                        return self._render_page(notification="Could not delete password (readonly source?)", notif_type="error")

                if path == 'update-password':
                    self._update_password(request.form.get('essid'), request.form.get('password'))
                    return self._render_page(notification="Password updated", notif_type="success")

                if path == 'delete-file':
                    fname = request.form.get('filename')
                    if self._delete_specific_file(fname):
                        return self._render_page(notification=f"Deleted {fname}", notif_type="success", active_tab="handshakes")
                    return self._render_page(notification=f"Failed to delete {fname}", notif_type="error", active_tab="handshakes")

                if path == 'clean-broken':
                    d, t = self._clean_broken_handshakes()
                    return self._render_page(notification=f"Removed {d}/{t} broken files", notif_type="success", active_tab='other')

                if path == 'nuke-all':
                    c = self._nuke_all_handshakes()
                    return self._render_page(notification=f"Nuked {c} files and passwords", notif_type="success", active_tab='other')

                if path == 'wpa-sec-upload':
                    res, is_err = self._handle_wpa_upload(request)
                    return self._render_page(notification=res, notif_type="error" if is_err else "success", active_tab="handshakes")

                if path == 'wpa-sec-upload-cluster':
                    res, is_err = self._handle_wpa_cluster_upload(request)
                    return self._render_page(notification=res, notif_type="error" if is_err else "success", active_tab="map")

                if path == 'ohc-upload-cluster':
                    res, is_err = self._handle_ohc_cluster_upload(request)
                    return self._render_page(notification=res, notif_type="error" if is_err else "success", active_tab="map")

                if path == 'ohc-upload-all-missing':
                    res, is_err = self._handle_ohc_all_missing()
                    return self._render_page(notification=res, notif_type="error" if is_err else "success", active_tab="handshakes")

                if path == 'add-password':
                    self._add_manual_password(request.form.get('essid'), request.form.get('bssid'), request.form.get('password'))
                    return self._render_page(notification="Password added", notif_type="success")

                if path == 'phone-gps':
                    ok, msg = self._update_phone_gps(request)
                    resp = make_response(json.dumps({'ok': ok, 'message': msg}))
                    resp.headers['Content-Type'] = 'application/json'
                    return resp

                if path == 'sync-time':
                    if self._sync_time_now():
                        return self._render_page(notification="Time synchronized!", notif_type="success", active_tab='other')
                    else:
                        return self._render_page(notification="Time sync failed (No Internet?)", notif_type="error", active_tab='other')

                if path == 'import':
                    if 'file' not in request.files:
                        return self._render_page(notification="No file uploaded", notif_type="error", active_tab='other')
                    f = request.files['file']
                    if f.filename == '':
                        return self._render_page(notification="No file selected", notif_type="error", active_tab='other')
                    try:
                        max_bytes = self._option_int('import_max_bytes', 2097152)
                        payload = f.stream.read(max_bytes + 1)
                        if len(payload) > max_bytes:
                            return self._render_page(notification="Import file is too large", notif_type="error", active_tab='other')
                        c = self._process_import(payload.decode('utf-8', errors='ignore'), f.filename)
                        return self._render_page(notification=f"Imported {c} passwords", notif_type="success", active_tab='other')
                    except Exception as e:
                        return self._render_page(notification=f"Import Error: {e}", notif_type="error", active_tab='other')

            if path == 'download-zip':
                return self._serve_zip()
            if path == 'download-uncracked':
                return self._serve_uncracked_zip()
            if path.startswith('download-cluster/'):
                return self._serve_cluster_zip(path.replace('download-cluster/', ''))
            if path == 'export-passwords':
                return self._serve_password_list()
            if path.startswith('download-22000/'):
                return self._serve_22000(path.replace('download-22000/', ''))
            if path.startswith('download/'):
                return self._serve_file(path.replace('download/', ''))

            if path == '/' or not path:
                return self._render_page()
            return make_response("Not found", 404)
        except Exception as e:
            logging.error(f"[A_pwmenu] Critical: {e}")
            return self._render_page(notification=f"System Error: {e}", notif_type="error")

    def _sync_time_now(self, silent=False):
        self.last_sync = time.time()
        try:
            response = requests.head(
                'http://connectivitycheck.gstatic.com/generate_204',
                timeout=5,
                allow_redirects=False
            )
            date_header = response.headers.get('Date')
            if not date_header:
                raise RuntimeError('time server returned no Date header')
            remote_time = email.utils.parsedate_to_datetime(date_header)
            subprocess.run(
                ['date', '-u', '-s', f'@{int(remote_time.timestamp())}'],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if not silent:
                logging.info("[A_pwmenu] Time synchronized.")
            return True
        except Exception as e:
            logging.debug(f"[A_pwmenu] Time sync failed: {e}")
            return False

    def _start_time_sync_thread(self):
        if self.time_sync_lock.locked():
            return
        self.last_sync = time.time()

        def worker():
            with self.time_sync_lock:
                self._sync_time_now(silent=True)

        threading.Thread(target=worker, daemon=True, name='pwmenu-time-sync').start()

    def _render_page(self, notification=None, notif_type=None, active_tab='cracked'):
        cracked = self._get_cracked_data()
        groups = self._scan_and_group_files(cracked)
        map_points = self._build_map_points(groups)
        no_gps_networks = self._build_no_gps_networks(groups)
        gps_status = self._gps_status()
        ohc_status = self._ohc_status()
        ach = self._update_achievements(groups, cracked)

        t_nets = len(groups)
        c_nets = len([g for g in groups if g['is_cracked']])
        pct = int((c_nets / t_nets * 100)) if t_nets > 0 else 0

        stats = {
            'cracked': c_nets, 'total': t_nets, 'percent': pct,
            'files': sum(len(g['files']) for g in groups),
            'level': ach['level'], 'xp': ach['xp'], 'next_xp': ach['next_xp'], 'rank': ach['rank'],
            'lvl_percent': ach['lvl_percent'],
            'gps_points': len(map_points),
            'cracked_gps': len([p for p in map_points if p['is_cracked']]),
            'no_gps': len([g for g in groups if g.get('lat') is None or g.get('lon') is None])
        }

        tok = generate_csrf() if generate_csrf else ""
        show_wpa = bool(self.options.get('wpa_sec_key'))

        html = render_template_string(self._get_html(),
            groups=groups, cracked=cracked, notif=notification, ntype=notif_type,
            tab=active_tab, stats=stats, ach=ach['badges'], token=tok,
            show_wpa=show_wpa, map_points=map_points, gps_status=gps_status,
            no_gps_networks=no_gps_networks, ohc_status=ohc_status
        )

        r = make_response(html)
        r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return r

    def _handle_wpa_upload(self, req):
        try:
            with socket.create_connection(("1.1.1.1", 53), timeout=5):
                pass
        except OSError:
            return "No Internet Connection", True

        fname = req.form.get('filename')
        key = self.options.get('wpa_sec_key')
        if not key:
            return "WPA-Sec Key missing in config", True

        path = self._find_handshake_path(fname)
        if not path:
            return "File not found", True

        return self._upload_path_to_wpa(path, key)

    def _handle_wpa_cluster_upload(self, req):
        try:
            with socket.create_connection(("1.1.1.1", 53), timeout=5):
                pass
        except OSError:
            return "No Internet Connection", True

        key = self.options.get('wpa_sec_key')
        if not key:
            return "WPA-Sec Key missing in config", True

        names = []
        for raw in (req.form.get('filenames') or '').split(','):
            name = self._safe_handshake_name(raw.strip())
            if name and name not in names:
                names.append(name)
        if not names:
            return "No files selected", True

        if self.wpa_upload_thread and self.wpa_upload_thread.is_alive():
            return "WPA-sec upload is already running", True

        self.wpa_upload_thread = threading.Thread(
            target=self._wpa_cluster_worker,
            args=(names, key),
            daemon=True,
            name='pwmenu-wpa-upload'
        )
        self.wpa_upload_thread.start()
        return "WPA-sec upload started", False

    def _wpa_cluster_worker(self, names, key):
        with self.wpa_upload_lock:
            uploaded = 0
            already = 0
            failed = []
            for name in names:
                path = self._find_handshake_path(name)
                if not path:
                    failed.append(name)
                    continue
                msg, is_err = self._upload_path_to_wpa(path, key)
                if is_err:
                    failed.append(name)
                elif "Already uploaded" in msg:
                    already += 1
                else:
                    uploaded += 1

            details = []
            if uploaded:
                details.append(f"{uploaded} uploaded")
            if already:
                details.append(f"{already} already uploaded")
            if failed:
                details.append(f"{len(failed)} failed")
            self.wpa_last_result = "WPA-sec cluster upload: " + ", ".join(details or ["no files processed"])
            if failed:
                logging.warning(f"[A_pwmenu] {self.wpa_last_result}")
            else:
                logging.info(f"[A_pwmenu] {self.wpa_last_result}")

    def _handle_ohc_cluster_upload(self, req):
        names = self._filenames_from_csv(req.form.get('filenames') or '')
        if not names:
            return "No files selected", True
        queued = self._queue_ohc_files(names, force=True)
        self._start_ohc_upload_thread()
        if time.time() < self._ohc_retry_at():
            return f"Queued {queued} file(s). {self._ohc_backoff_message()}", False
        return f"OHC upload started for {queued} file(s)", False

    def _handle_ohc_all_missing(self):
        if not self._option_bool('ohc_enabled', True):
            return "OHC disabled", True
        if not self._ohc_key():
            return "OHC API key missing", True
        with self.data_lock:
            self.data['ohc_reconcile_requested'] = True
        queued = self._queue_ohc_files(force=True)
        self._save_data()
        self._start_ohc_upload_thread()
        if time.time() < self._ohc_retry_at():
            return f"Queued {queued} file(s). {self._ohc_backoff_message()}", False
        return f"Scanning {queued} file(s) and sending hashes missing from OHC", False

    def _filenames_from_csv(self, text):
        names = []
        for raw in (text or '').split(','):
            name = self._safe_handshake_name(raw.strip())
            if name and name not in names:
                names.append(name)
        return names

    def _ohc_key(self):
        key = (self.options.get('ohc_api_key') or self.options.get('api_key') or '').strip()
        if key:
            return key
        cfg = '/etc/pwnagotchi/config.toml'
        try:
            if os.path.exists(cfg):
                with open(cfg, 'r', errors='ignore') as f:
                    text = f.read()
                for pat in (
                    r'main\.plugins\.A_pwmenu\.ohc_api_key\s*=\s*"([^"]+)"',
                    r"main\.plugins\.A_pwmenu\.ohc_api_key\s*=\s*'([^']+)'",
                    r'main\.plugins\.ohcapi\.api_key\s*=\s*"([^"]+)"',
                    r"main\.plugins\.ohcapi\.api_key\s*=\s*'([^']+)'"
                ):
                    m = re.search(pat, text)
                    if m:
                        return m.group(1).strip()
        except OSError as e:
            logging.debug(f"[A_pwmenu] OHC key lookup failed: {e}")
        return ''

    def _ohc_display_face_values(self):
        if self.ohc_display_faces:
            return self.ohc_display_faces
        values = {
            'upload': '(1__0)',
            'upload1': '(1__1)',
            'upload2': '(0__1)',
            'debug': '(#__#)'
        }
        cfg = '/etc/pwnagotchi/config.toml'
        try:
            if os.path.exists(cfg):
                with open(cfg, 'r', errors='ignore') as f:
                    text = f.read()
                for name in values:
                    key = re.escape(f'ui.faces.{name}')
                    m = re.search(key + r'\s*=\s*"([^"]+)"', text)
                    if not m:
                        m = re.search(key + r"\s*=\s*'([^']+)'", text)
                    if m:
                        values[name] = m.group(1)
        except Exception as e:
            logging.debug(f"[A_pwmenu] OHC face config read failed: {e}")
        self.ohc_display_faces = (
            values['upload'],
            values['upload1'],
            values['upload2'],
            values['debug']
        )
        return self.ohc_display_faces

    def _ohc_file_record(self, filename):
        if not filename:
            return {}
        with self.data_lock:
            records = self.data.setdefault('ohc_files', {})
            return dict(records.get(os.path.basename(filename), {}) or {})

    def _ohc_mark_file(self, filename, status, message='', hashes=0, request_id=''):
        name = os.path.basename(filename or '')
        if not name:
            return
        with self.data_lock:
            records = self.data.setdefault('ohc_files', {})
            prev = records.get(name, {})
            records[name] = {
                'status': status,
                'message': message,
                'hashes': int(hashes or prev.get('hashes', 0) or 0),
                'request_id': request_id or prev.get('request_id', ''),
                'updated_at': int(time.time())
            }

    def _ohc_mark_path(self, path, status, message='', hashes=0, request_id=''):
        self._ohc_mark_file(os.path.basename(path or ''), status, message, hashes, request_id)

    def _ohc_file_signature(self, path):
        try:
            stat = os.stat(path)
            return f"{stat.st_mtime_ns}:{stat.st_size}"
        except OSError:
            return ''

    def _candidate_ohc_paths(self, filenames=None):
        cracked = self._get_cracked_data()
        paths = []
        if filenames:
            for value in filenames:
                name = self._safe_handshake_name(os.path.basename(value or ''))
                if not name:
                    continue
                path = None
                if os.path.isabs(value) and os.path.basename(value) == name:
                    parent = os.path.realpath(os.path.dirname(value))
                    allowed = {os.path.realpath(d.rstrip('/')) for d in self.handshake_dirs}
                    if parent in allowed and os.path.isfile(value):
                        path = value
                if not path:
                    path = self._find_handshake_path(name)
                if path and self._essid_from_filename(name) not in cracked and path not in paths:
                    paths.append(path)
            return paths

        for directory in self.handshake_dirs:
            if not os.path.exists(directory):
                continue
            for path in glob.glob(os.path.join(directory, '*.pcap')):
                if self._essid_from_filename(os.path.basename(path)) not in cracked and path not in paths:
                    paths.append(path)
        return paths

    def _queue_ohc_files(self, filenames=None, force=False):
        paths = self._candidate_ohc_paths(filenames)
        now = int(time.time())
        queued = 0
        changed = False
        with self.data_lock:
            pending = self.data.setdefault('ohc_pending_files', {})
            signatures = self.data.setdefault('ohc_file_signatures', {})
            for path in paths:
                signature = self._ohc_file_signature(path)
                if not signature:
                    continue
                current = pending.get(path, {})
                if not force and signatures.get(path) == signature and not current:
                    continue
                if current.get('signature') != signature or force:
                    pending[path] = {
                        'signature': signature,
                        'queued_at': int(current.get('queued_at', now) or now),
                        'force': bool(force or current.get('force', False))
                    }
                    self._ohc_mark_path(path, 'queued', 'Waiting for OHC upload')
                    changed = True
                queued += 1
        if changed:
            self._save_data()
        self.ohc_scheduler_wakeup.set()
        return queued

    def _pending_ohc_paths(self):
        with self.data_lock:
            pending = dict(self.data.setdefault('ohc_pending_files', {}))
        paths = []
        changed = False
        for path, record in pending.items():
            signature = self._ohc_file_signature(path)
            if not signature:
                with self.data_lock:
                    self.data.setdefault('ohc_pending_files', {}).pop(path, None)
                changed = True
                continue
            if record.get('signature') != signature:
                with self.data_lock:
                    current = self.data.setdefault('ohc_pending_files', {}).setdefault(path, {})
                    current['signature'] = signature
                    current['queued_at'] = int(time.time())
                changed = True
            paths.append(path)
        if changed:
            self._save_data()
        return paths

    def _complete_ohc_path(self, path, signature=None):
        signature = signature or self._ohc_file_signature(path)
        with self.data_lock:
            self.data.setdefault('ohc_pending_files', {}).pop(path, None)
            if signature:
                self.data.setdefault('ohc_file_signatures', {})[path] = signature

    def _start_ohc_scheduler(self):
        if self.ohc_scheduler_thread and self.ohc_scheduler_thread.is_alive():
            return
        self.ohc_scheduler_running = True
        self.ohc_scheduler_thread = threading.Thread(
            target=self._ohc_scheduler_loop,
            daemon=True,
            name='pwmenu-ohc-scheduler'
        )
        self.ohc_scheduler_thread.start()

    def _ohc_scheduler_loop(self):
        while self.ohc_scheduler_running:
            pending = self._pending_ohc_paths()
            retry_in = max(0, self._ohc_retry_at() - time.time())
            if pending and retry_in <= 0:
                self._start_ohc_upload_thread()
                timeout = 10
            elif pending:
                timeout = min(max(1, retry_in), self._option_int('ohc_retry_poll_interval', 60))
            else:
                timeout = self._option_int('ohc_retry_poll_interval', 60)
            self.ohc_scheduler_wakeup.wait(max(1, timeout))
            self.ohc_scheduler_wakeup.clear()

    def _start_ohc_upload_thread(self, filenames=None):
        if not self._option_bool('ohc_enabled', True):
            return
        if filenames:
            self._queue_ohc_files(filenames, force=True)
        if time.time() < self._ohc_retry_at():
            self.ohc_last_result = self._ohc_backoff_message()
            self.ohc_scheduler_wakeup.set()
            return
        if self.ohc_upload_thread and self.ohc_upload_thread.is_alive():
            return
        todo = self._pending_ohc_paths()
        if not todo:
            return
        self.ohc_upload_thread = threading.Thread(
            target=self._ohc_upload_worker,
            args=(todo,),
            daemon=True,
            name='pwmenu-ohc-upload'
        )
        self.ohc_upload_thread.start()

    def _ohc_upload_worker(self, filenames=None):
        with self.ohc_upload_lock:
            self.ohc_uploading = True
            self.ohc_upload_face = '0__1'
            self.ohc_display_status = 'OHC upload'
            self.ohc_progress_current = 0
            self.ohc_progress_total = 0
            self.ohc_progress_name = ''
            try:
                msg, is_err = self._ohc_upload_files(filenames, manual=False)
                self.ohc_last_result = msg
                if msg == 'No Internet Connection':
                    logging.debug(f"[A_pwmenu] {msg}")
                else:
                    logging.info(f"[A_pwmenu] {msg}")
            finally:
                self.ohc_upload_face = '0__0'
                self.ohc_progress_current = 0
                self.ohc_progress_total = 0
                self.ohc_progress_name = ''
                self.ohc_display_status = ''
                self.ohc_display_result_until = 0
                self.ohc_uploading = False
                self.ohc_scheduler_wakeup.set()

    def _ohc_upload_files(self, filenames=None, manual=False):
        if not self._option_bool('ohc_enabled', True):
            return "OHC disabled", True
        key = self._ohc_key()
        if not key:
            return "OHC API key missing", True
        self.ohc_display_status = 'OHC upload'
        try:
            with socket.create_connection(("1.1.1.1", 53), timeout=5):
                pass
        except OSError:
            self._set_ohc_backoff(120, 'No Internet Connection')
            return "No Internet Connection", True

        self.ohc_display_status = 'OHC upload'
        paths = self._candidate_ohc_paths(filenames)

        with self.data_lock:
            reported = set(self.data.setdefault('ohc_reported', []))
        if not paths:
            return "OHC: no uncracked handshakes to upload", False

        path_hash_count = {}
        path_hashes = {}
        with self.data_lock:
            hash_files = dict(self.data.setdefault('ohc_hash_files', {}))
            reported_hashes = set(self.data.setdefault('ohc_reported_hashes', []))
            last_ohc_sync = float(self.data.get('ohc_tasks_synced_at', 0) or 0)
            reconcile_requested = bool(self.data.get('ohc_reconcile_requested', False))
        sync_interval = int(self.options.get('ohc_sync_interval', 3600) or 3600)
        if reconcile_requested or time.time() - last_ohc_sync > sync_interval:
            ok, server_hashes = self._ohc_list_task_hashes(key)
            if ok:
                if reconcile_requested:
                    reported_hashes = set(server_hashes)
                else:
                    reported_hashes.update(server_hashes)
                with self.data_lock:
                    self.data['ohc_reported_hashes'] = sorted(reported_hashes)
                    self.data['ohc_tasks_synced_at'] = time.time()
                    self.data['ohc_reconcile_requested'] = False
                self._save_data()
            elif time.time() < self._ohc_retry_at():
                return self._ohc_backoff_message(), True
            elif reconcile_requested:
                return "OHC task reconciliation failed; queued files were preserved", True

        hashes = []
        hash_sources = {}
        failed_extract = 0
        already_reported = 0
        self.ohc_progress_total = len(paths)
        for idx, path in enumerate(paths):
            self.ohc_progress_current = idx + 1
            self.ohc_progress_name = self._essid_from_filename(os.path.basename(path))
            self.ohc_display_status = 'OHC upload'
            self.ohc_upload_face = self.ohc_upload_faces[idx % len(self.ohc_upload_faces)]
            extracted = self._ohc_extract_hashes(path)
            if not extracted:
                failed_extract += 1
                self._ohc_mark_path(path, 'invalid', 'No valid 22000 hashes extracted')
                self._complete_ohc_path(path)
                continue
            path_hashes[path] = set()
            for h in extracted:
                h = h.strip()
                if not h:
                    continue
                path_hashes[path].add(h)
                path_hash_count[path] = path_hash_count.get(path, 0) + 1
                if h in reported_hashes:
                    already_reported += 1
                    self._ohc_mark_path(path, 'already_reported', 'Already exists in OHC tasks', path_hash_count.get(path, 0))
                    continue
                if h in hash_sources:
                    continue
                hash_files[h] = os.path.basename(path)
                hashes.append(h)
                hash_sources[h] = path

        for path, extracted in path_hashes.items():
            if extracted and extracted.issubset(reported_hashes):
                self._complete_ohc_path(path)

        if not hashes:
            with self.data_lock:
                self.data['ohc_hash_files'] = hash_files
            if already_reported:
                self._save_data()
                return f"OHC: {already_reported} hashes already reported", False
            if failed_extract:
                self._save_data()
            return f"OHC: no valid hashes extracted ({failed_extract} failed)", True

        accepted = 0
        skipped = 0
        rejected = 0
        failed = 0
        sent_paths = set()
        sent_hashes = set()
        self.ohc_progress_total = len(hashes)
        for i in range(0, len(hashes), 50):
            self.ohc_progress_current = min(i + len(hashes[i:i + 50]), len(hashes))
            first_path = hash_sources.get(hashes[i]) if hashes[i:i + 50] else ''
            if first_path:
                self.ohc_progress_name = self._essid_from_filename(os.path.basename(first_path))
            self.ohc_display_status = 'OHC upload'
            self.ohc_upload_face = self.ohc_upload_faces[(i // 50) % len(self.ohc_upload_faces)]
            batch = hashes[i:i + 50]
            ok, data = self._ohc_add_tasks(batch, key)
            if not ok:
                failed += len(batch)
                logging.error(f"[A_pwmenu] OHC upload failed: {data}")
                msg = data.get('message', str(data)) if isinstance(data, dict) else str(data)
                for h in batch:
                    path = hash_sources.get(h)
                    if path:
                        self._ohc_mark_path(path, 'failed', msg, path_hash_count.get(path, 0))
                break
            batch_accepted = int(data.get('accepted', {}).get('count', 0) or 0)
            batch_skipped = int(data.get('skipped', {}).get('count', 0) or 0)
            batch_rejected = int(data.get('rejected', {}).get('count', 0) or 0)
            request_id = data.get('request_id', '')
            accepted += batch_accepted
            skipped += batch_skipped
            rejected += batch_rejected
            rejected_reason = data.get('rejected', {}).get('reason', '')
            fully_accounted = batch_accepted + batch_skipped >= len(batch)
            terminal_rejection = rejected_reason in ('invalid_format', 'invalid_algorithm')
            should_cache_batch = fully_accounted or terminal_rejection
            if not should_cache_batch:
                delay = 3600 if rejected_reason == 'quota_exceeded' else 300
                self._set_ohc_backoff(delay, f"OHC {rejected_reason or 'partial batch failure'}")
                failed += max(1, batch_rejected)
                for h in batch:
                    path = hash_sources.get(h)
                    if path:
                        self._ohc_mark_path(path, 'failed', rejected_reason or 'Partial batch failure', path_hash_count.get(path, 0), request_id)
                break
            for h in batch:
                path = hash_sources.get(h)
                sent_paths.add(path)
                sent_hashes.add(h)
                if path:
                    if rejected_reason in ('invalid_format', 'invalid_algorithm') and not (batch_accepted or batch_skipped):
                        self._ohc_mark_path(path, 'invalid', rejected_reason, path_hash_count.get(path, 0), request_id)
                    elif batch_skipped and not batch_accepted:
                        self._ohc_mark_path(path, 'already_reported', 'OHC skipped: already sent', path_hash_count.get(path, 0), request_id)
                    else:
                        self._ohc_mark_path(path, 'sent', 'Submitted to OHC', path_hash_count.get(path, 0), request_id)

        if sent_hashes:
            for path in sent_paths:
                if path and path not in reported:
                    reported.add(path)
            with self.data_lock:
                self.data['ohc_reported'] = sorted(reported)
                self.data['ohc_hash_files'] = hash_files
            reported_hashes.update(sent_hashes)
            with self.data_lock:
                self.data['ohc_reported_hashes'] = sorted(reported_hashes)
        else:
            with self.data_lock:
                self.data['ohc_hash_files'] = hash_files

        resolved_hashes = reported_hashes | sent_hashes
        for path, extracted in path_hashes.items():
            if extracted and extracted.issubset(resolved_hashes):
                self._complete_ohc_path(path)

        msg = f"OHC: {accepted} accepted, {skipped} skipped, {rejected} rejected"
        if already_reported:
            msg += f", {already_reported} already reported"
        if failed:
            msg += f", {failed} failed"
        self._save_data()
        return msg, failed > 0 and accepted == 0 and skipped == 0

    def _ohc_retry_at(self):
        try:
            with self.data_lock:
                return float(self.data.get('ohc_retry_at', 0) or 0)
        except Exception:
            return 0

    def _ohc_backoff_message(self):
        remaining = max(0, int(self._ohc_retry_at() - time.time()))
        with self.data_lock:
            reason = str(self.data.get('ohc_retry_reason', 'retry later') or 'retry later')
        return f"OHC paused for {remaining}s: {reason}"

    def _set_ohc_backoff(self, seconds, reason):
        try:
            delay = max(60, min(int(seconds), 86400))
        except Exception:
            delay = 300
        retry_at = time.time() + delay
        if retry_at > self._ohc_retry_at():
            with self.data_lock:
                self.data['ohc_retry_at'] = retry_at
                self.data['ohc_retry_reason'] = str(reason or 'retry later')[:200]
            self._save_data()
            self.ohc_scheduler_wakeup.set()

    def _ohc_retry_after_delay(self, value):
        try:
            return int(float(value)) + 10
        except (TypeError, ValueError):
            return 3610

    def _clear_ohc_backoff(self):
        with self.data_lock:
            should_save = bool(self.data.get('ohc_retry_at') or self.data.get('ohc_retry_reason'))
            if should_save:
                self.data['ohc_retry_at'] = 0
                self.data['ohc_retry_reason'] = ''
        if should_save:
            self._save_data()
            self.ohc_scheduler_wakeup.set()

    def _ohc_extract_hashes(self, pcap_path):
        out = None
        try:
            with tempfile.NamedTemporaryFile(prefix='pwmenu-ohc-', suffix='.22000', delete=False) as tmp:
                out = tmp.name
            os.remove(out)
            subprocess.run(
                ['/usr/bin/hcxpcapngtool', '-o', out, pcap_path],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self._option_int('hcxpcapngtool_timeout', 90)
            )
            if os.path.exists(out) and os.path.getsize(out) > 0:
                with open(out, 'r', errors='ignore') as f:
                    return list(dict.fromkeys(line.strip() for line in f if line.strip()))
        except Exception as e:
            logging.error(f"[A_pwmenu] OHC extract failed for {pcap_path}: {e}")
        finally:
            if out:
                try:
                    os.remove(out)
                except FileNotFoundError:
                    pass
        return []

    def _ohc_add_tasks(self, hashes, key):
        payload = {
            'api_key': key,
            'agree_terms': 'yes',
            'action': 'add_tasks',
            'algo_mode': 22000,
            'hashes': [h.strip() for h in hashes if h.strip()],
            'receive_email': self.options.get('ohc_receive_email', 'yes')
        }
        try:
            res = requests.post('https://api.onlinehashcrack.com/v2', json=payload, timeout=30)
            try:
                data = res.json()
            except ValueError:
                data = {'message': res.text}
            if res.status_code == 429:
                retry_after = res.headers.get('Retry-After') or data.get('retry_after', 3600)
                self._set_ohc_backoff(self._ohc_retry_after_delay(retry_after), 'OHC rate limit')
                return False, self._ohc_backoff_message()
            if not res.ok or data.get('success') is False:
                return False, data
            self._clear_ohc_backoff()
            logging.info(f"[A_pwmenu] OHC response: request_id={data.get('request_id')} accepted={data.get('accepted', {}).get('count', 0)} skipped={data.get('skipped', {}).get('count', 0)} rejected={data.get('rejected', {}).get('count', 0)}")
            return True, data
        except Exception as e:
            self._set_ohc_backoff(300, f'OHC request failed: {e}')
            return False, str(e)

    def _ohc_list_task_hashes(self, key):
        payload = {
            'api_key': key,
            'agree_terms': 'yes',
            'action': 'list_tasks'
        }
        try:
            res = requests.post('https://api.onlinehashcrack.com/v2', json=payload, timeout=30)
            try:
                data = res.json()
            except ValueError:
                data = {'message': res.text}
            if res.status_code == 429:
                retry_after = res.headers.get('Retry-After') or data.get('retry_after', 3600)
                self._set_ohc_backoff(self._ohc_retry_after_delay(retry_after), 'OHC list_tasks rate limit')
                logging.warning(f"[A_pwmenu] {self._ohc_backoff_message()}")
                return False, set()
            if not res.ok or data.get('success') is False:
                logging.warning(f"[A_pwmenu] OHC list_tasks failed: {data}")
                return False, set()
            hashes = set()
            with self.data_lock:
                found_files = dict(self.data.setdefault('ohc_found_files', {}))
                hash_files = dict(self.data.setdefault('ohc_hash_files', {}))
            for task in data.get('tasks', []) or []:
                h = str(task.get('hash') or '').strip()
                if h:
                    hashes.add(h)
                    if str(task.get('status') or '').upper() == 'FOUND':
                        fname = hash_files.get(h)
                        if fname:
                            found_files[fname] = {
                                'status': 'found',
                                'updated_at': int(time.time())
                            }
                            self._ohc_mark_file(fname, 'found', 'Password available on OHC')
            if found_files:
                with self.data_lock:
                    self.data['ohc_found_files'] = found_files
                self._save_data()
            logging.info(f"[A_pwmenu] OHC list_tasks synced {len(hashes)} hashes, request_id={data.get('request_id')}")
            self._clear_ohc_backoff()
            return True, hashes
        except Exception as e:
            self._set_ohc_backoff(300, f'OHC list_tasks failed: {e}')
            logging.warning(f"[A_pwmenu] OHC list_tasks failed: {e}")
            return False, set()

    def _ohc_pending_found_notice(self):
        with self.data_lock:
            found = copy.deepcopy(self.data.get('ohc_found_files', {}))
        if not isinstance(found, dict) or not found:
            return ''
        cracked = self._get_cracked_data()
        for fname in sorted(found, key=lambda n: found.get(n, {}).get('updated_at', 0), reverse=True):
            essid = self._essid_from_filename(fname)
            if essid and essid not in cracked:
                return f"OHC found {essid}"
        return ''

    def _safe_handshake_name(self, value):
        if not isinstance(value, str):
            return None
        name = value.strip()
        if not name or len(name) > 255 or '\x00' in name:
            return None
        if name != os.path.basename(name) or '/' in name or '\\' in name:
            return None
        if not name.lower().endswith('.pcap'):
            return None
        return name

    def _find_handshake_path(self, fname):
        name = self._safe_handshake_name(fname)
        if not name:
            return None
        for d in self.handshake_dirs:
            fp = os.path.join(d, name)
            if os.path.isfile(fp):
                return fp
        return None

    def _upload_path_to_wpa(self, path, key):
        try:
            with open(path, 'rb') as f:
                r = requests.post(
                    'https://wpa-sec.stanev.org/',
                    params={'api_key': key},
                    files={'file': f},
                    timeout=(10, 30)
                )

            if r.status_code == 200:
                if "already in database" in r.text:
                    return "Already uploaded", False
                return "Uploaded successfully", False
            return f"Error {r.status_code}: {r.text}", True

        except requests.exceptions.RequestException as e:
            err = str(e)
            if "NameResolutionError" in err or "Temporary failure" in err:
                return "DNS Error: Check Internet", True
            return "Connection Failed", True
        except Exception as e:
            return f"Upload Error: {str(e)}", True

    def _serve_22000(self, name):
        safe_name = self._safe_handshake_name(name)
        p = self._find_handshake_path(safe_name)
        if not p:
            return make_response("Not found", 404)

        out = None
        try:
            with tempfile.NamedTemporaryFile(prefix='pwmenu-download-', suffix='.hc22000', delete=False) as tmp:
                out = tmp.name
            os.remove(out)
            subprocess.run(
                ['/usr/bin/hcxpcapngtool', '-o', out, p],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self._option_int('hcxpcapngtool_timeout', 90)
            )

            if os.path.exists(out) and os.path.getsize(out) > 0:
                payload = tempfile.SpooledTemporaryFile(
                    max_size=self._option_int('archive_memory_limit', 2097152),
                    mode='w+b'
                )
                with open(out, 'rb') as source:
                    shutil.copyfileobj(source, payload)
                payload.seek(0)
                download_name = os.path.splitext(safe_name)[0] + '.hc22000'
                return send_file(payload, as_attachment=True, download_name=download_name)
            else:
                tok = generate_csrf() if generate_csrf else ""
                escaped_name = html.escape(safe_name, quote=True)
                return f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8"><title>Error</title>
                    <style>body{{background:#1c1c1e;color:#fff;font-family:sans-serif;text-align:center;padding:50px;}} button{{background:#ff453a;color:#fff;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-weight:bold;}}</style>
                </head>
                <body>
                    <h2 style="color:#ff453a">Conversion Failed</h2>
                    <p>File <b>{escaped_name}</b> contains no valid PMKID/EAPOL.</p>
                    <form method="POST" action="/plugins/A_pwmenu/delete-file">
                        <input type="hidden" name="csrf_token" value="{tok}">
                        <input type="hidden" name="filename" value="{escaped_name}">
                        <button type="submit">Delete Invalid File</button>
                    </form>
                    <br><a href="/plugins/A_pwmenu/" style="color:#0a84ff">Back</a>
                </body>
                </html>
                """
        except Exception as e:
            logging.error(f"[A_pwmenu] 22000 conversion failed for {safe_name}: {e}")
            return f"Error: {e}"
        finally:
            if out:
                try:
                    os.remove(out)
                except FileNotFoundError:
                    pass

    def _load_data(self):
        self.data = {
            'xp': 0,
            'badges': [],
            'history_cracked': 0,
            'history_captured': 0,
            'locations': {},
            'seen_files': {},
            'phone_gps': {},
            'ohc_files': {},
            'ohc_hash_files': {},
            'ohc_found_files': {},
            'ohc_pending_files': {},
            'ohc_file_signatures': {},
            'ohc_reconcile_requested': False
        }
        candidates = [self.data_file, self.data_file + '.bak']
        candidates = [p for p in candidates if os.path.exists(p)]
        candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        for candidate in candidates:
            try:
                with open(candidate) as f:
                    self.data.update(json.load(f))
                if candidate != self.data_file:
                    logging.warning("[A_pwmenu] Recovered state from backup")
                break
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as e:
                logging.warning(f"[A_pwmenu] Could not load state from {candidate}: {e}")
        if not isinstance(self.data.get('locations'), dict):
            self.data['locations'] = {}
        if not isinstance(self.data.get('seen_files'), dict):
            self.data['seen_files'] = {}
        if not isinstance(self.data.get('phone_gps'), dict):
            self.data['phone_gps'] = {}
        if not isinstance(self.data.get('ohc_files'), dict):
            self.data['ohc_files'] = {}
        if not isinstance(self.data.get('ohc_hash_files'), dict):
            self.data['ohc_hash_files'] = {}
        if not isinstance(self.data.get('ohc_found_files'), dict):
            self.data['ohc_found_files'] = {}
        if not isinstance(self.data.get('ohc_pending_files'), dict):
            self.data['ohc_pending_files'] = {}
        if not isinstance(self.data.get('ohc_file_signatures'), dict):
            self.data['ohc_file_signatures'] = {}

    def _save_data(self):
        try:
            with self.save_lock:
                with self.data_lock:
                    snapshot = copy.deepcopy(self.data)
                payload = json.dumps(snapshot, sort_keys=True)
                directory = os.path.dirname(self.data_file)
                for target in (self.data_file + '.bak', self.data_file):
                    tmp_path = target + '.tmp'
                    with open(tmp_path, 'w') as f:
                        f.write(payload)
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp_path, target)
                    try:
                        flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)
                        dir_fd = os.open(directory, flags)
                        try:
                            os.fsync(dir_fd)
                        finally:
                            os.close(dir_fd)
                    except OSError:
                        pass
        except Exception as e:
            logging.error(f"[A_pwmenu] Could not save state: {e}")
            for target in (self.data_file + '.bak.tmp', self.data_file + '.tmp'):
                try:
                    if os.path.exists(target):
                        os.remove(target)
                except OSError:
                    pass

    def _option_bool(self, key, default=True):
        v = self.options.get(key, default)
        if isinstance(v, str):
            return v.strip().lower() not in ('0', 'false', 'no', 'off')
        return bool(v)

    def _option_int(self, key, default):
        try:
            return int(self.options.get(key, default))
        except (TypeError, ValueError):
            return default

    def _gps_float(self, value):
        try:
            if value is None or value == '':
                return None
            return float(str(value).replace(',', '.'))
        except (TypeError, ValueError):
            return None

    def _pick(self, data, keys):
        for key in keys:
            if key in data and data[key] not in (None, ''):
                return data[key]
        return None

    def _normalize_location(self, raw, source='gps'):
        if not isinstance(raw, dict):
            return None

        for key in ('gps', 'location', 'coords', 'position'):
            nested = raw.get(key)
            if isinstance(nested, dict):
                loc = self._normalize_location(nested, source)
                if loc:
                    loc['source'] = raw.get('source') or loc.get('source') or source
                    return loc

        lat = self._gps_float(self._pick(raw, ('lat', 'latitude', 'Latitude', 'LAT')))
        lon = self._gps_float(self._pick(raw, ('lon', 'lng', 'long', 'longitude', 'Longitude', 'LON')))
        if lat is None or lon is None:
            return None
        if lat < -90 or lat > 90 or lon < -180 or lon > 180:
            return None

        ts = self._gps_float(self._pick(raw, ('ts', 'time', 'timestamp', 'created_at', 'Timestamp')))
        if ts is None:
            ts = time.time()
        if ts > 100000000000:
            ts = ts / 1000

        acc = self._gps_float(self._pick(raw, ('accuracy', 'acc', 'hdop')))
        loc = {
            'lat': lat,
            'lon': lon,
            'accuracy': acc if acc is not None else 0,
            'ts': ts,
            'source': raw.get('source') or source
        }
        gps_age = self._gps_float(self._pick(raw, ('gps_age_at_capture', 'GPSAge')))
        if gps_age is not None:
            loc['gps_age_at_capture'] = gps_age
        gps_stale = self._pick(raw, ('gps_stale', 'GPSStale'))
        if gps_stale not in (None, ''):
            loc['gps_stale'] = str(gps_stale).lower() in ('1', 'true', 'yes', 'on')
        for key in ('heading', 'speed', 'provider'):
            if key in raw and raw[key] not in (None, ''):
                loc[key] = raw[key]
        return loc

    def _update_phone_gps(self, req):
        if not self._option_bool('phone_gps_enabled', True):
            return False, 'phone gps disabled'

        raw = {
            'lat': req.form.get('lat'),
            'lon': req.form.get('lon') or req.form.get('lng'),
            'accuracy': req.form.get('accuracy'),
            'heading': req.form.get('heading'),
            'speed': req.form.get('speed'),
            'provider': req.form.get('provider') or 'browser',
            'source': 'phone',
            'ts': time.time()
        }
        loc = self._normalize_location(raw, 'phone')
        if not loc:
            return False, 'invalid coordinates'

        with self.data_lock:
            self.data['phone_gps'] = loc
        self._save_data()
        return True, 'ok'

    def _fresh_phone_gps(self):
        if not self._option_bool('phone_gps_enabled', True):
            return None
        with self.data_lock:
            raw = dict(self.data.get('phone_gps') or {})
        loc = self._normalize_location(raw, 'phone')
        if not loc:
            return None
        if time.time() - loc.get('ts', 0) > self._option_int('phone_gps_max_age', 600):
            return None
        return loc

    def _start_pwndroid_ws(self):
        if not self._option_bool('pwndroid_ws_enabled', True):
            return
        if websockets is None:
            logging.warning("[A_pwmenu] websockets module not found; PwnDroid WS GPS disabled")
            return
        if self.pwndroid_thread and self.pwndroid_thread.is_alive():
            return

        self.pwndroid_running = True
        self.pwndroid_thread = threading.Thread(target=self._run_pwndroid_ws, daemon=True)
        self.pwndroid_thread.start()

    def _run_pwndroid_ws(self):
        try:
            asyncio.run(self._pwndroid_ws_loop())
        except Exception as e:
            self.pwndroid_ws_state = 'error'
            self.pwndroid_ws_error = str(e)
            logging.error(f"[A_pwmenu] PwnDroid WS stopped: {e}")

    def _default_gateway(self):
        try:
            with open('/proc/net/route') as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == '00000000':
                        raw = parts[2]
                        octets = [str(int(raw[i:i+2], 16)) for i in (6, 4, 2, 0)]
                        return '.'.join(octets)
        except (OSError, ValueError, IndexError) as e:
            logging.debug(f"[A_pwmenu] Default gateway lookup failed: {e}")
        return None

    def _gateway_from_ip(self, ip):
        if not ip or not isinstance(ip, str):
            return None
        parts = ip.strip().split('.')
        if len(parts) != 4:
            return None
        return '.'.join(parts[:3] + ['1'])

    def _gateway_from_mac(self, mac):
        if not mac or not isinstance(mac, str):
            return None
        target = mac.strip().lower()
        try:
            with open('/proc/net/arp') as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 6 and parts[3].lower() == target:
                        return parts[0]
        except OSError as e:
            logging.debug(f"[A_pwmenu] ARP gateway lookup failed: {e}")
        return None

    def _pwndroid_gateways(self):
        extra = self.options.get("pwndroid_extra_gateways", "")
        if isinstance(extra, str):
            extra_vals = [v.strip() for v in extra.split(',') if v.strip()]
        elif isinstance(extra, list):
            extra_vals = extra
        else:
            extra_vals = []

        vals = [
            self._gateway_from_mac(self.options.get("pwndroid_mac")),
            self.options.get("gateway"),
            self.options.get("pwndroid_gateway"),
            self._default_gateway()
        ] + extra_vals
        out = []
        for v in vals:
            if v and v not in out:
                out.append(v)
        return out

    async def _pwndroid_ws_loop(self):
        port = self._option_int("pwndroid_port", 8080)

        while self.pwndroid_running:
            for gateway in self._pwndroid_gateways():
                if not self.pwndroid_running:
                    break
                uri = f"ws://{gateway}:{port}"
                self.pwndroid_ws_uri = uri
                self.pwndroid_ws_state = 'connecting'
                websocket = None
                try:
                    websocket = await asyncio.wait_for(websockets.connect(uri), timeout=4)
                    self.pwndroid_ws_state = 'connected'
                    self.pwndroid_ws_error = ''
                    logging.info(f"[A_pwmenu] PwnDroid GPS connected: {uri}")
                    while self.pwndroid_running:
                        try:
                            msg = await asyncio.wait_for(websocket.recv(), timeout=20)
                        except asyncio.TimeoutError:
                            self.pwndroid_ws_state = 'connected, waiting GPS'
                            continue
                        if not msg:
                            continue
                        try:
                            raw = json.loads(msg)
                        except json.JSONDecodeError:
                            self.pwndroid_ws_state = 'connected, bad GPS json'
                            continue
                        loc = self._normalize_pwndroid_location(raw)
                        if loc:
                            with self.gps_lock:
                                self.pwndroid_coordinates = loc
                            self.pwndroid_ws_state = 'receiving GPS'
                except Exception as e:
                    self.pwndroid_ws_state = 'reconnecting'
                    self.pwndroid_ws_error_uri = uri
                    self.pwndroid_ws_error = str(e)
                    logging.debug(f"[A_pwmenu] PwnDroid GPS reconnecting from {uri}: {e}")
                finally:
                    try:
                        if websocket:
                            await websocket.close()
                    except Exception as e:
                        logging.debug(f"[A_pwmenu] PwnDroid websocket close failed: {e}")
            await asyncio.sleep(5)

    def _normalize_pwndroid_location(self, raw):
        loc = self._normalize_location({
            'lat': self._pick(raw, ('Latitude', 'latitude', 'lat')),
            'lon': self._pick(raw, ('Longitude', 'longitude', 'lon', 'lng')),
            'accuracy': self._pick(raw, ('Accuracy', 'accuracy')),
            'speed': self._pick(raw, ('Speed', 'speed')),
            'heading': self._pick(raw, ('Bearing', 'bearing', 'heading')),
            'source': 'pwndroid',
            'provider': 'pwndroid',
            'ts': time.time()
        }, 'pwndroid')
        if not loc:
            return None
        loc['altitude'] = self._pick(raw, ('Altitude', 'altitude')) or 0
        loc['bearing'] = self._pick(raw, ('Bearing', 'bearing', 'heading')) or 0
        return loc

    def _fresh_pwndroid_ws_gps(self):
        with self.gps_lock:
            coordinates = dict(self.pwndroid_coordinates or {})
        loc = self._normalize_location(coordinates, 'pwndroid')
        if not loc:
            return None
        if time.time() - loc.get('ts', 0) > self._option_int('phone_gps_max_age', 600):
            return None
        return coordinates

    def _gps_status(self):
        now = time.time()
        with self.gps_lock:
            pwndroid_coordinates = dict(self.pwndroid_coordinates or {})
        with self.data_lock:
            browser_coordinates = dict(self.data.get('phone_gps') or {})
        for label, loc in (
            ('PwnDroid', pwndroid_coordinates),
            ('Browser', browser_coordinates)
        ):
            norm = self._normalize_location(loc, label.lower())
            if norm:
                age = int(now - norm.get('ts', now))
                if age <= self._option_int('phone_gps_max_age', 600):
                    return {
                        'label': label,
                        'state': 'connected',
                        'age': age,
                        'lat': norm.get('lat'),
                        'lon': norm.get('lon'),
                        'accuracy': norm.get('accuracy', 0),
                        'detail': self.pwndroid_ws_uri if label == 'PwnDroid' else ''
                    }
        if websockets is None:
            return {'label': 'PwnDroid', 'state': 'websockets missing', 'age': 0, 'lat': None, 'lon': None, 'accuracy': 0, 'detail': 'install python3-websockets'}
        detail = self.pwndroid_ws_uri
        if self.pwndroid_ws_error:
            detail = f"{detail} - {self.pwndroid_ws_error}"
        return {'label': 'PwnDroid', 'state': self.pwndroid_ws_state, 'age': 0, 'lat': None, 'lon': None, 'accuracy': 0, 'detail': detail}

    def _ohc_status(self):
        with self.data_lock:
            pending = len(self.data.get('ohc_pending_files', {}) or {})
        retry_in = max(0, int(self._ohc_retry_at() - time.time()))
        return {
            'enabled': self._option_bool('ohc_enabled', True),
            'uploading': self.ohc_uploading,
            'face': self.ohc_upload_face if self.ohc_uploading else '0__0',
            'last': self.ohc_last_result,
            'pending': pending,
            'retry_in': retry_in
        }

    def _read_gpsd_location(self):
        if not self._option_bool('gpsd_enabled', True):
            return None

        host = self.options.get('gpsd_host', '127.0.0.1')
        port = self._option_int('gpsd_port', 2947)
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=0.35)
            sock.settimeout(0.45)
            sock.sendall(b'?WATCH={"enable":true,"json":true};\n')
            data = b''
            until = time.time() + 1.2
            while time.time() < until:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                data += chunk
                for line in data.decode('utf-8', errors='ignore').splitlines():
                    if '"class":"TPV"' not in line:
                        continue
                    try:
                        msg = json.loads(line)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    loc = self._normalize_location({
                        'lat': msg.get('lat'),
                        'lon': msg.get('lon'),
                        'accuracy': msg.get('eph') or msg.get('epx') or msg.get('epy') or 0,
                        'source': 'gpsd',
                        'provider': 'gpsd',
                        'ts': time.time()
                    }, 'gpsd')
                    if loc:
                        return loc
        except OSError as e:
            logging.debug(f"[A_pwmenu] GPSD read failed: {e}")
            return None
        finally:
            try:
                if sock:
                    sock.close()
            except OSError:
                pass
        return None

    def _fresh_live_gps(self):
        pwndroid = self._fresh_pwndroid_ws_gps()
        if pwndroid:
            return pwndroid
        phone = self._fresh_phone_gps()
        if phone:
            return phone

        now = time.time()
        interval = max(1, self._option_int('gpsd_poll_interval', 10))
        with self.gps_lock:
            if now - self.gpsd_last_poll < interval:
                return dict(self.gpsd_cached_location) if self.gpsd_cached_location else None
            self.gpsd_last_poll = now

        gpsd = self._read_gpsd_location()
        with self.gps_lock:
            self.gpsd_cached_location = dict(gpsd) if gpsd else None
        return gpsd

    def _read_sidecar_location(self, file_path):
        base, _ = os.path.splitext(file_path)
        candidates = [
            file_path + '.gps.json',
            file_path + '.geo.json',
            file_path + '.json',
            base + '.gps.json',
            base + '.geo.json',
            base + '.json'
        ]
        for path in candidates:
            if not os.path.exists(path):
                continue
            try:
                with open(path, 'r', errors='ignore') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    data = data[0] if data else {}
                loc = self._normalize_location(data, 'sidecar')
                if loc:
                    return loc
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as e:
                logging.debug(f"[A_pwmenu] Sidecar GPS read failed for {path}: {e}")
        return None

    def _should_assign_phone_gps(self, file_mtime, gps):
        window = self._option_int('gps_assign_window', 900)
        now = time.time()
        file_age = now - file_mtime
        gps_diff = abs(file_mtime - gps.get('ts', now))
        return file_age <= window or gps_diff <= window

    def _decorate_capture_location(self, loc, file_mtime):
        if not loc:
            return None
        out = loc.copy()
        gps_ts = out.get('ts')
        if gps_ts:
            age = abs(file_mtime - gps_ts)
            out['gps_age_at_capture'] = age
            out['gps_stale'] = age > self._option_int('gps_stale_seconds', 180)
        else:
            out['gps_age_at_capture'] = 0
            out['gps_stale'] = False
        return out

    def _location_for_file(self, filename, file_path, essid, bssid, file_mtime, date_str, live_gps=None):
        with self.data_lock:
            locs = self.data.setdefault('locations', {})
            stored_raw = dict(locs.get(filename) or {})
        stored = self._normalize_location(stored_raw, 'stored')
        if stored:
            return self._decorate_capture_location(stored, file_mtime), False

        loc = self._read_sidecar_location(file_path)
        if not loc:
            if live_gps and self._should_assign_phone_gps(file_mtime, live_gps):
                loc = live_gps.copy()

        if not loc:
            return None, False

        loc = self._decorate_capture_location(loc, file_mtime)
        loc.update({
            'filename': filename,
            'essid': essid,
            'bssid': bssid,
            'capture_ts': file_mtime,
            'date': date_str
        })
        with self.data_lock:
            self.data.setdefault('locations', {})[filename] = loc
        return loc, True

    def _distance_meters(self, a_lat, a_lon, b_lat, b_lon):
        try:
            from math import radians, sin, cos, asin, sqrt
            r = 6371000
            d_lat = radians(float(b_lat) - float(a_lat))
            d_lon = radians(float(b_lon) - float(a_lon))
            lat1 = radians(float(a_lat))
            lat2 = radians(float(b_lat))
            h = sin(d_lat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(d_lon / 2) ** 2
            return 2 * r * asin(sqrt(h))
        except (TypeError, ValueError):
            return 999999

    def _map_member_from_file(self, g, f):
        bssid = self._format_bssid(f.get('bssid', ''))
        return {
            'id': f.get('filename', ''),
            'essid': g['essid'],
            'bssid': bssid,
            'lat': f.get('lat'),
            'lon': f.get('lon'),
            'accuracy': f.get('accuracy', 0),
            'date': f.get('date', ''),
            'filename': f.get('filename', ''),
            'size': f.get('size', ''),
            'is_cracked': g.get('is_cracked', False),
            'password': g.get('pwd', '') if g.get('is_cracked') else '',
            'source': f.get('gps_source', ''),
            'captures': 1,
            'signal': f.get('signal', '-'),
            'encryption': f.get('encryption', 'WPA2'),
            'vendor': self._vendor_from_bssid(bssid, g['essid']),
            'gps_stale': bool(f.get('gps_stale', False)),
            'gps_age_at_capture': int(f.get('gps_age_at_capture', 0) or 0),
            'ohc': self._ohc_file_record(f.get('filename', '')),
            'status': 'cracked' if g.get('is_cracked') else 'handshake'
        }

    def _format_bssid(self, bssid):
        clean = re.sub(r'[^0-9A-Fa-f]', '', bssid or '').upper()
        if len(clean) == 12:
            return ':'.join(clean[i:i+2] for i in range(0, 12, 2))
        return bssid or ''

    def _vendor_from_bssid(self, bssid, essid=''):
        clean = re.sub(r'[^0-9A-Fa-f]', '', bssid or '').upper()
        name = (essid or '').lower().replace('-', '').replace('_', '').replace(' ', '')
        if 'tplink' in name or name.startswith('tp') and 'link' in name:
            return 'TP-Link'
        if 'keenetic' in name or 'zyxel' in name:
            return 'Keenetic'
        if 'huawei' in name:
            return 'Huawei'
        if 'xiaomi' in name or 'redmi' in name:
            return 'Xiaomi'
        if 'asus' in name:
            return 'ASUS'
        if 'dlink' in name:
            return 'D-Link'
        if 'tenda' in name:
            return 'Tenda'
        if len(clean) < 6:
            return 'Unknown vendor'
        oui = clean[:6]
        vendors = {
            '001018': 'Broadcom', '001A2B': 'Ayecom', '001B11': 'D-Link', '001D0F': 'TP-Link',
            '001E58': 'D-Link', '002191': 'D-Link', '0022B0': 'D-Link', '0023CD': 'TP-Link',
            '002401': 'D-Link', '00259C': 'Cisco', '00265A': 'D-Link', '002719': 'TP-Link',
            '004F62': 'Huawei', '0050F1': 'Cisco', '00664B': 'Huawei', '006B8E': 'Shanghai Feixun',
            '007263': 'Cisco', '00E04C': 'Realtek', '00E0FC': 'Huawei', '04A151': 'Netgear',
            '086361': 'Huawei', '0C80D3': 'D-Link', '0C96BF': 'Huawei', '0CC47A': 'Supermicro',
            '101B54': 'Huawei', '10BEF5': 'D-Link', '14CC20': 'TP-Link', '1816C9': 'Samsung',
            '18D6C7': 'TP-Link', '1C3BF3': 'TP-Link', '1C5F2B': 'D-Link', '1CBDB9': 'D-Link',
            '20AA4B': 'Cisco', '246511': 'AVM', '2C3033': 'Netgear', '30B5C2': 'TP-Link',
            '3495DB': 'Logitec', '34CE00': 'Xiaomi', '3822D6': 'H3C', '3C3300': 'Huawei',
            '3C3786': 'Netgear', '3C846A': 'TP-Link', '40B076': 'ASUS', '44650D': 'Amazon',
            '482254': 'TP-Link', '48A98A': 'Routerboard', '4C5E0C': 'Routerboard', '50C7BF': 'TP-Link', '54A050': 'ASUS',
            '5C628B': 'TP-Link', '5C8FE0': 'Huawei', '6045BD': 'Microsoft', '64002D': 'TP-Link',
            '6466B3': 'TP-Link', '6C198F': 'D-Link', '6C3B6B': 'Routerboard', '6CCDD6': 'Cisco',
            '74DA38': 'Edimax', '7802F8': 'Xiaomi', '78542E': 'D-Link', '7C8BCA': 'TP-Link',
            '8044FD': 'TP-Link', '8416F9': 'TP-Link', '84A9C4': 'Huawei', '8C210A': 'TP-Link',
            '8C3BAD': 'Netgear', '94D9B3': 'TP-Link', '984827': 'TP-Link', 'A0F3C1': 'TP-Link',
            'A42BB0': 'TP-Link', 'A8154D': 'TP-Link', 'AC9E17': 'ASUS', 'B0487A': 'TP-Link',
            'B0BE76': 'TP-Link', 'B4B024': 'TP-Link', 'B8A386': 'D-Link', 'BCF685': 'D-Link',
            'C025E9': 'TP-Link', 'C04A00': 'TP-Link', 'C46E1F': 'TP-Link', 'C47154': 'TP-Link',
            'C4A81D': 'D-Link', 'C83A35': 'Tenda', 'C86C87': 'ZTE', 'CC32E5': 'TP-Link',
            'D0D04B': 'Huawei', 'D4EE07': 'HiWiFi', 'D850E6': 'ASUS', 'D85D4C': 'TP-Link',
            'E0469A': 'Netgear', 'E894F6': 'TP-Link', 'EC086B': 'TP-Link', 'F0B429': 'Xiaomi',
            'F4F26D': 'TP-Link', 'F81A67': 'TP-Link', 'FCF528': 'ZTE'
        }
        return vendors.get(oui, 'Unknown vendor')

    def _build_map_points(self, groups):
        members = []
        for g in groups:
            for f in g.get('files', []):
                lat = f.get('lat')
                lon = f.get('lon')
                if lat is None or lon is None:
                    continue
                members.append(self._map_member_from_file(g, f))

        network_groups = []
        for m in members:
            bucket = None
            for item in network_groups:
                if item['essid'] == m['essid'] and item['bssid'] == m['bssid'] and self._distance_meters(item['lat'], item['lon'], m['lat'], m['lon']) <= 30:
                    bucket = item
                    break
            if bucket:
                bucket['history'].append(m)
                if m.get('date', '') > bucket.get('date', ''):
                    bucket.update(m)
                bucket['captures'] = len(bucket['history'])
            else:
                n = m.copy()
                n['history'] = [m]
                network_groups.append(n)

        clusters = []
        for m in network_groups:
            bucket = None
            for item in clusters:
                if self._distance_meters(item['lat'], item['lon'], m['lat'], m['lon']) <= 8:
                    bucket = item
                    break
            if bucket:
                bucket['members'].append(m)
                bucket['lat'] = sum(x['lat'] for x in bucket['members']) / len(bucket['members'])
                bucket['lon'] = sum(x['lon'] for x in bucket['members']) / len(bucket['members'])
                bucket['is_cracked'] = any(x.get('is_cracked') for x in bucket['members'])
                bucket['gps_stale'] = any(x.get('gps_stale') for x in bucket['members'])
                bucket['status'] = 'cracked' if bucket['is_cracked'] else 'handshake'
                bucket['count'] = sum(max(1, int(x.get('captures', 1) or 1)) for x in bucket['members'])
                bucket['essid'] = f"{bucket['count']} networks"
            else:
                c = m.copy()
                c['id'] = m.get('id') or f"{m['essid']}-{m['lat']}-{m['lon']}"
                c['members'] = [m]
                c['count'] = max(1, int(m.get('captures', 1) or 1))
                clusters.append(c)

        for c in clusters:
            if c.get('count', 1) == 1:
                c.update(c['members'][0])
                c['count'] = max(1, int(c.get('captures', 1) or 1))
        return clusters

    def _build_no_gps_networks(self, groups):
        items = []
        for g in groups:
            if g.get('lat') is not None and g.get('lon') is not None:
                continue
            first = g.get('files', [{}])[0] if g.get('files') else {}
            bssid = self._format_bssid(first.get('bssid', ''))
            files = []
            for f in g.get('files', []):
                files.append({
                    'filename': f.get('filename', ''),
                    'bssid': self._format_bssid(f.get('bssid', '')),
                    'date': f.get('date', ''),
                    'size': f.get('size', ''),
                    'ohc': self._ohc_file_record(f.get('filename', ''))
                })
            items.append({
                'essid': g.get('essid', ''),
                'bssid': bssid,
                'vendor': self._vendor_from_bssid(bssid, g.get('essid', '')),
                'date': g.get('last_seen', ''),
                'count': g.get('count', 0),
                'is_cracked': g.get('is_cracked', False),
                'password': g.get('pwd', '') if g.get('is_cracked') else '',
                'filename': first.get('filename', ''),
                'ohc': self._ohc_file_record(first.get('filename', '')),
                'files': files
            })
        return items

    def _update_achievements(self, groups, cracked):
        with self.data_lock:
            return self._update_achievements_locked(groups, cracked)

    def _update_achievements_locked(self, groups, cracked):
        curr_cracked = len(cracked)
        curr_captured = sum(len(g['files']) for g in groups)

        if curr_cracked > self.data['history_cracked']:
            diff = curr_cracked - self.data['history_cracked']
            self.data['xp'] += diff * 500
            self.data['history_cracked'] = curr_cracked

        if curr_captured > self.data['history_captured']:
            diff = curr_captured - self.data['history_captured']
            self.data['xp'] += diff * 50
            self.data['history_captured'] = curr_captured

        lvl_map = [
            (0, 'Script Kiddie'), (1000, 'Neophyte'), (2500, 'Hacker'),
            (5000, 'Elite'), (10000, 'Master'), (25000, 'Wizard'), (50000, 'Omniscient')
        ]
        xp = self.data['xp']
        lvl = 1
        rank = 'Script Kiddie'
        next_xp = 1000
        prev_xp = 0

        for i, (req, title) in enumerate(lvl_map):
            if xp >= req:
                lvl = i + 1
                rank = title
                prev_xp = req
                if i + 1 < len(lvl_map):
                    next_xp = lvl_map[i+1][0]
                else:
                    next_xp = xp * 2

        all_badges = [
            {'id':'b1','name':'First Blood','desc':'Crack 1 network','icon':'🩸','target':1,'curr':self.data['history_cracked']},
            {'id':'b2','name':'Pentester','desc':'Crack 5 networks','icon':'💻','target':5,'curr':self.data['history_cracked']},
            {'id':'b3','name':'Hacker','desc':'Crack 25 networks','icon':'💀','target':25,'curr':self.data['history_cracked']},
            {'id':'b4','name':'Master Key','desc':'Crack 50 networks','icon':'🔑','target':50,'curr':self.data['history_cracked']},
            {'id':'c1','name':'Collector','desc':'Capture 10 handshakes','icon':'🎒','target':10,'curr':self.data['history_captured']},
            {'id':'c2','name':'Hoarder','desc':'Capture 50 handshakes','icon':'📦','target':50,'curr':self.data['history_captured']},
            {'id':'c3','name':'Data Center','desc':'Capture 200 handshakes','icon':'🗄️','target':200,'curr':self.data['history_captured']},
            {'id':'c4','name':'Black Hole','desc':'Capture 500 handshakes','icon':'🌌','target':500,'curr':self.data['history_captured']}
        ]
        my_badges = []
        for b in all_badges:
            ul = b['id'] in self.data['badges']
            pct = 0
            if b['target'] > 0:
                pct = min(100, int((b['curr'] / b['target']) * 100))

            if not ul and b['curr'] >= b['target']:
                self.data['badges'].append(b['id'])
                self.data['xp'] += 1000
                ul = True
                pct = 100

            badge_info = b.copy()
            badge_info['unlocked'] = ul
            badge_info['progress'] = pct
            my_badges.append(badge_info)

        self._save_data()

        lvl_p = 100
        if next_xp > prev_xp:
            lvl_p = int(((xp - prev_xp) / (next_xp - prev_xp)) * 100)

        return {'level': lvl, 'rank': rank, 'xp': xp, 'next_xp': next_xp, 'lvl_percent': lvl_p, 'badges': my_badges}

    def _add_manual_password(self, essid, bssid, pwd):
        m = bssid if bssid and len(bssid)==17 else "00:00:00:00:00:00"
        try:
            with open(self.potfile_manual, 'a') as f:
                f.write(f"{m}:{m}:{essid}:{pwd}\n")
            with self.data_lock:
                self.data['xp'] += 200
            self._save_data()
        except OSError as e:
            logging.error(f"[A_pwmenu] Could not add manual password: {e}")

    def _delete_password(self, essid, pwd=None, source=None):
        deleted = False

        if os.path.exists(self.potfile_manual):
            lines = []
            with open(self.potfile_manual, 'r') as f:
                for l in f:
                    if f":{essid}:" not in l:
                        lines.append(l)
                    else:
                        deleted = True
            with open(self.potfile_manual, 'w') as f:
                f.writelines(lines)

        if os.path.exists(self.potfile_ohc):
            lines = []
            with open(self.potfile_ohc, 'r') as f:
                for l in f:
                    if f":{essid}:" not in l:
                        lines.append(l)
                    elif pwd and f":{pwd}" in l:
                         deleted = True
                    else:
                         deleted = True
            with open(self.potfile_ohc, 'w') as f:
                f.writelines(lines)

        return deleted

    def _update_password(self, essid, pwd):
        self._delete_password(essid)
        self._add_manual_password(essid, "", pwd)

    def _delete_specific_file(self, fname):
        name = self._safe_handshake_name(fname)
        if not name:
            logging.warning("[A_pwmenu] Rejected unsafe handshake filename for deletion")
            return False
        found = False
        for d in self.handshake_dirs:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                os.remove(p)
                found = True
            base = os.path.splitext(name)[0]
            for extension in ('.hc22000', '.22000'):
                companion = os.path.join(d, base + extension)
                if os.path.isfile(companion):
                    os.remove(companion)
        return found

    def _clean_broken_handshakes(self):
        d_cnt=0
        t_cnt=0
        for d in self.handshake_dirs:
            if not os.path.exists(d): continue
            for f in glob.glob(os.path.join(d, '*.pcap')):
                t_cnt += 1
                tmp = None
                try:
                    with tempfile.NamedTemporaryFile(prefix='pwmenu-check-', suffix='.hc22000', delete=False) as handle:
                        tmp = handle.name
                    os.remove(tmp)
                    subprocess.run(
                        ['/usr/bin/hcxpcapngtool', '-o', tmp, f],
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=self._option_int('hcxpcapngtool_timeout', 90)
                    )
                    valid = os.path.exists(tmp) and os.path.getsize(tmp) > 0
                    if not valid:
                        os.remove(f)
                        base = os.path.splitext(f)[0]
                        for ext in ['.hc22000', '.22000']:
                            h = base + ext
                            if os.path.isfile(h):
                                os.remove(h)
                        d_cnt += 1
                except Exception as e:
                    logging.error(f"[A_pwmenu] Handshake validation failed for {f}: {e}")
                finally:
                    if tmp:
                        try:
                            os.remove(tmp)
                        except FileNotFoundError:
                            pass
        return d_cnt, t_cnt

    def _nuke_all_handshakes(self):
        c = 0

        for d in self.handshake_dirs:
            if not os.path.exists(d): continue
            for f in glob.glob(os.path.join(d, '*.pcap')):
                try:
                    os.remove(f)
                    c += 1
                except OSError as e:
                    logging.warning(f"[A_pwmenu] Could not remove {f}: {e}")
            for f in glob.glob(os.path.join(d, '*.hc22000')):
                try: os.remove(f)
                except OSError as e:
                    logging.warning(f"[A_pwmenu] Could not remove {f}: {e}")
            for f in glob.glob(os.path.join(d, '*.22000')):
                try: os.remove(f)
                except OSError as e:
                    logging.warning(f"[A_pwmenu] Could not remove {f}: {e}")

        try:
            with open(self.potfile_manual, 'w') as f: f.write("")
            with open(self.potfile_ohc, 'w') as f: f.write("")
        except OSError as e:
            logging.error(f"[A_pwmenu] Could not clear potfiles: {e}")

        return c

    def _process_import(self, content, name):
        self._ensure_file(self.potfile_ohc)
        c=0
        is_json = name.lower().endswith('.json') or content.strip().startswith('[')
        if is_json:
            c = self._imp_json(json.loads(content))
        else:
            c = self._imp_csv(content)
        if c > 0:
            with self.data_lock:
                self.data['xp'] += c * 100
            self._save_data()
        return c

    def _imp_json(self, data):
        if isinstance(data, dict):
            data = data.get('tasks', [])
        if not isinstance(data, list):
            raise ValueError('JSON import must contain a task list')
        c=0
        ex=self._read_pot(self.potfile_ohc)
        with open(self.potfile_ohc, 'a') as f:
            for t in data:
                if not isinstance(t, dict):
                    continue
                if t.get('status')=='FOUND':
                    e = self._fmt(t.get('task',''), t.get('password',''))
                    if e and e not in ex:
                        f.write(e+'\n')
                        ex.add(e)
                        c += 1
        return c

    def _imp_csv(self, txt):
        c=0
        ex=self._read_pot(self.potfile_ohc)
        try:
            r = csv.DictReader(io.StringIO(txt))
            with open(self.potfile_ohc, 'a') as f:
                for row in r:
                    st = row.get('status') or row.get('Status')
                    pw = row.get('password') or row.get('Password')
                    tk = row.get('task') or row.get('Task') or row.get('SSID')
                    if st=='FOUND' and pw and tk:
                        tk = re.sub(r'<[^>]+>', '', tk).strip()
                        e = self._fmt(tk, pw)
                        if e and e not in ex:
                            f.write(e+'\n')
                            ex.add(e)
                            c += 1
        except (csv.Error, OSError, TypeError, ValueError) as e:
            logging.error(f"[A_pwmenu] CSV import failed: {e}")
        return c

    def _fmt(self, t, p):
        if len(t)>17:
            m=t[-17:]
            if ':' in m: return f"{m}:{m}:{t[:-17]}:{p}"
        return None

    def _read_pot(self, p):
        s=set()
        if os.path.exists(p):
            with open(p) as f:
                for l in f: s.add(l.strip())
        return s

    def _serve_zip(self):
        m = self._new_archive_buffer()
        seen = set()
        with zipfile.ZipFile(m, 'w', zipfile.ZIP_DEFLATED) as z:
            for d in self.handshake_dirs:
                if not os.path.exists(d): continue
                for f in glob.glob(os.path.join(d, '*.pcap')):
                    name = os.path.basename(f)
                    if name not in seen:
                        z.write(f, name)
                        seen.add(name)
        m.seek(0)
        return send_file(m, mimetype='application/zip', as_attachment=True, download_name='handshakes.zip')

    def _serve_uncracked_zip(self):
        cracked = self._get_cracked_data()
        m = self._new_archive_buffer()
        seen = set()
        with zipfile.ZipFile(m, 'w', zipfile.ZIP_DEFLATED) as z:
            for d in self.handshake_dirs:
                if not os.path.exists(d):
                    continue
                for f in glob.glob(os.path.join(d, '*.pcap')):
                    fn = os.path.basename(f)
                    essid = self._essid_from_filename(fn)
                    if essid not in cracked and fn not in seen:
                        z.write(f, fn)
                        seen.add(fn)
        m.seek(0)
        return send_file(m, mimetype='application/zip', as_attachment=True, download_name='uncracked-handshakes.zip')

    def _essid_from_filename(self, filename):
        nm = os.path.basename(filename).replace('.pcap', '')
        pts = nm.split('_')
        if len(pts) >= 2 and len(pts[-1]) in [12, 17]:
            return "_".join(pts[:-1])
        return nm

    def _serve_cluster_zip(self, names):
        safe_names = []
        for raw in names.split(','):
            name = self._safe_handshake_name(raw.strip())
            if name and name not in safe_names:
                safe_names.append(name)

        m = self._new_archive_buffer()
        with zipfile.ZipFile(m, 'w', zipfile.ZIP_DEFLATED) as z:
            for name in safe_names:
                for d in self.handshake_dirs:
                    fp = os.path.join(d, name)
                    if os.path.exists(fp):
                        z.write(fp, name)
                        break
        m.seek(0)
        return send_file(m, mimetype='application/zip', as_attachment=True, download_name='cluster-handshakes.zip')

    def _serve_password_list(self):
        c = self._get_cracked_data()
        t = "\n".join([f"{e}:{d['password']}" for e, d in c.items()])
        m = io.BytesIO(t.encode('utf-8'))
        return send_file(m, mimetype='text/plain', as_attachment=True, download_name='passwords.txt')

    def _serve_file(self, name):
        safe_name = self._safe_handshake_name(name)
        fp = self._find_handshake_path(safe_name)
        if fp:
            return send_file(fp, as_attachment=True, download_name=safe_name)
        return make_response("Not found", 404)

    def _new_archive_buffer(self):
        return tempfile.SpooledTemporaryFile(
            max_size=self._option_int('archive_memory_limit', 2097152),
            mode='w+b'
        )

    def _ensure_file(self, p):
        try:
            if not os.path.exists(os.path.dirname(p)):
                os.makedirs(os.path.dirname(p))
            if not os.path.exists(p):
                open(p, 'w').close()
        except OSError as e:
            logging.error(f"[A_pwmenu] Could not initialize file {p}: {e}")

    def _scan_and_group_files(self, cracked):
        grps = {}
        data_changed = False
        with self.data_lock:
            seen_files = dict(self.data.setdefault('seen_files', {}))
        live_gps = self._fresh_live_gps()
        try:
            tz_offset = int(self.options.get('timezone', 0))
        except (TypeError, ValueError):
            tz_offset = 0

        for d in self.handshake_dirs:
            if not os.path.exists(d): continue
            for f in glob.glob(os.path.join(d, '*.pcap')):
                try:
                    fn = os.path.basename(f)
                    st = os.stat(f)
                    nm = fn.replace('.pcap', '')
                    pts = nm.split('_')
                    if len(pts)>=2 and len(pts[-1]) in [12,17]:
                        bs=pts[-1]
                        es="_".join(pts[:-1])
                    elif len(pts)>=2 and len(pts[-1]) == 12:
                        bs=pts[-1]
                        es="_".join(pts[:-1])
                    else:
                        es=nm
                        bs=""

                    if es not in grps:
                        isc = es in cracked
                        grps[es] = {'essid': es, 'files': [], 'ts': 0, 'is_cracked': isc,
                                    'pwd': cracked[es]['password'] if isc else '', 'src': cracked[es]['source'] if isc else '',
                                    'lat': None, 'lon': None, 'gps_source': ''}

                    date_str = get_local_time(st.st_mtime, tz_offset)

                    sig = str(int(st.st_mtime)) + ':' + str(st.st_size)
                    if seen_files.get(fn) != sig:
                        seen_files[fn] = sig
                        data_changed = True

                    loc, loc_changed = self._location_for_file(fn, f, es, bs, st.st_mtime, date_str, live_gps)
                    if loc_changed:
                        data_changed = True

                    file_info = {
                        'filename': fn, 'bssid': bs, 'size': f"{round(st.st_size/1024,1)}KB",
                        'date': date_str,
                        'ts': st.st_mtime
                    }
                    if loc:
                        file_info.update({
                            'lat': loc.get('lat'),
                            'lon': loc.get('lon'),
                            'accuracy': loc.get('accuracy', 0),
                            'gps_source': loc.get('source', ''),
                            'gps_stale': loc.get('gps_stale', False),
                            'gps_age_at_capture': loc.get('gps_age_at_capture', 0)
                        })
                        if grps[es].get('lat') is None or st.st_mtime >= grps[es].get('gps_ts', 0):
                            grps[es]['lat'] = loc.get('lat')
                            grps[es]['lon'] = loc.get('lon')
                            grps[es]['gps_source'] = loc.get('source', '')
                            grps[es]['gps_ts'] = st.st_mtime

                    grps[es]['files'].append(file_info)
                    if st.st_mtime > grps[es]['ts']:
                        grps[es]['ts'] = st.st_mtime
                except (OSError, TypeError, ValueError) as e:
                    logging.warning(f"[A_pwmenu] Could not scan handshake {f}: {e}")
        if data_changed:
            with self.data_lock:
                self.data['seen_files'] = seen_files
            self._save_data()
        res = list(grps.values())
        for g in res:
            g['files'].sort(key=lambda x: x['ts'], reverse=True)
            g['last_seen'] = g['files'][0]['date']
            g['count'] = len(g['files'])
            g['gps_count'] = len([f for f in g['files'] if f.get('lat') is not None and f.get('lon') is not None])
            g['cls'] = "st-cracked" if g['is_cracked'] else "st-active"
            g['txt'] = "Cracked" if g['is_cracked'] else "Active"
        res.sort(key=lambda x: x['ts'], reverse=True)
        return res

    def _get_cracked_data(self):
        d = {}
        pots = [('/root/handshakes/wpa-sec.cracked.potfile', 'WPA-Sec'),
                ('/home/pi/handshakes/wpa-sec.cracked.potfile', 'WPA-Sec'),
                (self.potfile_ohc, 'OHC'), (self.potfile_manual, 'Manual')]
        for p, s in pots:
            if os.path.exists(p):
                try:
                    with open(p, 'r', errors='ignore') as f:
                        for l in f:
                            pt = l.strip().split(':')
                            if len(pt)>=3:
                                d[pt[-2]] = {'password': pt[-1], 'source': s}
                except OSError as e:
                    logging.warning(f"[A_pwmenu] Could not read potfile {p}: {e}")
        for ddir in self.handshake_dirs:
            if os.path.exists(ddir):
                for c in glob.glob(os.path.join(ddir, '*.pcap.cracked')):
                    try:
                        with open(c) as f:
                            pwd = f.read().strip()
                            if pwd:
                                nm = os.path.basename(c).replace('.pcap.cracked', '')
                                pts = nm.split('_')
                                es = "_".join(pts[:-1]) if len(pts)>1 else nm
                                d[es] = {'password': pwd, 'source': 'QuickDic'}
                    except (OSError, ValueError, TypeError) as e:
                        logging.warning(f"[A_pwmenu] Could not read QuickDic result {c}: {e}")
        return d

    def _get_html(self):
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>A_pwmenu</title>
    <script src="https://api-maps.yandex.ru/2.1/?apikey=&lang=en_US" type="text/javascript"></script>
    <style>
        :root { --bg: #000; --card: #151515; --text: #fff; --sub: #888; --accent: #0a84ff; --green: #30d158; --yellow: #ffcc00; --sep: #333; --input: #222; --danger: #ff453a; }
        body { font-family: -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 15px; }
        h1 { font-size: 24px; margin: 0 0 15px 0; font-weight: 700; }
        .s-box { width: 100%; background: var(--input); border: none; border-radius: 10px; padding: 12px; color: var(--text); font-size: 16px; outline: none; margin-bottom: 15px; box-sizing: border-box; }
        .tabs { display: flex; background: var(--input); border-radius: 10px; padding: 2px; margin-bottom: 20px; }
        .tab { flex: 1; padding: 8px; text-align: center; border-radius: 8px; border: none; background: transparent; color: var(--text); cursor: pointer; font-weight: 500; font-size: 13px; }
        .tab.active { background: #3a3a3c; }
        .list { background: var(--card); border-radius: 12px; overflow: hidden; }
        .row { padding: 15px; border-bottom: 1px solid var(--sep); cursor: pointer; display: flex; justify-content: space-between; align-items: center;}
        .row:last-child { border-bottom: none; }
        .tit { font-weight: 600; font-size: 16px; margin-bottom: 4px; display: flex; align-items: center; }
        .sub { font-size: 12px; color: var(--sub); }
        .pwd { color: var(--green); font-family: monospace; font-size: 14px; margin-top: 4px; display: block; user-select: text; }
        .st-cracked { color: var(--green); }
        .st-active { color: var(--sub); }
        .subs { display: none; background: #000; border-bottom: 1px solid var(--sep); }
        .sub-row { display: flex; justify-content: space-between; align-items: center; padding: 12px 15px; border-bottom: 1px solid #222; }
        .btn-grp { display: flex; gap: 8px; }
        .btn-xs { color: var(--accent); text-decoration: none; font-size: 11px; font-weight: bold; background: var(--input); padding: 5px 10px; border-radius: 15px; border: none; cursor: pointer; margin-left: 5px;}
        .btn-xs.hc { color: #ff9f0a; }
        .hidden { display: none !important; }
        .badge { background: var(--input); color: var(--sub); font-size: 10px; padding: 2px 6px; border-radius: 4px; margin-left: 6px; text-transform: uppercase; font-weight: bold;}
        .arr { font-size: 12px; color: #555; margin-left: 15px; }
        .add-btn { background: var(--input); border: none; color: var(--accent); width: 28px; height: 28px; border-radius: 14px; font-size: 18px; line-height: 28px; cursor: pointer; margin-left: 8px; padding: 0; }
        .notif { padding: 15px; text-align: center; border-radius: 12px; margin-bottom: 15px; animation: fi 0.5s; background: rgba(48, 209, 88, 0.2); color: var(--green); border: 1px solid var(--green); }
        .notif.err { background: rgba(255, 69, 58, 0.2); color: var(--danger); border: 1px solid var(--danger); }
        @keyframes fi { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
        .card { padding: 20px; background: var(--card); border-radius: 12px; margin-bottom: 20px; text-align: center; }
        .stat-g { display: flex; justify-content: space-around; text-align: center; }
        .sv { font-size: 24px; font-weight: bold; color: var(--text); }
        .sl { font-size: 11px; color: var(--sub); text-transform: uppercase; margin-top: 5px; }
        .upl { border: 2px dashed #444; border-radius: 12px; padding: 30px; margin-bottom: 15px; cursor: pointer; text-align: center; }
        .upl:hover { border-color: var(--accent); background: #1a1a1a; }
        .upl input { display: none; }
        .btn { background: var(--green); color: #000; border: none; padding: 12px; width: 100%; border-radius: 10px; font-weight: bold; font-size: 16px; cursor: pointer; display: block; text-decoration: none; box-sizing: border-box; text-align: center; margin-top: 10px;}
        .btn.red { background: rgba(255, 69, 58, 0.15); color: var(--danger); border: 1px solid var(--danger); }
        .ach-list { display: flex; flex-direction: column; gap: 10px; }
        .ach-row { display: flex; align-items: center; background: var(--bg); padding: 12px; border-radius: 10px; opacity: 0.5; transition: 0.3s; }
        .ach-row.unlocked { opacity: 1; border: 1px solid var(--green); background: rgba(52, 199, 89, 0.05); }
        .ach-icon { font-size: 28px; margin-right: 15px; width: 40px; text-align: center; }
        .ach-info { flex-grow: 1; text-align: left; }
        .ach-name { font-weight: bold; font-size: 15px; color: var(--text); }
        .ach-desc { font-size: 12px; color: var(--sub); margin-top: 2px; }
        .ach-prog { font-size: 12px; color: var(--accent); font-weight: bold; margin-left: 10px; white-space: nowrap; }
        .header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
        .lvl-info { text-align: right; }
        .lvl-num { font-size: 20px; font-weight: bold; color: var(--text); }
        .lvl-rank { font-size: 14px; color: var(--accent); font-weight: bold; }
        .lvl-xp { font-size: 12px; color: var(--sub); margin-top: 4px; }
        .icon-btn { background: none; border: none; font-size: 18px; cursor: pointer; padding: 5px; }
        .btn-edit { color: var(--yellow); transform: scaleX(-1); }
        .btn-del { color: var(--danger); font-weight: bold; }
        .btn-add { color: var(--green); font-size: 20px; font-weight: bold; }
        .map-shell { background: #1f242b; color: #f7f8fb; border-radius: 22px; overflow: hidden; min-height: 680px; position: relative; box-shadow: 0 20px 45px rgba(0,0,0,0.32); }
        .map-stage { height: 680px; position: relative; overflow: hidden; background-color: #1f242b; background-image: linear-gradient(28deg, transparent 0 43%, rgba(113,116,104,0.34) 44% 47%, transparent 48% 100%), linear-gradient(115deg, transparent 0 52%, rgba(102,110,122,0.28) 53% 56%, transparent 57% 100%), linear-gradient(72deg, transparent 0 64%, rgba(70,110,84,0.18) 65% 67%, transparent 68% 100%), repeating-linear-gradient(0deg, rgba(190,205,225,0.045) 0 2px, transparent 2px 74px), repeating-linear-gradient(90deg, rgba(190,205,225,0.045) 0 2px, transparent 2px 74px); }
        .map-stage:after { content: ""; position: absolute; inset: 0; background: rgba(10,12,15,0.08); pointer-events: none; }
        .ymap-real { position: absolute; inset: 0; z-index: 1; background: #1f242b; }
        .ymap-real.ready [class*="inner-panes"] { background-color: #1f242b !important; }
        .ymap-real.ready [class*="ground-pane"] { filter: invert(88%) hue-rotate(180deg) grayscale(0.45) saturate(0.72) brightness(0.62) contrast(0.95); }
        .ymap-real.ready [class*="copyright"], .ymap-real.ready [class*="map-copyrights"] { filter: invert(1); opacity: 0.58; }
        .ymap-real.ready + #mapMarkers .map-point { display: none; }
        .map-glass { background: rgba(20,22,27,0.82); backdrop-filter: blur(18px); -webkit-backdrop-filter: blur(18px); border: 1px solid rgba(255,255,255,0.08); box-shadow: 0 20px 50px rgba(0,0,0,0.22); }
        .map-topbar { position: absolute; z-index: 8; top: 18px; left: 18px; right: 18px; display: flex; gap: 10px; align-items: center; }
        .map-search-wrap { flex: 1; border-radius: 999px; padding: 8px 10px; display: flex; align-items: center; gap: 8px; min-width: 0; }
        .map-search { flex: 1; border: none; padding: 10px 6px; font-size: 15px; background: transparent; color: #f7f8fb; outline: none; box-sizing: border-box; min-width: 0; }
        .map-gps-dot { border: none; width: 46px; height: 46px; border-radius: 50%; background: rgba(255,255,255,0.92); color: #8a919f; cursor: pointer; box-shadow: 0 10px 28px rgba(27,39,66,0.16); display:flex; align-items:center; justify-content:center; position: relative; }
        .map-gps-dot:before { content: ""; width: 13px; height: 13px; border-radius: 50%; background: currentColor; box-shadow: 0 0 0 6px color-mix(in srgb, currentColor 18%, transparent); }
        .map-gps-dot.connected { color: #30d158; }
        .map-gps-dot.browser { color: #1e9bff; }
        .map-gps-dot.connecting { color: #ffcc00; }
        .map-gps-dot.offline { color: #8e8e93; }
        .map-gps-pop { position: absolute; z-index: 12; top: 74px; right: 18px; left: 18px; max-width: 330px; margin-left: auto; padding: 14px 15px; border-radius: 18px; background: rgba(18,19,21,0.92); color: #fff; box-shadow: 0 18px 50px rgba(0,0,0,0.22); backdrop-filter: blur(18px); -webkit-backdrop-filter: blur(18px); font-size: 13px; line-height: 1.35; box-sizing: border-box; overflow-wrap: anywhere; }
        .map-gps-pop b { display:block; font-size: 14px; margin-bottom: 4px; }
        .map-point { position: absolute; z-index: 4; transform: translate(-50%, -50%); min-width: 34px; height: 34px; padding: 0 8px; border-radius: 999px; border: 5px solid #1e9bff; background: rgba(255,255,255,0.96); color: #172033; font-weight: 800; display: flex; align-items: center; justify-content: center; cursor: pointer; box-shadow: 0 8px 18px rgba(0,97,200,0.25); box-sizing: border-box; }
        .map-point.cracked { border-color: #30d158; }
        .map-point.analyzing { border-color: #ffcc00; }
        .map-point.no-result { border-color: #8e8e93; }
        .map-point.me { z-index: 5; width: 24px; height: 24px; border-width: 6px; border-color: #050507; background: #1e9bff; color: #fff; font-size: 10px; box-shadow: 0 0 0 10px rgba(30,155,255,0.18), 0 8px 18px rgba(0,0,0,0.25); }
        .map-point.dim { opacity: 0.25; pointer-events: none; }
        .map-empty { position: absolute; z-index: 3; left: 24px; right: 24px; top: 115px; padding: 18px; border-radius: 18px; text-align: center; color: #c9ccd2; background: rgba(20,22,27,0.86); box-shadow: 0 14px 35px rgba(0,0,0,0.22); }
        .map-dock { position: absolute; z-index: 8; left: 50%; bottom: 22px; transform: translateX(-50%); display: flex; gap: 8px; padding: 8px; border-radius: 999px; }
        .map-dock-btn { border: none; border-radius: 999px; padding: 12px 16px; background: transparent; color: #687084; font-size: 13px; font-weight: 800; cursor: pointer; white-space: nowrap; }
        .map-dock-btn.active { background: #050507; color: #fff; }
        .map-dock-btn.green.active { background: #30d158; color: #fff; }
        .map-dock-btn.blue.active { background: #1e9bff; color: #fff; }
        .map-sheet { position: absolute; left: 0; right: 0; bottom: 0; z-index: 10; background: #17191b; color: #fff; border-radius: 28px 28px 0 0; padding: 34px 24px 24px; min-height: 230px; max-height: 82%; overflow-y: auto; box-shadow: 0 -18px 40px rgba(0,0,0,0.28); animation: mapSlideUp 0.24s ease-out; }
        @keyframes mapSlideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }
        .map-handle { position: absolute; top: 12px; left: 50%; transform: translateX(-50%); width: 48px; height: 6px; border-radius: 99px; background: rgba(255,255,255,0.11); }
        .map-title-row { display: flex; justify-content: space-between; gap: 14px; align-items: flex-start; margin-bottom: 18px; }
        .map-title { font-size: 32px; font-weight: 800; line-height: 1.05; overflow-wrap: anywhere; }
        .map-sub { margin-top: 8px; color: #a7aab1; font-size: 15px; overflow-wrap: anywhere; }
        .map-close { border: none; width: 44px; height: 44px; border-radius: 50%; background: rgba(255,255,255,0.06); color: #aeb2bb; font-size: 28px; cursor: pointer; flex: 0 0 auto; }
        .map-back { border: none; align-self: flex-start; border-radius: 999px; padding: 11px 15px; background: rgba(255,255,255,0.06); color: #dfe6f8; font-weight: 850; cursor: pointer; flex: 0 0 auto; }
        .map-metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-bottom: 18px; }
        .map-metric { background: rgba(255,255,255,0.025); border-radius: 16px; padding: 14px 10px; text-align: center; min-width: 0; }
        .map-metric-label { font-size: 11px; color: #a7aab1; text-transform: uppercase; font-weight: 800; }
        .map-metric-value { margin-top: 8px; font-size: 20px; font-weight: 800; color: #fff; overflow-wrap: anywhere; }
        .map-secret { background: #043f20; border: 1px solid #078c45; color: #8effb8; border-radius: 18px; padding: 16px; margin-top: 12px; }
        .map-secret.blue { background: #071f45; border-color: #0a66dc; color: #91c2ff; }
        .map-secret-row { display:flex; justify-content:space-between; gap:12px; align-items:center; }
        .map-copy { border:none; border-radius:14px; padding:11px 14px; background:rgba(142,255,184,0.12); color:#8effb8; font-weight:850; cursor:pointer; white-space:nowrap; }
        .map-password { font-size:28px; font-weight:800; margin-top:8px; overflow-wrap:anywhere; filter: blur(7px); user-select:none; cursor:pointer; transition:0.18s; }
        .map-password.visible { filter:none; user-select:text; }
        .map-toast { position:absolute; z-index:30; left:50%; bottom:92px; transform:translateX(-50%) translateY(18px); padding:12px 16px; border-radius:999px; background:rgba(247,248,251,0.94); color:#050507; font-weight:850; box-shadow:0 14px 35px rgba(0,0,0,0.25); opacity:0; pointer-events:none; transition:0.2s; }
        .map-toast.show { opacity:1; transform:translateX(-50%) translateY(0); }
        .map-status { background: rgba(255,255,255,0.04); border-radius: 16px; padding: 12px 14px; color: #c9ccd2; font-weight: 700; margin-top: 12px; }
        .map-chips { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }
        .map-chip { display:inline-flex; align-items:center; gap:7px; min-height:30px; border-radius:999px; padding:6px 10px; background:rgba(255,255,255,0.045); border:1px solid rgba(255,255,255,0.055); color:#cfd3da; font-size:12px; font-weight:800; box-sizing:border-box; letter-spacing:0; }
        .map-chip:before { content:""; width:7px; height:7px; border-radius:50%; background:currentColor; opacity:.9; }
        .map-chip.green { color:#76e39b; background:rgba(48,209,88,0.075); border-color:rgba(48,209,88,0.12); }
        .map-chip.blue { color:#8abfff; background:rgba(30,155,255,0.08); border-color:rgba(30,155,255,0.13); }
        .map-chip.yellow { color:#ffe08a; background:rgba(255,204,0,0.075); border-color:rgba(255,204,0,0.14); }
        .map-chip.red { color:#ff918b; background:rgba(255,69,58,0.075); border-color:rgba(255,69,58,0.13); }
        .map-chip.gray { color:#aeb2bb; background:rgba(255,255,255,0.04); border-color:rgba(255,255,255,0.055); }
        .map-actions { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 14px; }
        .map-actions.three { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) 54px; }
        .map-actions.single { grid-template-columns: 1fr; }
        .map-action { display: flex; align-items: center; justify-content: center; border: none; border-radius: 18px; padding: 15px 12px; min-height: 54px; text-align: center; font-weight: 800; text-decoration: none; background: #050507; color: #fff; cursor: pointer; box-sizing: border-box; }
        .map-action.soft { background: rgba(255,255,255,0.08); color: #dfe6f8; }
        .map-action.red { background: rgba(255,69,58,0.12); color: #ff6b62; }
        .map-action.trash { padding: 0; font-size: 22px; color: #ff6b62; }
        .trash-icon { position: relative; display: inline-block; width: 18px; height: 20px; border: 2px solid currentColor; border-top: none; border-radius: 0 0 4px 4px; box-sizing: border-box; }
        .trash-icon:before { content: ""; position: absolute; left: -3px; right: -3px; top: -6px; height: 2px; background: currentColor; border-radius: 2px; }
        .trash-icon:after { content: ""; position: absolute; left: 5px; top: -10px; width: 6px; height: 3px; border: 2px solid currentColor; border-bottom: none; border-radius: 3px 3px 0 0; }
        .map-list { display:flex; flex-direction:column; gap:10px; margin-top: 12px; }
        .map-list-item { border: none; width:100%; text-align:left; border-radius: 18px; padding: 14px; color:#fff; background: rgba(255,255,255,0.045); cursor:pointer; box-sizing:border-box; }
        .map-list-item.green { background: rgba(4, 63, 32, 0.85); border: 1px solid rgba(7,140,69,0.8); }
        .map-list-item.blue { background: rgba(7, 31, 69, 0.86); border: 1px solid rgba(10,102,220,0.75); }
        .map-list-title { font-size: 18px; font-weight: 850; overflow-wrap:anywhere; }
        .map-list-sub { margin-top: 5px; font-size: 12px; color:#aeb2bb; overflow-wrap:anywhere; }
        @media (max-width: 520px) {
            body { padding: 10px; }
            .tab { font-size: 12px; padding: 8px 4px; }
            .map-shell { border-radius: 18px; min-height: 640px; }
            .map-stage { height: 640px; }
            .map-sheet { padding: 32px 18px 20px; }
            .map-title { font-size: 27px; }
            .map-metrics { gap: 8px; }
            .map-metric-value { font-size: 18px; }
            .map-dock { bottom: 14px; max-width: calc(100% - 20px); }
            .map-dock-btn { padding: 11px 13px; }
        }
    </style>
</head>
<body>
    <div style="max-width: 800px; margin: 0 auto;">

        <div class="header">
            <h1>Passwords</h1>
            <div class="lvl-info">
                <div class="lvl-num">Level {{ stats.level }}</div>
                <div class="lvl-rank">{{ stats.rank }}</div>
                <div class="lvl-xp">{{ stats.xp }} / {{ stats.next_xp }} XP</div>
            </div>
        </div>

        <input type="text" id="s" class="s-box" onkeyup="flt()" placeholder="Search...">

        <div class="tabs">
            <button class="tab active" onclick="tab('cracked')" id="b-cracked">Cracked</button>
            <button class="tab" onclick="tab('handshakes')" id="b-handshakes">Handshakes</button>
            <button class="tab" onclick="tab('map')" id="b-map">Map</button>
            <button class="tab" onclick="tab('other')" id="b-other">Other</button>
        </div>

        {% if notif %}
        <div id="nt" class="notif {{ 'err' if ntype == 'error' else '' }}"><b>{{ notif }}</b></div>
        {% endif %}

        <div id="v-cracked" class="list hidden">
            {% for e, d in cracked.items() %}
            <div class="row si" data-t="{{ e }} {{ d.password }}">
                <div style="flex-grow:1">
                    <div class="tit">{{ e }}<span class="badge">{{ d.source }}</span></div>
                    <span class="pwd">{{ d.password }}</span>
                </div>
                <div style="display:flex; gap:10px;">
                    <button class="icon-btn btn-edit" onclick="ed('{{ e }}', '{{ d.password }}', '{{ d.source }}')" title="Edit">✎</button>
                    <button class="icon-btn btn-del" onclick="del('{{ e }}', '{{ d.password }}', '{{ d.source }}')" title="Delete">✖</button>
                </div>
            </div>
            {% endfor %}
            {% if not cracked %}<div style="padding:30px;text-align:center;color:var(--sub);">No cracked networks yet.</div>{% endif %}
        </div>

        <div id="v-handshakes" class="list hidden">
            {% for g in groups %}
            <div class="si" data-t="{{ g.essid }}">
                <div class="row">
                    <div style="flex-grow:1" onclick="tog('{{ loop.index }}')">
                        <div class="tit {{ g.cls }}">{{ g.essid }} {% if g.count > 1 %}<span class="badge">{{ g.count }}</span>{% endif %}{% if g.gps_count > 0 %}<span class="badge">GPS</span>{% endif %}</div>
                        <div class="sub">{{ g.last_seen }}</div>
                        {% if g.is_cracked %}<span class="pwd">🔑 {{ g.pwd }}</span>{% endif %}
                    </div>
                    <div style="display:flex;align-items:center;">
                        <button class="icon-btn btn-add" onclick="add('{{ g.essid }}')" title="Add Password">＋</button>
                        <span class="arr" onclick="tog('{{ loop.index }}')">▶</span>
                    </div>
                </div>
                <div id="s-{{ loop.index }}" class="subs">
                    {% for f in g.files %}
                    <div class="sub-row">
                        <div>
                            <div style="font-size:13px;">{{ f.bssid }}</div>
                            <div style="color:var(--sub);font-size:11px;">{{ f.date }} • {{ f.size }}</div>
                        </div>
                        <div class="btn-grp">
                            {% if show_wpa %}<button class="btn-xs" onclick='upl({{ f.filename|tojson }})'>WPA</button>{% endif %}
                            <button class="btn-xs hc" onclick='sendSingleToOhc({{ f.filename|tojson }})'>OHC</button>
                            <a href="/plugins/A_pwmenu/download-22000/{{ f.filename|urlencode }}" class="btn-xs hc">22000</a>
                            <a href="/plugins/A_pwmenu/download/{{ f.filename|urlencode }}" class="btn-xs">PCAP</a>
                            <button class="btn-xs" onclick='rm({{ f.filename|tojson }})' style="color:var(--danger)">×</button>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            {% endfor %}
        </div>

        <div id="v-map" class="map-shell hidden">
            <div class="map-stage" id="mapStage">
                <div class="map-topbar">
                    <div class="map-search-wrap map-glass">
                        <input type="text" id="mapSearch" class="map-search" oninput="renderMap()" placeholder="Search networks...">
                    </div>
                    <button id="gpsStatusDot" class="map-gps-dot offline" onclick="toggleGpsStatus()" title="GPS status"></button>
                </div>
                <div id="gpsStatusPop" class="map-gps-pop hidden"></div>
                <div id="mapEmpty" class="map-empty hidden">
                    <b>No GPS points</b>
                    <div style="margin-top:6px;">{{ stats.no_gps }} networks without coordinates</div>
                </div>
                <div id="yandexMap" class="ymap-real"></div>
                <div id="mapMarkers"></div>
                <div id="mapDock" class="map-dock map-glass">
                    <button id="mapAllBtn" class="map-dock-btn active" onclick="setMapFilter('all')">Map</button>
                    <button id="mapCrackedBtn" class="map-dock-btn green" onclick="setMapFilter('cracked')">Cracked</button>
                    <button id="mapNoGpsBtn" class="map-dock-btn blue" onclick="showNoGpsList()">No GPS</button>
                    <button id="mapSummaryBtn" class="map-dock-btn" onclick="showMapSummary()">Stats</button>
                </div>
                <div id="mapToast" class="map-toast">Copied</div>
            </div>
            <div id="mapSheet" class="map-sheet hidden">
                <div class="map-handle"></div>
                <div id="mapSummary">
                    <div class="map-title-row">
                        <div>
                            <div class="map-title">Summary</div>
                            <div class="map-sub">NewFPV Analytics</div>
                        </div>
                        <button class="map-close" onclick="hideMapPoint()">&times;</button>
                    </div>
                    <div class="map-metrics">
                        <div class="map-metric">
                            <div class="map-metric-label">Total</div>
                            <div class="map-metric-value">{{ stats.gps_points }}</div>
                        </div>
                        <div class="map-metric">
                            <div class="map-metric-label">Cracked</div>
                            <div class="map-metric-value" style="color:#20b866">{{ stats.cracked_gps }}</div>
                        </div>
                        <div class="map-metric">
                            <div class="map-metric-label">No GPS</div>
                            <div class="map-metric-value">{{ stats.no_gps }}</div>
                        </div>
                    </div>
                    <div class="map-status">
                        GPS: {{ gps_status.label }} {{ gps_status.state }}
                        {% if gps_status.lat is not none %}
                        - {{ gps_status.accuracy|round|int }}m - {{ gps_status.age }}s ago
                        {% endif %}
                        {% if gps_status.detail %}
                        <div style="margin-top:6px;font-size:11px;overflow-wrap:anywhere;">{{ gps_status.detail }}</div>
                        {% endif %}
                    </div>
                </div>
                <div id="mapDetails" class="hidden"></div>
            </div>
        </div>

        <div id="v-other" class="hidden">
            <div class="card" style="padding:15px;text-align:left;">
                <h3 style="margin-top:0;text-align:center;">OnlineHashCrack</h3>
                <button class="btn" style="margin-top:0;background:#ff9f0a;" onclick="sendAllMissingToOhc()">Send all missing to OHC</button>
                <div class="sub" style="margin-top:10px;">
                    Persistent queue: {{ ohc_status.pending }} file(s)
                    {% if ohc_status.retry_in > 0 %} • retry in {{ ohc_status.retry_in }}s{% endif %}
                </div>
                <div class="sub" style="margin-top:4px;">Scans every uncracked PCAP and submits only hashes absent from the OHC task list.</div>
            </div>

            <div class="card">
                <h3 style="margin-top:0">Achievements</h3>
                <div class="ach-list">
                    {% for a in ach %}
                    <div class="ach-row {{ 'unlocked' if a.unlocked else '' }}">
                        <div class="ach-icon">{{ a.icon }}</div>
                        <div class="ach-info">
                            <div class="ach-name">{{ a.name }}</div>
                            <div class="ach-desc">{{ a.desc }}</div>
                        </div>
                        <div class="ach-prog">{{ a.current }} / {{ a.target }}</div>
                    </div>
                    {% endfor %}
                </div>
            </div>

            <div class="card">
                <div class="stat-g">
                    <div class="stat-item"><div class="sv" style="color:var(--green)">{{ stats.percent }}%</div><div class="sl">Cracked</div></div>
                    <div class="stat-item"><div class="sv">{{ stats.total }}</div><div class="sl">Networks</div></div>
                    <div class="stat-item"><div class="sv">{{ stats.files }}</div><div class="sl">Files</div></div>
                </div>
                <a href="/plugins/A_pwmenu/export-passwords" class="btn" style="background:var(--accent);">Export List (.txt)</a>
                <a href="/plugins/A_pwmenu/download-zip" class="btn">Download All (.zip)</a>
                <a href="/plugins/A_pwmenu/download-uncracked" class="btn" style="background:#071f45;color:#91c2ff;">Download Uncracked (.zip)</a>
                <form method="POST" action="/plugins/A_pwmenu/sync-time" style="margin-top:10px;">
                    <input type="hidden" name="csrf_token" value="{{ token }}">
                    <button class="btn" style="background:var(--sub);">Sync Time (Google)</button>
                </form>
            </div>

            <div class="card">
                <h3 style="margin-top:0">Import</h3>
                <form method="POST" action="/plugins/A_pwmenu/import" enctype="multipart/form-data" id="if">
                    <input type="hidden" name="csrf_token" value="{{ token }}">
                    <div class="upl" onclick="document.getElementById('fi').click()">
                        <div style="font-size:30px; margin-bottom:10px;">📂</div>
                        <div id="fn" style="color:var(--sub);">Select .json or .csv</div>
                        <input type="file" id="fi" name="file" accept=".json,.csv" onchange="sel(this)">
                    </div>
                    <button class="btn" id="ib" style="display:none;">Import Passwords</button>
                </form>
            </div>

            <div class="card" style="border:1px solid var(--danger);">
                <h3 style="margin-top:0; color:var(--danger)">Danger Zone</h3>
                <form method="POST" action="/plugins/A_pwmenu/clean-broken" onsubmit="return confirm('Clean broken?')">
                    <input type="hidden" name="csrf_token" value="{{ token }}">
                    <button class="btn red">Clean Broken Files</button>
                </form>
                <form method="POST" action="/plugins/A_pwmenu/nuke-all" onsubmit="return confirm('NUKE ALL?')">
                    <input type="hidden" name="csrf_token" value="{{ token }}">
                    <button class="btn red" style="background:transparent; border-color:var(--sub); color:var(--sub);">Nuke Everything</button>
                </form>
            </div>
        </div>
    </div>

    <script>
        const csrfToken = '{{ token }}';
        const wpaEnabled = {{ 'true' if show_wpa else 'false' }};
        const mapPoints = {{ map_points|tojson }};
        const noGpsNetworks = {{ no_gps_networks|tojson }};
        const gpsStatus = {{ gps_status|tojson }};
        let gpsWatchId = null;
        let selectedMapPoint = null;
        let userLocation = null;
        let mapFilter = 'all';
        let yandexMap = null;
        let yandexObjects = null;
        let yandexReady = false;
        let activeMapGroup = null;

        const t0 = '{{ tab }}';
        tab(t0);
        startPhoneGps(false);
        updateGpsStatusDot();
        renderMap();
        if(document.getElementById('nt')) setTimeout(() => document.getElementById('nt').style.display='none', 3000);

        function post(u, d) {
            const f = document.createElement('form'); f.method='POST'; f.action='/plugins/A_pwmenu/'+u;
            const t = document.createElement('input'); t.type='hidden'; t.name='csrf_token'; t.value=csrfToken; f.appendChild(t);
            for(const k in d) { const i=document.createElement('input'); i.name=k; i.value=d[k]; f.appendChild(i); }
            document.body.appendChild(f); f.submit();
        }

        function sel(i) {
            if(i.files[0]) {
                document.getElementById('fn').innerText = i.files[0].name;
                document.getElementById('fn').style.color = '#fff';
                document.getElementById('ib').style.display = 'block';
            }
        }

        function add(e) { const p=prompt("Password for "+e+":"); if(p) post('add-password', {essid:e, password:p}); }
        function ed(e,o) { const p=prompt("Edit "+e+":", o); if(p&&p!==o) post('update-password', {essid:e, password:p}); }
        function del(e, p, s) {
            if(confirm("Delete password for "+e+"?")) {
                post('delete-password', {essid:e, password:p, source:s});
            }
        }
        function rm(f) { if(confirm("Delete file "+f+"?")) post('delete-file', {filename:f}); }
        function upl(f) {
            const k = '{{ show_wpa }}';
            if(k) post('wpa-sec-upload', {filename:f});
        }

        function esc(v) {
            return String(v || '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
        }

        function jsq(v) {
            return JSON.stringify(String(v || ''));
        }

        function copyText(v) {
            const text = String(v || '');
            if(!text) return;
            if(navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).catch(() => {});
            } else {
                const t = document.createElement('textarea');
                t.value = text;
                document.body.appendChild(t);
                t.select();
                document.execCommand('copy');
                document.body.removeChild(t);
            }
            showToast('Copied');
        }

        function showToast(text) {
            const toast = document.getElementById('mapToast');
            if(!toast) return;
            toast.textContent = text || 'Done';
            toast.classList.add('show');
            clearTimeout(showToast.t);
            showToast.t = setTimeout(() => toast.classList.remove('show'), 1300);
        }

        function revealPassword(id) {
            const el = document.getElementById(id);
            if(el) el.classList.toggle('visible');
        }

        function clusterDownloadUrl(p) {
            const names = clusterFileList(p);
            return '/plugins/A_pwmenu/download-cluster/' + encodeURIComponent(names.join(','));
        }

        function clusterFileList(p) {
            const out = [];
            (p.members || []).forEach(m => {
                if(m.filename) out.push(m.filename);
                (m.history || []).forEach(h => { if(h.filename) out.push(h.filename); });
            });
            return [...new Set(out)];
        }

        function clusterFilenames(p) {
            return clusterFileList(p).join(',');
        }

        function sendClusterToOhc(p) {
            const names = clusterFilenames(p);
            if(!names) return;
            post('ohc-upload-cluster', {filenames: names});
        }

        function sendClusterToWpa(p) {
            const names = clusterFilenames(p);
            if(!names || !wpaEnabled) return;
            post('wpa-sec-upload-cluster', {filenames: names});
        }

        function noGpsFilenames(n) {
            return (n.files || []).map(f => f.filename).filter(Boolean).join(',');
        }

        function sendNoGpsToOhc(n) {
            const names = noGpsFilenames(n);
            if(!names) return;
            post('ohc-upload-cluster', {filenames: names});
        }

        function sendNoGpsToWpa(n) {
            const names = noGpsFilenames(n);
            if(!names || !wpaEnabled) return;
            post('wpa-sec-upload-cluster', {filenames: names});
        }

        function sendSingleToOhc(filename) {
            if(!filename) return;
            post('ohc-upload-cluster', {filenames: filename});
        }

        function sendAllMissingToOhc() {
            if(!confirm('Scan all uncracked captures and send every hash missing from OHC?')) return;
            post('ohc-upload-all-missing', {});
        }

        function sendSingleToWpa(filename) {
            if(!filename || !wpaEnabled) return;
            post('wpa-sec-upload-cluster', {filenames: filename});
        }

        function ohcStatusBlock(item) {
            const o = (item && item.ohc) || {};
            if(!o.status) return '<span class="map-chip gray">OHC Not sent</span>';
            if(o.status === 'sent') return '<span class="map-chip green">OHC Sent</span>';
            if(o.status === 'already_reported') return '<span class="map-chip blue">OHC Already exists</span>';
            if(o.status === 'queued') return '<span class="map-chip yellow">OHC Queued</span>';
            if(o.status === 'failed') return '<span class="map-chip red">OHC Failed</span>';
            if(o.status === 'invalid') return '<span class="map-chip yellow">OHC Invalid</span>';
            return `<span class="map-chip gray">OHC ${esc(o.status)}</span>`;
        }

        function gpsStatusChip(item, missing) {
            if(missing) return '<span class="map-chip gray">GPS Missing</span>';
            if(item && item.gps_stale) {
                const mins = Math.max(1, Math.round((Number(item.gps_age_at_capture || 0)) / 60));
                return `<span class="map-chip yellow">GPS ${mins} min old</span>`;
            }
            return '<span class="map-chip green">GPS Fresh</span>';
        }

        function pointChips(item, missingGps) {
            return `<div class="map-chips">${ohcStatusBlock(item)}${gpsStatusChip(item, missingGps)}</div>`;
        }

        function networkActions(filename, isCracked, ohcExpr, wpaExpr) {
            if(isCracked) {
                return `<div class="map-actions single">
                    <button class="map-action red" onclick='rm(${jsq(filename)})'>Delete</button>
                </div>`;
            }
            const wpaAction = wpaEnabled ? `<button class="map-action soft" onclick='${wpaExpr}'>Send WPA-sec</button>` : '';
            return `<div class="map-actions">
                <a class="map-action" href="/plugins/A_pwmenu/download/${encodeURIComponent(filename)}">Download .pcap</a>
                <button class="map-action soft" onclick='${ohcExpr}'>Send OHC</button>
                ${wpaAction}
                <button class="map-action red trash" title="Delete" onclick='rm(${jsq(filename)})'><span class="trash-icon"></span></button>
            </div>`;
        }

        function gpsBody(pos) {
            const b = new URLSearchParams();
            b.append('csrf_token', csrfToken);
            b.append('lat', pos.coords.latitude);
            b.append('lon', pos.coords.longitude);
            b.append('accuracy', pos.coords.accuracy || 0);
            b.append('heading', pos.coords.heading || '');
            b.append('speed', pos.coords.speed || '');
            b.append('provider', 'browser');
            return b;
        }

        function startPhoneGps(force) {
            if(!navigator.geolocation) return;
            if(gpsWatchId !== null && !force) return;
            const send = pos => {
                userLocation = {
                    lat: pos.coords.latitude,
                    lon: pos.coords.longitude,
                    accuracy: pos.coords.accuracy || 0
                };
                gpsStatus.label = 'Browser GPS';
                gpsStatus.state = 'connected';
                gpsStatus.lat = userLocation.lat;
                gpsStatus.lon = userLocation.lon;
                gpsStatus.accuracy = userLocation.accuracy;
                gpsStatus.age = 0;
                gpsStatus.detail = 'Browser geolocation is active';
                updateGpsStatusDot();
                renderMap();
                fetch('/plugins/A_pwmenu/phone-gps', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: gpsBody(pos).toString()
                }).catch(() => {});
            };
            const opts = {enableHighAccuracy: true, maximumAge: 15000, timeout: 12000};
            if(gpsWatchId !== null) navigator.geolocation.clearWatch(gpsWatchId);
            navigator.geolocation.getCurrentPosition(send, () => {}, opts);
            gpsWatchId = navigator.geolocation.watchPosition(send, () => {}, opts);
        }

        function gpsClass() {
            const label = String(gpsStatus.label || '').toLowerCase();
            const state = String(gpsStatus.state || '').toLowerCase();
            if(label.includes('pwndroid') && state.includes('connected')) return 'connected';
            if(label.includes('browser') || (userLocation && state.includes('connected'))) return 'browser';
            if(state.includes('connecting')) return 'connecting';
            return 'offline';
        }

        function updateGpsStatusDot() {
            const dot = document.getElementById('gpsStatusDot');
            if(!dot) return;
            dot.className = 'map-gps-dot ' + gpsClass();
            dot.title = `${gpsStatus.label || 'GPS'} ${gpsStatus.state || ''}`.trim();
        }

        function gpsStatusText() {
            const parts = [];
            parts.push(`<b>${esc(gpsStatus.label || 'GPS')} ${esc(gpsStatus.state || '')}</b>`);
            if(gpsStatus.lat !== null && gpsStatus.lat !== undefined) {
                parts.push(`${Math.round(gpsStatus.accuracy || 0)}m accuracy`);
                parts.push(`Last fix ${gpsStatus.age || 0}s ago`);
            }
            if(gpsStatus.detail) parts.push(`<span style="overflow-wrap:anywhere">${esc(gpsStatus.detail)}</span>`);
            return parts.join('<br>');
        }

        function showGpsStatus(force) {
            const pop = document.getElementById('gpsStatusPop');
            if(!pop) return;
            pop.innerHTML = gpsStatusText();
            pop.classList.remove('hidden');
            if(force) setTimeout(() => pop.classList.add('hidden'), 4200);
        }

        function toggleGpsStatus() {
            const pop = document.getElementById('gpsStatusPop');
            if(!pop) return;
            if(pop.classList.contains('hidden')) showGpsStatus(false);
            else pop.classList.add('hidden');
        }

        function distanceMeters(a, b) {
            if(!a || !b) return null;
            const r = 6371000;
            const toRad = d => d * Math.PI / 180;
            const dLat = toRad(b.lat - a.lat);
            const dLon = toRad(b.lon - a.lon);
            const lat1 = toRad(a.lat);
            const lat2 = toRad(b.lat);
            const h = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
            return Math.round(2 * r * Math.asin(Math.sqrt(h)));
        }

        function fmtDistance(m) {
            if(m === null) return 'unknown';
            return m >= 1000 ? (m / 1000).toFixed(2) + ' km' : m + ' m';
        }

        function setMapFilter(mode) {
            mapFilter = mode;
            document.getElementById('mapAllBtn').classList.toggle('active', mode === 'all');
            document.getElementById('mapCrackedBtn').classList.toggle('active', mode === 'cracked');
            document.getElementById('mapNoGpsBtn').classList.toggle('active', false);
            hideMapPoint();
            renderMap();
        }

        function showMapSummary() {
            selectedMapPoint = null;
            document.getElementById('mapSheet').classList.remove('hidden');
            document.getElementById('mapSummary').classList.remove('hidden');
            document.getElementById('mapDetails').classList.add('hidden');
            document.getElementById('mapDock').classList.add('hidden');
        }

        function showNoGpsList() {
            selectedMapPoint = null;
            document.getElementById('mapNoGpsBtn').classList.add('active');
            document.getElementById('mapAllBtn').classList.remove('active');
            document.getElementById('mapCrackedBtn').classList.remove('active');
            document.getElementById('mapSheet').classList.remove('hidden');
            document.getElementById('mapSummary').classList.add('hidden');
            document.getElementById('mapDock').classList.add('hidden');
            const d = document.getElementById('mapDetails');
            d.classList.remove('hidden');
            const rows = noGpsNetworks.map((n, idx) => `
                <button class="map-list-item ${n.is_cracked ? 'green' : 'blue'}" onclick="showNoGpsPoint(${idx})">
                    <div class="map-list-title">${esc(n.essid)}</div>
                    <div class="map-list-sub">${esc(n.vendor || 'Unknown vendor')} - ${esc(n.bssid || 'no bssid')} - ${esc(n.date)} - ${n.count} capture${n.count === 1 ? '' : 's'}</div>
                    ${n.password ? `<div style="margin-top:10px;color:#8effb8;font-weight:850">Cracked</div>` : ''}
                </button>`).join('');
            d.innerHTML = `
                <div class="map-title-row">
                    <div>
                        <div class="map-title">No GPS</div>
                        <div class="map-sub">${noGpsNetworks.length} networks without coordinates</div>
                    </div>
                    <button class="map-close" onclick="hideMapPoint()">&times;</button>
                </div>
                <div class="map-list">${rows || '<div class="map-status">Every network has coordinates.</div>'}</div>`;
        }

        function showNoGpsPoint(idx) {
            const n = noGpsNetworks[idx];
            if(!n) return;
            selectedMapPoint = n;
            document.getElementById('mapSheet').classList.remove('hidden');
            document.getElementById('mapSummary').classList.add('hidden');
            document.getElementById('mapDock').classList.add('hidden');
            const d = document.getElementById('mapDetails');
            d.classList.remove('hidden');
            const pass = n.password ? `
                <div class="map-secret">
                    <div class="map-secret-row">
                        <div style="min-width:0">
                            <div class="map-metric-label" style="color:#8effb8">Access Key</div>
                            <div id="nogps-pw-${idx}" class="map-password" onclick='revealPassword(${jsq('nogps-pw-' + idx)})' title="Tap to reveal">${esc(n.password)}</div>
                        </div>
                        <button class="map-copy" onclick='copyText(${jsq(n.password)})'>Copy</button>
                    </div>
                </div>` : `
                <div class="map-secret blue"><b>Encrypted</b></div>`;
            const fileRows = (n.files || []).slice(0, 5).map(f => `
                <div class="map-list-item">
                    <div class="map-list-title" style="font-size:15px">${esc(f.filename)}</div>
                    <div class="map-list-sub">${esc(f.date)} - ${esc(f.size)}</div>
                </div>`).join('');
            d.innerHTML = `
                <div class="map-title-row">
                    <button class="map-back" onclick="showNoGpsList()">Back</button>
                    <div>
                        <div class="map-title">${esc(n.essid)}</div>
                        <div class="map-sub">${esc(n.bssid || 'no bssid')}</div>
                    </div>
                    <button class="map-close" onclick="hideMapPoint()">&times;</button>
                </div>
                <div class="map-metrics">
                    <div class="map-metric"><div class="map-metric-label">Captures</div><div class="map-metric-value" style="font-size:15px">${esc(n.count || 1)}</div></div>
                    <div class="map-metric"><div class="map-metric-label">GPS</div><div class="map-metric-value" style="font-size:15px">Missing</div></div>
                    <div class="map-metric"><div class="map-metric-label">Vendor</div><div class="map-metric-value" style="font-size:15px">${esc(n.vendor || 'Unknown vendor')}</div></div>
                </div>
                <div class="map-status">Captured: ${esc(n.date || 'unknown')}</div>
                ${pointChips(n, true)}
                ${pass}
                ${fileRows ? `<div class="map-status">${n.files.length} capture file${n.files.length === 1 ? '' : 's'}</div><div class="map-list">${fileRows}</div>` : ''}
                ${n.filename ? networkActions(n.filename, !!n.password, `sendNoGpsToOhc(noGpsNetworks[${idx}])`, `sendNoGpsToWpa(noGpsNetworks[${idx}])`) : ''}`;
        }

        function mapBounds(points) {
            let minLat = Infinity, maxLat = -Infinity, minLon = Infinity, maxLon = -Infinity;
            points.forEach(p => {
                minLat = Math.min(minLat, p.lat); maxLat = Math.max(maxLat, p.lat);
                minLon = Math.min(minLon, p.lon); maxLon = Math.max(maxLon, p.lon);
            });
            if(userLocation) {
                minLat = Math.min(minLat, userLocation.lat); maxLat = Math.max(maxLat, userLocation.lat);
                minLon = Math.min(minLon, userLocation.lon); maxLon = Math.max(maxLon, userLocation.lon);
            }
            if(minLat === Infinity) {
                minLat = userLocation.lat - 0.001; maxLat = userLocation.lat + 0.001;
                minLon = userLocation.lon - 0.001; maxLon = userLocation.lon + 0.001;
            }
            if(minLat === maxLat) { minLat -= 0.001; maxLat += 0.001; }
            if(minLon === maxLon) { minLon -= 0.001; maxLon += 0.001; }
            return {minLat, maxLat, minLon, maxLon};
        }

        function pointPos(p, b) {
            const pad = 10;
            const x = pad + ((p.lon - b.minLon) / (b.maxLon - b.minLon)) * (100 - pad * 2);
            const y = pad + ((b.maxLat - p.lat) / (b.maxLat - b.minLat)) * (100 - pad * 2);
            return {x, y};
        }

        function filteredMapPoints() {
            const mapSearch = document.getElementById('mapSearch');
            const q = ((mapSearch && mapSearch.value) || '').toUpperCase();
            return mapPoints.filter(p => {
                const memberText = (p.members || []).map(m => `${m.essid} ${m.bssid} ${m.filename}`).join(' ');
                const hay = (p.essid + ' ' + p.bssid + ' ' + p.filename + ' ' + memberText).toUpperCase();
                if(!hay.includes(q)) return false;
                if(mapFilter === 'cracked' && !p.is_cracked) return false;
                return true;
            });
        }

        function pointStatusClass(p) {
            if(p.status === 'analyzing') return 'analyzing';
            if(p.status === 'no_result') return 'no-result';
            if(p.is_cracked || p.status === 'cracked') return 'cracked';
            return '';
        }

        function mapPointCount(p) {
            const members = p.members || [];
            if(mapFilter === 'cracked' && members.length > 1) {
                return members.filter(m => m.is_cracked || m.status === 'cracked').length;
            }
            return Math.max(1, parseInt(p.count || 1, 10) || 1);
        }

        function yandexPreset(p) {
            return 'islands#circleIcon';
        }

        function yandexColor(p) {
            if(p.status === 'analyzing') return '#ffcc00';
            if(p.status === 'no_result') return '#8e8e93';
            if(p.is_cracked || p.status === 'cracked') return '#30d158';
            return '#1e9bff';
        }

        function initYandexMap() {
            if(!window.ymaps) return;
            window.ymaps.ready(() => {
                if(yandexMap) return;
                try {
                const pts = mapPoints.length ? mapPoints : [{lat: 55.751244, lon: 37.618423}];
                yandexMap = new ymaps.Map('yandexMap', {
                    center: [pts[0].lat, pts[0].lon],
                    zoom: mapPoints.length ? 14 : 10,
                    controls: []
                }, { suppressMapOpenBlock: true });
                yandexObjects = new ymaps.ObjectManager({
                    clusterize: true,
                    gridSize: 256,
                    geoObjectOpenBalloonOnClick: false,
                    clusterOpenBalloonOnClick: false,
                    clusterDisableClickZoom: false
                });
                yandexObjects.objects.options.set('openBalloonOnClick', false);
                yandexObjects.clusters.options.set('openBalloonOnClick', false);
                yandexMap.geoObjects.add(yandexObjects);
                yandexObjects.objects.events.add('click', e => {
                    const id = String(e.get('objectId')).split('__')[0];
                    if(id === '__me') return;
                    const p = mapPoints.find(pt => pt.id === id);
                    if(p) showMapPoint(p);
                });
                yandexObjects.clusters.events.add('click', e => {
                    const cluster = yandexObjects.clusters.getById(e.get('objectId'));
                    const objects = cluster && cluster.properties && cluster.properties.geoObjects ? cluster.properties.geoObjects : [];
                    const ids = [];
                    objects.forEach(o => {
                        const id = String(o.id || '').split('__')[0];
                        if(id && id !== '__me' && ids.indexOf(id) === -1) ids.push(id);
                    });
                    const points = ids.map(id => mapPoints.find(pt => pt.id === id)).filter(Boolean);
                    if(points.length === 1) {
                        showMapPoint(points[0]);
                        return;
                    }
                    if(points.length > 1) {
                        const members = [];
                        points.forEach(p => (p.members && p.members.length ? p.members : [p]).forEach(m => members.push(m)));
                        showMapGroup({
                            id: 'cluster-' + ids.join('-'),
                            essid: points.length + ' points',
                            count: points.reduce((sum, p) => sum + (parseInt(p.count || 1, 10) || 1), 0),
                            members: members
                        });
                    }
                });
                yandexReady = true;
                document.getElementById('yandexMap').classList.add('ready');
                setTimeout(() => yandexMap.container.fitToViewport(), 50);
                renderMap();
                } catch(e) {
                    yandexMap = null;
                    yandexObjects = null;
                    yandexReady = false;
                    const el = document.getElementById('yandexMap');
                    if(el) el.classList.remove('ready');
                    renderMap();
                }
            });
        }

        function renderYandexMap(pts) {
            if(!yandexReady || !yandexObjects) return false;
            yandexObjects.removeAll();
            yandexObjects.clusters.options.set('preset', mapFilter === 'cracked' ? 'islands#greenClusterIcons' : 'islands#blueClusterIcons');
            const features = [];
            pts.forEach(p => {
                const displayCount = mapPointCount(p);
                const repeats = Math.max(1, Math.min(99, displayCount));
                for(let i = 0; i < repeats; i++) {
                    features.push({
                        type: 'Feature',
                        id: `${p.id}__${i}`,
                        geometry: { type: 'Point', coordinates: [p.lat, p.lon] },
                        properties: {
                            hintContent: p.essid,
                            iconContent: String(displayCount)
                        },
                        options: { preset: yandexPreset(p), iconColor: yandexColor(p), openBalloonOnClick: false }
                    });
                }
            });
            if(userLocation) {
                features.push({
                    type: 'Feature',
                    id: '__me',
                    geometry: { type: 'Point', coordinates: [userLocation.lat, userLocation.lon] },
                    properties: { hintContent: 'My location' },
                    options: { preset: 'islands#blackCircleDotIcon' }
                });
            }
            yandexObjects.add({ type: 'FeatureCollection', features });
            return true;
        }

        function renderMap() {
            const box = document.getElementById('mapMarkers');
            if(!box) return;
            const pts = filteredMapPoints();
            const empty = document.getElementById('mapEmpty');
            box.innerHTML = '';
            empty.classList.toggle('hidden', pts.length > 0 || !!userLocation);
            if(pts.length === 0 && !userLocation) return;

            if(renderYandexMap(pts)) return;

            const b = mapBounds(pts);
            if(userLocation) {
                const mePos = pointPos(userLocation, b);
                const me = document.createElement('button');
                me.className = 'map-point me';
                me.style.left = mePos.x + '%';
                me.style.top = mePos.y + '%';
                me.innerText = '';
                me.title = 'My location';
                box.appendChild(me);
            }
            pts.forEach((p, i) => {
                const pos = pointPos(p, b);
                const m = document.createElement('button');
                m.className = 'map-point ' + pointStatusClass(p);
                m.style.left = pos.x + '%';
                m.style.top = pos.y + '%';
                m.innerText = String(mapPointCount(p));
                m.title = p.essid;
                m.onclick = () => showMapPoint(p);
                box.appendChild(m);
            });
        }

        function showMapPoint(p, fromGroup) {
            if((p.members || []).length > 1 && !fromGroup) {
                showMapGroup(p);
                return;
            }
            if(!fromGroup) activeMapGroup = null;
            selectedMapPoint = p;
            document.getElementById('mapSheet').classList.remove('hidden');
            document.getElementById('mapDock').classList.add('hidden');
            document.getElementById('mapSummary').classList.add('hidden');
            const d = document.getElementById('mapDetails');
            d.classList.remove('hidden');
            const backButton = activeMapGroup ? '<button class="map-back" onclick="showMapGroup(activeMapGroup)">Back</button>' : '<button class="map-back" onclick="hideMapPoint()">Back</button>';
            const pass = p.password ? `
                <div class="map-secret">
                    <div class="map-secret-row">
                        <div style="min-width:0">
                            <div class="map-metric-label" style="color:#8effb8">Access Key</div>
                            <div id="pw-${esc(p.id)}" class="map-password" onclick='revealPassword(${jsq('pw-' + p.id)})' title="Tap to reveal">${esc(p.password)}</div>
                        </div>
                        <button class="map-copy" onclick='copyText(${jsq(p.password)})'>Copy</button>
                    </div>
                </div>` : `
                <div class="map-secret blue">
                    <b>Encrypted</b>
                </div>`;
            const history = (p.history || []).slice(1, 5).map(h => `
                <div class="map-list-item">
                    <div class="map-list-title" style="font-size:15px">${esc(h.date)}</div>
                    <div class="map-list-sub">${esc(h.filename)} - ${Math.round(h.accuracy || 0)}m</div>
                </div>`).join('');
            d.innerHTML = `
                <div class="map-title-row">
                    ${backButton}
                    <div>
                        <div class="map-title">${esc(p.essid)}</div>
                        <div class="map-sub">${esc(p.bssid || 'no bssid')}</div>
                    </div>
                    <button class="map-close" onclick="hideMapPoint()">&times;</button>
                </div>
                <div class="map-metrics">
                    <div class="map-metric"><div class="map-metric-label">Captures</div><div class="map-metric-value" style="font-size:15px">${esc(p.captures || 1)}</div></div>
                    <div class="map-metric"><div class="map-metric-label">Security</div><div class="map-metric-value" style="font-size:15px">${esc(p.encryption || 'WPA2')}</div></div>
                    <div class="map-metric"><div class="map-metric-label">Vendor</div><div class="map-metric-value" style="font-size:15px">${esc(p.vendor || 'Unknown vendor')}</div></div>
                </div>
                <div class="map-status">Captured: ${esc(p.date)}</div>
                ${pointChips(p, false)}
                ${pass}
                ${history ? `<div class="map-status">${p.history.length} nearby captures</div><div class="map-list">${history}</div>` : ''}
                ${networkActions(p.filename, !!p.password, `sendSingleToOhc(${jsq(p.filename)})`, `sendSingleToWpa(${jsq(p.filename)})`)}`;
        }

        function showMapGroup(p) {
            activeMapGroup = p;
            selectedMapPoint = p;
            document.getElementById('mapSheet').classList.remove('hidden');
            document.getElementById('mapDock').classList.add('hidden');
            document.getElementById('mapSummary').classList.add('hidden');
            const d = document.getElementById('mapDetails');
            d.classList.remove('hidden');
            const visibleMembers = (p.members || []).filter(m => mapFilter !== 'cracked' || m.is_cracked || m.status === 'cracked');
            const rows = visibleMembers.map((m, idx) => {
                const gpsAge = m.gps_stale ? ` - GPS ${Math.max(1, Math.round((Number(m.gps_age_at_capture || 0)) / 60))} min old` : '';
                return `<button class="map-list-item ${m.is_cracked ? 'green' : 'blue'}" onclick="showMapPointFromGroup(${idx})">
                    <div class="map-list-title">${esc(m.essid)}</div>
                    <div class="map-list-sub">${esc(m.vendor || 'Unknown vendor')} - ${esc(m.bssid || 'no bssid')}${gpsAge}</div>
                    ${m.password ? `<div style="margin-top:10px;color:#8effb8;font-weight:850">Cracked</div>` : ''}
                </button>`;
            }).join('');
            p.visibleMembers = visibleMembers;
            d.innerHTML = `
                <div class="map-title-row">
                    <div>
                        <div class="map-title">${visibleMembers.length} networks</div>
                        <div class="map-sub">Same spot cluster</div>
                    </div>
                    <button class="map-close" onclick="hideMapPoint()">&times;</button>
                </div>
                <div class="map-actions">
                    <a class="map-action" href="${clusterDownloadUrl(p)}">Download all .pcap</a>
                    <button class="map-action soft" onclick="sendClusterToOhc(activeMapGroup)">Send OHC</button>
                    ${wpaEnabled ? '<button class="map-action soft" onclick="sendClusterToWpa(activeMapGroup)">Send WPA-sec</button>' : ''}
                </div>
                <div class="map-list">${rows || '<div class="map-status">No cracked networks here.</div>'}</div>`;
        }

        function showMapPointFromGroup(idx) {
            if(!selectedMapPoint || !selectedMapPoint.members) return;
            activeMapGroup = selectedMapPoint;
            const members = selectedMapPoint.visibleMembers || selectedMapPoint.members;
            showMapPoint(members[idx], true);
        }

        function hideMapPoint() {
            selectedMapPoint = null;
            activeMapGroup = null;
            document.getElementById('mapSheet').classList.add('hidden');
            document.getElementById('mapDetails').classList.add('hidden');
            document.getElementById('mapSummary').classList.add('hidden');
            document.getElementById('mapDock').classList.remove('hidden');
            document.getElementById('mapNoGpsBtn').classList.remove('active');
            document.getElementById('mapAllBtn').classList.toggle('active', mapFilter === 'all');
            document.getElementById('mapCrackedBtn').classList.toggle('active', mapFilter === 'cracked');
        }

        function tab(t) {
            document.querySelectorAll('.list, #v-other, #v-map').forEach(e=>e.classList.add('hidden'));
            const view = document.getElementById(t==='other'?'v-other':'v-'+t);
            view.classList.remove('hidden');
            if(t!=='other' && t!=='map') view.classList.add('list');
            document.querySelectorAll('.tab').forEach(e=>e.classList.remove('active'));
            document.getElementById('b-'+t).classList.add('active');
            if(t==='map') {
                startPhoneGps(false);
                initYandexMap();
                setTimeout(() => {
                    if(yandexMap) yandexMap.container.fitToViewport();
                    renderMap();
                }, 80);
            }
            flt();
        }

        function tog(id) {
            let s = document.getElementById('s-'+id);
            s.style.display = s.style.display==='block' ? 'none' : 'block';
        }

        function flt() {
            let v = document.getElementById('s').value.toUpperCase();
            let active = document.querySelector('.tab.active').id.replace('b-','');
            if(active === 'other') return;
            if(active === 'map') { renderMap(); return; }
            let act = 'v-' + active;
            document.getElementById(act).querySelectorAll('.si').forEach(el=>{
                el.style.display = el.getAttribute('data-t').toUpperCase().includes(v) ? '' : 'none';
            });
        }
    </script>
</body>
</html>
"""
