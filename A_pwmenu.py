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
import hashlib
import hmac
import shutil
import tempfile
import ast
import gzip
import math
import urllib.parse
import pwnagotchi.plugins as plugins
import pwnagotchi.ui.fonts as fonts
from flask import current_app, send_file, make_response, has_request_context
from flask import request as flask_request
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
    __version__ = '1.4.0'
    __ui_revision__ = '20260730-14'
    __license__ = 'GPL3'
    __description__ = 'Ultimate Password Manager'

    def __init__(self):
        self.ready = False
        self.storage_ready = False
        self.storage_lock = threading.RLock()
        self.storage_dir = ''
        self.handshake_dirs = []
        self.potfile_ohc = ''
        self.potfile_handshake_lab = ''
        self.potfile_manual = ''
        self.data_file = ''
        self.ohc_export_file = ''
        self.last_sync = 0
        self.data_lock = threading.RLock()
        self.save_lock = threading.Lock()
        self.potfile_lock = threading.RLock()
        self.time_sync_lock = threading.Lock()
        self.wpa_upload_lock = threading.Lock()
        self.wpa_pending_lock = threading.RLock()
        self.wpa_pending_files = {}
        self.wpa_upload_thread = None
        self.wpa_last_result = ''
        self.wpa_force_download = False
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
        self.ohc_thread_lock = threading.Lock()
        self.ohc_upload_thread = None
        self.ohc_upload_faces = ('0__1', '1__0', '0__0', '1__1')
        self.ohc_upload_face = '0__0'
        self.ohc_display_faces = None
        self.ohc_display_status = ''
        self.ohc_display_result_until = 0
        self.ohc_progress_current = 0
        self.ohc_progress_total = 0
        self.ohc_progress_name = ''
        self.ohc_last_result = ''
        self.ohc_scheduler_running = False
        self.ohc_scheduler_thread = None
        self.ohc_scheduler_wakeup = threading.Event()
        self.ohc_proxy_lock = threading.RLock()
        self.ohc_proxy_process = None
        self.ohc_proxy_config_file = '/run/a_pwmenu_ohc_xray.json'
        self.capture_analysis_lock = threading.Lock()
        self.password_verify_lock = threading.Lock()
        self.conflict_repair_lock = threading.RLock()
        self.conflict_repair_jobs = {}
        self.quality_thread_lock = threading.Lock()
        self.quality_scan_thread = None
        self.quality_pending = set()
        self.quality_scan_all = False
        self.quality_scan_running = False
        self._agent = None
        self.config_path = '/etc/pwnagotchi/config.toml'
        self.whitelist_lock = threading.RLock()
        self.display_password_element = 'pwmenu_password'
        self.quickdic_lock = threading.Lock()
        self.quickdic_pending = []
        self.quickdic_wakeup = threading.Event()
        self.quickdic_running = False
        self.quickdic_thread = None
        self.quickdic_display_status = ''
        self.quickdic_display_until = 0
        self.web_template_lock = threading.Lock()
        self.web_template = None
        self.web_template_environment = None
        self.web_data_cache_lock = threading.RLock()
        self.web_data_cache_revision = 0
        self.web_data_cache_key = None
        self.web_data_cache = None
        self.credential_cache_lock = threading.RLock()
        self.credential_cache_revision = None
        self.credential_cache = None
        self.credential_revision_value = None
        self.credential_revision_checked_at = 0
        self.source_inventory_cache_lock = threading.RLock()
        self.source_inventory_cache = {}
        self.web_resource_lock = threading.RLock()
        self.web_resource_cache = None
        self.web_snapshot_lock = threading.RLock()
        self.web_snapshot_cache = None
        self.web_snapshot_history = {}
        self.web_model_warm_lock = threading.Lock()
        self.web_model_warm_thread = None
        self.backup_lock = threading.Lock()
        self.loaded_at = time.time()

    def _module_enabled(self, name, default=True):
        return self._option_bool(f'module_{name}_enabled', default)

    def _active_agent_config(self, agent):
        if agent is None:
            return {}
        try:
            config_method = getattr(agent, 'config', None)
            config = config_method() if callable(config_method) else None
            if isinstance(config, dict):
                return config
        except (AttributeError, TypeError):
            pass
        config = getattr(agent, '_config', None)
        return config if isinstance(config, dict) else {}

    def _configured_handshake_directory(self, agent):
        config = self._active_agent_config(agent)
        bettercap = config.get('bettercap', {})
        configured = (
            bettercap.get('handshakes')
            if isinstance(bettercap, dict)
            else ''
        )
        raw_path = str(configured or '').strip()
        source = 'bettercap.handshakes'
        if not raw_path:
            raw_path = os.path.join(os.path.expanduser('~'), 'handshakes')
            source = 'user-home compatibility fallback'
        directory = os.path.realpath(
            os.path.abspath(
                os.path.expandvars(os.path.expanduser(raw_path))
            )
        )
        if directory == os.path.abspath(os.sep):
            raise ValueError('Handshake directory cannot be the filesystem root')
        return directory, source

    def _configure_storage_paths(self, agent):
        directory, source = self._configured_handshake_directory(agent)
        os.makedirs(directory, exist_ok=True)
        self.storage_dir = directory
        self.handshake_dirs = [directory]
        self.potfile_ohc = os.path.join(
            directory,
            'onlinehashcrack.cracked.potfile',
        )
        self.potfile_handshake_lab = os.path.join(
            directory,
            'handshake-lab.cracked.potfile',
        )
        self.potfile_manual = os.path.join(directory, 'manual.potfile')
        self.data_file = os.path.join(directory, '.a_pwmenu_data.json')
        self.ohc_export_file = os.path.join(
            directory,
            '.a_pwmenu_ohc_export.json',
        )
        logging.info(
            '[A_pwmenu] Handshake storage from %s: %s',
            source,
            directory,
        )

    def _read_newest_json_object(self, paths):
        candidates = [
            path for path in paths
            if path and os.path.isfile(path)
        ]
        candidates.sort(key=os.path.getmtime, reverse=True)
        for path in candidates:
            try:
                with open(path, 'r', encoding='utf-8') as handle:
                    payload = json.load(handle)
                if isinstance(payload, dict):
                    return payload, path
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
        return None, ''

    def _write_json_object_atomic(self, path, payload):
        directory = os.path.dirname(path)
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix='.a_pwmenu-storage-',
            dir=directory,
        )
        try:
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                fd = None
                json.dump(
                    payload,
                    handle,
                    ensure_ascii=False,
                    sort_keys=True,
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
        finally:
            if fd is not None:
                os.close(fd)
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def _merge_legacy_state_value(
        self,
        configured,
        legacy,
        prefer_legacy=True,
    ):
        if isinstance(configured, dict) and isinstance(legacy, dict):
            merged = copy.deepcopy(configured)
            for key, value in legacy.items():
                if key in merged:
                    merged[key] = self._merge_legacy_state_value(
                        merged[key],
                        value,
                        prefer_legacy=prefer_legacy,
                    )
                else:
                    merged[key] = copy.deepcopy(value)
            return merged
        if isinstance(configured, list) and isinstance(legacy, list):
            older = configured if prefer_legacy else legacy
            newer = legacy if prefer_legacy else configured
            merged = copy.deepcopy(older)
            fingerprints = set()
            for item in merged:
                try:
                    fingerprints.add(json.dumps(item, sort_keys=True))
                except (TypeError, ValueError):
                    fingerprints.add(repr(item))
            for item in newer:
                try:
                    fingerprint = json.dumps(item, sort_keys=True)
                except (TypeError, ValueError):
                    fingerprint = repr(item)
                if fingerprint not in fingerprints:
                    merged.append(copy.deepcopy(item))
                    fingerprints.add(fingerprint)
            return merged
        preferred = legacy if prefer_legacy else configured
        fallback = configured if prefer_legacy else legacy
        if preferred is None or preferred == '':
            return copy.deepcopy(fallback)
        return copy.deepcopy(preferred)

    def _migrate_legacy_state(self, legacy_directory):
        legacy_state, legacy_source = self._read_newest_json_object((
            os.path.join(legacy_directory, '.a_pwmenu_data.json'),
            os.path.join(legacy_directory, '.a_pwmenu_data.json.bak'),
        ))
        if legacy_state is None:
            return False

        configured_state, configured_source = self._read_newest_json_object((
            self.data_file,
            self.data_file + '.bak',
        ))
        if configured_state is None:
            configured_state = {}
        else:
            preservation = self.data_file + '.pre-config-path-migration'
            if configured_source and not os.path.exists(preservation):
                shutil.copy2(configured_source, preservation)

        prefer_legacy = bool(
            legacy_source
            and (
                not configured_source
                or os.path.getmtime(legacy_source)
                >= os.path.getmtime(configured_source)
            )
        )
        merged = self._merge_legacy_state_value(
            configured_state,
            legacy_state,
            prefer_legacy=prefer_legacy,
        )
        needs_write = (
            merged != configured_state
            or not os.path.isfile(self.data_file)
            or not os.path.isfile(self.data_file + '.bak')
        )
        if not needs_write:
            return False
        self._write_json_object_atomic(self.data_file, merged)
        self._write_json_object_atomic(self.data_file + '.bak', merged)
        return True

    def _migrate_legacy_ohc_snapshot(self, legacy_directory):
        source = os.path.join(
            legacy_directory,
            os.path.basename(self.ohc_export_file),
        )
        legacy, _ = self._read_newest_json_object((source,))
        if legacy is None:
            return False
        configured, _ = self._read_newest_json_object(
            (self.ohc_export_file,)
        )
        if configured is None:
            configured = {}

        identities = {
            str(value) for value in (
                list(configured.get('identities', []) or [])
                + list(legacy.get('identities', []) or [])
            )
            if isinstance(value, str) and value
        }
        bssids = {
            str(value).lower() for value in (
                list(configured.get('bssids', []) or [])
                + list(legacy.get('bssids', []) or [])
            )
            if isinstance(value, str) and value
        }
        merged = {
            'version': 1,
            'source': 'configured-path migration',
            'imported_at': max(
                int(configured.get('imported_at', 0) or 0),
                int(legacy.get('imported_at', 0) or 0),
            ),
            'tasks': len(identities),
            'identities': sorted(identities),
            'bssids': sorted(bssids),
        }
        if merged == configured and os.path.isfile(self.ohc_export_file):
            return False
        self._write_json_object_atomic(self.ohc_export_file, merged)
        return True

    def _legacy_storage_directories(self):
        home_directories = {os.path.expanduser('~')}
        try:
            import pwd
            home_directories.update(
                entry.pw_dir for entry in pwd.getpwall()
                if str(entry.pw_dir or '').strip()
            )
        except (ImportError, AttributeError, OSError):
            pass

        marker_names = {
            'onlinehashcrack.cracked.potfile',
            'handshake-lab.cracked.potfile',
            'manual.potfile',
            '.a_pwmenu_data.json',
            '.a_pwmenu_data.json.bak',
            '.a_pwmenu_ohc_export.json',
        }
        directories = []
        for home in home_directories:
            directory = os.path.realpath(
                os.path.join(str(home), 'handshakes')
            )
            if (
                directory == self.storage_dir
                or not os.path.isdir(directory)
            ):
                continue
            try:
                present = set(os.listdir(directory))
            except OSError:
                continue
            if present.intersection(marker_names):
                directories.append(directory)
        return sorted(set(directories))

    def _legacy_migration_marker(self, legacy_directory):
        fingerprint = hashlib.sha256(
            os.path.realpath(legacy_directory).encode('utf-8')
        ).hexdigest()[:16]
        return os.path.join(
            self.storage_dir,
            f'.a_pwmenu_migration_{fingerprint}.json',
        )

    def _migrate_legacy_directory(self, legacy_directory):
        marker = self._legacy_migration_marker(legacy_directory)
        if os.path.isfile(marker):
            return 0
        migrated = 0
        credential_destinations = (
            self.potfile_ohc,
            self.potfile_handshake_lab,
            self.potfile_manual,
        )
        for destination in credential_destinations:
            source = os.path.join(
                legacy_directory,
                os.path.basename(destination),
            )
            if not os.path.isfile(source):
                continue
            source_lines, _ = self._read_pot_lines(source)
            destination_lines, _ = self._read_pot_lines(destination)
            merged, _, _ = self._dedupe_pot_lines(
                destination_lines + source_lines
            )
            if merged != destination_lines:
                self._write_pot_lines(destination, merged)
                migrated += 1

        if self._migrate_legacy_state(legacy_directory):
            migrated += 1
        if self._migrate_legacy_ohc_snapshot(legacy_directory):
            migrated += 1

        self._write_json_object_atomic(marker, {
            'version': 1,
            'completed_at': int(time.time()),
            'source_id': os.path.basename(marker).split('_')[-1][:-5],
            'items_changed': migrated,
        })
        return migrated

    def _migrate_legacy_storage(self):
        migrated = 0
        sources = self._legacy_storage_directories()
        for legacy_directory in sources:
            migrated += self._migrate_legacy_directory(legacy_directory)
        if sources:
            logging.info(
                '[A_pwmenu] Checked %d legacy storage location(s); '
                'migrated %d PWMenu data group(s) into configured '
                'handshake directory',
                len(sources),
                migrated,
            )
        return migrated

    def _initialize_from_agent(self, agent):
        with self.storage_lock:
            if self.storage_ready:
                return True
            try:
                self._configure_storage_paths(agent)
                self._migrate_legacy_storage()
                self._ensure_file(self.potfile_ohc)
                self._ensure_file(self.potfile_handshake_lab)
                self._ensure_file(self.potfile_manual)
                self._normalize_potfile(self.potfile_ohc)
                self._normalize_potfile(self.potfile_handshake_lab)
                self._normalize_potfile(self.potfile_manual)
                self._load_data()
                self._migrate_wpa_sec_state()
                self._repair_whitelist_aliases()
                self.storage_ready = True
                self.ready = True

                if (
                    self._module_enabled('gps')
                    and self._option_bool('pwndroid_ws_enabled', True)
                ):
                    self._start_pwndroid_ws()
                self.quality_scan_running = self._module_enabled('quality')
                if (
                    self.quality_scan_running
                    and self._option_bool('quality_auto_scan', True)
                ):
                    self._start_quality_scan_thread(scan_all=True)
                if (
                    self._module_enabled('ohc')
                    and self._option_bool('ohc_enabled', True)
                    and self._option_bool('ohc_auto_upload', True)
                ):
                    self._ensure_ohc_proxy()
                    reconcile = self._option_bool(
                        'ohc_reconcile_on_start',
                        False,
                    )
                    if reconcile:
                        with self.data_lock:
                            self.data['ohc_reconcile_requested'] = True
                    self._queue_ohc_files(force=reconcile)
                    self._start_ohc_scheduler()
                if self._module_enabled('quickdic'):
                    self._start_quickdic_worker()
                self._record_action(
                    'system',
                    'PWMenu started',
                    (
                        'Plugin modules and background workers are ready; '
                        f'captures: {self.storage_dir}'
                    ),
                    source='Pwnagotchi',
                    dedupe_key='pwmenu-started',
                    dedupe_window=30,
                )
                return True
            except Exception as error:
                self.ready = False
                self.storage_ready = False
                logging.exception(
                    '[A_pwmenu] Could not initialize configured handshake '
                    'storage: %s',
                    error,
                )
                return False

    def on_loaded(self):
        logging.info("[A_pwmenu] Loaded.")
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
        self.options.setdefault('ohc_vless_url', '')
        self.options.setdefault('ohc_vless_flow', 'auto')
        self.options.setdefault('ohc_xray_binary', '/usr/local/bin/xray')
        self.options.setdefault('ohc_proxy_port', 10809)
        self.options.setdefault('import_max_bytes', 2097152)
        self.options.setdefault('archive_memory_limit', 2097152)
        self.options.setdefault('web_gzip_level', 1)
        self.options.setdefault('web_notification_duration_ms', 2600)
        self.options.setdefault('web_inventory_cache_seconds', 30)
        self.options.setdefault('web_credential_cache_seconds', 10)
        self.options.setdefault('web_snapshot_seconds', 5)
        self.options.setdefault('web_background_preload', True)
        self.options.setdefault('web_model_warmup', True)
        self.options.setdefault('web_page_size', 24)
        self.options.setdefault('web_background_batch_size', 12)
        self.options.setdefault('web_background_batch_delay_ms', 120)
        self.options.setdefault('web_foreground_batch_size', 24)
        self.options.setdefault('web_foreground_batch_delay_ms', 50)
        self.options.setdefault('activity_history_max', 200)
        self.options.setdefault('activity_history_hours', 24)
        self.options.setdefault('backup_max_bytes', 2147483648)
        self.options.setdefault('backup_restart_after_restore', True)
        self.options.setdefault('health_memory_warning_mb', 64)
        self.options.setdefault('health_disk_warning_percent', 10)
        self.options.setdefault('health_gps_grace_seconds', 900)
        self.options.setdefault('health_queue_stuck_seconds', 3600)
        self.options.setdefault('hcxpcapngtool_timeout', 90)
        self.options.setdefault('password_verify_timeout', 45)
        self.options.setdefault('wpa_sec_api_url', 'https://wpa-sec.stanev.org')
        self.options.setdefault('wpa_sec_auto_upload', True)
        self.options.setdefault('wpa_sec_download_results', True)
        self.options.setdefault('wpa_sec_sync_interval', 3600)
        self.options.setdefault('ohc_retry_poll_interval', 60)
        self.options.setdefault('ohc_reconcile_on_start', False)
        self.options.setdefault('quality_auto_scan', True)
        self.options.setdefault('quality_scan_delay_ms', 250)
        self.options.setdefault('auto_replace_unusable', True)
        self.options.setdefault('module_web_enabled', True)
        self.options.setdefault('module_gps_enabled', True)
        self.options.setdefault('module_ohc_enabled', True)
        self.options.setdefault('module_wpa_sec_enabled', True)
        self.options.setdefault('module_quality_enabled', True)
        self.options.setdefault('module_whitelist_enabled', True)
        self.options.setdefault('module_time_sync_enabled', True)
        self.options.setdefault('module_display_password_enabled', True)
        self.options.setdefault('module_quickdic_enabled', True)
        self.options.setdefault('display_password_orientation', 'horizontal')
        self.options.setdefault('display_password_max_length', 22)
        self.options.setdefault('display_password_empty_text', 'No cracked passwords')
        self.options.setdefault('display_password_wpa_sec', True)
        self.options.setdefault('display_password_ohc', True)
        self.options.setdefault('display_password_handshake_lab', True)
        self.options.setdefault('display_password_manual', True)
        self.options.setdefault('display_password_quickdic', True)
        self.options.setdefault('display_password_horizontal_x', -1)
        self.options.setdefault('display_password_horizontal_y', -1)
        self.options.setdefault('display_password_vertical_x', -1)
        self.options.setdefault('display_password_vertical_y', -1)
        self.options.setdefault('quickdic_wordlist_folder', '/home/pi/wordlists/')
        self.options.setdefault('quickdic_recursive', False)
        self.options.setdefault('quickdic_timeout', 300)
        self.options.setdefault('quickdic_max_queue', 32)
        self.options.setdefault('quickdic_face', '(·ω·)')
        self.options.setdefault('quickdic_update_display', True)
        self.options.setdefault('quickdic_status_seconds', 12)
        self.options.setdefault('quickdic_status_template', 'Cracked password: {password}')
        self.options.setdefault('quickdic_telegram_enabled', False)
        self.options.setdefault('quickdic_telegram_bot_token', '')
        self.options.setdefault('quickdic_telegram_chat_id', '')
        self.options.setdefault('quickdic_telegram_timeout', 15)

    def on_ui_setup(self, ui):
        with ui._lock:
            if self._module_enabled('gps'):
                ui.add_element(self.gps_indicator_name, LabeledValue(
                    color=BLACK,
                    label='G',
                    value='-',
                    position=(ui.width() / 2 - 38, 0),
                    label_font=fonts.Bold,
                    text_font=fonts.Medium
                ))
            if self._module_enabled('display_password'):
                ui.add_element(self.display_password_element, LabeledValue(
                    color=BLACK,
                    label='',
                    value='',
                    position=self._display_password_position(ui),
                    label_font=fonts.Bold,
                    text_font=getattr(fonts, 'Small', fonts.Medium),
                ))

    def on_ready(self, agent):
        self._agent = agent
        self._initialize_from_agent(agent)
        if not self.ready:
            return
        self._record_action(
            'system',
            'Pwnagotchi ready',
            'Agent and Web UI are available',
            source='Pwnagotchi',
            dedupe_key='pwnagotchi-ready',
            dedupe_window=30,
        )

    def on_ui_update(self, ui):
        if not self.ready:
            return
        if self._module_enabled('gps'):
            try:
                ui.set(self.gps_indicator_name, 'C' if self._fresh_live_gps() else '-')
            except Exception as e:
                logging.debug(f"[A_pwmenu] GPS indicator update failed: {e}")
        if self._module_enabled('display_password'):
            try:
                ui.set(self.display_password_element, self._display_password_text())
            except Exception as e:
                logging.debug(f"[A_pwmenu] Password display update failed: {e}")
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
        elif self.quickdic_display_status and time.time() < self.quickdic_display_until:
            try:
                ui.set('face', str(self.options.get('quickdic_face') or '(·ω·)'))
                ui.set('status', self.quickdic_display_status[:64])
            except Exception as e:
                logging.debug(f"[A_pwmenu] QuickDic display result failed: {e}")
        try:
            interval = int(self.options.get('time_sync_interval', 1800))
        except (TypeError, ValueError):
            interval = 1800

        if self._module_enabled('time_sync') and time.time() - self.last_sync > interval:
            self._start_time_sync_thread()

    def on_unload(self, ui):
        self.ready = False
        self._record_action(
            'system',
            'PWMenu stopped',
            'Plugin unload requested',
            source='Pwnagotchi',
            dedupe_key='pwmenu-stopped',
            dedupe_window=30,
        )
        self.pwndroid_running = False
        self.ohc_scheduler_running = False
        self.quality_scan_running = False
        self.quickdic_running = False
        self.ohc_scheduler_wakeup.set()
        self.quickdic_wakeup.set()
        self._stop_ohc_proxy()
        self.storage_ready = False
        try:
            with ui._lock:
                if self._module_enabled('gps'):
                    ui.remove_element(self.gps_indicator_name)
                if self._module_enabled('display_password'):
                    ui.remove_element(self.display_password_element)
        except Exception:
            pass

    def on_internet_available(self, agent):
        self._agent = agent
        if not self.storage_ready and not self._initialize_from_agent(agent):
            return
        self._record_action(
            'network',
            'Internet connection available',
            'Cloud synchronization can run',
            source='Pwnagotchi',
            dedupe_key='internet-available',
            dedupe_window=1800,
        )
        if (
            self.ready
            and self._module_enabled('ohc')
            and self._option_bool('ohc_enabled', True)
            and self._option_bool('ohc_auto_upload', True)
        ):
            self._queue_ohc_files(force=False)
            self._start_ohc_upload_thread()
        if (
            self.ready
            and self._module_enabled('wpa_sec')
            and self.options.get('wpa_sec_key')
        ):
            queued = 0
            if self._option_bool('wpa_sec_auto_upload', True):
                queued = self._queue_wpa_files(force=False)
            if queued or self._wpa_download_is_due():
                self._start_wpa_sync_thread()

    def on_handshake(self, agent, filename, access_point, client_station):
        self._agent = agent
        if not self.storage_ready and not self._initialize_from_agent(agent):
            return
        self._invalidate_web_data_cache(files=True)
        access_point = access_point or {}
        captured_essid = str(
            access_point.get('hostname')
            or access_point.get('essid')
            or self._essid_from_filename(filename)
            or 'Unknown network'
        )
        captured_bssid = self._format_bssid(
            access_point.get('mac')
            or access_point.get('bssid')
            or ''
        )
        capture_detail = os.path.basename(filename)
        if captured_bssid:
            capture_detail += f' · {captured_bssid}'
        self._record_action(
            'capture',
            f'Handshake captured: {captured_essid}',
            capture_detail,
            source='Pwnagotchi',
        )
        loc = self._fresh_live_gps() if self._module_enabled('gps') else None
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
        if (
            self._module_enabled('ohc')
            and self._option_bool('ohc_enabled', True)
            and self._option_bool('ohc_auto_upload', True)
        ):
            self._queue_ohc_files([os.path.basename(filename)], force=False)
            self._start_ohc_upload_thread()
        if self._module_enabled('quality'):
            self._start_quality_scan_thread([os.path.basename(filename)])
        if self._module_enabled('quickdic'):
            self._queue_quickdic(agent, filename, access_point)
        if (
            self._module_enabled('wpa_sec')
            and self._option_bool('wpa_sec_auto_upload', True)
            and self.options.get('wpa_sec_key')
        ):
            if self._queue_wpa_files(
                [os.path.basename(filename)], force=False
            ):
                self._start_wpa_sync_thread()

    def on_peer_detected(self, agent, peer):
        peer_name = str(
            getattr(peer, 'name', None)
            or getattr(peer, 'identity', None)
            or getattr(peer, 'fingerprint', None)
            or 'Pwnagotchi peer'
        )
        self._record_action(
            'peer',
            f'Peer detected: {peer_name}',
            'Nearby Pwnagotchi announced itself',
            source='Pwnagotchi',
            dedupe_key=f'peer:{peer_name}',
            dedupe_window=3600,
        )

    def on_rebooting(self, agent):
        self._record_action(
            'system',
            'Pwnagotchi reboot requested',
            'The operating system reported a reboot event',
            source='Pwnagotchi',
            dedupe_key='pwnagotchi-rebooting',
            dedupe_window=60,
        )

    def _display_password_position(self, ui):
        if (
            getattr(ui, 'is_waveshare_v2', lambda: False)()
            or getattr(ui, 'is_waveshare_v3', lambda: False)()
            or getattr(ui, 'is_waveshare_v4', lambda: False)()
        ):
            horizontal, vertical = (0, 95), (180, 61)
        elif getattr(ui, 'is_waveshare_v1', lambda: False)():
            horizontal, vertical = (0, 95), (170, 61)
        elif getattr(ui, 'is_waveshare144lcd', lambda: False)():
            horizontal, vertical = (0, 92), (78, 67)
        elif getattr(ui, 'is_inky', lambda: False)():
            horizontal, vertical = (0, 83), (165, 54)
        elif getattr(ui, 'is_waveshare27inch', lambda: False)():
            horizontal, vertical = (0, 153), (216, 122)
        else:
            horizontal, vertical = (0, 91), (180, 61)
        orientation = str(
            self.options.get('display_password_orientation', 'horizontal')
        ).strip().lower()
        default = vertical if orientation == 'vertical' else horizontal
        prefix = 'vertical' if orientation == 'vertical' else 'horizontal'
        x = self._option_int(f'display_password_{prefix}_x', -1)
        y = self._option_int(f'display_password_{prefix}_y', -1)
        return (default[0] if x < 0 else x, default[1] if y < 0 else y)

    def _latest_display_credential(self):
        sources = []
        potfiles = []
        if self._option_bool('display_password_wpa_sec', True):
            potfiles.extend(self._wpa_potfile_paths())
        if self._option_bool('display_password_ohc', True):
            potfiles.append(self.potfile_ohc)
        if self._option_bool('display_password_handshake_lab', True):
            potfiles.append(self.potfile_handshake_lab)
        if self._option_bool('display_password_manual', True):
            potfiles.append(self.potfile_manual)
        for path in dict.fromkeys(potfiles):
            try:
                lines, _ = self._read_pot_lines(path)
                record = next(
                    (
                        parsed for parsed in (
                            self._parse_pot_line(line) for line in reversed(lines)
                        )
                        if parsed and parsed.get('password')
                    ),
                    None,
                )
                if record:
                    sources.append((
                        os.path.getmtime(path),
                        str(record.get('essid') or ''),
                        str(record.get('password') or ''),
                    ))
            except OSError as error:
                logging.debug(f"[A_pwmenu] Password display could not read {path}: {error}")
        if self._option_bool('display_password_quickdic', True):
            for directory in self.handshake_dirs:
                if not os.path.isdir(directory):
                    continue
                for path in glob.glob(os.path.join(directory, '*.pcap.cracked')):
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
                            password = handle.read().strip()
                        if not password:
                            continue
                        essid, _ = self._handshake_identity(
                            os.path.basename(path)[:-len('.cracked')]
                        )
                        sources.append((os.path.getmtime(path), essid, password))
                    except OSError as error:
                        logging.debug(
                            f"[A_pwmenu] Password display could not read {path}: {error}"
                        )
        return max(sources, default=None, key=lambda item: item[0])

    def _display_password_text(self):
        latest = self._latest_display_credential()
        if not latest:
            return str(
                self.options.get('display_password_empty_text')
                or 'No cracked passwords'
            )
        _, essid, password = latest
        max_length = max(8, self._option_int('display_password_max_length', 22))
        text = f"{essid}:{password}"
        if len(text) <= max_length:
            return text
        available = max_length - len(password) - 2
        if available > 0:
            return f"{essid[:available]}.:{password}"
        password_room = max(1, max_length - 4)
        return f"{essid[:1]}.:{password[:password_room]}."

    def _start_quickdic_worker(self):
        if self.quickdic_thread and self.quickdic_thread.is_alive():
            return
        self.quickdic_running = True
        self.quickdic_thread = threading.Thread(
            target=self._quickdic_worker_loop,
            daemon=True,
            name='pwmenu-quickdic',
        )
        self.quickdic_thread.start()

    def _queue_quickdic(self, agent, filename, access_point):
        if not filename or not os.path.isfile(filename):
            return False
        maximum = max(1, self._option_int('quickdic_max_queue', 32))
        with self.quickdic_lock:
            known = {item[1] for item in self.quickdic_pending}
            if filename in known or len(self.quickdic_pending) >= maximum:
                return False
            self.quickdic_pending.append((agent, filename, access_point))
        self.quickdic_wakeup.set()
        return True

    def _quickdic_worker_loop(self):
        while self.quickdic_running:
            with self.quickdic_lock:
                item = self.quickdic_pending.pop(0) if self.quickdic_pending else None
                if not self.quickdic_pending:
                    self.quickdic_wakeup.clear()
            if not item:
                self.quickdic_wakeup.wait(5)
                continue
            try:
                self._run_quickdic(*item)
            except Exception as error:
                logging.error(f"[A_pwmenu] QuickDic worker failed: {error}")

    def _quickdic_access_point_bssid(self, access_point, filename):
        if isinstance(access_point, dict):
            for key in ('bssid', 'BSSID', 'mac', 'MAC'):
                compact = self._compact_bssid(access_point.get(key))
                if compact:
                    return compact
        _, bssid = self._handshake_identity(filename)
        return bssid

    def _quickdic_wordlists(self):
        folder = os.path.realpath(
            str(self.options.get('quickdic_wordlist_folder') or '/home/pi/wordlists/')
        )
        recursive = self._option_bool('quickdic_recursive', False)
        pattern = os.path.join(folder, '**', '*.txt') if recursive else os.path.join(folder, '*.txt')
        return sorted(
            path for path in glob.glob(
                pattern,
                recursive=recursive,
            )
            if os.path.isfile(path)
        )

    def _run_quickdic(self, agent, filename, access_point):
        executable = shutil.which('aircrack-ng')
        if not executable and os.path.isfile('/usr/bin/aircrack-ng'):
            executable = '/usr/bin/aircrack-ng'
        if not executable:
            logging.warning("[A_pwmenu] QuickDic disabled at runtime: aircrack-ng is unavailable")
            return False
        bssid = self._quickdic_access_point_bssid(access_point, filename)
        essid, filename_bssid = self._handshake_identity(filename)
        bssid = bssid or filename_bssid
        if not bssid:
            check = subprocess.run(
                [executable, filename],
                check=False,
                capture_output=True,
                text=True,
                errors='replace',
                timeout=min(60, self._option_int('quickdic_timeout', 300)),
            )
            match = re.search(
                r'((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}).*?\b1\s+handshake\b',
                check.stdout or '',
                re.IGNORECASE,
            )
            bssid = self._compact_bssid(match.group(1)) if match else ''
        if not bssid:
            logging.info(f"[A_pwmenu] QuickDic skipped {os.path.basename(filename)}: no complete handshake")
            return False

        cracked = self._get_cracked_data()
        passwords, exact_essid = self._known_passwords_for_capture(
            cracked, essid, bssid
        )
        if passwords:
            verified, changed = self._verify_capture_passwords(
                filename,
                exact_essid,
                bssid,
                passwords,
                self._credential_source_revision(),
            )
            if changed:
                self._save_data()
            if verified:
                logging.info(
                    f"[A_pwmenu] QuickDic skipped {os.path.basename(filename)}: known password verified"
                )
                return True

        wordlists = self._quickdic_wordlists()
        if not wordlists:
            logging.warning("[A_pwmenu] QuickDic has no .txt wordlists")
            return False
        output_path = filename + '.cracked'
        try:
            os.remove(output_path)
        except FileNotFoundError:
            pass
        result = subprocess.run(
            [
                executable,
                '-w', ','.join(wordlists),
                '-l', output_path,
                '-q',
                '-b', self._colon_bssid(bssid),
                filename,
            ],
            check=False,
            capture_output=True,
            text=True,
            errors='replace',
            timeout=self._option_int('quickdic_timeout', 300),
        )
        output = (result.stdout or '') + '\n' + (result.stderr or '')
        if not re.search(r'\bKEY\s+FOUND!?\s*(?:\[|$)', output, re.IGNORECASE):
            logging.info(f"[A_pwmenu] QuickDic exhausted {os.path.basename(filename)}")
            return False
        try:
            with open(output_path, 'r', encoding='utf-8', errors='ignore') as handle:
                password = handle.read().strip()
        except OSError:
            password = ''
        if not password:
            match = re.search(r'\bKEY\s+FOUND!?\s*\[(.*?)\]', output, re.IGNORECASE)
            password = match.group(1).strip() if match else ''
        if not password:
            logging.warning("[A_pwmenu] QuickDic found a key but could not read it")
            return False

        self._invalidate_web_data_cache(credentials=True, files=True)
        with self.data_lock:
            self.data.setdefault('capture_password_checks', {}).pop(
                os.path.basename(filename), None
            )
        self._save_data()
        template = str(
            self.options.get('quickdic_status_template')
            or 'Cracked password: {password}'
        )
        try:
            status = template.format(essid=exact_essid or essid, password=password)
        except (KeyError, ValueError):
            status = f"Cracked password: {password}"
        if self._option_bool('quickdic_update_display', True):
            self.quickdic_display_status = status
            self.quickdic_display_until = time.time() + max(
                1, self._option_int('quickdic_status_seconds', 12)
            )
            try:
                view = agent.view()
                view.set('face', str(self.options.get('quickdic_face') or '(·ω·)'))
                view.set('status', status[:64])
                view.update(force=True)
            except Exception as error:
                logging.debug(f"[A_pwmenu] QuickDic display update failed: {error}")
        if self._option_bool('quickdic_telegram_enabled', False):
            self._quickdic_send_telegram(exact_essid or essid, password)
        try:
            plugins.on('cracked', access_point, password)
        except Exception as error:
            logging.debug(f"[A_pwmenu] QuickDic cracked event failed: {error}")
        self._record_action(
            'password',
            f'QuickDic recovered: {exact_essid or essid}',
            self._format_bssid(bssid)
            or 'Password verified against the capture',
        )
        logging.info(f"[A_pwmenu] QuickDic recovered {exact_essid or essid}")
        return True

    def _quickdic_send_telegram(self, essid, password):
        token = str(self.options.get('quickdic_telegram_bot_token') or '').strip()
        chat_id = str(self.options.get('quickdic_telegram_chat_id') or '').strip()
        if not token or not chat_id:
            logging.warning("[A_pwmenu] QuickDic Telegram is enabled but credentials are missing")
            return False
        try:
            response = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                data={
                    'chat_id': chat_id,
                    'text': f"Pwnagotchi cracked {essid}: {password}",
                },
                timeout=self._option_int('quickdic_telegram_timeout', 15),
            )
            response.raise_for_status()
            return True
        except requests.RequestException as error:
            logging.warning(f"[A_pwmenu] QuickDic Telegram send failed: {error}")
            return False

    def on_webhook(self, path, request):
        if not self.ready:
            return "Loading..."
        if not self._module_enabled('web'):
            return make_response("PWMenu web module is disabled", 404)
        if path is None:
            path = '/'

        try:
            if request.method == 'GET' and path.startswith('assets/'):
                return self._serve_web_asset(
                    path.replace('assets/', '', 1), request
                )

            if request.method == 'GET' and path.startswith('api/tab/'):
                return self._tab_fragment_response(
                    path.replace('api/tab/', '', 1), request
                )

            if request.method == 'GET' and path == 'api/history':
                return self._activity_history_response(request)

            if (
                request.method == 'GET'
                and path.startswith('api/repair-password-conflict/')
            ):
                return self._password_conflict_repair_status(
                    path.replace(
                        'api/repair-password-conflict/',
                        '',
                        1,
                    )
                )

            if request.method == 'GET' and path.startswith('api/details/'):
                return self._details_fragment_response(
                    request, path.replace('api/details/', '', 1)
                )

            if request.method == 'GET' and path.startswith('api/detail/'):
                detail_path = path.replace('api/detail/', '', 1)
                detail_parts = detail_path.split('/')
                if len(detail_parts) != 2:
                    return self._json_response(
                        {'ok': False, 'message': 'Invalid detail route'},
                        404,
                    )
                return self._detail_fragment_response(
                    request, detail_parts[0], detail_parts[1]
                )

            if request.method == 'POST':
                if path == 'backup-export':
                    return self._serve_backup(request)

                if path == 'backup-restore':
                    ok, message = self._restore_backup(request)
                    if ok:
                        self._record_action(
                            'backup',
                            'PWMenu backup restored',
                            'Settings, state and credential files were restored',
                        )
                    response = self._action_response(
                        request, message, not ok, 'other'
                    )
                    if (
                        ok
                        and self._option_bool(
                            'backup_restart_after_restore', True
                        )
                    ):
                        self._schedule_pwnagotchi_service_restart()
                    return response

                if path == 'repair-password-conflict':
                    ok, payload = self._start_password_conflict_repair(
                        request.form.get('bssid')
                    )
                    return self._json_response(payload, 202 if ok else 409)

                if path == 'delete-password':
                    essid = request.form.get('essid')
                    pwd = request.form.get('password')
                    source = request.form.get('source')
                    bssid = request.form.get('bssid')
                    deleted = self._delete_password(essid, pwd, source, bssid)
                    if deleted:
                        self._record_action(
                            'password',
                            f'Password removed: {essid or "Unknown network"}',
                            self._format_bssid(bssid) or str(source or ''),
                        )
                    message = (
                        "Password deleted"
                        if deleted
                        else "Could not delete password (readonly source?)"
                    )
                    return self._password_action_response(
                        request, deleted, message, essid, bssid, action='delete'
                    )

                if path == 'update-password':
                    ok, message = self._update_password(
                        request.form.get('essid'),
                        request.form.get('password'),
                        request.form.get('bssid'),
                        request.form.get('old_password'),
                    )
                    if ok:
                        self._record_action(
                            'password',
                            'Password updated: '
                            + str(request.form.get('essid') or 'Unknown network'),
                            self._format_bssid(request.form.get('bssid')),
                        )
                    return self._password_action_response(
                        request,
                        ok,
                        message,
                        request.form.get('essid'),
                        request.form.get('bssid'),
                        action='update',
                    )

                if path == 'delete-file':
                    fname = request.form.get('filename')
                    if self._delete_specific_file(fname):
                        self._record_action(
                            'capture',
                            'Handshake deleted',
                            os.path.basename(str(fname or '')),
                        )
                        return self._render_page(notification=f"Deleted {fname}", notif_type="success", active_tab="handshakes")
                    return self._render_page(notification=f"Failed to delete {fname}", notif_type="error", active_tab="handshakes")

                if path == 'clean-captures':
                    deleted, total, message = self._clean_capture_candidates(request.form.get('report_token') or '')
                    if deleted:
                        self._record_action(
                            'cleanup',
                            f'Capture cleanup removed {deleted} file(s)',
                            f'{total} reviewed candidate(s)',
                        )
                    return self._render_page(
                        notification=message or f"Removed {deleted}/{total} unusable capture files",
                        notif_type="success" if deleted == total else "error",
                        active_tab='other'
                    )

                if path == 'whitelist-add':
                    if not self._module_enabled('whitelist'):
                        return self._render_page(notification="Whitelist module is disabled", notif_type="error")
                    name = request.form.get('network') or ''
                    changed, message = self._add_to_whitelist(
                        name,
                        request.form.get('bssid') or '',
                    )
                    requested_tab = request.form.get('return_tab') or 'other'
                    active_tab = requested_tab if requested_tab in ('handshakes', 'map', 'other') else 'other'
                    return self._whitelist_action_response(request, changed, message, active_tab)

                if path == 'whitelist-add-excellent':
                    if not self._module_enabled('whitelist'):
                        return self._whitelist_action_response(
                            request, False, "Whitelist module is disabled", 'map'
                        )
                    try:
                        names = json.loads(request.form.get('networks') or '[]')
                        if not isinstance(names, list):
                            raise ValueError('Network list must be an array')
                        changed, message = self._add_excellent_to_whitelist(names)
                    except (TypeError, ValueError, json.JSONDecodeError) as error:
                        changed, message = False, str(error)
                    return self._whitelist_action_response(request, changed, message, 'map')

                if path == 'whitelist-remove':
                    if not self._module_enabled('whitelist'):
                        return self._whitelist_action_response(
                            request, False, "Whitelist module is disabled", 'other'
                        )
                    changed, message = self._remove_from_whitelist(request.form.get('network') or '')
                    requested_tab = request.form.get('return_tab') or 'other'
                    active_tab = requested_tab if requested_tab in ('handshakes', 'map', 'other') else 'other'
                    return self._whitelist_action_response(request, changed, message, active_tab)

                if path == 'wpa-sec-upload':
                    if not self._module_enabled('wpa_sec'):
                        return self._action_response(
                            request, "WPA-sec module is disabled", True, 'handshakes'
                        )
                    res, is_err = self._handle_wpa_upload(request)
                    return self._action_response(request, res, is_err, 'handshakes')

                if path == 'wpa-sec-upload-cluster':
                    if not self._module_enabled('wpa_sec'):
                        return self._action_response(request, "WPA-sec module is disabled", True, 'map')
                    res, is_err = self._handle_wpa_cluster_upload(request)
                    return self._action_response(request, res, is_err, 'map')

                if path == 'wpa-sec-sync':
                    if not self._module_enabled('wpa_sec'):
                        return self._action_response(
                            request, "WPA-sec module is disabled", True, 'other'
                        )
                    if not self.options.get('wpa_sec_key'):
                        return self._action_response(
                            request, "WPA-sec key is missing", True, 'other'
                        )
                    self.wpa_force_download = True
                    queued = self._queue_wpa_files(force=False)
                    self._start_wpa_sync_thread()
                    self._record_action(
                        'cloud',
                        'WPA-sec synchronization started',
                        f'{queued} new capture(s) queued',
                    )
                    return self._action_response(
                        request,
                        f"WPA-sec sync started; {queued} new capture(s) queued",
                        False,
                        'other',
                    )

                if path == 'ohc-upload-cluster':
                    if not self._module_enabled('ohc'):
                        return self._action_response(request, "OHC module is disabled", True, 'map')
                    res, is_err = self._handle_ohc_cluster_upload(request)
                    return self._action_response(request, res, is_err, 'map')

                if path == 'ohc-upload-all-missing':
                    if not self._module_enabled('ohc'):
                        return self._render_page(notification="OHC module is disabled", notif_type="error")
                    res, is_err = self._handle_ohc_all_missing()
                    if not is_err:
                        self._record_action(
                            'cloud',
                            'OHC synchronization started',
                            res,
                        )
                    return self._render_page(notification=res, notif_type="error" if is_err else "success", active_tab="handshakes")

                if path == 'add-password':
                    essid = request.form.get('essid')
                    bssid = request.form.get('bssid')
                    ok, message = self._add_manual_password(
                        essid, bssid, request.form.get('password')
                    )
                    return self._password_action_response(
                        request, ok, message, essid, bssid, action='add'
                    )

                if path == 'capture-map-set':
                    ok, message, filename = self._set_capture_map_location(
                        request.form.get('filename'),
                        request.form.get('lat'),
                        request.form.get('lon'),
                    )
                    if ok:
                        self._record_action(
                            'map',
                            'Handshake placed on map',
                            filename,
                        )
                    return self._map_point_action_response(
                        request, ok, message, filename
                    )

                if path == 'phone-gps':
                    if not self._module_enabled('gps'):
                        resp = make_response(json.dumps({'ok': False, 'message': 'GPS module disabled'}))
                        resp.headers['Content-Type'] = 'application/json'
                        return resp
                    ok, msg = self._update_phone_gps(request)
                    resp = make_response(json.dumps({'ok': ok, 'message': msg}))
                    resp.headers['Content-Type'] = 'application/json'
                    return resp

                if path == 'sync-time':
                    if not self._module_enabled('time_sync'):
                        return self._render_page(notification="Time sync module is disabled", notif_type="error", active_tab='other')
                    if self._sync_time_now():
                        self._record_action(
                            'system',
                            'System time synchronized',
                            'Google connectivity time was applied',
                            source='Pwnagotchi',
                        )
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
                        report = self._process_import(payload.decode('utf-8', errors='ignore'), f.filename)
                        message = (
                            f"Import: {report['added']} added, {report['already']} already present, "
                            f"{report['duplicates']} duplicate rows, {report['ignored']} ignored"
                        )
                        if report['invalid']:
                            message += f", {report['invalid']} invalid"
                        if report.get('source'):
                            message += f", source {report['source']}"
                        if report.get('ohc_tasks'):
                            message += f", OHC snapshot {report['ohc_tasks']} task(s)"
                        self._record_action(
                            'import',
                            'Password data imported',
                            message,
                        )
                        return self._render_page(notification=message, notif_type="success", active_tab='other')
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
        snapshot = self._page_snapshot()
        tok = generate_csrf() if generate_csrf else ""
        tab_name = (
            active_tab
            if active_tab in ('cracked', 'handshakes', 'map', 'other')
            else 'cracked'
        )
        notification_html = ''
        if notification:
            css_class = ' err' if notif_type == 'error' else ''
            notification_html = (
                f'<div id="nt" class="notif{css_class}"><b>'
                f'{html.escape(str(notification))}</b></div>'
            )
        page = (
            snapshot['shell']
            .replace('__PWMENU_CSRF__', tok)
            .replace('__PWMENU_TAB__', tab_name)
            .replace('<!-- PWMENU_NOTIFICATION -->', notification_html)
        )
        return self._html_response(page)

    def _invalidate_web_data_cache(self, credentials=False, files=False):
        """Discard derived Web UI data after files or persistent state change."""
        with self.web_data_cache_lock:
            self.web_data_cache_revision += 1
            self.web_data_cache_key = None
            self.web_data_cache = None
        with self.web_snapshot_lock:
            if self.web_snapshot_cache:
                snapshot_id = str(
                    self.web_snapshot_cache.get('id') or ''
                )
                if snapshot_id:
                    self.web_snapshot_history[snapshot_id] = (
                        self.web_snapshot_cache
                    )
                newest = sorted(
                    self.web_snapshot_history.values(),
                    key=lambda item: float(item.get('created_at', 0)),
                    reverse=True,
                )[:4]
                self.web_snapshot_history = {
                    item['id']: item for item in newest
                }
            self.web_snapshot_cache = None
        if credentials:
            with self.credential_cache_lock:
                self.credential_cache_revision = None
                self.credential_cache = None
                self.credential_revision_value = None
                self.credential_revision_checked_at = 0
        if files:
            with self.source_inventory_cache_lock:
                self.source_inventory_cache.clear()
        if (
            self.ready
            and self._option_bool('web_model_warmup', True)
            and self._module_enabled('web')
        ):
            self._schedule_web_model_warmup()

    def _schedule_web_model_warmup(self):
        """Debounce changes and rebuild the expensive model off the HTTP path."""
        with self.web_model_warm_lock:
            if (
                self.web_model_warm_thread
                and self.web_model_warm_thread.is_alive()
            ):
                return

            def worker():
                try:
                    time.sleep(0.35)
                    observed = -1
                    for _ in range(3):
                        with self.web_data_cache_lock:
                            revision = self.web_data_cache_revision
                        if revision == observed:
                            break
                        observed = revision
                        self._web_page_model()
                        time.sleep(0.1)
                except Exception as error:
                    logging.debug(
                        f"[A_pwmenu] Web model warmup failed: {error}"
                    )
                finally:
                    with self.web_model_warm_lock:
                        self.web_model_warm_thread = None

            self.web_model_warm_thread = threading.Thread(
                target=worker,
                daemon=True,
                name='pwmenu-web-model-warmup',
            )
            self.web_model_warm_thread.start()

    def _web_page_model(self):
        """Build expensive, stable page data once and reuse it until inputs change."""
        with self.web_data_cache_lock:
            capture_revision = self._capture_source_revision()
            credential_revision = self._credential_source_revision()
            cache_key = (
                capture_revision,
                credential_revision,
                self.web_data_cache_revision,
            )
            if (
                self.web_data_cache is not None
                and self.web_data_cache_key == cache_key
            ):
                return self.web_data_cache

            cracked = self._get_cracked_data(credential_revision)
            groups = self._scan_and_group_files(cracked)
            map_points = self._build_map_points(groups)
            no_gps_networks = self._build_no_gps_networks(groups)
            conflicts = self._build_conflicts(groups, cracked)
            activity_history = self._activity_history_page()
            pot_health = self._potfile_health(self.potfile_ohc)
            cleanup_report = self._capture_cleanup_report(groups)
            for group in groups:
                for file_info in group.get('files', []):
                    file_info.pop('_path', None)
                    file_info.pop('_signature', None)
            achievements = self._update_achievements(groups, cracked)

            total_networks = len(groups)
            cracked_networks = sum(
                1 for group in groups if group['is_cracked']
            )
            percent = (
                int(cracked_networks / total_networks * 100)
                if total_networks else 0
            )
            stats = {
                'cracked': cracked_networks,
                'total': total_networks,
                'percent': percent,
                'files': sum(len(group['files']) for group in groups),
                'level': achievements['level'],
                'xp': achievements['xp'],
                'next_xp': achievements['next_xp'],
                'rank': achievements['rank'],
                'lvl_percent': achievements['lvl_percent'],
                'gps_points': len(map_points),
                'cracked_gps': sum(
                    1 for point in map_points if point['is_cracked']
                ),
                'no_gps': sum(
                    1 for group in groups
                    if group.get('lat') is None or group.get('lon') is None
                ),
            }
            model = {
                'cracked': cracked,
                'groups': groups,
                'map_points': map_points,
                'no_gps_networks': no_gps_networks,
                'pot_health': pot_health,
                'cleanup_report': cleanup_report,
                'conflicts': conflicts,
                'activity_history': activity_history,
                'achievements': achievements,
                'stats': stats,
            }

            # A first scan can discover a sidecar/location or award XP and save
            # state. Keep the source fingerprints from the start (so a file
            # changed during the build forces one safe retry), but cache against
            # the resulting in-memory generation.
            self.web_data_cache_key = (
                capture_revision,
                credential_revision,
                self.web_data_cache_revision,
            )
            self.web_data_cache = model
            return model

    def _snapshot_sections(self, rendered):
        details = {'cracked': {}, 'handshake': {}}
        paged_tabs = {}
        detail_pattern = re.compile(
            r'<!-- PWMENU_DETAIL_(CRACKED|HANDSHAKE)_(\d+)_START -->'
            r'(?P<body>.*?)'
            r'<!-- PWMENU_DETAIL_\1_\2_END -->',
            re.DOTALL,
        )

        def remove_detail(match):
            kind = match.group(1).lower()
            details[kind][match.group(2)] = match.group('body').strip()
            return ''

        without_details = detail_pattern.sub(remove_detail, rendered)
        fragments = {}
        shell = without_details
        skeleton = (
            '<div class="pwmenu-tab-skeleton" aria-busy="true">'
            '<i></i><i></i><i></i></div>'
        )
        map_skeleton = (
            '<div class="pwmenu-map-loading" aria-busy="true">'
            '<div class="pwmenu-map-loading-core"><i></i></div>'
            '<b>Loading map...</b>'
            '<span>Preparing locations and map tiles</span>'
            '</div>'
        )
        for tab_name in ('cracked', 'handshakes', 'map', 'other'):
            upper = tab_name.upper()
            pattern = re.compile(
                rf'<!-- PWMENU_TAB_{upper}_START -->'
                rf'(?P<body>.*?)'
                rf'<!-- PWMENU_TAB_{upper}_END -->',
                re.DOTALL,
            )
            match = pattern.search(shell)
            if not match:
                raise RuntimeError(
                    f'PWMenu {tab_name} snapshot marker was not found'
                )
            fragments[tab_name] = match.group('body').strip()
            if tab_name in ('cracked', 'handshakes'):
                card_pattern = re.compile(
                    rf'<!-- PWMENU_CARD_{upper}_(\d+)_START -->'
                    rf'(?P<body>.*?)'
                    rf'<!-- PWMENU_CARD_{upper}_\1_END -->',
                    re.DOTALL,
                )
                cards = []
                for card_match in card_pattern.finditer(
                    fragments[tab_name]
                ):
                    card_html = card_match.group('body').strip()
                    search_match = re.search(
                        r'\bdata-t="([^"]*)"', card_html,
                        re.IGNORECASE,
                    )
                    search_text = html.unescape(
                        search_match.group(1) if search_match else ''
                    )
                    cards.append({
                        'id': card_match.group(1),
                        'html': card_html,
                        'search': search_text.casefold(),
                    })
                paged_tabs[tab_name] = {
                    'cards': cards,
                    'tail': card_pattern.sub(
                        '', fragments[tab_name]
                    ).strip(),
                }
            shell = pattern.sub(
                map_skeleton if tab_name == 'map' else skeleton,
                shell,
                count=1,
            )
        return shell, fragments, details, paged_tabs

    def _page_snapshot(self):
        """Render one full snapshot, then serve a thin shell and lazy fragments."""
        model = self._web_page_model()
        whitelist = (
            self._get_whitelist()
            if self._module_enabled('whitelist') else []
        )
        show_wpa = bool(
            self._module_enabled('wpa_sec')
            and self.options.get('wpa_sec_key')
        )
        with self.web_data_cache_lock:
            model_key = self.web_data_cache_key
        snapshot_key = (
            model_key,
            show_wpa,
            tuple(whitelist),
        )
        now = time.monotonic()
        maximum_age = max(
            0,
            self._option_int('web_snapshot_seconds', 5),
        )
        with self.web_snapshot_lock:
            cached = self.web_snapshot_cache
            if (
                cached
                and cached['key'] == snapshot_key
                and maximum_age
                and now - cached['created_at'] <= maximum_age
            ):
                return cached

            gps_status = self._gps_status()
            ohc_status = self._ohc_status()
            wpa_status = self._wpa_status()
            health_issues = self._health_issues(
                gps_status, ohc_status, wpa_status
            )
            snapshot_id = hashlib.sha256(
                repr(snapshot_key).encode('utf-8')
            ).hexdigest()[:20]
            notification_duration_ms = max(
                250,
                min(
                    self._option_int(
                        'web_notification_duration_ms', 2600
                    ),
                    60000,
                ),
            )
            rendered = self._render_cached_template(
                groups=model['groups'],
                cracked=model['cracked'],
                notif=None,
                ntype=None,
                tab='__PWMENU_TAB__',
                stats=model['stats'],
                ach=model['achievements']['badges'],
                token='__PWMENU_CSRF__',
                show_wpa=show_wpa,
                map_points=[],
                gps_status=gps_status,
                no_gps_networks=[],
                ohc_status=ohc_status,
                wpa_status=wpa_status,
                pot_health=model['pot_health'],
                cleanup_report=model['cleanup_report'],
                conflicts=model['conflicts'],
                activity_history=model['activity_history'],
                whitelist=whitelist,
                notification_duration_ms=notification_duration_ms,
                snapshot_id=snapshot_id,
                web_background_preload=self._option_bool(
                    'web_background_preload', True
                ),
                web_background_batch_size=max(
                    2,
                    min(
                        self._option_int(
                            'web_background_batch_size', 12
                        ),
                        24,
                    ),
                ),
                web_background_batch_delay_ms=max(
                    50,
                    min(
                        self._option_int(
                            'web_background_batch_delay_ms', 120
                        ),
                        5000,
                    ),
                ),
                web_foreground_batch_size=max(
                    2,
                    min(
                        self._option_int(
                            'web_foreground_batch_size', 24
                        ),
                        100,
                    ),
                ),
                web_foreground_batch_delay_ms=max(
                    25,
                    min(
                        self._option_int(
                            'web_foreground_batch_delay_ms', 50
                        ),
                        5000,
                    ),
                ),
                health_issues=health_issues,
                ui_revision=self.__ui_revision__,
            )
            shell, fragments, details, paged_tabs = (
                self._snapshot_sections(rendered)
            )
            snapshot = {
                'key': snapshot_key,
                'id': snapshot_id,
                'created_at': now,
                'shell': shell,
                'fragments': fragments,
                'details': details,
                'paged_tabs': paged_tabs,
                'map_points': model['map_points'],
                'no_gps_networks': model['no_gps_networks'],
                'gps_status': gps_status,
                'health_issues': health_issues,
            }
            previous = self.web_snapshot_cache
            if previous and previous.get('id') != snapshot_id:
                self.web_snapshot_history[previous['id']] = previous
            newest = sorted(
                self.web_snapshot_history.values(),
                key=lambda item: float(item.get('created_at', 0)),
                reverse=True,
            )[:4]
            self.web_snapshot_history = {
                item['id']: item for item in newest
            }
            self.web_snapshot_cache = snapshot
            return snapshot

    def _snapshot_for_request(self, request=None):
        requested = ''
        if request is not None:
            requested = str(
                request.args.get('snapshot') or ''
            ).strip()
        if requested:
            with self.web_snapshot_lock:
                current = self.web_snapshot_cache
                if current and current.get('id') == requested:
                    return current
                historical = self.web_snapshot_history.get(requested)
                if historical:
                    return historical
        return self._page_snapshot()

    def _json_response(self, payload, status=200):
        body = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(',', ':'),
        ).encode('utf-8')
        response = make_response(body, status)
        response.headers['Content-Type'] = (
            'application/json; charset=utf-8'
        )
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Vary'] = 'Accept-Encoding'
        accepts_gzip = (
            has_request_context()
            and flask_request.accept_encodings['gzip'] > 0
        )
        if accepts_gzip and len(body) >= 1024:
            compressed = gzip.compress(body, compresslevel=1)
            if len(compressed) < len(body):
                response.set_data(compressed)
                response.headers['Content-Encoding'] = 'gzip'
                response.headers['Content-Length'] = str(len(compressed))
        return response

    def _tab_fragment_response(self, tab_name, request=None):
        if tab_name not in ('cracked', 'handshakes', 'map', 'other'):
            return self._json_response(
                {'ok': False, 'message': 'Unknown tab'}, 404
            )
        snapshot = self._snapshot_for_request(request)
        token = generate_csrf() if generate_csrf else ''
        fragment = snapshot['fragments'][tab_name]
        page_number = 1
        page_size = max(
            2,
            min(self._option_int('web_page_size', 24), 100),
        )
        total = 0
        has_more = False
        detail_ids = []
        query = ''
        start = 0
        if tab_name in snapshot.get('paged_tabs', {}):
            if request is not None:
                try:
                    page_number = max(
                        1, int(request.args.get('page') or 1)
                    )
                except (TypeError, ValueError):
                    page_number = 1
                try:
                    requested_size = int(
                        request.args.get('limit') or page_size
                    )
                    page_size = max(2, min(requested_size, 100))
                except (TypeError, ValueError):
                    pass
                query = str(request.args.get('q') or '').strip()[:128]
            paged = snapshot['paged_tabs'][tab_name]
            cards = paged['cards']
            if query:
                query_key = query.casefold()
                cards = [
                    card for card in cards
                    if query_key in card['search']
                ]
            total = len(cards)
            if (
                request is not None
                and request.args.get('offset') is not None
            ):
                try:
                    start = max(
                        0, int(request.args.get('offset') or 0)
                    )
                except (TypeError, ValueError):
                    start = 0
                page_number = start // page_size + 1
            else:
                start = (page_number - 1) * page_size
            selected = cards[start:start + page_size]
            detail_ids = [card['id'] for card in selected]
            has_more = start + len(selected) < total
            fragment = ''.join(card['html'] for card in selected)
            if not has_more:
                if not selected and query:
                    fragment += (
                        '<div class="pwmenu-page-empty">'
                        'No matching networks.</div>'
                    )
                fragment += paged['tail']
        payload = {
            'ok': True,
            'tab': tab_name,
            'snapshotId': snapshot['id'],
            'html': fragment.replace(
                '__PWMENU_CSRF__', token
            ),
            'page': page_number,
            'pageSize': page_size,
            'total': total,
            'hasMore': has_more,
            'nextPage': page_number + 1 if has_more else None,
            'offset': start,
            'nextOffset': start + len(detail_ids),
            'detailIds': detail_ids,
            'query': query,
        }
        if tab_name == 'map':
            payload.update({
                'mapPoints': snapshot['map_points'],
                'noGpsNetworks': snapshot['no_gps_networks'],
                'gpsStatus': snapshot['gps_status'],
            })
        return self._json_response(payload)

    def _detail_fragment_response(
        self, request, detail_kind, detail_id
    ):
        if detail_kind not in ('cracked', 'handshake'):
            return self._json_response(
                {'ok': False, 'message': 'Unknown detail type'}, 404
            )
        if not re.fullmatch(r'\d{1,6}', str(detail_id or '')):
            return self._json_response(
                {'ok': False, 'message': 'Invalid detail id'}, 400
            )
        snapshot = self._snapshot_for_request(request)
        requested_snapshot = str(
            request.args.get('snapshot') or ''
        )
        if (
            requested_snapshot
            and requested_snapshot != snapshot['id']
        ):
            return self._json_response({
                'ok': False,
                'reload': True,
                'snapshotId': snapshot['id'],
                'message': 'Capture data changed; refreshing the tab',
            }, 409)
        fragment = snapshot['details'].get(
            detail_kind, {}
        ).get(str(detail_id))
        if fragment is None:
            return self._json_response(
                {'ok': False, 'message': 'Detail was not found'}, 404
            )
        token = generate_csrf() if generate_csrf else ''
        return self._json_response({
            'ok': True,
            'snapshotId': snapshot['id'],
            'html': fragment.replace('__PWMENU_CSRF__', token),
        })

    def _details_fragment_response(self, request, tab_name):
        detail_kind = {
            'cracked': 'cracked',
            'handshakes': 'handshake',
        }.get(str(tab_name or ''))
        if not detail_kind:
            return self._json_response(
                {'ok': False, 'message': 'This tab has no card details'},
                404,
            )
        snapshot = self._snapshot_for_request(request)
        requested_snapshot = str(request.args.get('snapshot') or '')
        if requested_snapshot and requested_snapshot != snapshot['id']:
            return self._json_response({
                'ok': False,
                'reload': True,
                'snapshotId': snapshot['id'],
                'message': 'Capture data changed; refreshing the tab',
            }, 409)
        token = generate_csrf() if generate_csrf else ''
        available = snapshot['details'].get(detail_kind, {})
        requested_ids = []
        for raw_id in str(request.args.get('ids') or '').split(','):
            value = raw_id.strip()
            if re.fullmatch(r'\d{1,6}', value):
                requested_ids.append(value)
            if len(requested_ids) >= 100:
                break
        selected_ids = (
            list(dict.fromkeys(requested_ids))
            if requested_ids else list(available)
        )
        details = {
            detail_id: available[detail_id].replace(
                '__PWMENU_CSRF__', token
            )
            for detail_id in selected_ids
            if detail_id in available
        }
        return self._json_response({
            'ok': True,
            'tab': tab_name,
            'kind': detail_kind,
            'snapshotId': snapshot['id'],
            'details': details,
        })

    def _render_cached_template(self, **context):
        """Compile the large Jinja template once per Flask environment."""
        app = current_app._get_current_object()
        app.update_template_context(context)
        environment = app.jinja_env
        with self.web_template_lock:
            if (
                self.web_template is None
                or self.web_template_environment is not environment
            ):
                self.web_template = environment.from_string(
                    self._web_resources()['page']
                )
                self.web_template_environment = environment
            template = self.web_template
        return template.render(context)

    def _html_response(self, html):
        """Return the UI efficiently, especially over low-bandwidth Bluetooth PAN."""
        body = html.encode('utf-8') if isinstance(html, str) else bytes(html)
        r = make_response(body)
        r.headers["Content-Type"] = "text/html; charset=utf-8"
        r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        r.headers["Pragma"] = "no-cache"
        r.headers["Expires"] = "0"
        r.headers["X-PWMenu-UI-Revision"] = self.__ui_revision__
        r.headers["Vary"] = "Accept-Encoding"
        if (
            has_request_context()
            and flask_request.cookies.get('pwmenu_ui_revision')
            != self.__ui_revision__
        ):
            r.headers['Clear-Site-Data'] = '"cache"'
            r.set_cookie(
                'pwmenu_ui_revision',
                self.__ui_revision__,
                max_age=31536000,
                httponly=True,
                samesite='Lax',
                path='/plugins/A_pwmenu/',
            )

        accepts_gzip = (
            has_request_context()
            and flask_request.accept_encodings['gzip'] > 0
        )
        if accepts_gzip and len(body) >= 1024:
            gzip_level = max(
                1,
                min(self._option_int('web_gzip_level', 1), 9),
            )
            compressed = gzip.compress(body, compresslevel=gzip_level)
            if len(compressed) < len(body):
                r.set_data(compressed)
                r.headers["Content-Encoding"] = "gzip"
                r.headers["Content-Length"] = str(len(compressed))
        return r

    def _critical_web_css(self):
        return """
        :root{--bg:#050607;--text:#f3f6f7;--sub:#899095;--accent:#20e4f4}
        *{box-sizing:border-box}
        html,body{min-height:100%;margin:0;background:var(--bg);color:var(--text)}
        body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
        .pwmenu-shell-loading{min-height:100vh;padding:18px;display:grid;place-items:center}
        .pwmenu-shell-loading i{width:34px;height:34px;border:3px solid rgba(255,255,255,.12);border-top-color:var(--accent);border-radius:50%;animation:pwboot .75s linear infinite}
        .pwmenu-tab-skeleton{display:grid;gap:10px;padding:8px 0}
        .pwmenu-tab-skeleton i{display:block;height:86px;border-radius:18px;background:linear-gradient(90deg,#111518,#1b2225,#111518);background-size:200% 100%;animation:pwshimmer 1.1s linear infinite}
        .pwmenu-map-loading{min-height:min(72vh,720px);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;border:1px solid rgba(255,255,255,.08);border-radius:24px;background:radial-gradient(circle at center,rgba(32,228,244,.08),transparent 30%),linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px),#090c0e;background-size:auto,34px 34px,34px 34px;color:var(--text);text-align:center}
        .pwmenu-map-loading-core{width:58px;height:58px;margin-bottom:8px;display:grid;place-items:center;border:1px solid rgba(32,228,244,.28);border-radius:50%;box-shadow:0 0 28px rgba(32,228,244,.12)}
        .pwmenu-map-loading-core i{width:18px;height:18px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 0 rgba(32,228,244,.45);animation:pwmapload 1.35s ease-out infinite}
        .pwmenu-map-loading b{font-size:15px;letter-spacing:.02em}
        .pwmenu-map-loading span{font-size:12px;color:var(--sub)}
        .pwmenu-load-error{margin:18px 0;padding:22px;border:1px solid rgba(255,255,255,.1);border-radius:18px;background:#0e1214;text-align:center}
        .pwmenu-load-error b{display:block;margin-bottom:12px}
        .pwmenu-load-error button{border:0;border-radius:12px;padding:9px 16px;background:var(--accent);font-weight:800}
        .pwmenu-detail-loading{padding:18px;color:var(--sub);text-align:center}
        .pwmenu-page-more{grid-column:1/-1;display:flex;justify-content:center;padding:14px 0 4px}
        .pwmenu-page-more button{min-width:170px;padding:11px 18px;border:1px solid rgba(32,228,244,.28);border-radius:14px;background:#0d1315;color:var(--text);font:inherit;cursor:pointer}
        .pwmenu-page-more button b,.pwmenu-page-more button span{display:block}
        .pwmenu-page-more button span{margin-top:2px;color:var(--sub);font-size:11px}
        .pwmenu-page-more.loading{opacity:.55;pointer-events:none}
        .pwmenu-card-placeholder{min-height:92px!important;display:flex;flex-direction:column;justify-content:center;gap:10px;padding:20px!important;pointer-events:none;background:linear-gradient(110deg,rgba(255,255,255,.025) 20%,rgba(255,255,255,.065) 36%,rgba(255,255,255,.025) 52%)!important;background-size:240% 100%!important;animation:pwplaceholder 1.6s ease-in-out infinite}
        .pwmenu-card-placeholder-line{width:44%;height:9px;border-radius:999px;background:rgba(255,255,255,.075)}
        .pwmenu-card-placeholder-line.wide{width:68%;height:13px}
        .pwmenu-card-placeholder.stale{animation:none;opacity:.4}
        .pwmenu-card-arrival{animation:pwcardarrival .42s ease-out both}
        @keyframes pwplaceholder{0%{background-position:120% 0}100%{background-position:-120% 0}}
        @keyframes pwcardarrival{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:none}}
        .pwmenu-page-empty{grid-column:1/-1;padding:38px 14px;color:var(--sub);text-align:center}
        .backup-actions{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-top:13px}
        .backup-actions .btn{margin:0}
        .backup-restore-button{background:#20262a!important}
        .backup-warning{margin-top:10px;padding:9px 10px;border:1px solid rgba(255,159,10,.28);border-radius:11px;background:rgba(255,159,10,.07);color:#d8b47a;font-size:11px;line-height:1.4}
        .health-panel{margin:0 0 14px;border:1px solid rgba(255,159,10,.38);border-radius:16px;background:rgba(255,159,10,.07);overflow:hidden}
        .health-panel summary{display:flex;align-items:center;justify-content:space-between;padding:12px 14px;cursor:pointer;list-style:none}
        .health-panel summary::-webkit-details-marker{display:none}
        .health-panel summary span{display:flex;align-items:center;gap:9px}
        .health-panel summary span>i{width:8px;height:8px;border-radius:50%;background:#ff9f0a;box-shadow:0 0 14px rgba(255,159,10,.55)}
        .health-panel summary strong{min-width:25px;padding:3px 7px;border-radius:999px;background:#ff9f0a;color:#111;text-align:center;font-size:11px}
        .health-issue-list{padding:0 8px 8px}
        .health-issue{width:100%;display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px;border:0;border-top:1px solid rgba(255,255,255,.07);background:transparent;color:var(--text);text-align:left;cursor:pointer}
        .health-issue span,.health-issue b,.health-issue small{display:block}
        .health-issue small{margin-top:3px;color:var(--sub);font-size:11px}
        .health-issue>i{color:#ff9f0a;font-size:22px;font-style:normal}
        @media(max-width:520px){.backup-actions{grid-template-columns:1fr}}
        @keyframes pwboot{to{transform:rotate(360deg)}}
        @keyframes pwshimmer{to{background-position:-200% 0}}
        @keyframes pwmapload{70%,100%{box-shadow:0 0 0 22px rgba(32,228,244,0)}}
        """

    def _replace_web_svgs(self, source, symbols):
        asset_url = (
            '/plugins/A_pwmenu/assets/icons.svg'
            '?h=__PWMENU_ICON_REV__'
        )
        pattern = re.compile(
            r'<svg(?P<attrs>[^>]*)>(?P<body>.*?)</svg>',
            re.DOTALL | re.IGNORECASE,
        )

        def replace(match):
            attrs = match.group('attrs')
            body = match.group('body')
            viewbox_match = re.search(
                r'\bviewBox\s*=\s*["\']([^"\']+)["\']',
                attrs,
                re.IGNORECASE,
            )
            if not viewbox_match:
                return match.group(0)
            viewbox = viewbox_match.group(1)
            digest = hashlib.sha256(
                (viewbox + '\0' + body).encode('utf-8')
            ).hexdigest()[:12]
            symbol_id = f'pw-{digest}'
            symbols.setdefault(
                symbol_id,
                f'<symbol id="{symbol_id}" viewBox="{viewbox}">'
                f'{body}</symbol>',
            )
            return (
                f'<svg{attrs}><use href="{asset_url}#{symbol_id}">'
                '</use></svg>'
            )

        return pattern.sub(replace, source)

    def _web_resources(self):
        """Split the single-file UI into immutable browser-cached resources."""
        with self.web_resource_lock:
            if self.web_resource_cache is not None:
                return self.web_resource_cache

            page = self._get_html()
            style_match = re.search(
                r'<style>(?P<body>.*?)</style>',
                page,
                re.DOTALL | re.IGNORECASE,
            )
            scripts = list(re.finditer(
                r'<script>(?P<body>.*?)</script>',
                page,
                re.DOTALL | re.IGNORECASE,
            ))
            if not style_match or not scripts:
                # Keep lightweight template overrides usable for diagnostics
                # and downstream integrations which deliberately replace the
                # bundled UI with a minimal Jinja page.
                self.web_resource_cache = {
                    'page': page,
                    'app.css': '',
                    'app.js': '',
                    'icons.svg': '',
                    'encoded': {},
                }
                return self.web_resource_cache

            css = style_match.group('body').strip()
            script_match = scripts[-1]
            javascript = script_match.group('body').strip()
            dynamic_lines = """const csrfToken = '{{ token }}';
        const wpaEnabled = {{ 'true' if show_wpa else 'false' }};
        let mapPoints = {{ map_points|tojson }};
        let noGpsNetworks = {{ no_gps_networks|tojson }};
        const gpsStatus = {{ gps_status|tojson }};
        const whitelistedNetworks = new Set({{ whitelist|tojson }});
        const notificationDurationMs = {{ notification_duration_ms }};
        const backgroundBatchSize = {{ web_background_batch_size|default(12) }};
        const backgroundBatchDelayMs = {{ web_background_batch_delay_ms|default(120) }};
        const foregroundBatchSize = {{ web_foreground_batch_size|default(24) }};
        const foregroundBatchDelayMs = {{ web_foreground_batch_delay_ms|default(50) }};"""
            static_lines = """const bootstrap = window.PWMenuBootstrap || {};
        const csrfToken = String(bootstrap.csrfToken || '');
        const wpaEnabled = !!bootstrap.wpaEnabled;
        let mapPoints = Array.isArray(bootstrap.mapPoints) ? bootstrap.mapPoints : [];
        let noGpsNetworks = Array.isArray(bootstrap.noGpsNetworks) ? bootstrap.noGpsNetworks : [];
        let gpsStatus = bootstrap.gpsStatus || {};
        const whitelistedNetworks = new Set(bootstrap.whitelist || []);
        const notificationDurationMs = Number(bootstrap.notificationDurationMs || 2600);
        const backgroundBatchSize = Math.max(2, Number(bootstrap.backgroundBatchSize || 12));
        const backgroundBatchDelayMs = Math.max(50, Number(bootstrap.backgroundBatchDelayMs || 120));
        const foregroundBatchSize = Math.max(backgroundBatchSize, Number(bootstrap.foregroundBatchSize || 24));
        const foregroundBatchDelayMs = Math.max(25, Number(bootstrap.foregroundBatchDelayMs || 50));
        let currentSnapshotId = String(bootstrap.snapshotId || '');
        const loadedTabs = new Set();
        const loadingTabs = new Map();
        const tabPageState = new Map();
        const tabBackfillTasks = new Map();
        const tabRequestGeneration = new Map();
        const detailHtmlCache = new Map();
        const loadingDetailBatches = new Map();
        let tabSearchTimer = null;"""
            if dynamic_lines not in javascript:
                raise RuntimeError('PWMenu dynamic JavaScript block was not found')
            javascript = javascript.replace(
                dynamic_lines, static_lines, 1
            )
            javascript = javascript.replace(
                "        const t0 = '{{ tab }}';",
                "        const t0 = String(bootstrap.tab || 'cracked');",
                1,
            )
            javascript = javascript.replace(
                """        initAccentPicker();
        tab(t0);
        startPhoneGps(false);
        updateGpsStatusDot();
        renderMap();""",
                """        initAccentPicker();
        tab(t0);
        startPhoneGps(false);
        updateGpsStatusDot();
        scheduleBackgroundPreload();""",
                1,
            )

            css_url = (
                '/plugins/A_pwmenu/assets/app.css'
                '?h=__PWMENU_CSS_REV__'
            )
            resource_links = (
                '<style>' + self._critical_web_css() + '</style>'
                f'<link rel="preload" href="{css_url}" as="style" '
                'onload="this.onload=null;this.rel=\'stylesheet\'">'
                f'<noscript><link rel="stylesheet" href="{css_url}">'
                '</noscript>'
            )
            page = (
                page[:style_match.start()]
                + resource_links
                + page[style_match.end():script_match.start()]
                + """
    <script>
        window.PWMenuBootstrap = {
            csrfToken: {{ token|tojson }},
            wpaEnabled: {{ 'true' if show_wpa else 'false' }},
            mapPoints: [],
            noGpsNetworks: [],
            gpsStatus: {{ gps_status|tojson }},
            whitelist: {{ whitelist|tojson }},
            notificationDurationMs: {{ notification_duration_ms }},
            tab: {{ tab|tojson }},
            snapshotId: {{ snapshot_id|default('')|tojson }},
            backgroundPreload: {{ 'true' if web_background_preload|default(true) else 'false' }}
            ,backgroundBatchSize: {{ web_background_batch_size|default(12) }}
            ,backgroundBatchDelayMs: {{ web_background_batch_delay_ms|default(120) }}
            ,foregroundBatchSize: {{ web_foreground_batch_size|default(24) }}
            ,foregroundBatchDelayMs: {{ web_foreground_batch_delay_ms|default(50) }}
        };
    </script>
    <script defer src="/plugins/A_pwmenu/assets/app.js?h=__PWMENU_JS_REV__"></script>
"""
                + page[script_match.end():]
            )

            symbols = {}
            page = self._replace_web_svgs(page, symbols)
            javascript = self._replace_web_svgs(javascript, symbols)
            sprite = (
                '<svg xmlns="http://www.w3.org/2000/svg">'
                '<defs>' + ''.join(symbols.values()) + '</defs></svg>'
            )
            icon_revision = hashlib.sha256(
                sprite.encode('utf-8')
            ).hexdigest()[:12]
            page = page.replace(
                '__PWMENU_ICON_REV__', icon_revision
            )
            javascript = javascript.replace(
                '__PWMENU_ICON_REV__', icon_revision
            )
            css_revision = hashlib.sha256(
                css.encode('utf-8')
            ).hexdigest()[:12]
            javascript_revision = hashlib.sha256(
                javascript.encode('utf-8')
            ).hexdigest()[:12]
            page = (
                page
                .replace('__PWMENU_CSS_REV__', css_revision)
                .replace('__PWMENU_JS_REV__', javascript_revision)
            )
            resources = {
                'page': page,
                'app.css': css,
                'app.js': javascript,
                'icons.svg': sprite,
            }
            encoded = {}
            mime_types = {
                'app.css': 'text/css; charset=utf-8',
                'app.js': 'application/javascript; charset=utf-8',
                'icons.svg': 'image/svg+xml; charset=utf-8',
            }
            for name, mime_type in mime_types.items():
                body = resources[name].encode('utf-8')
                encoded[name] = {
                    'body': body,
                    'gzip': gzip.compress(body, compresslevel=1),
                    'etag': hashlib.sha256(body).hexdigest(),
                    'mime': mime_type,
                }
            resources['encoded'] = encoded
            self.web_resource_cache = resources
            return resources

    def _serve_web_asset(self, name, request):
        resource = self._web_resources()['encoded'].get(name)
        if resource is None:
            return make_response('Not found', 404)
        etag = f'"{resource["etag"]}"'
        if request.headers.get('If-None-Match') == etag:
            response = make_response('', 304)
        else:
            use_gzip = request.accept_encodings['gzip'] > 0
            body = resource['gzip'] if use_gzip else resource['body']
            response = make_response(body)
            response.headers['Content-Type'] = resource['mime']
            response.headers['Content-Length'] = str(len(body))
            if use_gzip:
                response.headers['Content-Encoding'] = 'gzip'
        response.headers['ETag'] = etag
        response.headers['Cache-Control'] = (
            'public, max-age=31536000, immutable'
        )
        response.headers['Vary'] = 'Accept-Encoding'
        return response

    def _backup_sources(self):
        sources = [
            ('config/config.toml', self.config_path),
            ('state/a_pwmenu_data.json', self.data_file),
            ('state/ohc_export.json', self.ohc_export_file),
            ('credentials/ohc.potfile', self.potfile_ohc),
            (
                'credentials/handshake-lab.potfile',
                self.potfile_handshake_lab,
            ),
            ('credentials/manual.potfile', self.potfile_manual),
        ]
        if not os.path.isfile(self.data_file):
            sources[1] = (
                'state/a_pwmenu_data.json',
                self.data_file + '.bak',
            )
        for index, directory in enumerate(self.handshake_dirs):
            sources.append((
                f'credentials/wpa-sec-{index}.potfile',
                os.path.join(directory, 'wpa-sec.cracked.potfile'),
            ))
            try:
                with os.scandir(directory) as iterator:
                    file_names = sorted(
                        entry.name for entry in iterator
                        if entry.is_file(follow_symlinks=False)
                    )
            except OSError:
                file_names = []
            supported_sidecars = set()
            for capture_name in (
                name for name in file_names
                if name.lower().endswith('.pcap')
            ):
                base_name = os.path.splitext(capture_name)[0]
                supported_sidecars.update((
                    capture_name + '.gps.json',
                    capture_name + '.geo.json',
                    capture_name + '.json',
                    base_name + '.gps.json',
                    base_name + '.geo.json',
                    base_name + '.json',
                ))
            for name in file_names:
                if name.lower().endswith('.pcap'):
                    sources.append((
                        f'captures/{index}/{name}',
                        os.path.join(directory, name),
                    ))
                if name not in supported_sidecars:
                    continue
                sources.append((
                    f'locations/{index}/{name}',
                    os.path.join(directory, name),
                ))
        unique = []
        seen = set()
        for logical_name, path in sources:
            absolute = os.path.abspath(path)
            if absolute in seen or not os.path.isfile(absolute):
                continue
            seen.add(absolute)
            unique.append((logical_name, absolute))
        return unique

    def _backup_size_limit(self):
        return max(
            1048576,
            min(
                self._option_int(
                    'backup_max_bytes', 2147483648
                ),
                4294967296,
            ),
        )

    def _build_backup_file(self):
        maximum = max(
            1048576, self._backup_size_limit()
        )
        sources = self._backup_sources()
        if len(sources) > 5000:
            raise ValueError('Backup contains too many files')
        records = []
        total = 0
        for logical_name, path in sources:
            try:
                size = os.path.getsize(path)
            except OSError as error:
                raise ValueError(
                    f'Could not inspect backup source {logical_name}: {error}'
                )
            total += max(0, int(size))
            if total > maximum:
                raise ValueError(
                    'Backup data exceeds the configured size limit'
                )
            try:
                digest = hashlib.sha256()
                with open(path, 'rb') as handle:
                    while True:
                        chunk = handle.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
            except OSError as error:
                raise ValueError(
                    f'Could not read backup source {logical_name}: {error}'
                )
            records.append({
                'name': logical_name,
                'path': path,
                'size': size,
                'sha256': digest.hexdigest(),
            })

        manifest = {
            'format': 'newfpv-pwmenu-backup-v1',
            'plugin_version': self.__version__,
            'created_at': int(time.time()),
            'files': [
                {
                    'name': record['name'],
                    'size': record['size'],
                    'sha256': record['sha256'],
                }
                for record in records
            ],
        }
        output = tempfile.SpooledTemporaryFile(
            max_size=max(
                1048576,
                min(
                    self._option_int(
                        'archive_memory_limit', 2097152
                    ),
                    16777216,
                ),
            ),
            mode='w+b',
        )
        with zipfile.ZipFile(
            output, 'w', zipfile.ZIP_DEFLATED, compresslevel=6
        ) as archive:
            archive.writestr(
                'manifest.json',
                json.dumps(
                    manifest,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(',', ':'),
                ).encode('utf-8'),
            )
            for record in records:
                archive.write(
                    record['path'],
                    'data/' + record['name'],
                )
        output.seek(0, os.SEEK_END)
        archive_size = output.tell()
        if archive_size > maximum:
            output.close()
            raise ValueError(
                'Compressed backup exceeds the configured size limit'
            )
        output.seek(0)
        return output, len(records), archive_size

    def _build_backup_archive(self):
        output, count, _ = self._build_backup_file()
        try:
            return output.read(), count
        finally:
            output.close()

    def _serve_backup(self, request):
        try:
            with self.backup_lock:
                archive, file_count, archive_size = (
                    self._build_backup_file()
                )
            stamp = datetime.datetime.utcnow().strftime(
                '%Y%m%d-%H%M%S'
            )
            response = send_file(
                archive,
                mimetype='application/zip',
                as_attachment=True,
                download_name=(
                    f'PWMenu-backup-{stamp}.pwmenu-backup'
                ),
            )
            response.headers['Content-Length'] = str(archive_size)
            response.headers['Cache-Control'] = 'no-store'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-PWMenu-Backup-Files'] = str(file_count)
            logging.info(
                f'[A_pwmenu] Created backup with '
                f'{file_count} file(s)'
            )
            self._record_action(
                'backup',
                'PWMenu backup downloaded',
                f'{file_count} file(s) · {archive_size} byte(s)',
            )
            return response
        except (OSError, ValueError, zipfile.BadZipFile) as error:
            logging.warning(
                f'[A_pwmenu] Backup failed: {error}'
            )
            if request.headers.get('X-PWMenu-Async') == '1':
                return self._json_response({
                    'ok': False,
                    'message': str(error),
                }, 400)
            return self._render_page(
                notification=str(error),
                notif_type='error',
                active_tab='other',
            )

    def _backup_restore_target(self, logical_name):
        fixed = {
            'config/config.toml': self.config_path,
            'state/a_pwmenu_data.json': self.data_file,
            'state/ohc_export.json': self.ohc_export_file,
            'credentials/ohc.potfile': self.potfile_ohc,
            'credentials/handshake-lab.potfile': (
                self.potfile_handshake_lab
            ),
            'credentials/manual.potfile': self.potfile_manual,
        }
        if logical_name in fixed:
            return os.path.abspath(fixed[logical_name])
        wpa_match = re.fullmatch(
            r'credentials/wpa-sec-(\d{1,3})\.potfile',
            logical_name,
        )
        if wpa_match:
            index = int(wpa_match.group(1))
            if index >= len(self.handshake_dirs):
                raise ValueError(
                    'Backup references an unavailable handshake directory'
                )
            return os.path.abspath(os.path.join(
                self.handshake_dirs[index],
                'wpa-sec.cracked.potfile',
            ))
        capture_match = re.fullmatch(
            r'captures/(\d{1,3})/([^/\\]+\.pcap)',
            logical_name,
            re.IGNORECASE,
        )
        if capture_match:
            index = int(capture_match.group(1))
            name = self._safe_handshake_name(
                capture_match.group(2)
            )
            if index >= len(self.handshake_dirs) or not name:
                raise ValueError(
                    'Backup contains an invalid capture destination'
                )
            return os.path.abspath(os.path.join(
                self.handshake_dirs[index], name
            ))
        location_match = re.fullmatch(
            r'locations/(\d{1,3})/([^/\\]+)',
            logical_name,
        )
        if location_match:
            index = int(location_match.group(1))
            name = location_match.group(2)
            if (
                index >= len(self.handshake_dirs)
                or name != os.path.basename(name)
                or not name.lower().endswith('.json')
            ):
                raise ValueError(
                    'Backup contains an invalid location sidecar'
                )
            return os.path.abspath(os.path.join(
                self.handshake_dirs[index], name
            ))
        raise ValueError(
            f'Backup contains unsupported data: {logical_name}'
        )

    def _atomic_restore_file(self, target, content):
        return self._atomic_restore_stream(
            target, io.BytesIO(content)
        )

    def _atomic_restore_stream(self, target, source):
        directory = os.path.dirname(target)
        os.makedirs(directory, exist_ok=True)
        mode = 0o600
        try:
            mode = os.stat(target).st_mode & 0o777
        except OSError:
            pass
        descriptor, temporary = tempfile.mkstemp(
            prefix='.pwmenu-restore-', dir=directory
        )
        try:
            with os.fdopen(descriptor, 'wb') as handle:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, target)
            try:
                flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)
                directory_fd = os.open(directory, flags)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        finally:
            try:
                if os.path.exists(temporary):
                    os.remove(temporary)
            except OSError:
                pass

    def _restore_backup(self, request):
        uploaded = request.files.get('file')
        if uploaded is None or not uploaded.filename:
            return False, 'Select a .pwmenu-backup file'
        owned_stream = None
        try:
            maximum = self._backup_size_limit()
            source = uploaded.stream
            try:
                source.seek(0, os.SEEK_END)
                archive_size = source.tell()
                source.seek(0)
            except (AttributeError, OSError):
                owned_stream = tempfile.SpooledTemporaryFile(
                    max_size=max(
                        1048576,
                        min(
                            self._option_int(
                                'archive_memory_limit', 2097152
                            ),
                            16777216,
                        ),
                    ),
                    mode='w+b',
                )
                archive_size = 0
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    archive_size += len(chunk)
                    if archive_size > maximum:
                        raise ValueError(
                            'Backup exceeds the configured size limit'
                        )
                    owned_stream.write(chunk)
                owned_stream.seek(0)
                source = owned_stream
            if archive_size > maximum:
                raise ValueError(
                    'Backup exceeds the configured size limit'
                )
            with self.backup_lock:
                with zipfile.ZipFile(source, 'r') as archive:
                    infos = archive.infolist()
                    if len(infos) > 5001:
                        raise ValueError(
                            'Backup contains too many files'
                        )
                    total = sum(max(0, info.file_size) for info in infos)
                    if total > maximum:
                        raise ValueError(
                            'Backup expands beyond the configured limit'
                        )
                    try:
                        manifest = json.loads(
                            archive.read('manifest.json').decode(
                                'utf-8'
                            )
                        )
                    except (
                        KeyError, UnicodeDecodeError, ValueError,
                        TypeError, json.JSONDecodeError,
                    ) as error:
                        raise ValueError(
                            f'Backup manifest is invalid: {error}'
                        )
                    if (
                        not isinstance(manifest, dict)
                        or manifest.get('format')
                        != 'newfpv-pwmenu-backup-v1'
                        or not isinstance(manifest.get('files'), list)
                    ):
                        raise ValueError(
                            'Unsupported PWMenu backup format'
                        )
                    writes = []
                    targets = set()
                    archive_names = [info.filename for info in infos]
                    if len(archive_names) != len(set(archive_names)):
                        raise ValueError(
                            'Backup contains duplicate ZIP entries'
                        )
                    for record in manifest['files']:
                        if not isinstance(record, dict):
                            raise ValueError(
                                'Backup manifest contains an invalid entry'
                            )
                        logical_name = str(record.get('name') or '')
                        archive_name = 'data/' + logical_name
                        try:
                            info = archive.getinfo(archive_name)
                        except KeyError:
                            raise ValueError(
                                f'Backup data is missing: {logical_name}'
                            )
                        try:
                            expected_size = int(
                                record.get('size', -1)
                            )
                        except (TypeError, ValueError):
                            expected_size = -1
                        if info.file_size != expected_size:
                            raise ValueError(
                                f'Backup integrity check failed: '
                                f'{logical_name}'
                            )
                        digest = hashlib.sha256()
                        size = 0
                        with archive.open(info, 'r') as handle:
                            while True:
                                chunk = handle.read(1024 * 1024)
                                if not chunk:
                                    break
                                size += len(chunk)
                                digest.update(chunk)
                        if (
                            size != expected_size
                            or digest.hexdigest()
                            != str(record.get('sha256') or '')
                        ):
                            raise ValueError(
                                f'Backup integrity check failed: '
                                f'{logical_name}'
                            )
                        target = self._backup_restore_target(
                            logical_name
                        )
                        if target in targets:
                            raise ValueError(
                                'Backup contains duplicate destinations'
                            )
                        targets.add(target)
                        writes.append((
                            target,
                            archive_name,
                            logical_name,
                        ))

                    declared_names = {
                        'data/' + str(record.get('name') or '')
                        for record in manifest['files']
                    }
                    if set(archive_names) != (
                        declared_names | {'manifest.json'}
                    ):
                        raise ValueError(
                            'Backup contains undeclared ZIP entries'
                        )

                    for target, _, logical_name in writes:
                        if (
                            os.path.isfile(target)
                            and not logical_name.startswith('captures/')
                        ):
                            shutil.copy2(
                                target,
                                target + '.pwmenu-restore.bak'
                            )
                    for target, archive_name, _ in writes:
                        with archive.open(archive_name, 'r') as handle:
                            self._atomic_restore_stream(target, handle)
                        if target == os.path.abspath(self.data_file):
                            with archive.open(
                                archive_name, 'r'
                            ) as handle:
                                self._atomic_restore_stream(
                                    self.data_file + '.bak', handle
                                )
                with self.data_lock:
                    self._load_data()
                self._invalidate_web_data_cache(
                    credentials=True, files=True
                )
            logging.warning(
                f'[A_pwmenu] Restored {len(writes)} file(s) from '
                'a backup'
            )
            return (
                True,
                f'Restored {len(writes)} file(s). '
                'PWMenu service is restarting.',
            )
        except (
            OSError, ValueError, TypeError, zipfile.BadZipFile,
        ) as error:
            logging.warning(
                f'[A_pwmenu] Backup restore rejected: {error}'
            )
            return False, str(error)
        finally:
            if owned_stream is not None:
                owned_stream.close()

    def _schedule_pwnagotchi_service_restart(self):
        def worker():
            time.sleep(2.5)
            try:
                subprocess.run(
                    ['systemctl', 'restart', 'pwnagotchi'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as error:
                logging.error(
                    f'[A_pwmenu] Could not restart service after '
                    f'backup restore: {error}'
                )

        threading.Thread(
            target=worker,
            daemon=True,
            name='pwmenu-backup-restore-restart',
        ).start()

    def _whitelist_action_response(self, req, changed, message, active_tab):
        if req.headers.get('X-PWMenu-Async') == '1':
            response = make_response(json.dumps({
                'ok': bool(changed),
                'message': str(message or ''),
                'whitelist': self._get_whitelist(),
            }))
            response.headers['Content-Type'] = 'application/json; charset=utf-8'
            response.headers['Cache-Control'] = 'no-store'
            return response
        return self._render_page(
            notification=message,
            notif_type="success" if changed else "error",
            active_tab=active_tab,
        )

    def _action_response(self, req, message, is_error, active_tab):
        """Return a compact response to in-page actions with a full-page fallback."""
        if req.headers.get('X-PWMenu-Async') == '1':
            response = make_response(json.dumps({
                'ok': not bool(is_error),
                'message': str(message or ''),
            }))
            response.headers['Content-Type'] = 'application/json; charset=utf-8'
            response.headers['Cache-Control'] = 'no-store'
            return response
        return self._render_page(
            notification=message,
            notif_type="error" if is_error else "success",
            active_tab=active_tab,
        )

    def _password_action_response(
        self, req, ok, message, essid, bssid, action='update'
    ):
        if req.headers.get('X-PWMenu-Async') == '1':
            cracked = self._get_cracked_data()
            credential = self._find_cracked_record(
                cracked, str(essid or ''), str(bssid or '')
            )
            response = make_response(json.dumps({
                'ok': bool(ok),
                'message': str(message or ''),
                'action': action,
                'essid': str(essid or ''),
                'bssid': self._format_bssid(str(bssid or '')),
                'credential': credential,
            }))
            response.headers['Content-Type'] = 'application/json; charset=utf-8'
            response.headers['Cache-Control'] = 'no-store'
            return response
        return self._render_page(
            notification=message,
            notif_type='success' if ok else 'error',
            active_tab='cracked' if action != 'add' else 'handshakes',
        )

    def _map_point_action_response(self, req, ok, message, point_id=None):
        if req.headers.get('X-PWMenu-Async') == '1':
            cracked = self._get_cracked_data()
            groups = self._scan_and_group_files(cracked)
            response = make_response(json.dumps({
                'ok': bool(ok),
                'message': str(message or ''),
                'point_id': str(point_id or ''),
                'map_points': self._build_map_points(groups),
                'no_gps_networks': self._build_no_gps_networks(groups),
            }))
            response.headers['Content-Type'] = 'application/json; charset=utf-8'
            response.headers['Cache-Control'] = 'no-store'
            return response
        return self._render_page(
            notification=message,
            notif_type='success' if ok else 'error',
            active_tab='map',
        )

    def _wpa_status(self):
        status = {
            'configured': bool(self.options.get('wpa_sec_key')),
            'results_present': False,
            'results_bytes': 0,
            'results_updated': '',
            'last_upload': self.wpa_last_result,
            'submitted': 0,
            'pending': 0,
            'integrated': True,
        }
        with self.data_lock:
            status['submitted'] = len(self.data.get('wpa_networks', {}) or {})
        with self.wpa_pending_lock:
            status['pending'] = len(self.wpa_pending_files)
        newest = None
        for path in self._wpa_potfile_paths():
            try:
                stat = os.stat(path)
            except OSError:
                continue
            if newest is None or stat.st_mtime > newest.st_mtime:
                newest = stat
        if newest is not None:
            status.update({
                'results_present': True,
                'results_bytes': int(newest.st_size),
                'results_updated': get_local_time(
                    newest.st_mtime, self._option_int('timezone', 0)
                ),
            })
        return status

    def _wpa_potfile_paths(self):
        return list(dict.fromkeys(
            os.path.join(directory, 'wpa-sec.cracked.potfile')
            for directory in self.handshake_dirs
        ))

    def _handle_wpa_upload(self, req):
        fname = req.form.get('filename')
        if not self.options.get('wpa_sec_key'):
            return "WPA-Sec Key missing in config", True
        if not self._find_handshake_path(fname):
            return "File not found", True
        queued = self._queue_wpa_files([fname], force=False)
        if not queued:
            return "Capture is already recovered, submitted, or queued", False
        self._start_wpa_sync_thread()
        return "WPA-sec upload queued", False

    def _handle_wpa_cluster_upload(self, req):
        if not self.options.get('wpa_sec_key'):
            return "WPA-Sec Key missing in config", True
        names = []
        for raw in (req.form.get('filenames') or '').split(','):
            name = self._safe_handshake_name(raw.strip())
            if name and name not in names:
                names.append(name)
        if not names:
            return "No files selected", True
        queued = self._queue_wpa_files(names, force=False)
        if not queued:
            return "Selected captures are already recovered, submitted, or queued", False
        self._start_wpa_sync_thread()
        return f"WPA-sec upload queued for {queued} capture(s)", False

    def _wpa_network_key(self, path):
        essid, bssid = self._capture_export_network(path)
        compact_bssid = self._compact_bssid(bssid)
        if compact_bssid:
            return f'bssid:{compact_bssid}'
        normalized = self._normalized_essid_key(essid)
        return f'essid:{normalized}' if normalized else ''

    def _queue_wpa_files(self, filenames=None, force=False):
        if not self._module_enabled('wpa_sec'):
            return 0
        if filenames is None:
            names = []
            for directory in self.handshake_dirs:
                if os.path.isdir(directory):
                    names.extend(
                        os.path.basename(path)
                        for path in glob.glob(os.path.join(directory, '*.pcap'))
                    )
        else:
            names = list(filenames)

        cracked = self._get_cracked_data()
        selected = {}
        for raw_name in names:
            name = self._safe_handshake_name(raw_name)
            path = self._find_handshake_path(name)
            if not path or self._capture_has_known_password(path, cracked):
                continue
            network_key = self._wpa_network_key(path)
            if not network_key:
                continue
            current = selected.get(network_key)
            if (
                current is None
                or self._capture_export_score(path)
                > self._capture_export_score(current)
            ):
                selected[network_key] = path

        queued = 0
        with self.data_lock:
            submitted = dict(self.data.setdefault('wpa_networks', {}))
        with self.wpa_pending_lock:
            for network_key, path in selected.items():
                name = os.path.basename(path)
                previous = submitted.get(network_key) or {}
                if (
                    not force
                    and previous.get('status') in ('submitted', 'already_submitted')
                ):
                    continue
                was_pending = name in self.wpa_pending_files
                self.wpa_pending_files[name] = bool(
                    force or self.wpa_pending_files.get(name)
                )
                if not was_pending:
                    queued += 1
        return queued

    def _start_wpa_sync_thread(self):
        with self.wpa_pending_lock:
            if self.wpa_upload_thread and self.wpa_upload_thread.is_alive():
                return
            self.wpa_upload_thread = threading.Thread(
                target=self._wpa_sync_worker,
                daemon=True,
                name='pwmenu-wpa-sync',
            )
            self.wpa_upload_thread.start()

    def _wpa_download_is_due(self):
        if self.wpa_force_download:
            return True
        if not self._option_bool('wpa_sec_download_results', True):
            return False
        with self.data_lock:
            last_download = float(
                self.data.get('wpa_last_download', 0) or 0
            )
        return (
            time.time() - last_download
            >= self._option_int('wpa_sec_sync_interval', 3600)
        )

    def _wpa_sync_worker(self):
        key = str(self.options.get('wpa_sec_key') or '')
        if not key:
            return
        with self.wpa_upload_lock:
            uploaded = 0
            already = 0
            failed = []
            while True:
                with self.wpa_pending_lock:
                    if not self.wpa_pending_files:
                        break
                    name, force = self.wpa_pending_files.popitem()
                path = self._find_handshake_path(name)
                if not path:
                    failed.append(name)
                    continue
                if not force and self._capture_has_known_password(path):
                    continue
                msg, is_err = self._upload_path_to_wpa(path, key)
                if is_err:
                    failed.append(name)
                else:
                    status = (
                        'already_submitted'
                        if "Already uploaded" in msg
                        else 'submitted'
                    )
                    if status == 'already_submitted':
                        already += 1
                    else:
                        uploaded += 1
                    network_key = self._wpa_network_key(path)
                    record = {
                        'filename': name,
                        'signature': self._ohc_file_signature(path),
                        'status': status,
                        'reported_at': int(time.time()),
                    }
                    with self.data_lock:
                        self.data.setdefault('wpa_files', {})[name] = record
                        if network_key:
                            self.data.setdefault('wpa_networks', {})[
                                network_key
                            ] = record
                    self._save_data()

            details = []
            if uploaded:
                details.append(f"{uploaded} uploaded")
            if already:
                details.append(f"{already} already uploaded")
            if failed:
                details.append(f"{len(failed)} failed")
            download_due = self._wpa_download_is_due()
            self.wpa_force_download = False
            if download_due:
                message, is_error = self._download_wpa_results(key)
                details.append(message)
                if is_error:
                    failed.append('results download')

            self.wpa_last_result = (
                "WPA-sec sync: " + ", ".join(details or ["already up to date"])
            )
            self._record_action(
                'cloud',
                'WPA-sec synchronization finished',
                self.wpa_last_result,
            )
            if failed:
                logging.warning(f"[A_pwmenu] {self.wpa_last_result}")
            else:
                logging.info(f"[A_pwmenu] {self.wpa_last_result}")
        with self.wpa_pending_lock:
            self.wpa_upload_thread = None
            restart = bool(self.wpa_pending_files)
        if restart:
            self._start_wpa_sync_thread()

    def _wpa_results_path(self):
        directory = self.storage_dir
        if not directory and self.handshake_dirs:
            directory = self.handshake_dirs[0]
        if not directory:
            directory = os.path.realpath(
                os.path.join(os.path.expanduser('~'), 'handshakes')
            )
        os.makedirs(directory, exist_ok=True)
        return os.path.join(directory, 'wpa-sec.cracked.potfile')

    def _download_wpa_results(self, key):
        api_url = str(
            self.options.get('wpa_sec_api_url')
            or 'https://wpa-sec.stanev.org'
        ).strip().rstrip('/') + '/?api&dl=1'
        try:
            response = requests.get(
                api_url,
                cookies={'key': str(key)},
                headers={'User-Agent': 'PWMenu/1.4.0'},
                timeout=(10, 30),
            )
            response.raise_for_status()
            payload = bytes(response.content or b'')
            if (
                b'<html' in payload[:512].lower()
                or b'<!doctype html' in payload[:512].lower()
            ):
                return 'results rejected by WPA-sec', True

            target = self._wpa_results_path()
            fd, tmp_path = tempfile.mkstemp(
                prefix='.pwmenu-wpa-', dir=os.path.dirname(target)
            )
            os.close(fd)
            try:
                with open(tmp_path, 'wb') as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_path, target)
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            self._invalidate_web_data_cache(credentials=True)
            with self.data_lock:
                self.data['wpa_last_download'] = int(time.time())
            self._save_data()
            return f"results downloaded ({len(payload)} bytes)", False
        except (OSError, requests.RequestException) as error:
            logging.warning(f"[A_pwmenu] WPA-sec results download failed: {error}")
            return 'results download failed', True

    def _handle_ohc_cluster_upload(self, req):
        names = self._filenames_from_csv(req.form.get('filenames') or '')
        if not names:
            return "No files selected", True
        queued = self._queue_ohc_files(names, force=True)
        if not queued:
            reasons = []
            for name in names:
                record = self._ohc_file_record(name)
                message = str(record.get('message') or '').strip()
                if message and message not in reasons:
                    reasons.append(message)
            if reasons:
                return "Nothing queued: " + "; ".join(reasons[:3]), True
            return "Nothing queued: no unresolved usable capture was selected", True
        self._start_ohc_upload_thread()
        if time.time() < self._ohc_retry_at():
            return f"Queued {queued} file(s). {self._ohc_backoff_message()}", False
        return f"OHC upload started for {queued} file(s)", False

    def _handle_ohc_all_missing(self):
        if not self._module_enabled('ohc') or not self._option_bool('ohc_enabled', True):
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

    def _ohc_vless_config(self):
        """Build an Xray client config without persisting the VLESS URL."""
        value = str(self.options.get('ohc_vless_url') or '').strip()
        if not value:
            return None
        try:
            parsed = urllib.parse.urlsplit(value)
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

            def option(name, default=''):
                return str((query.get(name) or [default])[0] or default)

            if parsed.scheme.lower() != 'vless':
                raise ValueError('unsupported scheme')
            user_id = urllib.parse.unquote(parsed.username or '').strip()
            host = parsed.hostname or ''
            port = int(parsed.port or 443)
            transport = option('type', 'tcp').lower()
            security = option('security', '').lower()
            if not re.fullmatch(
                r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
                user_id,
            ):
                raise ValueError('invalid client id')
            if not host or transport not in ('tcp', 'raw'):
                raise ValueError('unsupported transport')
            if security not in ('reality', 'tls', 'none', ''):
                raise ValueError('unsupported security')

            stream = {
                'network': 'tcp',
                'security': security or 'none',
            }
            flow_override = str(
                self.options.get('ohc_vless_flow', 'auto')
            ).strip()
            flow = option('flow') if flow_override.lower() == 'auto' else flow_override
            if security == 'reality':
                public_key = option('pbk')
                server_name = option('sni')
                if not public_key or not server_name:
                    raise ValueError('incomplete REALITY settings')
                stream['realitySettings'] = {
                    'serverName': server_name,
                    'fingerprint': option('fp', 'chrome'),
                    'password': public_key,
                    'shortId': option('sid'),
                    'spiderX': urllib.parse.unquote(option('spx', '/')),
                }
            elif security == 'tls':
                stream['tlsSettings'] = {
                    'serverName': option('sni', host),
                    'fingerprint': option('fp', 'chrome'),
                    'allowInsecure': option('allowInsecure', '0') in ('1', 'true'),
                }

            return {
                'log': {'loglevel': 'warning'},
                'inbounds': [{
                    'tag': 'ohc-http',
                    'listen': '127.0.0.1',
                    'port': self._option_int('ohc_proxy_port', 10809),
                    'protocol': 'http',
                    'settings': {},
                }],
                'outbounds': [{
                    'tag': 'ohc-vless',
                    'protocol': 'vless',
                    'settings': {
                        'address': host,
                        'port': port,
                        'id': user_id,
                        'encryption': option('encryption', 'none'),
                        'flow': flow,
                    },
                    'streamSettings': stream,
                }],
            }
        except (TypeError, ValueError):
            logging.error('[A_pwmenu] Invalid ohc_vless_url; OHC proxy was not started')
            return False

    def _stop_ohc_proxy(self):
        with self.ohc_proxy_lock:
            process = self.ohc_proxy_process
            self.ohc_proxy_process = None
            if process and process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=3)
                except (OSError, subprocess.SubprocessError):
                    try:
                        process.kill()
                    except OSError:
                        pass
            try:
                os.remove(self.ohc_proxy_config_file)
            except FileNotFoundError:
                pass
            except OSError as error:
                logging.debug(f'[A_pwmenu] Could not remove OHC proxy config: {error}')

    def _ensure_ohc_proxy(self):
        config = self._ohc_vless_config()
        if config is None:
            self._stop_ohc_proxy()
            return True
        if config is False:
            self._stop_ohc_proxy()
            return False

        with self.ohc_proxy_lock:
            process = self.ohc_proxy_process
            if process and process.poll() is None:
                return True
            self.ohc_proxy_process = None
            binary = str(self.options.get('ohc_xray_binary') or '/usr/local/bin/xray')
            if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
                logging.error('[A_pwmenu] Xray binary is missing or not executable')
                return False
            try:
                fd, tmp_path = tempfile.mkstemp(
                    prefix='.a_pwmenu-ohc-xray-',
                    dir=os.path.dirname(self.ohc_proxy_config_file),
                )
                try:
                    os.fchmod(fd, 0o600)
                    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                        fd = None
                        json.dump(config, handle, ensure_ascii=False)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(tmp_path, self.ohc_proxy_config_file)
                finally:
                    if fd is not None:
                        os.close(fd)
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                self.ohc_proxy_process = subprocess.Popen(
                    [binary, 'run', '-c', self.ohc_proxy_config_file],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                )
                for _ in range(20):
                    if self.ohc_proxy_process.poll() is not None:
                        raise RuntimeError('Xray exited during startup')
                    try:
                        with socket.create_connection(
                            ('127.0.0.1', self._option_int('ohc_proxy_port', 10809)),
                            timeout=0.1,
                        ):
                            logging.info('[A_pwmenu] OHC-only VLESS proxy is ready')
                            return True
                    except OSError:
                        time.sleep(0.1)
                raise RuntimeError('Xray proxy port did not open')
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                logging.error(f'[A_pwmenu] OHC VLESS proxy failed: {error}')
                process = self.ohc_proxy_process
                self.ohc_proxy_process = None
                if process and process.poll() is None:
                    try:
                        process.terminate()
                    except OSError:
                        pass
                return False

    def _ohc_request_proxies(self):
        if not str(self.options.get('ohc_vless_url') or '').strip():
            return None
        if not self._ensure_ohc_proxy():
            raise requests.ConnectionError('OHC VLESS proxy unavailable')
        proxy = f"http://127.0.0.1:{self._option_int('ohc_proxy_port', 10809)}"
        return {'http': proxy, 'https': proxy}

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

    def _quality_file_record(self, filename, path=None):
        if not filename:
            return {}
        name = os.path.basename(filename)
        with self.data_lock:
            record = dict(self.data.setdefault('capture_quality', {}).get(name, {}) or {})
        if path and record.get('signature') != self._ohc_file_signature(path):
            return {}
        return record

    def _handshake_identity(self, filename):
        name = os.path.splitext(os.path.basename(filename or ''))[0]
        if '_' not in name:
            # Hidden/unknown ESSIDs are commonly saved as `<bssid>.pcap`.
            # Retain the visible stem while still exposing the exact AP identity.
            return name, self._compact_bssid(name)
        essid, raw_bssid = name.rsplit('_', 1)
        bssid = self._compact_bssid(raw_bssid)
        if len(bssid) != 12:
            return name, ''
        return essid, bssid

    def _compact_bssid(self, value):
        compact = re.sub(r'[^0-9a-f]', '', str(value or '').lower())
        return compact if len(compact) == 12 else ''

    def _colon_bssid(self, value):
        compact = self._compact_bssid(value)
        if not compact:
            return ''
        return ':'.join(compact[index:index + 2] for index in range(0, 12, 2))

    def _normalized_essid_key(self, value):
        return re.sub(r'[\W_]+', '', str(value or ''), flags=re.UNICODE).casefold()

    def _quality_metric(self, report, label):
        match = re.search(rf'^{re.escape(label)}\.*:\s*(\d+)', report, re.MULTILINE | re.IGNORECASE)
        return int(match.group(1)) if match else 0

    def _classify_capture_quality(self, report, hashes, file_size):
        eapol = self._quality_metric(report, 'EAPOL messages (total)')
        m1 = self._quality_metric(report, 'EAPOL M1 messages (total)')
        m2 = self._quality_metric(report, 'EAPOL M2 messages (total)')
        m3 = self._quality_metric(report, 'EAPOL M3 messages (total)')
        m4 = self._quality_metric(report, 'EAPOL M4 messages (total)')
        best_pairs = self._quality_metric(report, 'EAPOL pairs (best)')
        packets = self._quality_metric(report, 'packets inside')
        authorized = sum(
            int(value) for value in re.findall(
                r'^EAPOL M(?:32E2|34E4).*?authorized.*?\.*:\s*(\d+)',
                report,
                re.MULTILINE | re.IGNORECASE,
            )
        )
        pmkid_written = sum(
            int(value) for value in re.findall(
                r'^.*PMKID.*written.*?\.*:\s*(\d+)',
                report,
                re.MULTILINE | re.IGNORECASE,
            )
        )
        pmkid_total = sum(
            int(value) for value in re.findall(
                r'^.*PMKID.*?\.*:\s*(\d+)',
                report,
                re.MULTILINE | re.IGNORECASE,
            )
        )
        hash_count = len(hashes)

        if hash_count and (authorized or pmkid_written):
            grade, rank = 'Excellent', 3
            summary = f"{hash_count} usable hash(es), authorized exchange"
        elif hash_count:
            grade, rank = 'Usable', 2
            summary = f"{hash_count} usable WPA/PMKID hash(es)"
        elif eapol or pmkid_total:
            grade, rank = 'Partial', 1
            present = '/'.join(str(value) for value in (m1, m2, m3, m4))
            summary = f"Incomplete EAPOL exchange (M1/M2/M3/M4: {present})"
        else:
            grade, rank = 'Unusable', 0
            summary = 'Empty PCAP header' if file_size == 24 else 'No WPA/PMKID material found'

        return {
            'grade': grade,
            'rank': rank,
            'summary': summary,
            'hashes': hash_count,
            'packets': packets,
            'eapol': eapol,
            'm1': m1,
            'm2': m2,
            'm3': m3,
            'm4': m4,
            'best_pairs': best_pairs,
            'authorized': authorized,
            'pmkid_written': pmkid_written,
        }

    def _store_capture_quality(self, path, quality):
        name = os.path.basename(path)
        record = dict(quality)
        record['signature'] = self._ohc_file_signature(path)
        record['updated_at'] = int(time.time())
        with self.data_lock:
            records = self.data.setdefault('capture_quality', {})
            previous = dict(records.get(name, {}) or {})
            records[name] = record
            if (
                previous.get('signature')
                and previous.get('signature') != record['signature']
                and int(previous.get('rank', -1)) < 2
                and int(record.get('rank', -1)) >= 2
            ):
                history = self.data.setdefault('replacement_history', [])
                history.append({
                    'old': name,
                    'replacement': name,
                    'upgraded_in_place': True,
                    'from_quality': previous.get('grade', 'Unknown'),
                    'to_quality': record.get('grade', 'Unknown'),
                    'updated_at': int(time.time())
                })
                del history[:-100]
        self._save_data()
        return record

    def _run_capture_analysis(self, path):
        output_path = None
        try:
            file_size = os.path.getsize(path)
            if file_size == 24:
                quality = self._classify_capture_quality('', [], file_size)
                return [], self._store_capture_quality(path, quality)

            with self.capture_analysis_lock:
                with tempfile.NamedTemporaryFile(prefix='pwmenu-quality-', suffix='.22000', delete=False) as handle:
                    output_path = handle.name
                os.remove(output_path)
                result = subprocess.run(
                    ['/usr/bin/hcxpcapngtool', '-o', output_path, path],
                    check=False,
                    capture_output=True,
                    text=True,
                    errors='replace',
                    timeout=self._option_int('hcxpcapngtool_timeout', 90)
                )
                hashes = []
                if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                    with open(output_path, 'r', errors='ignore') as handle:
                        hashes = list(dict.fromkeys(line.strip() for line in handle if line.strip()))
                report = (result.stdout or '') + '\n' + (result.stderr or '')
                quality = self._classify_capture_quality(report, hashes, file_size)
                capture_essid, capture_bssid = self._handshake_identity(path)
                hash_networks = [
                    self._wpa_hash_network(hash_line)
                    for hash_line in hashes
                ]
                hash_networks = [network for network in hash_networks if network[0]]
                exact = next(
                    (
                        network for network in hash_networks
                        if capture_bssid and network[1] == capture_bssid
                    ),
                    hash_networks[0] if len(hash_networks) == 1 else None,
                )
                if exact:
                    quality['essid'], quality['bssid'] = exact
                elif capture_essid:
                    quality['essid'], quality['bssid'] = capture_essid, capture_bssid
                return hashes, self._store_capture_quality(path, quality)
        except Exception as e:
            logging.error(f"[A_pwmenu] Capture analysis failed for {path}: {e}")
            return [], {}
        finally:
            if output_path:
                try:
                    os.remove(output_path)
                except FileNotFoundError:
                    pass

    def _start_quality_scan_thread(self, filenames=None, scan_all=False):
        if not self.quality_scan_running:
            return
        with self.quality_thread_lock:
            for filename in filenames or []:
                name = self._safe_handshake_name(os.path.basename(filename or ''))
                if name:
                    self.quality_pending.add(name)
            if scan_all:
                self.quality_scan_all = True
            if self.quality_scan_thread and self.quality_scan_thread.is_alive():
                return
            self.quality_scan_thread = threading.Thread(
                target=self._quality_scan_worker,
                daemon=True,
                name='pwmenu-quality-scan'
            )
            self.quality_scan_thread.start()

    def _quality_scan_worker(self):
        while self.quality_scan_running:
            with self.quality_thread_lock:
                if self.quality_pending:
                    name = self.quality_pending.pop()
                elif self.quality_scan_all:
                    self.quality_scan_all = False
                    for directory in self.handshake_dirs:
                        if os.path.isdir(directory):
                            for path in glob.glob(os.path.join(directory, '*.pcap')):
                                self.quality_pending.add(os.path.basename(path))
                    continue
                else:
                    self.quality_scan_thread = None
                    return
            path = self._find_handshake_path(name)
            if not path:
                continue
            signature = self._ohc_file_signature(path)
            quality = self._quality_file_record(name, path)
            if not quality or quality.get('signature') != signature:
                _, quality = self._run_capture_analysis(path)
            if quality:
                essid, bssid = self._handshake_identity(name)
                self._replace_weaker_captures(essid, bssid)
            delay = max(0, self._option_int('quality_scan_delay_ms', 250)) / 1000.0
            if delay:
                time.sleep(delay)

    def _forget_handshake_state_locked(self, name, path):
        self.data.setdefault('seen_files', {}).pop(name, None)
        self.data.setdefault('locations', {}).pop(name, None)
        self.data.setdefault('ohc_files', {}).pop(name, None)
        self.data.setdefault('ohc_found_files', {}).pop(name, None)
        self.data.setdefault('capture_quality', {}).pop(name, None)
        self.data.setdefault('capture_password_checks', {}).pop(name, None)
        self.data.setdefault('ohc_pending_files', {}).pop(path, None)
        self.data.setdefault('ohc_file_signatures', {}).pop(path, None)
        hash_files = self.data.setdefault('ohc_hash_files', {})
        for hash_value, filename in list(hash_files.items()):
            if filename == name:
                hash_files.pop(hash_value, None)

    def _archive_replaced_capture(self, old_path, replacement_path):
        if not os.path.isfile(old_path) or old_path == replacement_path:
            return False
        name = os.path.basename(old_path)
        suffix = f".replaced-{int(time.time())}"
        archived_path = old_path + suffix
        os.replace(old_path, archived_path)
        base = os.path.splitext(old_path)[0]
        for extension in ('.gps.json', '.geo.json', '.hc22000', '.22000'):
            companion = base + extension
            if os.path.isfile(companion):
                os.replace(companion, companion + suffix)
        try:
            fd = os.open(os.path.dirname(old_path), os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass
        with self.data_lock:
            self._forget_handshake_state_locked(name, old_path)
            history = self.data.setdefault('replacement_history', [])
            history.append({
                'old': name,
                'replacement': os.path.basename(replacement_path),
                'archived': os.path.basename(archived_path),
                'updated_at': int(time.time())
            })
            del history[:-100]
        self._save_data()
        logging.info(f"[A_pwmenu] Replaced weak capture {name} with {os.path.basename(replacement_path)}")
        return True

    def _replace_weaker_captures(self, essid, bssid):
        if not self._option_bool('auto_replace_unusable', True) or not essid or not bssid:
            return 0
        candidates = []
        for directory in self.handshake_dirs:
            if not os.path.isdir(directory):
                continue
            for path in glob.glob(os.path.join(directory, '*.pcap')):
                _, candidate_bssid = self._handshake_identity(path)
                if candidate_bssid != bssid:
                    continue
                quality = self._quality_file_record(os.path.basename(path), path)
                if quality:
                    candidates.append((path, quality))
        usable = [item for item in candidates if int(item[1].get('rank', -1)) >= 2]
        if not usable:
            return 0
        best_path, _ = max(
            usable,
            key=lambda item: (
                int(item[1].get('rank', 0)),
                int(item[1].get('hashes', 0)),
                os.path.getmtime(item[0])
            )
        )
        replaced = 0
        for path, quality in candidates:
            if path == best_path or int(quality.get('rank', -1)) >= 2:
                continue
            if os.path.getmtime(best_path) <= os.path.getmtime(path):
                continue
            if os.path.getsize(path) == 24:
                continue
            try:
                replaced += int(self._archive_replaced_capture(path, best_path))
            except OSError as e:
                logging.warning(f"[A_pwmenu] Could not archive weak capture {path}: {e}")
        return replaced

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
        self._invalidate_web_data_cache()

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
                if path and not self._capture_has_known_password(path, cracked) and path not in paths:
                    paths.append(path)
            return paths

        for directory in self.handshake_dirs:
            if not os.path.exists(directory):
                continue
            for path in glob.glob(os.path.join(directory, '*.pcap')):
                if not self._capture_has_known_password(path, cracked) and path not in paths:
                    paths.append(path)
        return paths

    def _best_capture_paths_by_ap(self, paths):
        """Keep the strongest capture for each resolved BSSID."""
        selected = {}
        for path in paths:
            _, bssid = self._capture_export_network(path)
            identity = ('bssid', bssid) if bssid else ('file', os.path.realpath(path))
            score = self._capture_export_score(path)
            current = selected.get(identity)
            if current is None or score > current[0]:
                selected[identity] = (score, path)
        return [item[1] for item in selected.values()]

    def _best_capture_for_path(self, path):
        """Resolve any capture link to the strongest file for that AP."""
        if not path or not os.path.isfile(path):
            return path
        essid, bssid = self._capture_export_network(path)
        matches = self._matching_capture_paths(essid, bssid)
        return matches[0] if matches else path

    def _ohc_reported_bssids(self, hashes):
        bssids = set()
        for hash_line in hashes:
            _, bssid = self._ohc_hash_task_identity(hash_line)
            if bssid:
                bssids.add(bssid)
        return bssids

    def _ohc_prequeue_paths(self, paths):
        """Drop known OHC tasks before they can enter the persistent queue."""
        paths = list(dict.fromkeys(paths or []))
        best_paths = self._best_capture_paths_by_ap(paths)
        duplicate_paths = set(paths) - set(best_paths)
        changed = False
        for path in duplicate_paths:
            self._ohc_mark_path(
                path,
                'already_reported',
                'Better capture selected for the same AP',
            )
            self._complete_ohc_path(path)
            changed = True

        _, export_bssids, _ = self._load_ohc_export_snapshot()
        with self.data_lock:
            reported_hashes = set(self.data.setdefault('ohc_reported_hashes', []))
            reported_paths = set(self.data.setdefault('ohc_reported', []))
            records = dict(self.data.setdefault('ohc_files', {}))
            signatures = dict(self.data.setdefault('ohc_file_signatures', {}))
        reported_realpaths = {
            os.path.realpath(value) for value in reported_paths if value
        }
        reported_bssids = self._ohc_reported_bssids(reported_hashes)

        missing = []
        for path in best_paths:
            name = os.path.basename(path)
            record = dict(records.get(name, {}) or {})
            status = str(record.get('status') or '')
            signature = self._ohc_file_signature(path)
            stop_status = ''
            stop_message = ''

            if path in reported_paths or os.path.realpath(path) in reported_realpaths:
                stop_status = 'already_reported'
                stop_message = 'Already sent to OHC'
            elif status in ('sent', 'already_reported'):
                stop_status = 'already_reported'
                stop_message = record.get('message') or 'Already sent to OHC'
            elif status == 'found':
                stop_status = 'found'
                stop_message = record.get('message') or 'Password available on OHC'
            elif (
                status == 'invalid'
                and signature
                and signatures.get(path) == signature
            ):
                stop_status = 'invalid'
                stop_message = record.get('message') or 'Unchanged capture has no usable WPA hash'
            else:
                _, compact_bssid = self._capture_export_network(path)
                bssid = self._colon_bssid(compact_bssid)
                if bssid and bssid in export_bssids:
                    stop_status = 'already_reported'
                    stop_message = 'Present in the last imported OHC export'
                elif bssid and bssid in reported_bssids:
                    stop_status = 'already_reported'
                    stop_message = 'Already sent to OHC'

            if stop_status:
                self._ohc_mark_path(path, stop_status, stop_message)
                self._complete_ohc_path(path, signature)
                changed = True
            else:
                missing.append(path)

        if changed:
            self._save_data()
        return missing

    def _queue_ohc_files(self, filenames=None, force=False):
        paths = self._ohc_prequeue_paths(self._candidate_ohc_paths(filenames))
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
        cracked = self._get_cracked_data()
        paths = []
        changed = False
        for path, record in pending.items():
            if self._capture_has_known_password(path, cracked):
                with self.data_lock:
                    self.data.setdefault('ohc_pending_files', {}).pop(path, None)
                self._ohc_mark_path(path, 'local_cracked', 'Password already known locally')
                changed = True
                continue
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
        if not self._module_enabled('ohc') or not self._option_bool('ohc_enabled', True):
            return
        if filenames:
            self._queue_ohc_files(filenames, force=True)
        if time.time() < self._ohc_retry_at():
            self.ohc_last_result = self._ohc_backoff_message()
            self.ohc_scheduler_wakeup.set()
            return
        with self.ohc_thread_lock:
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
                self._record_action(
                    'cloud',
                    'OHC synchronization finished',
                    msg,
                )
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
        if not self._module_enabled('ohc') or not self._option_bool('ohc_enabled', True):
            return "OHC disabled", True
        key = self._ohc_key()
        if not key:
            return "OHC API key missing", True
        self.ohc_display_status = 'OHC upload'
        paths = self._candidate_ohc_paths(filenames)
        best_paths = self._best_capture_paths_by_ap(paths)
        duplicate_paths = set(paths) - set(best_paths)
        for path in duplicate_paths:
            self._ohc_mark_path(
                path,
                'already_reported',
                'Better capture selected for the same AP',
            )
            self._complete_ohc_path(path)
        paths = best_paths
        if duplicate_paths:
            self._save_data()

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
        export_identities, export_bssids, export_info = self._load_ohc_export_snapshot()
        if export_info.get('tasks'):
            logging.info(
                f"[A_pwmenu] OHC export snapshot loaded: {export_info['tasks']} task(s), "
                f"source={export_info.get('source', 'unknown')}"
            )
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
            elif (
                time.time() < self._ohc_retry_at()
                and 'rate limit' in str(self.data.get('ohc_retry_reason', '')).lower()
            ):
                return self._ohc_backoff_message(), True
            else:
                logging.warning(
                    "[A_pwmenu] OHC task reconciliation unavailable; "
                    "continuing upload with persistent local state"
                )
                with self.data_lock:
                    self.data['ohc_tasks_synced_at'] = time.time()
                    self.data['ohc_reconcile_requested'] = False
                self._clear_ohc_backoff()
                self._save_data()

        hashes = []
        hash_sources = {}
        failed_extract = 0
        already_reported = 0
        already_exported = 0
        queued_bssids = set()
        self.ohc_progress_total = len(paths)
        for idx, path in enumerate(paths):
            self.ohc_progress_current = idx + 1
            self.ohc_progress_name = self._essid_from_filename(os.path.basename(path))
            self.ohc_display_status = 'OHC upload'
            self.ohc_upload_face = self.ohc_upload_faces[idx % len(self.ohc_upload_faces)]
            extracted = self._ohc_extract_hashes(path)
            if not extracted:
                failed_extract += 1
                self._ohc_mark_path(path, 'invalid', 'No usable WPA or PMKID hash found')
                self._complete_ohc_path(path)
                continue
            path_hashes[path] = set()
            for h in extracted:
                h = h.strip()
                if not h:
                    continue
                path_hash_count[path] = path_hash_count.get(path, 0) + 1
                if self._ohc_hash_in_export(h, export_identities, export_bssids):
                    path_hashes[path].add(h)
                    already_reported += 1
                    already_exported += 1
                    reported_hashes.add(h)
                    self._ohc_mark_path(
                        path,
                        'already_reported',
                        'Present in the last imported OHC export',
                        path_hash_count.get(path, 0)
                    )
                    continue
                if h in reported_hashes:
                    path_hashes[path].add(h)
                    already_reported += 1
                    self._ohc_mark_path(path, 'already_reported', 'Already exists in OHC tasks', path_hash_count.get(path, 0))
                    continue
                _, hash_bssid = self._ohc_hash_task_identity(h)
                if hash_bssid and hash_bssid in queued_bssids:
                    continue
                if h in hash_sources:
                    continue
                path_hashes[path].add(h)
                hash_files[h] = os.path.basename(path)
                hashes.append(h)
                hash_sources[h] = path
                if hash_bssid:
                    queued_bssids.add(hash_bssid)

        for path, extracted in path_hashes.items():
            if extracted and extracted.issubset(reported_hashes):
                self._complete_ohc_path(path)

        if not hashes:
            with self.data_lock:
                self.data['ohc_hash_files'] = hash_files
                self.data['ohc_reported_hashes'] = sorted(reported_hashes)
            if already_reported:
                self._save_data()
                msg = f"OHC: {already_reported} hashes already reported"
                if already_exported:
                    msg += f" ({already_exported} from last export)"
                return msg, False
            if failed_extract:
                self._save_data()
            return f"OHC: no usable hashes ({failed_extract} capture(s))", True

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

            reported_hashes.update(batch)
            with self.data_lock:
                self.data['ohc_reported_hashes'] = sorted(reported_hashes)
                self.data['ohc_hash_files'] = hash_files
            self._save_data()

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
        if already_exported:
            msg += f" ({already_exported} from last export)"
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
        hashes, _ = self._run_capture_analysis(pcap_path)
        return hashes

    def _ohc_add_tasks(self, hashes, key):
        payload = {
            'api_key': key,
            'agree_terms': 'yes',
            'action': 'add_tasks',
            'algo_mode': 22000,
            'hashes': [h.strip() for h in hashes if h.strip()]
        }
        try:
            res = requests.post(
                'https://api.onlinehashcrack.com/v2',
                json=payload,
                timeout=30,
                proxies=self._ohc_request_proxies(),
            )
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
            res = requests.post(
                'https://api.onlinehashcrack.com/v2',
                json=payload,
                timeout=30,
                proxies=self._ohc_request_proxies(),
            )
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
            api_url = str(
                self.options.get('wpa_sec_api_url')
                or 'https://wpa-sec.stanev.org'
            ).strip().rstrip('/') + '/'
            with open(path, 'rb') as f:
                r = requests.post(
                    api_url,
                    cookies={'key': str(key)},
                    files={'file': f},
                    headers={
                        'User-Agent': (
                            'Mozilla/5.0 (X11; Linux aarch64) '
                            'PWMenu/1.4.0'
                        )
                    },
                    timeout=(10, 30)
                )

            if r.status_code == 200:
                body = str(r.text or '').lower()
                if "already in database" in body or "already submitted" in body:
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
        p = self._best_capture_for_path(p)
        safe_name = os.path.basename(p)

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
            'ohc_reconcile_requested': False,
            'capture_quality': {},
            'capture_password_checks': {},
            'wpa_files': {},
            'wpa_networks': {},
            'wpa_last_download': 0,
            'replacement_history': [],
            'empty_cleanup_history': [],
            'action_history': [],
            'credential_rejections': [],
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
        if not isinstance(self.data.get('capture_quality'), dict):
            self.data['capture_quality'] = {}
        if not isinstance(self.data.get('capture_password_checks'), dict):
            self.data['capture_password_checks'] = {}
        if not isinstance(self.data.get('wpa_files'), dict):
            self.data['wpa_files'] = {}
        if not isinstance(self.data.get('wpa_networks'), dict):
            self.data['wpa_networks'] = {}
        try:
            self.data['wpa_last_download'] = int(
                self.data.get('wpa_last_download', 0) or 0
            )
        except (TypeError, ValueError):
            self.data['wpa_last_download'] = 0
        if not isinstance(self.data.get('replacement_history'), list):
            self.data['replacement_history'] = []
        if not isinstance(self.data.get('empty_cleanup_history'), list):
            self.data['empty_cleanup_history'] = []
        if not isinstance(self.data.get('action_history'), list):
            self.data['action_history'] = []
        if not isinstance(self.data.get('credential_rejections'), list):
            self.data['credential_rejections'] = []

    def _record_action(
        self,
        kind,
        title,
        detail='',
        source='PWMenu',
        dedupe_key='',
        dedupe_window=0,
    ):
        if not hasattr(self, 'data') or not isinstance(self.data, dict):
            return False
        now = int(time.time())
        key = str(dedupe_key or '').strip()
        record = {
            'ts': now,
            'kind': str(kind or 'system')[:32],
            'title': str(title or 'Activity')[:180],
            'detail': str(detail or '')[:320],
            'source': str(source or 'PWMenu')[:64],
            'key': key[:180],
        }
        with self.data_lock:
            history = self.data.setdefault('action_history', [])
            if key and dedupe_window:
                for previous in reversed(history[-100:]):
                    if (
                        str(previous.get('key') or '') == key
                        and now - int(previous.get('ts', 0) or 0)
                        < int(dedupe_window)
                    ):
                        return False
            history.append(record)
            maximum = max(
                1,
                min(
                    self._option_int('activity_history_max', 200),
                    200,
                ),
            )
            hours = max(
                1,
                min(self._option_int('activity_history_hours', 24), 24 * 30),
            )
            cutoff = now - (hours * 3600)
            history[:] = [
                item for item in history
                if self._activity_is_recent(item, cutoff)
            ]
            if len(history) > maximum:
                del history[:-maximum]
        self._save_data()
        return True

    def _activity_is_recent(self, item, cutoff):
        if not isinstance(item, dict):
            return False
        try:
            return int(item.get('ts', 0) or 0) >= int(cutoff)
        except (TypeError, ValueError):
            return False

    def _activity_history_page(self, offset=0, limit=None):
        maximum = max(
            1,
            min(self._option_int('activity_history_max', 200), 200),
        )
        page_size = max(
            1,
            min(
                int(
                    limit
                    if limit is not None
                    else maximum
                ),
                maximum,
            ),
        )
        start = max(0, int(offset or 0))
        hours = max(
            1,
            min(self._option_int('activity_history_hours', 24), 24 * 30),
        )
        cutoff = int(time.time()) - (hours * 3600)
        with self.data_lock:
            history = [
                dict(item)
                for item in reversed(
                    self.data.get('action_history', []) or []
                )
                if self._activity_is_recent(item, cutoff)
            ][:maximum]
        total = len(history)
        selected = history[start:start + page_size]
        timezone = self._option_int('timezone', 0)
        for item in selected:
            try:
                item['time'] = get_local_time(
                    float(item.get('ts', 0) or 0), timezone
                )
            except (TypeError, ValueError, OSError):
                item['time'] = ''
            item.pop('key', None)
        next_offset = start + len(selected)
        return {
            'items': selected,
            'total': total,
            'offset': start,
            'nextOffset': next_offset,
            'hasMore': next_offset < total,
        }

    def _activity_history_response(self, request):
        try:
            offset = int(request.args.get('offset') or 0)
        except (TypeError, ValueError):
            offset = 0
        try:
            limit = int(
                request.args.get('limit')
                or self._option_int('activity_history_max', 200)
            )
        except (TypeError, ValueError):
            limit = self._option_int('activity_history_max', 200)
        payload = self._activity_history_page(offset, limit)
        payload['ok'] = True
        return self._json_response(payload)

    def _migrate_wpa_sec_state(self):
        """Import the stock plugin report once so PWMenu does not resubmit it."""
        with self.data_lock:
            if self.data.setdefault('wpa_files', {}):
                return
        report_path = '/home/pi/.wpa_sec_uploads'
        try:
            with open(report_path, 'r', encoding='utf-8') as handle:
                payload = json.load(handle)
            reported = (
                payload.get('reported', [])
                if isinstance(payload, dict) else []
            )
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return

        changed = False
        for old_path in reported:
            name = self._safe_handshake_name(os.path.basename(str(old_path)))
            path = self._find_handshake_path(name)
            if not path:
                continue
            record = {
                'filename': name,
                'signature': self._ohc_file_signature(path),
                'status': 'submitted',
                'reported_at': 0,
                'migrated': True,
            }
            network_key = self._wpa_network_key(path)
            with self.data_lock:
                self.data.setdefault('wpa_files', {})[name] = record
                if network_key:
                    self.data.setdefault('wpa_networks', {})[
                        network_key
                    ] = record
            changed = True
        if changed:
            self._save_data()
            logging.info(
                f"[A_pwmenu] Migrated {len(self.data.get('wpa_files', {}))} "
                "WPA-sec upload records"
            )

    def _save_data(self):
        saved = False
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
                saved = True
        except Exception as e:
            logging.error(f"[A_pwmenu] Could not save state: {e}")
            for target in (self.data_file + '.bak.tmp', self.data_file + '.tmp'):
                try:
                    if os.path.exists(target):
                        os.remove(target)
                except OSError:
                    pass
        if saved:
            self._invalidate_web_data_cache()

    def _option_bool(self, key, default=True):
        v = getattr(self, 'options', {}).get(key, default)
        if isinstance(v, str):
            return v.strip().lower() not in ('0', 'false', 'no', 'off')
        return bool(v)

    def _option_int(self, key, default):
        try:
            return int(getattr(self, 'options', {}).get(key, default))
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
            records = dict(self.data.get('ohc_files', {}) or {})
        uncrackable = 0
        for name, record in records.items():
            try:
                hash_count = int((record or {}).get('hashes', 0) or 0)
            except (TypeError, ValueError):
                hash_count = 0
            if (
                str((record or {}).get('status') or '') == 'invalid'
                and hash_count <= 0
                and self._find_handshake_path(name)
            ):
                uncrackable += 1
        retry_in = max(0, int(self._ohc_retry_at() - time.time()))
        return {
            'enabled': (
                self._module_enabled('ohc')
                and self._option_bool('ohc_enabled', True)
            ),
            'uploading': self.ohc_uploading,
            'face': self.ohc_upload_face if self.ohc_uploading else '0__0',
            'last': self.ohc_last_result,
            'pending': pending,
            'uncrackable': uncrackable,
            'retry_in': retry_in
        }

    def _health_issues(self, gps_status, ohc_status, wpa_status):
        issues = []
        memory_limit = max(
            16,
            self._option_int('health_memory_warning_mb', 64),
        )
        try:
            available_kb = None
            with open('/proc/meminfo', 'r', encoding='utf-8') as handle:
                for line in handle:
                    if line.startswith('MemAvailable:'):
                        available_kb = int(line.split()[1])
                        break
            if (
                available_kb is not None
                and available_kb < memory_limit * 1024
            ):
                issues.append({
                    'kind': 'memory',
                    'title': 'Low available memory',
                    'detail': (
                        f'{available_kb // 1024} MB available; '
                        f'warning threshold is {memory_limit} MB'
                    ),
                    'tab': 'other',
                })
        except (OSError, ValueError, IndexError):
            pass

        disk_limit = max(
            1,
            min(
                self._option_int(
                    'health_disk_warning_percent', 10
                ),
                50,
            ),
        )
        try:
            usage = shutil.disk_usage('/')
            free_percent = (
                int(usage.free * 100 / usage.total)
                if usage.total else 100
            )
            if free_percent < disk_limit:
                issues.append({
                    'kind': 'disk',
                    'title': 'Low storage space',
                    'detail': (
                        f'{free_percent}% free on the system volume; '
                        f'warning threshold is {disk_limit}%'
                    ),
                    'tab': 'other',
                })
        except OSError:
            pass

        gps_grace = max(
            0,
            self._option_int('health_gps_grace_seconds', 900),
        )
        gps_state = str(
            (gps_status or {}).get('state') or ''
        ).casefold()
        gps_healthy = (
            'connected' in gps_state
            or 'receiving gps' in gps_state
        )
        if (
            self._module_enabled('gps')
            and time.time() - self.loaded_at >= gps_grace
            and not gps_healthy
        ):
            issues.append({
                'kind': 'gps',
                'title': 'GPS is not providing coordinates',
                'detail': (
                    f"{(gps_status or {}).get('label') or 'GPS'}: "
                    f"{(gps_status or {}).get('state') or 'offline'}"
                ),
                'tab': 'map',
            })

        queue_limit = max(
            300,
            self._option_int('health_queue_stuck_seconds', 3600),
        )
        with self.data_lock:
            pending_records = list(
                (self.data.get('ohc_pending_files', {}) or {}).values()
            )
        queued_times = []
        for record in pending_records:
            try:
                queued_at = int(
                    (record or {}).get('queued_at', 0) or 0
                )
            except (TypeError, ValueError):
                continue
            if queued_at > 0:
                queued_times.append(queued_at)
        oldest_ohc = min(queued_times, default=0)
        if (
            (ohc_status or {}).get('pending', 0)
            and oldest_ohc
            and time.time() - oldest_ohc >= queue_limit
            and not (ohc_status or {}).get('uploading')
        ):
            retry_in = int(
                (ohc_status or {}).get('retry_in', 0) or 0
            )
            detail = (
                f"{(ohc_status or {}).get('pending', 0)} file(s) "
                f"waiting for more than {queue_limit // 60} minutes"
            )
            if retry_in:
                detail += f'; retry in {retry_in} seconds'
            issues.append({
                'kind': 'ohc',
                'title': 'OHC queue is delayed',
                'detail': detail,
                'tab': 'other',
            })

        wpa_pending = int(
            (wpa_status or {}).get('pending', 0) or 0
        )
        wpa_worker_alive = bool(
            self.wpa_upload_thread
            and self.wpa_upload_thread.is_alive()
        )
        if wpa_pending and not wpa_worker_alive:
            issues.append({
                'kind': 'wpa',
                'title': 'WPA-sec queue is not running',
                'detail': (
                    f'{wpa_pending} capture(s) are waiting while '
                    'the upload worker is stopped'
                ),
                'tab': 'other',
            })
        return issues

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

    def _fresh_live_gps(self, poll_gpsd=True):
        pwndroid = self._fresh_pwndroid_ws_gps()
        if pwndroid:
            return pwndroid
        phone = self._fresh_phone_gps()
        if phone:
            return phone

        now = time.time()
        interval = max(1, self._option_int('gpsd_poll_interval', 10))
        with self.gps_lock:
            if not poll_gpsd:
                return (
                    dict(self.gpsd_cached_location)
                    if self.gpsd_cached_location else None
                )
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

    def _set_capture_map_location(self, filename, lat, lon):
        name = self._safe_handshake_name(filename)
        path = self._find_handshake_path(name)
        if not path:
            return False, 'Handshake file was not found', name or ''
        try:
            try:
                latitude = float(lat)
                longitude = float(lon)
            except (TypeError, ValueError):
                return False, 'Map coordinates are invalid', name or ''
            if not math.isfinite(latitude) or not math.isfinite(longitude):
                return False, 'Map coordinates are invalid', name or ''
            if not -90 <= latitude <= 90:
                raise ValueError('Latitude must be between -90 and 90')
            if not -180 <= longitude <= 180:
                raise ValueError('Longitude must be between -180 and 180')
            stat = os.stat(path)
            essid, bssid = self._capture_export_network(path)
            location = {
                'lat': latitude,
                'lon': longitude,
                'accuracy': 0,
                'source': 'manual-map',
                'provider': 'pwmenu-map',
                # This is an intentional assignment to the capture, not a GPS
                # sample measured later. Keep it fresh relative to capture time.
                'ts': float(stat.st_mtime),
                'manual_assigned_at': int(time.time()),
                'filename': name,
                'essid': essid,
                'bssid': bssid,
                'capture_ts': float(stat.st_mtime),
                'date': get_local_time(
                    stat.st_mtime, self._option_int('timezone', 0)
                ),
            }
            with self.data_lock:
                self.data.setdefault('locations', {})[name] = location
            self._save_data()
            logging.info(
                "[A_pwmenu] Map location saved for %s at %.7f, %.7f",
                name, latitude, longitude
            )
            return True, f'Placed {name} on the map', name
        except (OSError, TypeError, ValueError) as error:
            return False, str(error), name or ''

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
            'credential_source': g.get('src', '') if g.get('is_cracked') else '',
            'source': f.get('gps_source', ''),
            'captures': 1,
            'signal': f.get('signal', '-'),
            'encryption': f.get('encryption', 'WPA2'),
            'vendor': self._vendor_from_bssid(bssid, g['essid']),
            'gps_stale': bool(f.get('gps_stale', False)),
            'gps_age_at_capture': int(f.get('gps_age_at_capture', 0) or 0),
            'ohc': self._ohc_file_record(f.get('filename', '')),
            'quality': dict(f.get('quality') or {}),
            'status': 'cracked' if g.get('is_cracked') else 'handshake',
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
                if (
                    item['essid'] == m['essid']
                    and item['bssid'] == m['bssid']
                    and self._distance_meters(
                        item['lat'], item['lon'], m['lat'], m['lon']
                    ) <= 30
                ):
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

        # A one-capture network already contains the complete capture record.
        # Keeping an identical self-copy in `history` nearly doubles map JSON
        # for the common case and provides no UI information.
        for network in network_groups:
            if len(network.get('history', [])) <= 1:
                network['history'] = []

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
                c = {
                    'id': m.get('id') or f"{m['essid']}-{m['lat']}-{m['lon']}",
                    'essid': m.get('essid', ''),
                    'bssid': '',
                    'lat': m.get('lat'),
                    'lon': m.get('lon'),
                    'is_cracked': bool(m.get('is_cracked')),
                    'gps_stale': bool(m.get('gps_stale')),
                    'status': m.get('status', 'handshake'),
                    'count': max(1, int(m.get('captures', 1) or 1)),
                    'members': [m],
                }
                clusters.append(c)

        compact_clusters = []
        for cluster in clusters:
            members = cluster.get('members', [])
            if len(members) == 1:
                # A singleton already carries all display fields. Do not send
                # a second complete copy of it in `members` on every page load.
                single = members[0].copy()
                single['members'] = []
                single['count'] = max(
                    1,
                    int(single.get('captures', 1) or 1),
                )
                compact_clusters.append(single)
            else:
                compact_clusters.append(cluster)
        return compact_clusters

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
                    'ohc': self._ohc_file_record(f.get('filename', '')),
                    'quality': dict(f.get('quality') or {})
                })
            items.append({
                'essid': g.get('essid', ''),
                'bssid': bssid,
                'vendor': self._vendor_from_bssid(bssid, g.get('essid', '')),
                'date': g.get('last_seen', ''),
                'count': g.get('count', 0),
                'is_cracked': g.get('is_cracked', False),
                'password': g.get('pwd', '') if g.get('is_cracked') else '',
                'credential_source': g.get('src', '') if g.get('is_cracked') else '',
                'filename': first.get('filename', ''),
                'ohc': self._ohc_file_record(first.get('filename', '')),
                'quality': dict(first.get('quality') or {}),
                'files': files
            })
        return items

    def _build_conflicts(self, groups, cracked):
        """Return only identity, password and duplicate records needing review."""
        conflicts = []
        identities = {}
        bssids_by_name = {}
        for group in groups or []:
            group_bssid = self._compact_bssid(group.get('bssid'))
            if group_bssid == '000000000000':
                group_bssid = ''
            file_essids = {
                str(file_info.get('essid') or '').strip()
                for file_info in group.get('files', [])
                if str(file_info.get('essid') or '').strip()
            }
            display_name = str(group.get('essid') or '').strip()
            if display_name:
                file_essids.add(display_name)
            if group_bssid:
                for essid in file_essids:
                    normalized = self._normalized_essid_key(essid)
                    if normalized:
                        bssids_by_name.setdefault(normalized, set()).add(
                            group_bssid
                        )
                bucket = identities.setdefault(
                    group_bssid,
                    {'essids': set(), 'passwords': set()},
                )
                bucket['essids'].update(file_essids)
            files = list(group.get('files', []) or [])
            if len(files) > 1:
                best = group.get('best_file') or files[0]
                conflicts.append({
                    'kind': 'duplicate',
                    'title': display_name or 'Duplicate captures',
                    'detail': (
                        f'{len(files)} captures; '
                        f'{best.get("filename", "best capture")} selected'
                    ),
                    'bssid': self._format_bssid(group_bssid),
                    'count': len(files),
                })

        for record in (cracked or {}).values():
            essid = str(record.get('essid') or '').strip()
            password = str(record.get('password') or '')
            bssid = self._compact_bssid(record.get('bssid'))
            if bssid == '000000000000':
                bssid = ''
            if not bssid:
                candidates = bssids_by_name.get(
                    self._normalized_essid_key(essid),
                    set(),
                )
                if len(candidates) == 1:
                    # A legacy zero/name-only credential can be linked safely
                    # when one and only one captured AP has the same normalized
                    # name. This prevents 00:00:00:00:00:00 from becoming one
                    # fake shared access point.
                    bssid = next(iter(candidates))
            if not bssid:
                conflicts.append({
                    'kind': 'name-only',
                    'title': essid or 'Name-only credential',
                    'detail': (
                        'Credential has no BSSID and cannot be tied '
                        'to one exact access point'
                    ),
                    'bssid': '',
                    'count': 1,
                })
                continue
            bucket = identities.setdefault(
                bssid,
                {'essids': set(), 'passwords': set()},
            )
            if essid:
                bucket['essids'].add(essid)
            if password:
                bucket['passwords'].add(password)

        for bssid, bucket in identities.items():
            essids = sorted(bucket['essids'], key=str.casefold)
            passwords = bucket['passwords']
            formatted = self._format_bssid(bssid)
            normalized_names = {
                self._normalized_essid_key(essid)
                for essid in essids
                if self._normalized_essid_key(essid)
            }
            if len(normalized_names) > 1:
                conflicts.append({
                    'kind': 'identity',
                    'title': formatted,
                    'detail': (
                        f'{len(essids)} network names: '
                        + ', '.join(essids[:3])
                        + ('…' if len(essids) > 3 else '')
                    ),
                    'bssid': formatted,
                    'count': len(essids),
                })
            if len(passwords) > 1:
                conflicts.append({
                    'kind': 'password',
                    'title': formatted,
                    'detail': (
                        f'{len(passwords)} different recovered passwords '
                        'are attached to this BSSID'
                    ),
                    'bssid': formatted,
                    'count': len(passwords),
                    'repairable': True,
                })

        priority = {
            'password': 0,
            'identity': 1,
            'name-only': 2,
            'duplicate': 3,
        }
        conflicts.sort(key=lambda item: (
            priority.get(item.get('kind'), 9),
            str(item.get('title') or '').casefold(),
        ))
        return conflicts

    def _update_achievements(self, groups, cracked):
        with self.data_lock:
            return self._update_achievements_locked(groups, cracked)

    def _update_achievements_locked(self, groups, cracked):
        curr_cracked = len(cracked)
        curr_captured = sum(len(g['files']) for g in groups)
        changed = False

        if curr_cracked > self.data['history_cracked']:
            diff = curr_cracked - self.data['history_cracked']
            self.data['xp'] += diff * 500
            self.data['history_cracked'] = curr_cracked
            changed = True

        if curr_captured > self.data['history_captured']:
            diff = curr_captured - self.data['history_captured']
            self.data['xp'] += diff * 50
            self.data['history_captured'] = curr_captured
            changed = True

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
                changed = True

            badge_info = b.copy()
            badge_info['unlocked'] = ul
            badge_info['progress'] = pct
            my_badges.append(badge_info)

        if changed:
            self._save_data()

        lvl_p = 100
        if next_xp > prev_xp:
            lvl_p = int(((xp - prev_xp) / (next_xp - prev_xp)) * 100)

        return {'level': lvl, 'rank': rank, 'xp': xp, 'next_xp': next_xp, 'lvl_percent': lvl_p, 'badges': my_badges}

    def _validate_manual_password(self, essid, bssid, pwd):
        name = self._validate_whitelist_name(essid)
        password = str(pwd or '')
        if any(char in password for char in ('\x00', '\r', '\n')):
            raise ValueError('Password contains unsupported control characters')
        if not 8 <= len(password) <= 63:
            raise ValueError('WPA password must contain 8 to 63 characters')
        compact_bssid = self._compact_bssid(bssid)
        if bssid and not compact_bssid:
            raise ValueError('BSSID must contain 12 hexadecimal digits')
        return name, compact_bssid, password

    def _matching_capture_paths(self, essid, bssid):
        target_bssid = self._compact_bssid(bssid)
        target_essid = self._normalized_essid_key(essid)
        matches = []
        for directory in self.handshake_dirs:
            if not os.path.isdir(directory):
                continue
            for path in glob.glob(os.path.join(directory, '*.pcap')):
                capture_essid, capture_bssid = self._capture_export_network(path)
                if target_bssid:
                    matched = self._compact_bssid(capture_bssid) == target_bssid
                else:
                    matched = (
                        bool(target_essid)
                        and self._normalized_essid_key(capture_essid)
                        == target_essid
                    )
                if matched and path not in matches:
                    matches.append(path)
        return sorted(matches, key=self._capture_export_score, reverse=True)

    def _run_aircrack_password_check(self, path, essid, bssid, passwords):
        executable = shutil.which('aircrack-ng')
        if not executable and os.path.isfile('/usr/bin/aircrack-ng'):
            executable = '/usr/bin/aircrack-ng'
        if not executable:
            return False, False, 'aircrack-ng is unavailable'

        candidates = [
            str(password) for password in passwords
            if str(password)
            and not any(char in str(password) for char in ('\x00', '\r', '\n'))
        ]
        if not candidates:
            return False, False, 'No valid password candidate was supplied'

        wordlist_path = None
        try:
            fd, wordlist_path = tempfile.mkstemp(
                prefix='pwmenu-verify-', suffix='.txt'
            )
            try:
                os.chmod(wordlist_path, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
                handle.write('\n'.join(candidates) + '\n')
                handle.flush()
                os.fsync(handle.fileno())

            compact_bssid = self._compact_bssid(bssid)
            selector = (
                ['-b', self._colon_bssid(compact_bssid)]
                if compact_bssid
                else ['-e', str(essid or '')]
            )
            result = subprocess.run(
                [executable, '-q', *selector, '-w', wordlist_path, path],
                check=False,
                capture_output=True,
                text=True,
                errors='replace',
                timeout=self._option_int('password_verify_timeout', 45),
            )
            output = (result.stdout or '') + '\n' + (result.stderr or '')
            verified = bool(
                re.search(
                    r'\bKEY\s+FOUND!?\s*(?:\[|$)', output, re.IGNORECASE
                )
            )
            conclusive = verified or bool(
                re.search(r'\bKEY\s+NOT\s+FOUND\b', output, re.IGNORECASE)
            )
            return verified, conclusive, output[-1000:]
        except subprocess.TimeoutExpired:
            return False, False, 'aircrack-ng verification timed out'
        except (OSError, subprocess.SubprocessError) as error:
            return False, False, str(error)
        finally:
            if wordlist_path:
                try:
                    os.remove(wordlist_path)
                except FileNotFoundError:
                    pass

    def _verify_pmkid_hash_password(self, hash_line, password):
        """Verify one WPA*01 PMKID record locally without spawning a process."""
        parts = str(hash_line or '').strip().lstrip('$').split('*')
        if len(parts) < 6 or parts[0] != 'WPA' or parts[1] != '01':
            return None
        try:
            expected_pmkid = bytes.fromhex(parts[2])
            ap_mac = bytes.fromhex(parts[3])
            station_mac = bytes.fromhex(parts[4])
            essid_bytes = bytes.fromhex(parts[5])
        except (TypeError, ValueError):
            return None
        if (
            len(expected_pmkid) != 16
            or len(ap_mac) != 6
            or len(station_mac) != 6
            or not essid_bytes
        ):
            return None
        try:
            password_bytes = str(password).encode('utf-8')
            pmk = hashlib.pbkdf2_hmac(
                'sha1',
                password_bytes,
                essid_bytes,
                4096,
                dklen=32,
            )
            calculated = hmac.new(
                pmk,
                b'PMK Name' + ap_mac + station_mac,
                hashlib.sha1,
            ).digest()[:16]
            return hmac.compare_digest(calculated, expected_pmkid)
        except (TypeError, ValueError, UnicodeError):
            return None

    def _run_hcxpmk_password_check(self, path, essid, bssid, passwords):
        """Extract and verify PMKID hashes without exposing passwords in argv."""
        converter = (
            shutil.which('hcxpcapngtool')
            or (
                '/usr/bin/hcxpcapngtool'
                if os.path.isfile('/usr/bin/hcxpcapngtool')
                else ''
            )
        )
        if not converter:
            return False, False, 'PMKID extraction is unavailable'

        candidates = [
            str(password) for password in passwords
            if str(password)
            and not any(
                char in str(password) for char in ('\x00', '\r', '\n')
            )
        ]
        if not candidates:
            return False, False, 'No valid password candidate was supplied'

        output_path = None
        try:
            fd, output_path = tempfile.mkstemp(
                prefix='pwmenu-verify-', suffix='.22000'
            )
            os.close(fd)
            os.remove(output_path)
            hashes = []
            conversion = None
            conversion_commands = (
                [converter, '-o', output_path, path],
                [converter, '--all', '-o', output_path, path],
            )
            for conversion_command in conversion_commands:
                try:
                    os.remove(output_path)
                except FileNotFoundError:
                    pass
                with self.capture_analysis_lock:
                    conversion = subprocess.run(
                        conversion_command,
                        check=False,
                        capture_output=True,
                        text=True,
                        errors='replace',
                        timeout=self._option_int(
                            'hcxpcapngtool_timeout', 90
                        ),
                    )
                if os.path.isfile(output_path):
                    with open(
                        output_path,
                        'r',
                        encoding='utf-8',
                        errors='ignore',
                    ) as handle:
                        hashes = list(dict.fromkeys(
                            line.strip() for line in handle if line.strip()
                        ))
                if hashes:
                    break

            compact_bssid = self._compact_bssid(bssid)
            normalized_essid = self._normalized_essid_key(essid)
            matching_hashes = []
            for hash_line in hashes:
                hash_essid, hash_bssid = self._wpa_hash_network(hash_line)
                if compact_bssid:
                    matched = hash_bssid == compact_bssid
                else:
                    matched = (
                        bool(normalized_essid)
                        and self._normalized_essid_key(hash_essid)
                        == normalized_essid
                    )
                if matched:
                    matching_hashes.append(hash_line)

            if not matching_hashes:
                detail = (
                    (conversion.stdout or '') + '\n'
                    + (conversion.stderr or '')
                ).strip()
                return (
                    False,
                    False,
                    'No matching PMKID/EAPOL hash was extracted'
                    + (f": {detail[-300:]}" if detail else ''),
                )

            tested = False
            for hash_line in matching_hashes:
                for password in candidates:
                    confirmed = self._verify_pmkid_hash_password(
                        hash_line, password
                    )
                    if confirmed is True:
                        return (
                            True,
                            True,
                            'Password confirmed against PMKID',
                        )
                    if confirmed is False:
                        tested = True
            if tested:
                return False, True, 'Password was not confirmed by PMKID'
            return False, False, 'No verifiable PMKID hash was extracted'
        except (OSError, subprocess.SubprocessError) as error:
            return False, False, str(error)
        finally:
            if output_path:
                try:
                    os.remove(output_path)
                except FileNotFoundError:
                    pass

    def _verify_manual_password(self, essid, bssid, password):
        paths = self._matching_capture_paths(essid, bssid)
        if not paths:
            identity = self._format_bssid(bssid) or essid
            return (
                False,
                f'No matching capture is available for {identity}; '
                'the password was not saved',
            )

        conclusive_failure = False
        inconclusive_details = []
        for path in paths[:3]:
            verified, aircrack_conclusive, aircrack_detail = (
                self._run_aircrack_password_check(
                    path, essid, bssid, [password]
                )
            )
            if verified:
                return (
                    True,
                    f'Password verified against {os.path.basename(path)}',
                )

            verified, hcx_conclusive, hcx_detail = (
                self._run_hcxpmk_password_check(
                    path, essid, bssid, [password]
                )
            )
            if verified:
                return (
                    True,
                    f'Password verified against {os.path.basename(path)}',
                )

            if aircrack_conclusive or hcx_conclusive:
                conclusive_failure = True
                continue
            detail = '; '.join(
                value for value in (aircrack_detail, hcx_detail) if value
            )
            inconclusive_details.append(detail)
            logging.warning(
                f"[A_pwmenu] Manual password verification was inconclusive "
                f"for {os.path.basename(path)}: {detail}"
            )

        if conclusive_failure:
            return False, 'Password does not match the captured handshake'
        if inconclusive_details:
            combined = ' '.join(inconclusive_details)
            if re.search(
                r'no matching pmkid|no hashes|no eapol|contained no eapol',
                combined,
                re.IGNORECASE,
            ):
                return (
                    False,
                    'Password cannot be verified because this capture '
                    'contains no usable WPA/PMKID hash. Recapture the '
                    'access point',
                )
            return (
                False,
                'The password could not be verified conclusively and was not saved',
            )
        return False, 'Password does not match the captured handshake'

    def _add_manual_password(self, essid, bssid, pwd):
        try:
            name, compact_bssid, password = self._validate_manual_password(
                essid, bssid, pwd
            )
            verified, message = self._verify_manual_password(
                name, compact_bssid, password
            )
            if not verified:
                logging.warning(
                    "[A_pwmenu] Manual password rejected for %s: %s",
                    self._format_bssid(compact_bssid) or name,
                    message,
                )
                return False, message

            mac = self._colon_bssid(compact_bssid) or "00:00:00:00:00:00"
            with self.potfile_lock:
                self._normalize_potfile(self.potfile_manual)
                lines, _ = self._read_pot_lines(self.potfile_manual)
                lines, keys, _ = self._dedupe_pot_lines(lines)
                line = f"{mac}:{mac}:{name}:{password}"
                added = self._pot_line_key(line) not in keys
                if added:
                    self._write_pot_lines(self.potfile_manual, lines + [line])
            if added:
                with self.data_lock:
                    self.data['xp'] += 200
                self._save_data()
                self._record_action(
                    'password',
                    f'Password verified: {name}',
                    self._format_bssid(compact_bssid)
                    or 'Verified against a local capture',
                )
                logging.info(
                    "[A_pwmenu] Manual password saved for %s",
                    self._format_bssid(compact_bssid) or name,
                )
                return True, message + '; password saved'
            logging.info(
                "[A_pwmenu] Manual password was already saved for %s",
                self._format_bssid(compact_bssid) or name,
            )
            return True, message + '; password was already saved'
        except (OSError, ValueError) as error:
            logging.error(f"[A_pwmenu] Could not add manual password: {error}")
            return False, str(error)

    def _delete_password(self, essid, pwd=None, source=None, bssid=None):
        deleted = False
        compact_bssid = self._compact_bssid(bssid)

        def keep(line):
            record = self._parse_pot_line(line)
            if not record:
                return True
            identity_matches = (
                self._compact_bssid(record.get('bssid')) == compact_bssid
                if compact_bssid else record.get('essid') == essid
            )
            password_matches = not pwd or record.get('password') == pwd
            return not (identity_matches and password_matches)

        for path in (self.potfile_manual, self.potfile_ohc, self.potfile_handshake_lab):
            if not os.path.exists(path):
                continue
            original, _ = self._read_pot_lines(path)
            lines = [line for line in original if keep(line)]
            deleted = deleted or len(lines) != len(original)
            if len(lines) != len(original):
                self._write_pot_lines(path, lines)
        return deleted

    def _update_password(self, essid, pwd, bssid=None, old_password=None):
        if not old_password:
            return False, 'The existing password was not supplied'
        ok, message = self._add_manual_password(essid, bssid, pwd)
        if not ok:
            return False, message
        self._delete_password(essid, old_password, None, bssid)
        return True, message.replace('password saved', 'password updated')

    def _credential_rejection_key(self, bssid, password):
        compact_bssid = self._compact_bssid(bssid)
        if not compact_bssid or compact_bssid == '000000000000':
            return ''
        payload = (
            compact_bssid + '\0' + str(password or '')
        ).encode('utf-8', errors='surrogatepass')
        return hashlib.sha256(payload).hexdigest()

    def _conflict_repair_payload(self, compact_bssid, job):
        return {
            'ok': True,
            'bssid': self._format_bssid(compact_bssid),
            'status': str(job.get('status') or 'running'),
            'message': str(
                job.get('message')
                or 'Local password verification is running'
            ),
            'current': int(job.get('current', 0) or 0),
            'total': int(job.get('total', 0) or 0),
        }

    def _update_conflict_repair_job(self, compact_bssid, **updates):
        with self.conflict_repair_lock:
            job = self.conflict_repair_jobs.get(compact_bssid)
            if not job:
                return
            job.update(updates)
            job['updated_at'] = int(time.time())

    def _start_password_conflict_repair(self, bssid):
        compact_bssid = self._compact_bssid(bssid)
        if not compact_bssid or compact_bssid == '000000000000':
            return False, {
                'ok': False,
                'message': 'A real BSSID is required for local verification',
            }

        with self.conflict_repair_lock:
            existing = self.conflict_repair_jobs.get(compact_bssid)
            if existing and existing.get('status') == 'running':
                return True, self._conflict_repair_payload(
                    compact_bssid,
                    existing,
                )
            now = int(time.time())
            self.conflict_repair_jobs[compact_bssid] = {
                'status': 'running',
                'message': 'Loading local password candidates...',
                'current': 0,
                'total': 0,
                'started_at': now,
                'updated_at': now,
            }
            if len(self.conflict_repair_jobs) > 32:
                completed = sorted(
                    (
                        (key, value)
                        for key, value in self.conflict_repair_jobs.items()
                        if value.get('status') != 'running'
                    ),
                    key=lambda item: int(
                        item[1].get('updated_at', 0) or 0
                    ),
                )
                for key, _ in completed[
                    :max(0, len(self.conflict_repair_jobs) - 32)
                ]:
                    self.conflict_repair_jobs.pop(key, None)
            payload = self._conflict_repair_payload(
                compact_bssid,
                self.conflict_repair_jobs[compact_bssid],
            )

        def progress(current, total, message):
            self._update_conflict_repair_job(
                compact_bssid,
                current=current,
                total=total,
                message=message,
            )

        def worker():
            try:
                ok, message = self._repair_password_conflict(
                    compact_bssid,
                    progress=progress,
                )
                self._update_conflict_repair_job(
                    compact_bssid,
                    status='done' if ok else 'error',
                    message=message,
                )
            except Exception as error:
                logging.exception(
                    '[A_pwmenu] Password conflict repair failed for %s',
                    self._format_bssid(compact_bssid),
                )
                self._update_conflict_repair_job(
                    compact_bssid,
                    status='error',
                    message=f'Local verification failed: {error}',
                )

        threading.Thread(
            target=worker,
            daemon=True,
            name='pwmenu-password-conflict-repair',
        ).start()
        return True, payload

    def _password_conflict_repair_status(self, bssid):
        compact_bssid = self._compact_bssid(
            urllib.parse.unquote(str(bssid or ''))
        )
        with self.conflict_repair_lock:
            job = self.conflict_repair_jobs.get(compact_bssid)
            if not job:
                return self._json_response(
                    {
                        'ok': False,
                        'message': 'Password verification job was not found',
                    },
                    404,
                )
            payload = self._conflict_repair_payload(
                compact_bssid,
                dict(job),
            )
        return self._json_response(payload)

    def _repair_password_conflict(self, bssid, progress=None):
        compact_bssid = self._compact_bssid(bssid)
        if not compact_bssid or compact_bssid == '000000000000':
            return False, 'A real BSSID is required for local verification'

        with self.password_verify_lock:
            cracked = self._get_cracked_data()
            candidates = {}
            for record in cracked.values():
                if self._compact_bssid(record.get('bssid')) != compact_bssid:
                    continue
                password = str(record.get('password') or '')
                if password:
                    candidates.setdefault(
                        password,
                        str(record.get('essid') or ''),
                    )
            if len(candidates) < 2:
                return True, 'The password conflict is already resolved'

            verified = []
            conclusive_failures = []
            inconclusive = []
            total = len(candidates)
            for index, (password, essid) in enumerate(
                candidates.items(),
                start=1,
            ):
                if progress:
                    progress(
                        index,
                        total,
                        f'Checking local candidate {index} of {total}...',
                    )
                ok, detail = self._verify_manual_password(
                    essid,
                    compact_bssid,
                    password,
                )
                if ok:
                    verified.append(password)
                elif re.search(
                    r'cannot be verified|could not be verified|no matching capture',
                    str(detail),
                    re.IGNORECASE,
                ):
                    inconclusive.append(password)
                else:
                    conclusive_failures.append(password)

            if len(verified) != 1:
                if not verified and inconclusive:
                    return (
                        False,
                        'No password was changed: the local capture has no '
                        'usable hash for conclusive verification',
                    )
                if len(verified) > 1:
                    return (
                        False,
                        'No password was changed: multiple passwords match '
                        'different local captures for this BSSID',
                    )
                return (
                    False,
                    'No password was changed: none of the candidates matched '
                    'the local capture',
                )
            if inconclusive:
                return (
                    False,
                    'No password was changed: one candidate matched, but '
                    'another could not be checked conclusively',
                )

            confirmed = verified[0]
            rejected = list(conclusive_failures)
            rejection_keys = {
                self._credential_rejection_key(compact_bssid, password)
                for password in rejected
            }
            rejection_keys.discard('')
            confirmed_key = self._credential_rejection_key(
                compact_bssid,
                confirmed,
            )
            with self.data_lock:
                stored = set(
                    self.data.setdefault('credential_rejections', [])
                )
                stored.update(rejection_keys)
                stored.discard(confirmed_key)
                self.data['credential_rejections'] = sorted(stored)

            for password in rejected:
                self._delete_password(
                    '',
                    password,
                    bssid=compact_bssid,
                )
            self._save_data()
            self._invalidate_web_data_cache(credentials=True)
            self._record_action(
                'password',
                'Password conflict repaired',
                (
                    f'{self._format_bssid(compact_bssid)}: one locally '
                    f'verified credential kept, {len(rejected)} rejected'
                ),
            )
            return (
                True,
                f'Conflict repaired: one verified password kept and '
                f'{len(rejected)} invalid candidate(s) rejected',
            )

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

    def _whitelist_block_bounds(self, lines):
        for index, line in enumerate(lines):
            if line.lstrip().startswith('#'):
                continue
            if not re.match(r'^\s*main\.whitelist\s*=', line):
                continue
            value = line.split('=', 1)[1]
            if re.search(r'\]\s*(?:#.*)?$', value):
                return index, index
            for end in range(index + 1, len(lines)):
                if re.match(r'^\s*\]\s*(?:#.*)?$', lines[end]):
                    return index, end
            raise ValueError('main.whitelist has no closing bracket')
        return None

    def _read_config_whitelist(self):
        try:
            with open(self.config_path, 'r', encoding='utf-8') as handle:
                lines = handle.readlines()
            bounds = self._whitelist_block_bounds(lines)
            if bounds is None:
                return [], False
            start, end = bounds
            value = ''.join(lines[start:end + 1]).split('=', 1)[1].strip()
            parsed = ast.literal_eval(value)
            if not isinstance(parsed, (list, tuple)):
                raise ValueError('main.whitelist is not an array')
            names = [str(item).strip() for item in parsed if str(item).strip()]
            return list(dict.fromkeys(names)), True
        except (OSError, SyntaxError, ValueError, TypeError) as error:
            logging.warning(f"[A_pwmenu] Could not read whitelist from config: {error}")
            return [], False

    def _runtime_whitelist(self):
        try:
            values = self._agent._config.get('main', {}).get('whitelist', []) if self._agent else []
            return list(dict.fromkeys(str(item).strip() for item in values if str(item).strip()))
        except (AttributeError, TypeError):
            return []

    def _get_whitelist(self):
        names, configured = self._read_config_whitelist()
        if not configured:
            names = self._runtime_whitelist()
        return sorted(names, key=str.casefold)

    def _write_whitelist_config(self, names):
        with open(self.config_path, 'r', encoding='utf-8') as handle:
            text = handle.read()
        newline = '\r\n' if '\r\n' in text else '\n'
        lines = text.splitlines(keepends=True)
        block = ['main.whitelist = [' + newline]
        block.extend(f"  {json.dumps(name, ensure_ascii=False)}," + newline for name in names)
        block.extend([']' + newline, newline])

        bounds = self._whitelist_block_bounds(lines)
        if bounds is not None:
            start, end = bounds
            lines[start:end + 1] = block
        else:
            insert_at = next(
                (index for index, line in enumerate(lines) if line.startswith('# Whitelist temporarily disabled')),
                None,
            )
            if insert_at is None:
                insert_at = next(
                    (index + 1 for index, line in enumerate(lines) if re.match(r'^\s*main\.name\s*=', line)),
                    0,
                )
            lines[insert_at:insert_at] = block

        directory = os.path.dirname(self.config_path)
        original_stat = os.stat(self.config_path)
        backup_path = self.config_path + '.pwmenu-whitelist.bak'
        shutil.copy2(self.config_path, backup_path)
        fd, temporary_path = tempfile.mkstemp(prefix='.config.toml.pwmenu-', dir=directory)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8', newline='') as handle:
                handle.write(''.join(lines))
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_path, original_stat.st_mode)
            try:
                if not hasattr(os, 'chown'):
                    raise PermissionError
                os.chown(temporary_path, original_stat.st_uid, original_stat.st_gid)
            except PermissionError:
                pass
            os.replace(temporary_path, self.config_path)
            try:
                directory_fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        finally:
            if os.path.exists(temporary_path):
                os.remove(temporary_path)

    def _set_runtime_whitelist(self, names):
        if not self._agent:
            return
        try:
            self._agent._config.setdefault('main', {})['whitelist'] = list(names)
        except (AttributeError, TypeError) as error:
            logging.warning(f"[A_pwmenu] Could not update runtime whitelist: {error}")

    def _repair_whitelist_aliases(self):
        """Replace punctuation-stripped aliases only when one exact recovered SSID is known."""
        try:
            current = self._get_whitelist()
            if not current:
                return 0
            canonical = {}
            exact_names = set()
            for record in self._get_cracked_data().values():
                essid = str(record.get('essid') or '').strip()
                if essid:
                    exact_names.add(essid)
            identities, _, _ = self._load_ohc_export_snapshot()
            for identity in identities:
                if '|' in identity:
                    essid = identity.split('|', 1)[1].strip()
                    if essid:
                        exact_names.add(essid)
            with self.data_lock:
                quality_records = list(
                    getattr(self, 'data', {}).get('capture_quality', {}).values()
                )
            for record in quality_records:
                essid = str((record or {}).get('essid') or '').strip()
                if essid:
                    exact_names.add(essid)
            for essid in exact_names:
                key = self._normalized_essid_key(essid)
                if essid and key:
                    canonical.setdefault(key, set()).add(essid)
            repaired = []
            changed = 0
            for name in current:
                candidates = canonical.get(self._normalized_essid_key(name), set())
                replacement = next(iter(candidates)) if len(candidates) == 1 else name
                changed += int(replacement != name)
                if replacement not in repaired:
                    repaired.append(replacement)
                elif replacement == name:
                    changed += 1
            repaired = sorted(repaired, key=str.casefold)
            if repaired != current:
                self._write_whitelist_config(repaired)
                self._set_runtime_whitelist(repaired)
                logging.info(
                    f"[A_pwmenu] Repaired {changed} punctuation-stripped whitelist alias(es)"
                )
            return changed
        except (OSError, ValueError, TypeError) as error:
            logging.warning(f"[A_pwmenu] Could not repair whitelist aliases: {error}")
            return 0

    def _canonical_whitelist_name(self, name, bssid):
        value = self._validate_whitelist_name(name)
        compact_bssid = self._compact_bssid(bssid)
        if not compact_bssid:
            return value, False

        cracked = self._get_cracked_data()
        matches = [
            record for record in cracked.values()
            if self._compact_bssid(record.get('bssid')) == compact_bssid
            and str(record.get('essid') or '').strip()
        ]
        if matches:
            return self._validate_whitelist_name(matches[-1]['essid']), True

        for directory in self.handshake_dirs:
            if not os.path.isdir(directory):
                continue
            for path in glob.glob(os.path.join(directory, '*.pcap')):
                _, file_bssid = self._handshake_identity(path)
                if file_bssid != compact_bssid:
                    continue
                quality = self._quality_file_record(os.path.basename(path), path)
                if not quality.get('essid'):
                    _, quality = self._run_capture_analysis(path)
                exact = str(quality.get('essid') or '').strip()
                quality_bssid = self._compact_bssid(quality.get('bssid'))
                if exact and (not quality_bssid or quality_bssid == compact_bssid):
                    return self._validate_whitelist_name(exact), True
        return value, False

    def _validate_whitelist_name(self, name):
        value = str(name or '').strip()
        if not value:
            raise ValueError('Enter a network name')
        if len(value) > 128:
            raise ValueError('Network name is too long')
        if any(char in value for char in ('\x00', '\r', '\n')):
            raise ValueError('Network name contains unsupported characters')
        return value

    def _add_to_whitelist(self, name, bssid=''):
        try:
            value, resolved = self._canonical_whitelist_name(name, bssid)
            with self.whitelist_lock:
                names = self._get_whitelist()
                original = list(names)
                if resolved:
                    key = self._normalized_essid_key(value)
                    names = [
                        item for item in names
                        if self._normalized_essid_key(item) != key
                    ]
                if value in names:
                    return False, f"{value} is already in the whitelist"
                names.append(value)
                names = sorted(dict.fromkeys(names), key=str.casefold)
                if names == original:
                    return False, f"{value} is already in the whitelist"
                self._write_whitelist_config(names)
                self._set_runtime_whitelist(names)
            self._invalidate_web_data_cache()
            self._record_action(
                'whitelist',
                f'Whitelist added: {value}',
                'Applied to the running Pwnagotchi session',
            )
            logging.info(f"[A_pwmenu] Added network to whitelist: {value}")
            return True, f"Added {value} to the whitelist"
        except (OSError, ValueError) as error:
            logging.error(f"[A_pwmenu] Could not add whitelist entry: {error}")
            return False, str(error)

    def _add_excellent_to_whitelist(self, requested_names, groups=None):
        try:
            if not isinstance(requested_names, (list, tuple)):
                raise ValueError('Network list must be an array')
            if len(requested_names) > 256:
                raise ValueError('Too many networks in one whitelist request')

            requested = []
            for name in requested_names:
                value = self._validate_whitelist_name(name)
                if value not in requested:
                    requested.append(value)
            if not requested:
                raise ValueError('No networks selected')

            if groups is None:
                groups = self._scan_and_group_files(self._get_cracked_data())
            excellent = {
                str(group.get('essid') or '').strip()
                for group in (groups or [])
                if any(
                    (capture.get('quality') or {}).get('grade') == 'Excellent'
                    for capture in group.get('files', [])
                )
            }
            eligible = [name for name in requested if name in excellent]
            skipped = len(requested) - len(eligible)

            with self.whitelist_lock:
                current = self._get_whitelist()
                added = [name for name in eligible if name not in current]
                already = len(eligible) - len(added)
                if added:
                    updated = sorted(dict.fromkeys(current + added), key=str.casefold)
                    self._write_whitelist_config(updated)
                    self._set_runtime_whitelist(updated)
            if added:
                self._invalidate_web_data_cache()
                self._record_action(
                    'whitelist',
                    f'Whitelist added {len(added)} network(s)',
                    'Excellent-quality map group',
                )

            parts = []
            if added:
                parts.append(f"Added {len(added)} Excellent-quality network(s) to the whitelist")
            else:
                parts.append("No new Excellent-quality networks to whitelist")
            if already:
                parts.append(f"{already} already whitelisted")
            if skipped:
                parts.append(f"{skipped} skipped because quality is not Excellent")
            message = '; '.join(parts)
            logging.info(f"[A_pwmenu] Excellent-only group whitelist: {message}")
            return bool(added), message
        except (OSError, ValueError) as error:
            logging.error(f"[A_pwmenu] Could not whitelist Excellent-quality group: {error}")
            return False, str(error)

    def _remove_from_whitelist(self, name):
        try:
            value = self._validate_whitelist_name(name)
            with self.whitelist_lock:
                names = self._get_whitelist()
                if value not in names:
                    return False, f"{value} is not in the whitelist"
                names = [item for item in names if item != value]
                self._write_whitelist_config(names)
                self._set_runtime_whitelist(names)
            self._invalidate_web_data_cache()
            self._record_action(
                'whitelist',
                f'Whitelist removed: {value}',
                'Applied to the running Pwnagotchi session',
            )
            logging.info(f"[A_pwmenu] Removed network from whitelist: {value}")
            return True, f"Removed {value} from the whitelist"
        except (OSError, ValueError) as error:
            logging.error(f"[A_pwmenu] Could not remove whitelist entry: {error}")
            return False, str(error)

    def _is_empty_pcap(self, path):
        try:
            if os.path.getsize(path) != 24:
                return False
            with open(path, 'rb') as handle:
                magic = handle.read(4)
            return magic in (
                b'\xd4\xc3\xb2\xa1',
                b'\xa1\xb2\xc3\xd4',
                b'\x4d\x3c\xb2\xa1',
                b'\xa1\xb2\x3c\x4d',
            )
        except OSError:
            return False

    def _quality_is_uncrackable(self, quality):
        if not isinstance(quality, dict) or quality.get('grade') != 'Partial':
            return False
        try:
            return int(quality.get('hashes', 0) or 0) <= 0
        except (TypeError, ValueError):
            return True

    def _capture_cleanup_report(self, groups=None):
        entries = []
        if groups is None:
            candidates = []
            for directory in self.handshake_dirs:
                if not os.path.isdir(directory):
                    continue
                for path in sorted(glob.glob(os.path.join(directory, '*.pcap'))):
                    candidates.append((path, None, ''))
        else:
            candidates = [
                (
                    file_info.get('_path', ''),
                    file_info.get('quality') or {},
                    file_info.get('_signature', ''),
                )
                for group in groups
                for file_info in group.get('files', [])
            ]

        for path, cached_quality, cached_signature in candidates:
            if not path:
                continue
            try:
                name = os.path.basename(path)
                empty = self._is_empty_pcap(path)
                quality = (
                    cached_quality
                    if cached_quality is not None
                    else self._quality_file_record(name, path)
                )
                unusable = quality.get('grade') == 'Unusable'
                uncrackable = self._quality_is_uncrackable(quality)
                if not empty and not unusable and not uncrackable:
                    continue
                if empty:
                    reason = 'Empty PCAP header'
                    category = 'empty'
                elif uncrackable:
                    reason = (
                        quality.get('summary')
                        or 'Incomplete exchange; no usable WPA/PMKID hash'
                    )
                    category = 'uncrackable'
                else:
                    reason = (
                        quality.get('summary')
                        or 'No usable WPA/PMKID material'
                    )
                    category = 'unusable'
                entries.append({
                    'name': name,
                    'path': path,
                    'signature': (
                        cached_signature
                        or self._ohc_file_signature(path)
                    ),
                    'reason': reason,
                    'empty': empty,
                    'category': category,
                })
            except (OSError, TypeError, ValueError) as error:
                logging.debug(
                    f"[A_pwmenu] Could not inspect cleanup candidate "
                    f"{path}: {error}"
                )
        fingerprint = json.dumps(
            [(entry['path'], entry['signature'], entry['reason']) for entry in entries],
            separators=(',', ':'),
            ensure_ascii=True,
        ).encode('utf-8')
        return {
            'count': len(entries),
            'empty_count': len([entry for entry in entries if entry['empty']]),
            'uncrackable_count': len([
                entry for entry in entries
                if entry['category'] == 'uncrackable'
            ]),
            'unusable_count': len([
                entry for entry in entries
                if entry['category'] == 'unusable'
            ]),
            'display_files': entries[:12],
            'more': max(0, len(entries) - 12),
            'token': hashlib.sha256(fingerprint).hexdigest(),
            'entries': entries,
        }

    def _clean_capture_candidates(self, report_token):
        report = self._capture_cleanup_report()
        total = report['count']
        if not total:
            return (
                0,
                total,
                'No empty, uncrackable, or unusable capture files to remove',
            )
        if not report_token:
            return 0, total, 'Review the current cleanup report and confirm again.'
        if not re.fullmatch(r'[0-9a-f]{64}', report_token) or report_token != report['token']:
            return 0, total, 'Cleanup report changed. Review the current list and confirm again.'

        deleted = 0
        for entry in report['entries']:
            path = entry['path']
            if self._ohc_file_signature(path) != entry['signature']:
                continue
            quality = self._quality_file_record(entry['name'], path)
            still_uncrackable = self._quality_is_uncrackable(quality)
            if (
                not self._is_empty_pcap(path)
                and quality.get('grade') != 'Unusable'
                and not still_uncrackable
            ):
                continue
            try:
                os.remove(path)
                base = os.path.splitext(path)[0]
                for extension in ('.gps.json', '.geo.json', '.hc22000', '.22000'):
                    companion = base + extension
                    if os.path.isfile(companion):
                        os.remove(companion)
                with self.data_lock:
                    self._forget_handshake_state_locked(entry['name'], path)
                    history = self.data.setdefault('capture_cleanup_history', [])
                    history.append({
                        'file': entry['name'],
                        'reason': entry['reason'],
                        'deleted_at': int(time.time()),
                    })
                    del history[:-200]
                self._save_data()
                deleted += 1
            except OSError as error:
                logging.warning(f"[A_pwmenu] Could not remove capture {path}: {error}")
        logging.info(f"[A_pwmenu] Capture cleanup removed {deleted}/{total} file(s)")
        return (
            deleted,
            total,
            f"Removed {deleted}/{total} empty, uncrackable, or unusable capture files",
        )

    def _process_import(self, content, name):
        self._ensure_file(self.potfile_ohc)
        is_json = name.lower().endswith('.json') or content.strip().startswith('[')
        is_handshake_lab_export = False
        if is_json:
            parsed = json.loads(content)
            report = self._imp_json(parsed)
            export_tasks = self._ohc_export_tasks_from_json(parsed)
        else:
            report = self._imp_csv(content)
            export_tasks = self._ohc_export_tasks_from_csv(content)
            is_handshake_lab_export = any(
                self._is_handshake_lab_row(row) for row in export_tasks
            )
        # A Handshake Lab result import updates recovered credentials, but it is
        # not an OHC task inventory. Never let it erase the last real OHC export.
        report['ohc_tasks'] = (
            0
            if is_handshake_lab_export
            else self._store_ohc_export_snapshot(export_tasks, name)
        )
        if report['added'] > 0:
            with self.data_lock:
                self.data['xp'] += report['added'] * 100
            self._save_data()
        return report

    def _new_import_report(self):
        return {
            'added': 0,
            'already': 0,
            'duplicates': 0,
            'ignored': 0,
            'invalid': 0,
            'ohc_tasks': 0,
            'source': ''
        }

    def _ohc_export_tasks_from_json(self, data):
        if isinstance(data, dict):
            data = data.get('tasks', [])
        if not isinstance(data, list):
            return []
        return [task for task in data if isinstance(task, dict)]

    def _ohc_export_tasks_from_csv(self, content):
        try:
            return [dict(row) for row in csv.DictReader(io.StringIO(content))]
        except (csv.Error, OSError, TypeError, ValueError):
            return []

    def _ohc_export_task_identity(self, task):
        clean = html.unescape(re.sub(r'<[^>]+>', '', str(task or ''))).replace('\xa0', ' ').strip()
        match = re.search(r'((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})$', clean)
        if not match:
            return None, None
        bssid = match.group(1).lower()
        essid = clean[:match.start()].strip()
        return f"{bssid}|{essid}", bssid

    def _ohc_hash_task_identity(self, hash_line):
        essid, mac = self._wpa_hash_network(hash_line)
        if not mac:
            return None, None
        bssid = ':'.join(mac[i:i + 2] for i in range(0, 12, 2))
        return f"{bssid}|{essid}", bssid

    def _wpa_hash_network(self, hash_line):
        parts = str(hash_line or '').strip().lstrip('$').split('*')
        if len(parts) < 6 or parts[0] != 'WPA' or parts[1] not in ('01', '02'):
            return '', ''
        mac = parts[3].lower()
        if not re.fullmatch(r'[0-9a-f]{12}', mac):
            return '', ''
        try:
            essid = bytes.fromhex(parts[5]).decode('utf-8', errors='replace').strip()
        except (TypeError, ValueError):
            essid = ''
        return essid, mac

    def _ohc_hash_in_export(self, hash_line, identities, bssids):
        identity, bssid = self._ohc_hash_task_identity(hash_line)
        return bool(
            (identity and identity in identities)
            or (bssid and bssid in bssids)
        )

    def _store_ohc_export_snapshot(self, tasks, source):
        identities = set()
        bssids = set()
        for task in tasks:
            if not isinstance(task, dict):
                continue
            value = task.get('task') or task.get('Task') or task.get('SSID') or ''
            identity, bssid = self._ohc_export_task_identity(value)
            if identity:
                identities.add(identity)
                bssids.add(bssid)
        if not identities:
            return 0

        snapshot = {
            'version': 1,
            'source': os.path.basename(str(source or ''))[:200],
            'imported_at': int(time.time()),
            'tasks': len(identities),
            'identities': sorted(identities),
            'bssids': sorted(bssids)
        }
        directory = os.path.dirname(self.ohc_export_file)
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix='.a_pwmenu-ohc-export-', dir=directory)
        try:
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                fd = None
                json.dump(snapshot, handle, ensure_ascii=False, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, self.ohc_export_file)
            try:
                dir_fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
        finally:
            if fd is not None:
                os.close(fd)
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        logging.info(
            f"[A_pwmenu] Saved OHC export snapshot: {len(identities)} task(s), "
            f"{len(bssids)} BSSID(s), source={snapshot['source']}"
        )
        return len(identities)

    def _load_ohc_export_snapshot(self):
        try:
            with open(self.ohc_export_file, 'r', encoding='utf-8') as handle:
                snapshot = json.load(handle)
            if not isinstance(snapshot, dict):
                raise ValueError('snapshot root must be an object')
            identities = {
                str(value) for value in snapshot.get('identities', [])
                if isinstance(value, str) and value
            }
            bssids = {
                str(value).lower() for value in snapshot.get('bssids', [])
                if isinstance(value, str) and re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', value)
            }
            info = {
                'source': str(snapshot.get('source') or ''),
                'tasks': len(identities),
                'imported_at': int(snapshot.get('imported_at', 0) or 0)
            }
            return identities, bssids, info
        except FileNotFoundError:
            return set(), set(), {}
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            logging.warning(f"[A_pwmenu] Could not load OHC export snapshot: {error}")
            return set(), set(), {}

    def _imp_json(self, data):
        if isinstance(data, dict):
            data = data.get('tasks', [])
        if not isinstance(data, list):
            raise ValueError('JSON import must contain a task list')
        report = self._new_import_report()
        entries = []
        for task in data:
            if not isinstance(task, dict):
                report['invalid'] += 1
                continue
            if task.get('status') != 'FOUND':
                report['ignored'] += 1
                continue
            line = self._fmt_task(task.get('task', ''), task.get('password', ''))
            if line:
                entries.append(line)
            else:
                report['invalid'] += 1
        return self._merge_import_lines(entries, report)

    def _imp_csv(self, txt):
        report = self._new_import_report()
        entries = []
        handshake_lab_entries = []
        try:
            reader = csv.DictReader(io.StringIO(txt))
            for row in reader:
                status = row.get('status') or row.get('Status')
                password = row.get('password') or row.get('Password')
                task = row.get('task') or row.get('Task') or row.get('SSID')
                if str(status or '').upper() != 'FOUND':
                    report['ignored'] += 1
                    continue
                is_handshake_lab = self._is_handshake_lab_row(row)
                line = self._fmt_structured_task(row, password) if is_handshake_lab else None
                if not line:
                    line = self._fmt_task(task, password)
                if line:
                    if is_handshake_lab:
                        handshake_lab_entries.append(line)
                        report['source'] = 'Handshake Lab'
                    else:
                        entries.append(line)
                else:
                    report['invalid'] += 1
        except (csv.Error, OSError, TypeError, ValueError) as e:
            logging.error(f"[A_pwmenu] CSV import failed: {e}")
            raise ValueError(f"CSV import failed: {e}")
        self._merge_import_lines(entries, report, self.potfile_ohc)
        self._merge_import_lines(
            handshake_lab_entries,
            report,
            self.potfile_handshake_lab,
        )
        return report

    def _is_handshake_lab_row(self, row):
        source = str(row.get('source') or row.get('Source') or '')
        version = str(row.get('format_version') or row.get('Format Version') or '')
        return (
            'handshake lab' in source.casefold()
            or version.casefold().startswith('newfpv-handshake-lab-results-')
        )

    def _fmt_structured_task(self, row, password):
        essid = row.get('essid')
        if essid is None:
            essid = row.get('ESSID')
        bssid = row.get('bssid')
        if bssid is None:
            bssid = row.get('BSSID')
        mac = self._colon_bssid(bssid)
        if essid is None or not mac or not password:
            return None
        return f"{mac}:{mac}:{str(essid)}:{str(password)}"

    def _fmt_task(self, task, password):
        if not task or not password:
            return None
        clean_task = html.unescape(re.sub(r'<[^>]+>', '', str(task))).replace('\xa0', ' ').strip()
        return self._fmt(clean_task, str(password))

    def _fmt(self, t, p):
        if len(t) > 17:
            mac = t[-17:]
            if re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', mac):
                return f"{mac}:{mac}:{t[:-17]}:{p}"
        return None

    def _parse_pot_line(self, line):
        value = line or ''
        mac = r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'
        match = re.fullmatch(
            rf'({mac}):({mac}):(.*?):(.*)',
            value,
        )
        if not match:
            # WPA-sec's downloadable potfile uses compact 12-hex MAC fields:
            # BSSID:STATION:ESSID:PASSWORD. Preserve the exact AP identity
            # instead of falling back to an ESSID-only credential.
            match = re.fullmatch(
                r'([0-9A-Fa-f]{12}):([0-9A-Fa-f]{12}):(.*?):(.*)',
                value,
            )
        if not match:
            return None
        return {
            'bssid': self._colon_bssid(match.group(1)),
            'station': self._colon_bssid(match.group(2)),
            'essid': match.group(3),
            'password': match.group(4),
        }

    def _pot_line_key(self, line):
        record = self._parse_pot_line(line)
        if record:
            return record['bssid'], record['essid'], record['password']
        return 'raw', line

    def _credential_key(self, line):
        record = self._parse_pot_line(line)
        if not record:
            return 'raw', line
        bssid = self._compact_bssid(record.get('bssid'))
        if bssid and bssid != '000000000000':
            return 'bssid', bssid, record['password']
        return 'essid', self._normalized_essid_key(record.get('essid')), record['password']

    def _read_pot_lines(self, path):
        if not os.path.exists(path):
            return [], b''
        with self.potfile_lock:
            with open(path, 'rb') as handle:
                raw = handle.read()
        text = raw.replace(b'\0', b'').decode('utf-8', errors='ignore')
        lines = [line.strip('\r\n') for line in text.splitlines() if line.strip('\r\n')]
        return lines, raw

    def _dedupe_pot_lines(self, lines):
        unique = []
        keys = set()
        duplicates = 0
        for line in lines:
            clean = line.replace('\0', '')
            if not clean:
                continue
            key = self._pot_line_key(clean)
            if key in keys:
                duplicates += 1
                continue
            keys.add(key)
            unique.append(clean)
        return unique, keys, duplicates

    def _write_pot_lines(self, path, lines):
        payload = ('\n'.join(lines) + ('\n' if lines else '')).encode('utf-8')
        directory = os.path.dirname(path)
        os.makedirs(directory, exist_ok=True)
        with self.potfile_lock:
            fd, tmp_path = tempfile.mkstemp(prefix='.pwmenu-pot-', dir=directory)
            os.close(fd)
            try:
                try:
                    os.chmod(tmp_path, 0o644)
                except OSError:
                    pass
                with open(tmp_path, 'wb') as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_path, path)
                try:
                    flags = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)
                    dir_fd = os.open(directory, flags)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except OSError:
                    pass
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
        self._invalidate_web_data_cache(credentials=True)

    def _normalize_potfile(self, path):
        try:
            with self.potfile_lock:
                lines, raw = self._read_pot_lines(path)
                unique, _, duplicates = self._dedupe_pot_lines(lines)
                expected = ('\n'.join(unique) + ('\n' if unique else '')).encode('utf-8')
                if raw != expected:
                    self._write_pot_lines(path, unique)
                    logging.info(
                        f"[A_pwmenu] Normalized potfile {os.path.basename(path)}: "
                        f"{raw.count(bytes([0]))} NUL byte(s), {duplicates} duplicate(s) removed"
                    )
            return self._potfile_health(path)
        except OSError as e:
            logging.warning(f"[A_pwmenu] Could not normalize potfile {path}: {e}")
            return self._potfile_health(path)

    def _potfile_health(self, path):
        try:
            lines, raw = self._read_pot_lines(path)
            unique, _, duplicates = self._dedupe_pot_lines(lines)
            invalid = sum(1 for line in unique if not self._parse_pot_line(line))
            nul_bytes = raw.count(bytes([0]))
            return {
                'ok': nul_bytes == 0 and duplicates == 0 and invalid == 0,
                'credentials': len(unique) - invalid,
                'lines': len(lines),
                'duplicates': duplicates,
                'invalid': invalid,
                'nul_bytes': nul_bytes,
                'bytes': len(raw)
            }
        except OSError as e:
            return {
                'ok': False, 'credentials': 0, 'lines': 0, 'duplicates': 0,
                'invalid': 0, 'nul_bytes': 0, 'bytes': 0, 'error': str(e)
            }

    def _merge_import_lines(self, entries, report, destination=None):
        destination = destination or self.potfile_ohc
        if not entries:
            return report
        with self.potfile_lock:
            self._normalize_potfile(destination)
            existing_lines, _ = self._read_pot_lines(destination)
            existing_lines, _, _ = self._dedupe_pot_lines(existing_lines)
            existing_keys = {self._credential_key(line) for line in existing_lines}
            input_keys = set()
            additions = []
            for line in entries:
                key = self._credential_key(line)
                if key in input_keys:
                    report['duplicates'] += 1
                    continue
                input_keys.add(key)
                if key in existing_keys:
                    report['already'] += 1
                    continue
                existing_keys.add(key)
                additions.append(line)
            if additions:
                self._write_pot_lines(destination, existing_lines + additions)
        report['added'] += len(additions)
        return report

    def _read_pot(self, p):
        lines, _ = self._read_pot_lines(p)
        clean, _, _ = self._dedupe_pot_lines(lines)
        return set(clean)

    def _serve_zip(self):
        m = self._new_archive_buffer()
        candidates = {}
        for directory in self.handshake_dirs:
            if not os.path.exists(directory):
                continue
            for path in glob.glob(os.path.join(directory, '*.pcap')):
                name = os.path.basename(path)
                previous = candidates.get(name)
                if (
                    previous is None
                    or self._capture_export_score(path)
                    > self._capture_export_score(previous)
                ):
                    candidates[name] = path
        best_paths = self._best_capture_paths_by_ap(
            list(candidates.values())
        )
        with zipfile.ZipFile(m, 'w', zipfile.ZIP_DEFLATED) as z:
            for path in sorted(
                best_paths,
                key=lambda item: os.path.basename(item).casefold(),
            ):
                z.write(path, os.path.basename(path))
        m.seek(0)
        return send_file(m, mimetype='application/zip', as_attachment=True, download_name='handshakes.zip')

    def _serve_uncracked_zip(self):
        m = self._new_archive_buffer()
        with zipfile.ZipFile(m, 'w', zipfile.ZIP_DEFLATED) as z:
            for path, name in self._uncracked_export_files():
                z.write(path, name)
        m.seek(0)
        return send_file(m, mimetype='application/zip', as_attachment=True, download_name='uncracked-handshakes.zip')

    def _source_directory_entries(self, directory):
        """Return lightweight file metadata with a short, safe inventory cache."""
        real_directory = os.path.realpath(directory)
        try:
            directory_stat = os.stat(directory)
            directory_signature = (
                directory_stat.st_mtime_ns,
                directory_stat.st_ctime_ns,
                directory_stat.st_size,
            )
        except OSError:
            return {}

        now = time.monotonic()
        maximum_age = max(
            0,
            self._option_int('web_inventory_cache_seconds', 30),
        )
        with self.source_inventory_cache_lock:
            cached = self.source_inventory_cache.get(real_directory)
            if (
                cached
                and cached['signature'] == directory_signature
                and maximum_age
                and now - cached['checked_at'] <= maximum_age
            ):
                return cached['entries']

        entries = {}
        try:
            with os.scandir(directory) as iterator:
                candidates = {
                    entry.name: entry
                    for entry in iterator
                    if (
                        entry.name.endswith('.pcap')
                        or entry.name.endswith('.pcap.cracked')
                        or entry.name.endswith('.json')
                    )
                }
                names = tuple(sorted(candidates))
                for name, entry in candidates.items():
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    try:
                        stat = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    entries[name] = (
                        entry.path,
                        stat.st_mtime_ns,
                        stat.st_size,
                    )
        except OSError as error:
            logging.debug(
                f"[A_pwmenu] Could not inventory {directory}: {error}"
            )
            return {}

        with self.source_inventory_cache_lock:
            self.source_inventory_cache[real_directory] = {
                'signature': directory_signature,
                'names': names,
                'checked_at': now,
                'entries': entries,
            }
        return entries

    def _quickdic_result_paths(self):
        paths = []
        seen_directories = set()
        for directory in self.handshake_dirs:
            real_directory = os.path.realpath(directory)
            if real_directory in seen_directories or not os.path.isdir(directory):
                continue
            seen_directories.add(real_directory)
            paths.extend(
                metadata[0]
                for name, metadata in self._source_directory_entries(
                    directory
                ).items()
                if name.endswith('.pcap.cracked')
            )
        return sorted(paths)

    def _capture_source_revision(self):
        """Fingerprint PCAPs and their possible GPS sidecars with one scan."""
        metadata = []
        seen_directories = set()
        for directory in self.handshake_dirs:
            real_directory = os.path.realpath(directory)
            if real_directory in seen_directories or not os.path.isdir(directory):
                continue
            seen_directories.add(real_directory)
            entries = self._source_directory_entries(directory)

            pcap_names = sorted(
                name for name in entries if name.endswith('.pcap')
            )
            relevant_names = set(pcap_names)
            for name in pcap_names:
                base = os.path.splitext(name)[0]
                relevant_names.update((
                    name + '.gps.json',
                    name + '.geo.json',
                    name + '.json',
                    base + '.gps.json',
                    base + '.geo.json',
                    base + '.json',
                ))
            for name in sorted(relevant_names):
                file_metadata = entries.get(name)
                if file_metadata is None:
                    continue
                _, modified_ns, size = file_metadata
                metadata.append(
                    f"{real_directory}:{name}:{modified_ns}:{size}"
                )
        return hashlib.sha256(
            '\n'.join(metadata).encode('utf-8')
        ).hexdigest()

    def _credential_source_revision(self):
        """Fingerprint credential files by metadata without reading passwords."""
        now = time.monotonic()
        maximum_age = max(
            0,
            self._option_int('web_credential_cache_seconds', 10),
        )
        with self.credential_cache_lock:
            if (
                self.credential_revision_value is not None
                and maximum_age
                and now - self.credential_revision_checked_at <= maximum_age
            ):
                return self.credential_revision_value

        paths = [
            self.potfile_ohc,
            self.potfile_handshake_lab,
            self.potfile_manual,
        ] + self._wpa_potfile_paths()
        paths.extend(self._quickdic_result_paths())
        metadata = []
        for path in sorted(set(paths)):
            try:
                stat = os.stat(path)
                metadata.append(
                    f"{os.path.realpath(path)}:{stat.st_mtime_ns}:{stat.st_size}"
                )
            except OSError:
                continue
        revision = hashlib.sha256(
            '\n'.join(metadata).encode('utf-8')
        ).hexdigest()
        with self.credential_cache_lock:
            self.credential_revision_value = revision
            self.credential_revision_checked_at = now
        return revision

    def _known_passwords_for_capture(self, cracked, essid, bssid):
        compact_bssid = self._compact_bssid(bssid)
        matches = []
        if compact_bssid:
            matches = [
                record for record in cracked.values()
                if self._compact_bssid(record.get('bssid')) == compact_bssid
            ]
        else:
            normalized = self._normalized_essid_key(essid)
            matches = [
                record for record in cracked.values()
                if (
                    not self._compact_bssid(record.get('bssid'))
                    and self._normalized_essid_key(record.get('essid')) == normalized
                )
            ]
        passwords = []
        for record in matches:
            password = str(record.get('password') or '')
            if (
                password
                and '\x00' not in password
                and '\r' not in password
                and '\n' not in password
                and password not in passwords
            ):
                passwords.append(password)
        exact_essid = next(
            (
                str(record.get('essid') or '').strip()
                for record in reversed(matches)
                if str(record.get('essid') or '').strip()
            ),
            essid,
        )
        return passwords, exact_essid

    def _capture_has_known_password(self, path, cracked=None):
        essid, bssid = self._capture_export_network(path)
        passwords, _ = self._known_passwords_for_capture(
            cracked if cracked is not None else self._get_cracked_data(),
            essid,
            bssid,
        )
        return bool(passwords)

    def _capture_is_crackable(self, path):
        name = os.path.basename(path)
        quality = self._quality_file_record(name, path)
        if not quality:
            hashes, quality = self._run_capture_analysis(path)
            return bool(hashes)
        try:
            return int(quality.get('hashes', 0) or 0) > 0
        except (TypeError, ValueError):
            return False

    def _verify_capture_passwords(self, path, essid, bssid, passwords, credential_revision):
        """Return (verified, cache_changed) after an aircrack-ng dictionary check."""
        if not passwords:
            return False, False
        name = os.path.basename(path)
        capture_signature = self._ohc_file_signature(path)
        with self.data_lock:
            cached = dict(
                self.data.setdefault('capture_password_checks', {}).get(name, {}) or {}
            )
        if (
            cached.get('capture_signature') == capture_signature
            and cached.get('credential_revision') == credential_revision
            and cached.get('tool') == 'aircrack-ng'
        ):
            return bool(cached.get('verified')), False

        verified, conclusive, detail = self._run_aircrack_password_check(
            path, essid, bssid, passwords
        )
        if not conclusive:
            logging.warning(
                f"[A_pwmenu] aircrack-ng could not conclusively verify "
                f"{name}; keeping it exportable: {detail}"
            )
            return False, False
        with self.data_lock:
            self.data.setdefault('capture_password_checks', {})[name] = {
                'capture_signature': capture_signature,
                'credential_revision': credential_revision,
                'verified': verified,
                'candidate_count': len(passwords),
                'tool': 'aircrack-ng',
                'checked_at': int(time.time()),
            }
        return verified, True

    def _capture_export_score(self, path):
        name = os.path.basename(path)
        quality = self._quality_file_record(name, path)
        def metric(field, default=0):
            try:
                return int(quality.get(field, default))
            except (TypeError, ValueError):
                return default
        try:
            stat = os.stat(path)
            modified = float(stat.st_mtime)
            size = int(stat.st_size)
        except OSError:
            modified, size = 0.0, 0
        return (
            metric('rank', -1),
            metric('hashes'),
            metric('authorized'),
            metric('best_pairs'),
            modified,
            size,
        )

    def _capture_export_network(self, path):
        """Resolve the AP identity from capture data when its filename is incomplete."""
        name = os.path.basename(path)
        essid, bssid = self._handshake_identity(name)
        quality = self._quality_file_record(name, path)
        quality_bssid = self._compact_bssid(quality.get('bssid'))
        quality_essid = str(quality.get('essid') or '').strip()

        # Older quality records did not persist ESSID/BSSID. Refresh only the
        # ambiguous filenames so normal exports do not reconvert every PCAP.
        if not bssid and not quality_bssid:
            _, refreshed = self._run_capture_analysis(path)
            if refreshed:
                quality = refreshed
                quality_bssid = self._compact_bssid(quality.get('bssid'))
                quality_essid = str(quality.get('essid') or '').strip()

        if quality_bssid:
            bssid = quality_bssid
            if quality_essid:
                essid = quality_essid
        elif quality_essid and not essid:
            essid = quality_essid
        return essid, bssid

    def _uncracked_export_files(self):
        """Export every crackable unresolved AP, using its best remaining capture."""
        cracked = self._get_cracked_data()
        selected = {}
        with self.password_verify_lock:
            paths_by_name = {}
            for directory in self.handshake_dirs:
                if not os.path.exists(directory):
                    continue
                for path in glob.glob(os.path.join(directory, '*.pcap')):
                    name = os.path.basename(path)
                    current = paths_by_name.get(name)
                    if (
                        current is None
                        or self._capture_export_score(path)
                        > self._capture_export_score(current)
                    ):
                        paths_by_name[name] = path

            for name, path in paths_by_name.items():
                if not self._capture_is_crackable(path):
                    continue
                essid, bssid = self._capture_export_network(path)
                passwords, _ = self._known_passwords_for_capture(
                    cracked, essid, bssid
                )
                # A recovered credential for this exact BSSID already makes
                # the AP resolved for Handshake Lab. Re-exporting another
                # capture only creates duplicate Recovered cards there.
                if passwords:
                    continue

                # BSSID is the AP identity even if its ESSID or filename
                # changed. Without one, keep files separate conservatively.
                identity = ('bssid', bssid) if bssid else ('file', name)
                score = self._capture_export_score(path)
                current = selected.get(identity)
                if current is None or score > current[0]:
                    selected[identity] = (score, path, name)

        files = [(item[1], item[2]) for item in selected.values()]
        files.sort(key=lambda item: item[1].casefold())
        return files

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

        selected_paths = []
        for name in safe_names:
            path = self._find_handshake_path(name)
            if path:
                selected_paths.append(path)
        selected_paths = self._best_capture_paths_by_ap(
            selected_paths
        )
        m = self._new_archive_buffer()
        with zipfile.ZipFile(m, 'w', zipfile.ZIP_DEFLATED) as z:
            for path in selected_paths:
                z.write(path, os.path.basename(path))
        m.seek(0)
        return send_file(m, mimetype='application/zip', as_attachment=True, download_name='cluster-handshakes.zip')

    def _serve_password_list(self):
        cracked = self._get_cracked_data()
        seen = set()
        rows = []
        for record in cracked.values():
            value = (
                str(record.get('essid') or ''),
                self._format_bssid(str(record.get('bssid') or '')),
                str(record.get('password') or ''),
                str(record.get('source') or ''),
            )
            identity = value[:3]
            if not value[0] or not value[2] or identity in seen:
                continue
            seen.add(identity)
            rows.append(value)
        rows.sort(key=lambda row: (
            row[0].casefold(), row[1].casefold(), row[2]
        ))

        output = io.StringIO(newline='')
        writer = csv.writer(
            output,
            dialect='excel-tab',
            lineterminator='\r\n',
            quoting=csv.QUOTE_MINIMAL,
        )
        writer.writerow(('ESSID', 'BSSID', 'PASSWORD', 'SOURCE'))
        writer.writerows(rows)
        payload = b'\xef\xbb\xbf' + output.getvalue().encode('utf-8')
        return send_file(
            io.BytesIO(payload),
            mimetype='text/plain',
            as_attachment=True,
            download_name='pwmenu-passwords.txt',
        )

    def _serve_file(self, name):
        safe_name = self._safe_handshake_name(name)
        fp = self._find_handshake_path(safe_name)
        if fp:
            fp = self._best_capture_for_path(fp)
            return send_file(
                fp,
                as_attachment=True,
                download_name=os.path.basename(fp),
            )
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
        quality_pending = []
        credential_lookup = self._build_credential_lookup(cracked)
        with self.data_lock:
            seen_files = dict(self.data.setdefault('seen_files', {}))
        # Rendering the page must never wait on a GPSD socket. The UI/display
        # loop and on_handshake keep this cache warm when GPSD is available.
        live_gps = self._fresh_live_gps(poll_gpsd=False)
        try:
            tz_offset = int(self.options.get('timezone', 0))
        except (TypeError, ValueError):
            tz_offset = 0

        for directory in self.handshake_dirs:
            if not os.path.isdir(directory):
                continue
            try:
                with os.scandir(directory) as iterator:
                    capture_entries = sorted(
                        (
                            entry for entry in iterator
                            if (
                                entry.name.endswith('.pcap')
                                and entry.is_file()
                            )
                        ),
                        key=lambda entry: entry.name,
                    )
            except OSError as error:
                logging.warning(
                    f"[A_pwmenu] Could not scan handshake directory "
                    f"{directory}: {error}"
                )
                continue
            for entry in capture_entries:
                path = entry.path
                try:
                    fn = entry.name
                    st = entry.stat()
                    es, bs = self._handshake_identity(fn)
                    credential = self._find_cracked_record(
                        cracked, es, bs, credential_lookup
                    )
                    quality = self._quality_file_record(fn, path)
                    quality_essid = str(quality.get('essid') or '').strip()
                    quality_bssid = self._compact_bssid(quality.get('bssid'))
                    if quality_bssid and bs and quality_bssid != bs:
                        quality_essid = ''
                    resolved_bssid = (
                        quality_bssid
                        if quality_bssid and (not bs or quality_bssid == bs)
                        else bs
                    )
                    group_key = (
                        ('bssid', resolved_bssid)
                        if resolved_bssid else ('essid', es)
                    )
                    if group_key not in grps:
                        display_essid = (
                            credential.get('essid')
                            if credential
                            else quality_essid or es
                        )
                        grps[group_key] = {
                            'essid': display_essid or es,
                            'capture_essid': es,
                            'bssid': resolved_bssid,
                            'files': [],
                            'ts': 0,
                            'is_cracked': bool(credential),
                            'pwd': credential.get('password', '') if credential else '',
                            'src': credential.get('source', '') if credential else '',
                            'lat': None,
                            'lon': None,
                            'gps_source': ''
                        }
                    group = grps[group_key]

                    date_str = get_local_time(st.st_mtime, tz_offset)

                    sig = str(int(st.st_mtime)) + ':' + str(st.st_size)
                    if seen_files.get(fn) != sig:
                        seen_files[fn] = sig
                        data_changed = True

                    loc, loc_changed = self._location_for_file(
                        fn, path, es, bs, st.st_mtime, date_str, live_gps
                    )
                    if loc_changed:
                        data_changed = True

                    file_info = {
                        'filename': fn,
                        'essid': quality_essid or es,
                        'bssid': resolved_bssid,
                        'size': f"{round(st.st_size/1024,1)}KB",
                        'date': date_str,
                        'ts': st.st_mtime,
                        'quality': quality,
                        '_path': path,
                        '_signature': f"{st.st_mtime_ns}:{st.st_size}",
                    }
                    if not file_info['quality']:
                        quality_pending.append(fn)
                    if loc:
                        file_info.update({
                            'lat': loc.get('lat'),
                            'lon': loc.get('lon'),
                            'accuracy': loc.get('accuracy', 0),
                            'gps_source': loc.get('source', ''),
                            'gps_stale': loc.get('gps_stale', False),
                            'gps_age_at_capture': loc.get('gps_age_at_capture', 0)
                        })
                        if group.get('lat') is None or st.st_mtime >= group.get('gps_ts', 0):
                            group['lat'] = loc.get('lat')
                            group['lon'] = loc.get('lon')
                            group['gps_source'] = loc.get('source', '')
                            group['gps_ts'] = st.st_mtime

                    group['files'].append(file_info)
                    if st.st_mtime > group['ts']:
                        group['ts'] = st.st_mtime
                except (OSError, TypeError, ValueError) as e:
                    logging.warning(
                        f"[A_pwmenu] Could not scan handshake {path}: {e}"
                    )
        if data_changed:
            with self.data_lock:
                self.data['seen_files'] = seen_files
            self._save_data()
        if quality_pending:
            self._start_quality_scan_thread(quality_pending)
        res = list(grps.values())
        for g in res:
            g['files'].sort(key=lambda x: x['ts'], reverse=True)
            best_file = max(
                g['files'],
                key=lambda item: self._capture_export_score(
                    item.get('_path') or ''
                ),
            )
            for file_info in g['files']:
                file_info['is_best'] = file_info is best_file
            g['best_file'] = best_file
            g['other_files'] = sorted(
                [
                    file_info for file_info in g['files']
                    if file_info is not best_file
                ],
                key=lambda item: self._capture_export_score(
                    item.get('_path') or ''
                ),
                reverse=True,
            )
            g['last_seen'] = g['files'][0]['date']
            g['count'] = len(g['files'])
            g['gps_count'] = len([f for f in g['files'] if f.get('lat') is not None and f.get('lon') is not None])
            g['map_count'] = len([
                f for f in g['files']
                if f.get('gps_source') in ('manual-map', 'map', 'pwmenu-map')
            ])
            g['cls'] = "st-cracked" if g['is_cracked'] else "st-active"
            g['txt'] = "Cracked" if g['is_cracked'] else "Active"
        res.sort(key=lambda x: x['ts'], reverse=True)
        return res

    def _get_cracked_data(self, revision=None):
        revision = revision or self._credential_source_revision()
        with self.credential_cache_lock:
            if (
                self.credential_cache is not None
                and self.credential_cache_revision == revision
            ):
                return self.credential_cache
            records = self._load_cracked_data()
            self.credential_cache_revision = revision
            self.credential_cache = records
            return records

    def _load_cracked_data(self):
        records = {}
        with self.data_lock:
            rejected_credentials = set(
                self.data.get('credential_rejections', []) or []
            )

        def add_record(record, source):
            if not record or not record.get('password'):
                return
            essid = str(record.get('essid') or '')
            password = str(record.get('password') or '')
            bssid = self._compact_bssid(record.get('bssid'))
            rejection_key = self._credential_rejection_key(bssid, password)
            if rejection_key and rejection_key in rejected_credentials:
                return
            identity = (
                ('bssid', bssid, password)
                if bssid and bssid != '000000000000'
                else ('essid', self._normalized_essid_key(essid), password)
            )
            existing = records.get(identity)
            if existing:
                sources = existing.setdefault('sources', [])
                if source not in sources:
                    sources.append(source)
                if source == 'Handshake Lab' and essid:
                    existing['essid'] = essid
                existing['source'] = ' · '.join(sources)
                return
            records[identity] = {
                'essid': essid,
                'bssid': bssid,
                'password': password,
                'source': source,
                'sources': [source],
            }

        pots = [(path, 'WPA-Sec') for path in self._wpa_potfile_paths()]
        pots.extend([(self.potfile_ohc, 'OHC'),
                (self.potfile_handshake_lab, 'Handshake Lab'),
                (self.potfile_manual, 'Manual')])
        for p, s in pots:
            if os.path.exists(p):
                try:
                    lines, _ = self._read_pot_lines(p)
                    for line in lines:
                        record = self._parse_pot_line(line)
                        if record:
                            add_record(record, s)
                            continue
                        parts = line.split(':')
                        if len(parts) >= 3:
                            add_record({
                                'essid': parts[-2],
                                'bssid': '',
                                'password': parts[-1],
                            }, s)
                except OSError as e:
                    logging.warning(f"[A_pwmenu] Could not read potfile {p}: {e}")
        for path in self._quickdic_result_paths():
            try:
                with open(path) as handle:
                    password = handle.read().strip()
                    if password:
                        essid, bssid = self._handshake_identity(
                            os.path.basename(path)[:-len('.cracked')]
                        )
                        add_record({
                            'essid': essid,
                            'bssid': bssid,
                            'password': password,
                        }, 'QuickDic')
            except (OSError, ValueError, TypeError) as error:
                logging.warning(
                    f"[A_pwmenu] Could not read QuickDic result "
                    f"{path}: {error}"
                )
        return records

    def _build_credential_lookup(self, cracked):
        by_bssid = {}
        by_exact_essid = {}
        normalized_records = {}
        normalized_identities = {}
        for record in cracked.values():
            bssid = self._compact_bssid(record.get('bssid'))
            essid = str(record.get('essid') or '')
            if bssid:
                by_bssid[bssid] = record
            by_exact_essid[essid] = record
            normalized = self._normalized_essid_key(essid)
            if normalized:
                normalized_records[normalized] = record
                normalized_identities.setdefault(normalized, set()).add(
                    bssid or essid
                )
        by_normalized_essid = {
            normalized: record
            for normalized, record in normalized_records.items()
            if len(normalized_identities.get(normalized, ())) == 1
        }
        return {
            'bssid': by_bssid,
            'exact_essid': by_exact_essid,
            'normalized_essid': by_normalized_essid,
        }

    def _find_cracked_record(self, cracked, essid, bssid, lookup=None):
        if lookup is None:
            lookup = self._build_credential_lookup(cracked)
        compact_bssid = self._compact_bssid(bssid)
        if compact_bssid:
            matched = lookup['bssid'].get(compact_bssid)
            if matched:
                return matched

        exact = lookup['exact_essid'].get(essid)
        if exact:
            return exact

        normalized = self._normalized_essid_key(essid)
        if not normalized:
            return None
        return lookup['normalized_essid'].get(normalized)

    def _is_locally_cracked(self, filename, cracked=None):
        essid, bssid = self._handshake_identity(filename)
        return bool(self._find_cracked_record(
            cracked if cracked is not None else self._get_cracked_data(),
            essid,
            bssid,
        ))

    def _get_html(self):
        return """
{% set wpa_status = wpa_status|default({}) %}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="pwmenu-ui-revision" content="{{ ui_revision|default('') }}">
    <title>A_pwmenu</title>
    <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='16' fill='%23080b0c'/%3E%3Ccircle cx='14' cy='16' r='5' fill='%2320e4f4'/%3E%3Cpath d='M16 24h10c12 0 20 6 20 17S38 57 26 57H16V24Zm10 9v15c7 0 10-2 10-7s-3-8-10-8Z' fill='%23f4f6f7'/%3E%3C/svg%3E">
    <script>
        (() => {
            try {
                let saved = JSON.parse(localStorage.getItem('a_pwmenu_accent_v1') || 'null');
                let color = saved && saved.color;
                if(!color) {
                const cookie = document.cookie.match(/(?:^|;\\s*)a_pwmenu_accent=([0-9a-f]{6})/i);
                    if(cookie) color = '#' + cookie[1];
                }
                if(!/^#[0-9a-f]{6}$/i.test(String(color || ''))) return;
                const value = color.slice(1);
                const rgb = [0,2,4].map(i => parseInt(value.slice(i,i+2),16) / 255);
                const linear = rgb.map(c => c <= .03928 ? c / 12.92 : Math.pow((c + .055) / 1.055, 2.4));
                const luminance = .2126 * linear[0] + .7152 * linear[1] + .0722 * linear[2];
                document.documentElement.style.setProperty('--accent', color.toLowerCase());
                document.documentElement.style.setProperty('--accent-contrast', luminance > .42 ? '#001013' : '#ffffff');
            } catch(error) {}
        })();
    </script>
    <style>
        :root { --bg: #000; --card: #151515; --text: #fff; --sub: #888; --accent: #0a84ff; --green: #30d158; --yellow: #ffcc00; --sep: #333; --input: #222; --danger: #ff453a; }
        html, body { min-height: 100%; background: var(--bg); }
        body { min-height: 100vh; box-sizing: border-box; font-family: -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 15px; }
        .pwmenu-page { width: 100%; max-width: 800px; min-height: calc(100vh - 30px); margin: 0 auto; }
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
        .quality-badge { display:inline-flex;align-items:center;margin-top:5px;padding:3px 7px;border-radius:999px;font-size:10px;font-weight:850;letter-spacing:.04em;text-transform:uppercase;background:rgba(255,255,255,.06);color:#aeb2bb; }
        .quality-badge.excellent { background:rgba(48,209,88,.12);color:#76e39b; }
        .quality-badge.usable { background:rgba(30,155,255,.12);color:#8abfff; }
        .quality-badge.partial { background:rgba(255,204,0,.12);color:#ffe08a; }
        .quality-badge.unusable { background:rgba(255,69,58,.12);color:#ff918b; }
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
        .btn-whitelist { color: #20e4f4; min-width: 34px; font-size: 10px; font-weight: 900; letter-spacing: .04em; }
        .map-shell { height: calc(100vh - 205px); min-height: 680px; background: #1f242b; color: #f7f8fb; border-radius: 22px; overflow: hidden; position: relative; box-shadow: 0 20px 45px rgba(0,0,0,0.32); }
        .map-stage { height: 100%; min-height: inherit; position: relative; overflow: hidden; background-color: #1f242b; background-image: linear-gradient(28deg, transparent 0 43%, rgba(113,116,104,0.34) 44% 47%, transparent 48% 100%), linear-gradient(115deg, transparent 0 52%, rgba(102,110,122,0.28) 53% 56%, transparent 57% 100%), linear-gradient(72deg, transparent 0 64%, rgba(70,110,84,0.18) 65% 67%, transparent 68% 100%), repeating-linear-gradient(0deg, rgba(190,205,225,0.045) 0 2px, transparent 2px 74px), repeating-linear-gradient(90deg, rgba(190,205,225,0.045) 0 2px, transparent 2px 74px); }
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
        .map-point.unusable { border-color: #ff453a; box-shadow: 0 8px 18px rgba(255,69,58,0.32); }
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
        .map-toast { position:fixed; z-index:300; left:50%; bottom:92px; transform:translateX(-50%) translateY(18px); padding:12px 16px; border-radius:999px; background:rgba(247,248,251,0.94); color:#050507; font-weight:850; box-shadow:0 14px 35px rgba(0,0,0,0.25); opacity:0; pointer-events:none; transition:0.2s; }
        .map-toast.show { opacity:1; transform:translateX(-50%) translateY(0); }
        .map-toast.error { background:#ff453a;color:#fff; }
        .map-status { background: rgba(255,255,255,0.04); border-radius: 16px; padding: 12px 14px; color: #c9ccd2; font-weight: 700; margin-top: 12px; }
        .map-chips { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }
        .map-chip { display:inline-flex; align-items:center; gap:7px; min-height:30px; border-radius:999px; padding:6px 10px; background:rgba(255,255,255,0.045); border:1px solid rgba(255,255,255,0.055); color:#cfd3da; font-size:12px; font-weight:800; box-sizing:border-box; letter-spacing:0; }
        .map-chip:before { content:""; width:7px; height:7px; border-radius:50%; background:currentColor; opacity:.9; }
        .map-chip.green { color:#76e39b; background:rgba(48,209,88,0.075); border-color:rgba(48,209,88,0.12); }
        .map-chip.blue { color:#8abfff; background:rgba(30,155,255,0.08); border-color:rgba(30,155,255,0.13); }
        .map-chip.yellow { color:#ffe08a; background:rgba(255,204,0,0.075); border-color:rgba(255,204,0,0.14); }
        .map-chip.red { color:#ff918b; background:rgba(255,69,58,0.075); border-color:rgba(255,69,58,0.13); }
        .map-chip.gray { color:#aeb2bb; background:rgba(255,255,255,0.04); border-color:rgba(255,255,255,0.055); }
        .map-actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-top: 14px; }
        .map-actions.three { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) 54px; }
        .map-actions.single { grid-template-columns: 1fr; }
        .map-action { display: flex; align-items: center; justify-content: center; border: none; border-radius: 18px; padding: 15px 12px; min-height: 54px; text-align: center; font-weight: 800; text-decoration: none; background: #050507; color: #fff; cursor: pointer; box-sizing: border-box; }
        .map-action.soft { background: rgba(255,255,255,0.08); color: #dfe6f8; }
        .map-action.cyan { background: rgba(32,228,244,0.10); color: #6ff4ff; }
        .map-action.red { background: rgba(255,69,58,0.12); color: #ff6b62; }
        .map-action.map-placement-card-action { width:100%;margin-top:12px; }
        .map-action.trash { padding: 0; font-size: 22px; color: #ff6b62; }
        .trash-icon { position: relative; display: inline-block; width: 18px; height: 20px; border: 2px solid currentColor; border-top: none; border-radius: 0 0 4px 4px; box-sizing: border-box; }
        .trash-icon:before { content: ""; position: absolute; left: -3px; right: -3px; top: -6px; height: 2px; background: currentColor; border-radius: 2px; }
        .trash-icon:after { content: ""; position: absolute; left: 5px; top: -10px; width: 6px; height: 3px; border: 2px solid currentColor; border-bottom: none; border-radius: 3px 3px 0 0; }
        .map-list { display:flex; flex-direction:column; gap:10px; margin-top: 12px; }
        .map-list-item { border: none; width:100%; text-align:left; border-radius: 18px; padding: 14px; color:#fff; background: rgba(255,255,255,0.045); cursor:pointer; box-sizing:border-box; }
        .map-list-item.green { background: rgba(4, 63, 32, 0.85); border: 1px solid rgba(7,140,69,0.8); }
        .map-list-item.blue { background: rgba(7, 31, 69, 0.86); border: 1px solid rgba(10,102,220,0.75); }
        .map-list-item.red { background: rgba(74, 15, 18, 0.88); border: 1px solid rgba(255,69,58,0.72); }
        .cleanup-file-list { margin:12px 0 0;padding:0;list-style:none;display:grid;gap:7px; }
        .cleanup-file-list li { padding:9px 10px;border-radius:11px;background:rgba(255,255,255,.035);color:#aeb2bb;font-size:11px;overflow-wrap:anywhere; }
        .cleanup-file-list strong { display:block;color:#d8dcdf;font-family:monospace;font-size:11px; }
        .cleanup-file-list span { display:block;margin-top:3px;color:#7f898e; }
        .whitelist-form { display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;margin-top:12px; }
        .whitelist-input { min-width:0;border:1px solid #333;border-radius:12px;outline:none;background:#0b0d0f;color:#fff;padding:11px 12px;font-size:14px; }
        .whitelist-input:focus { border-color:rgba(32,228,244,.58);box-shadow:0 0 0 3px rgba(32,228,244,.08); }
        .whitelist-submit { border:1px solid rgba(32,228,244,.35);border-radius:12px;background:rgba(32,228,244,.08);color:#20e4f4;padding:0 15px;font-weight:850;cursor:pointer; }
        .compact-card-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px}
        .compact-card-heading small,.compact-card-heading h3{display:block;margin:0}
        .compact-card-heading small{margin-bottom:3px;color:var(--sub);font-size:9px;font-weight:800;letter-spacing:.11em;text-transform:uppercase}
        .compact-card-heading h3{font-size:1.05rem}
        .compact-card-heading>strong{min-width:31px;padding:5px 8px;border-radius:999px;background:color-mix(in srgb,var(--accent) 10%,transparent);color:var(--accent);font-size:12px;text-align:center}
        .compact-card-heading-actions{display:flex;align-items:center;gap:7px}
        .compact-card-heading-actions>strong{min-width:31px;padding:5px 8px;border-radius:999px;background:color-mix(in srgb,var(--accent) 10%,transparent);color:var(--accent);font-size:12px;text-align:center}
        .compact-copy-button{display:grid;width:31px;height:31px;min-width:31px;place-items:center;padding:0;border:1px solid var(--line);border-radius:10px;background:rgba(255,255,255,.025);color:var(--accent);cursor:pointer}
        .compact-copy-button svg{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
        .conflict-list,.activity-history-list,.whitelist-compact-list{max-height:305px;margin-top:12px;display:grid;gap:7px;overflow:auto;overscroll-behavior:contain;scrollbar-width:thin}
        .conflict-item,.activity-history-item,.whitelist-compact-item{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;gap:9px;padding:10px;border:1px solid rgba(255,255,255,.055);border-radius:12px;background:rgba(255,255,255,.025)}
        .conflict-item>i,.activity-history-item>i,.whitelist-compact-item>i{width:8px;height:8px;border-radius:50%;background:#ff9f0a;box-shadow:0 0 11px rgba(255,159,10,.3)}
        .conflict-item.password>i{background:var(--danger)}
        .conflict-item.identity>i{background:#ffcc00}
        .conflict-item.name-only>i{background:#5fa8ff}
        .conflict-item.duplicate>i{background:var(--sub)}
        .conflict-item span,.conflict-item b,.conflict-item small,.activity-history-item span,.activity-history-item b,.activity-history-item small,.whitelist-compact-item span,.whitelist-compact-item b,.whitelist-compact-item small{display:block;min-width:0}
        .conflict-item b,.activity-history-item b,.whitelist-compact-item b{overflow:hidden;color:var(--text);font-size:12px;text-overflow:ellipsis;white-space:nowrap}
        .conflict-item small,.activity-history-item small,.whitelist-compact-item small{margin-top:3px;color:var(--sub);font-size:10px;line-height:1.35}
        .conflict-item em{padding:3px 6px;border-radius:999px;background:rgba(255,255,255,.055);color:var(--sub);font-size:8px;font-style:normal;font-weight:850;text-transform:uppercase}
        .conflict-item-actions{display:grid;justify-items:end;gap:5px}
        .conflict-repair{padding:5px 7px;border:1px solid color-mix(in srgb,var(--accent) 32%,transparent);border-radius:9px;background:color-mix(in srgb,var(--accent) 8%,transparent);color:var(--accent);font-size:8px;font-weight:900;cursor:pointer}
        .conflict-repair:disabled{opacity:.5;cursor:wait}
        .conflict-repair.loading{opacity:1}
        .conflict-repair.loading:before{content:"";display:inline-block;width:8px;height:8px;margin-right:5px;border:1.5px solid currentColor;border-right-color:transparent;border-radius:50%;vertical-align:-1px;animation:pwmenu-spin .75s linear infinite}
        @keyframes pwmenu-spin{to{transform:rotate(360deg)}}
        .activity-history-item>i{background:var(--accent);box-shadow:0 0 11px color-mix(in srgb,var(--accent) 30%,transparent)}
        .activity-history-item.capture>i{background:#42d982}
        .activity-history-item.cloud>i{background:#5fa8ff}
        .activity-history-item.password>i{background:#bd7cff}
        .activity-history-item.cleanup>i{background:#ff6b62}
        .activity-history-item time{color:var(--sub);font-size:9px;text-align:right;white-space:nowrap}
        .activity-history-item time small{font-size:8px}
        .whitelist-compact-item>i{background:#42d982;box-shadow:0 0 11px rgba(66,217,130,.3)}
        .whitelist-remove{flex:0 0 auto;border:1px solid color-mix(in srgb,var(--danger) 28%,transparent);border-radius:999px;background:color-mix(in srgb,var(--danger) 7%,transparent);color:var(--danger);padding:5px 8px;font-size:9px;font-weight:850;cursor:pointer}
        .activity-history-empty,.whitelist-compact-empty{padding:18px;color:var(--sub);font-size:11px;text-align:center}
        .compact-load-more{width:100%;margin-top:9px;padding:10px;border:1px solid var(--line);border-radius:11px;background:rgba(255,255,255,.025);color:var(--accent);font-weight:850;cursor:pointer}
        .compact-load-more:disabled{opacity:.5;cursor:wait}
        .identity-card{padding:15px!important;text-align:left}
        .identity-card-top{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:9px}
        .identity-disclosure{display:grid;width:100%;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:10px;padding:0;border:0;background:transparent;color:inherit;text-align:left;cursor:pointer}
        .identity-disclosure small,.identity-disclosure strong,.identity-disclosure span span{display:block}
        .identity-disclosure small{color:var(--accent);font-size:9px;font-weight:900;letter-spacing:.13em;text-transform:uppercase}
        .identity-disclosure strong{margin-top:2px;color:var(--text);font-size:1.1rem;letter-spacing:-.03em}
        .identity-disclosure span span{margin-top:2px;color:var(--sub);font-size:10px}
        .identity-chevron{width:30px;height:30px;display:grid;place-items:center;border:1px solid var(--line);border-radius:50%;color:var(--sub);transition:transform .2s,color .2s,border-color .2s}
        .identity-chevron svg{width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
        .identity-disclosure[aria-expanded="true"] .identity-chevron{border-color:color-mix(in srgb,var(--accent) 35%,transparent);color:var(--accent);transform:rotate(180deg)}
        .identity-theme{display:none;min-height:36px;align-items:center;gap:7px;padding:7px 9px;border:1px solid var(--line);border-radius:11px;background:rgba(255,255,255,.03);color:var(--text);font-size:9px;font-weight:850;cursor:pointer}
        .identity-theme .accent-current{display:block;width:11px;height:11px}
        .identity-card .mobile-xp-track{height:4px;overflow:hidden;margin-top:11px;border-radius:999px;background:rgba(255,255,255,.07)}
        .identity-card .mobile-xp-track i{display:block;height:100%;border-radius:inherit;background:var(--accent);box-shadow:0 0 12px color-mix(in srgb,var(--accent) 55%,transparent)}
        .identity-achievements{margin-top:12px;padding-top:12px;border-top:1px solid var(--line)}
        .identity-achievements.hidden{display:none}
        .other-stat-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px}
        .other-stat{padding:11px 8px;border:1px solid var(--line);border-radius:13px;background:rgba(255,255,255,.025);text-align:center}
        .other-stat strong,.other-stat small{display:block}
        .other-stat strong{color:var(--text);font-size:1.12rem}
        .other-stat.primary strong{color:var(--green)}
        .other-stat small{margin-top:2px;color:var(--sub);font-size:8px;font-weight:850;letter-spacing:.08em;text-transform:uppercase}
        .other-action-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:10px}
        .other-action{display:flex;min-height:42px;align-items:center;justify-content:center;padding:8px 10px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.03);color:#dce2e4;font-size:10px;font-weight:850;text-align:center;text-decoration:none;cursor:pointer}
        .other-action.primary{border-color:color-mix(in srgb,var(--accent) 30%,transparent);background:color-mix(in srgb,var(--accent) 8%,transparent);color:var(--accent)}
        .compact-import-state{display:none;margin-top:8px;padding:9px;border:1px solid var(--line);border-radius:11px;background:rgba(255,255,255,.02);color:var(--sub);font-size:10px}
        .compact-import-state.ready{display:flex;align-items:center;justify-content:space-between;gap:8px}
        .compact-import-state button{flex:0 0 auto;border:0;border-radius:9px;background:var(--accent);color:var(--accent-contrast);padding:7px 9px;font-weight:850;cursor:pointer}
        .service-alert{margin-top:10px;padding:10px;border:1px solid rgba(255,69,58,.25);border-radius:12px;background:rgba(255,69,58,.06);color:#ff8c85;font-size:10px;line-height:1.45}
        .service-alert b,.service-alert span{display:block}
        .service-alert span{margin-top:3px;color:var(--sub)}
        .external-service-link { color:inherit;text-decoration:none; }
        .external-service-link:hover { color:var(--accent); }
        .map-placement-target { position:absolute;z-index:20;left:50%;top:50%;width:58px;height:58px;transform:translate(-50%,-100%);pointer-events:none;filter:drop-shadow(0 14px 18px rgba(0,0,0,.46)); }
        .map-placement-pin { width:58px;height:58px;display:grid;place-items:center;color:var(--accent); }
        .map-placement-pin svg { width:58px;height:58px;overflow:visible;fill:#071113;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round; }
        .map-placement-pin circle { fill:color-mix(in srgb,var(--accent) 18%,#071113); }
        .map-placement-controls { position:absolute;z-index:21;left:50%;bottom:20px;display:grid;grid-template-columns:repeat(2,46px);gap:9px;transform:translateX(-50%);padding:8px 11px;border:1px solid rgba(255,255,255,.12);border-radius:18px;background:rgba(7,12,14,.94);box-shadow:0 16px 45px rgba(0,0,0,.42);pointer-events:auto; }
        .map-placement-controls button { display:grid;width:46px;min-width:46px;max-width:46px;height:46px;min-height:46px;max-height:46px;box-sizing:border-box;aspect-ratio:1/1;place-items:center;padding:0;border:0;border-radius:50%;color:#fff;cursor:pointer; }
        .map-placement-controls svg { width:21px;height:21px;fill:none;stroke:currentColor;stroke-width:2.8;stroke-linecap:round;stroke-linejoin:round; }
        .map-placement-cancel { background:rgba(255,255,255,.09); }
        .map-placement-confirm { background:var(--accent);color:var(--accent-contrast)!important;box-shadow:0 0 24px color-mix(in srgb,var(--accent) 34%,transparent); }
        .map-placement-label { position:absolute;z-index:21;top:78px;left:50%;width:max-content;max-width:min(420px,72vw);transform:translateX(-50%);padding:8px 11px;border:1px solid rgba(255,255,255,.1);border-radius:13px;background:rgba(7,12,14,.92);color:#eafcff;font-size:.64rem;font-weight:800;text-align:center;pointer-events:none; }
        .map-stage.placing #mapMarkers, .map-stage.placing .ymap-real { cursor:grab!important; }
        .map-stage.placing .ymap-real:active { cursor:grabbing!important; }
        .newfpv-credit { --credit-accent:#20e4f4;display:flex;min-width:230px;width:max-content;max-width:100%;box-sizing:border-box;align-items:center;justify-content:space-between;gap:18px;margin:24px auto 8px;padding:12px 13px 12px 16px;border:1px solid rgba(255,255,255,.12);border-radius:17px;background:linear-gradient(110deg,rgba(255,255,255,.055),color-mix(in srgb,var(--credit-accent) 4.5%,transparent));color:#f4f6f7;font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;text-decoration:none;transition:border-color .2s,background .2s,transform .2s; }
        .newfpv-credit:hover { border-color:color-mix(in srgb,var(--credit-accent) 45%,transparent);background:linear-gradient(110deg,rgba(255,255,255,.075),color-mix(in srgb,var(--credit-accent) 9%,transparent));transform:translateY(-2px); }
        .newfpv-credit small, .newfpv-credit strong { display:block; }
        .newfpv-credit small { margin-bottom:1px;color:#7f898e;font-size:9px;font-weight:800;letter-spacing:.15em;text-transform:uppercase; }
        .newfpv-credit strong { font-size:13px;letter-spacing:.01em; }
        .newfpv-credit .mark { color:var(--credit-accent); }
        .newfpv-credit i { display:grid;width:32px;height:32px;flex:0 0 32px;place-items:center;border:1px solid color-mix(in srgb,var(--credit-accent) 30%,transparent);border-radius:50%;color:var(--credit-accent); }
        .newfpv-credit svg { width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:2.15;stroke-linecap:round;stroke-linejoin:round; }
        .newfpv-credit.compact { min-width:170px;padding:7px 8px 7px 11px;border-radius:13px; }
        .newfpv-credit.compact small { font-size:7px; }
        .newfpv-credit.compact strong { font-size:11px; }
        .newfpv-credit.compact i { width:27px;height:27px;flex-basis:27px; }
        .newfpv-credit.compact svg { width:13px;height:13px; }
        .map-list-title { font-size: 18px; font-weight: 850; overflow-wrap:anywhere; }
        .map-list-sub { margin-top: 5px; font-size: 12px; color:#aeb2bb; overflow-wrap:anywhere; }
        @media (max-width: 520px) {
            body { padding: 10px; }
            .tab { font-size: 12px; padding: 8px 4px; }
            .map-shell { height: 640px; min-height: 640px; border-radius: 18px; }
            .map-stage { height: 100%; min-height: 640px; }
            .map-sheet { padding: 32px 18px 20px; }
            .map-title { font-size: 27px; }
            .map-metrics { gap: 8px; }
            .map-metric-value { font-size: 18px; }
            .map-dock { bottom: 14px; max-width: calc(100% - 20px); }
            .map-dock-btn { padding: 11px 13px; }
            .newfpv-credit { width:100%;min-width:0; }
            .whitelist-form { grid-template-columns:1fr; }
            .whitelist-submit { min-height:44px; }
            .identity-theme{display:flex}
        }

        :root {
            color-scheme: dark;
            --bg: #070809;
            --card: #101214;
            --surface-2: #15181b;
            --text: #f4f6f7;
            --sub: #9ba3a8;
            --quiet: #697177;
            --line: rgba(255,255,255,.10);
            --line-strong: rgba(255,255,255,.18);
            --accent: #20e4f4;
            --accent-contrast: #001013;
            --input: #0b0d0f;
            --sep: rgba(255,255,255,.08);
            --max: 1180px;
            --radius: 24px;
        }
        *, *::before, *::after { box-sizing: border-box; }
        html { min-height:100%; background:var(--bg); scroll-behavior:smooth; }
        body {
            min-height:100vh;
            overflow-x:hidden;
            padding:0;
            background:var(--bg);
            color:var(--text);
            font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
            line-height:1.55;
            -webkit-font-smoothing:antialiased;
        }
        body::before {
            content:"";
            position:fixed;
            inset:0;
            z-index:-3;
            background:
                radial-gradient(circle at 8% 3%,color-mix(in srgb,var(--accent) 13%,transparent),transparent 29%),
                radial-gradient(circle at 93% 68%,rgba(157,99,255,.10),transparent 31%),
                #070809;
            pointer-events:none;
        }
        body::after {
            content:"";
            position:fixed;
            inset:0;
            z-index:-2;
            opacity:.72;
            background-image:linear-gradient(rgba(255,255,255,.018) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.018) 1px,transparent 1px);
            background-size:90px 90px;
            pointer-events:none;
        }
        button, input { font:inherit; }
        button:focus-visible, input:focus-visible, a:focus-visible { outline:3px solid var(--accent); outline-offset:3px; }
        ::selection { background:var(--accent); color:var(--accent-contrast); }
        .pwmenu-page { width:100%; max-width:none; min-height:100vh; margin:0; }
        .pw-nav-wrap { position:sticky; top:14px; z-index:100; width:min(calc(100% - 40px),var(--max)); margin:14px auto 0; }
        .pw-nav {
            display:grid;
            grid-template-columns:minmax(0,1fr) auto auto;
            align-items:center;
            gap:22px;
            min-height:64px;
            padding:8px 10px 8px 18px;
            border:1px solid var(--line);
            border-radius:999px;
            background:rgba(8,10,11,.80);
            box-shadow:0 16px 60px rgba(0,0,0,.30);
            backdrop-filter:blur(18px);
            -webkit-backdrop-filter:blur(18px);
        }
        .pw-brand { display:flex;align-items:center;gap:10px;width:max-content;padding:0;border:0;background:transparent;color:#fff;font-size:.78rem;font-weight:900;letter-spacing:.14em;text-transform:uppercase;cursor:pointer; }
        .pw-brand-dot { width:9px;height:9px;border-radius:50%;background:var(--accent);box-shadow:0 0 16px var(--accent); }
        .pw-brand-mark { color:var(--accent); }
        .pw-nav-meta { display:flex;align-items:center;gap:10px;color:#8f989d;font-size:.68rem;font-weight:750;letter-spacing:.045em;text-transform:uppercase; }
        .pw-nav-meta strong { color:#e8ebed;font-size:.7rem; }
        .pw-live-dot { width:7px;height:7px;border-radius:50%;background:#30d158;box-shadow:0 0 12px rgba(48,209,88,.75); }
        .pw-nav-separator { width:1px;height:18px;background:var(--line); }
        .accent-toggle { display:flex;min-height:44px;align-items:center;justify-content:center;gap:9px;padding:9px 15px;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.035);color:#dce1e3;font-size:.72rem;font-weight:800;cursor:pointer;transition:border-color .2s,background .2s,transform .2s; }
        .mobile-search-toggle, .mobile-search-close { display:none; }
        .mobile-search-toggle svg { width:18px;height:18px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round; }
        .accent-toggle:hover, .accent-toggle[aria-expanded="true"] { border-color:color-mix(in srgb,var(--accent) 45%,transparent);background:color-mix(in srgb,var(--accent) 8%,transparent);transform:translateY(-1px); }
        .accent-current { width:14px;height:14px;border:3px solid rgba(255,255,255,.82);border-radius:50%;background:var(--accent);box-shadow:0 0 15px color-mix(in srgb,var(--accent) 60%,transparent); }
        .accent-panel { position:fixed;z-index:180;top:90px;right:max(20px,calc((100vw - var(--max))/2));width:min(330px,calc(100vw - 28px));padding:17px;border:1px solid var(--line-strong);border-radius:22px;background:rgba(13,16,18,.96);box-shadow:0 28px 80px rgba(0,0,0,.58);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);animation:accent-in .2s ease both; }
        @keyframes accent-in { from { opacity:0;transform:translateY(-8px) scale(.98); } to { opacity:1;transform:none; } }
        .accent-panel-head { display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:15px; }
        .accent-panel-head small, .accent-panel-head strong { display:block; }
        .accent-panel-head small { color:var(--accent);font-size:.58rem;font-weight:850;letter-spacing:.14em;text-transform:uppercase; }
        .accent-panel-head strong { margin-top:2px;font-size:1rem; }
        .accent-panel-head button { display:grid;width:34px;height:34px;place-items:center;border:1px solid var(--line);border-radius:50%;background:rgba(255,255,255,.035);color:#9ba3a8;font-size:22px;cursor:pointer; }
        .accent-presets { display:grid;grid-template-columns:repeat(6,1fr);gap:8px; }
        .accent-swatch { position:relative;aspect-ratio:1;border:2px solid transparent;border-radius:50%;background:var(--swatch);box-shadow:inset 0 0 0 4px #111518;cursor:pointer;transition:transform .18s,border-color .18s; }
        .accent-swatch:hover { transform:translateY(-2px) scale(1.06); }
        .accent-swatch.active { border-color:#fff;transform:scale(1.08); }
        .accent-custom { display:flex;align-items:center;justify-content:space-between;gap:16px;margin-top:15px;padding:12px 13px;border:1px solid var(--line);border-radius:15px;background:rgba(255,255,255,.025); }
        .accent-custom small, .accent-custom strong { display:block; }
        .accent-custom small { color:#788186;font-size:.55rem;font-weight:850;letter-spacing:.12em;text-transform:uppercase; }
        .accent-custom strong { margin-top:2px;font-size:.75rem; }
        .accent-custom input { width:42px;height:32px;padding:0;border:0;border-radius:10px;background:transparent;cursor:pointer; }
        .pwmenu-main { width:min(calc(100% - 40px),var(--max));margin:0 auto;padding:0 0 70px; }
        .pw-hero { position:relative;display:grid;min-height:480px;overflow:hidden;grid-template-columns:minmax(0,1.2fr) minmax(330px,.72fr);align-items:center;gap:70px;padding:82px 0 62px;isolation:isolate; }
        .pw-hero::before { content:"";position:absolute;left:-9%;top:5%;z-index:-2;width:620px;height:620px;border:1px solid color-mix(in srgb,var(--accent) 13%,transparent);border-radius:50%;box-shadow:0 0 140px color-mix(in srgb,var(--accent) 6%,transparent);pointer-events:none; }
        .pw-hero::after { content:"";position:absolute;inset:0;z-index:-3;opacity:.14;background-image:linear-gradient(rgba(255,255,255,.1) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.1) 1px,transparent 1px);background-size:72px 72px;mask-image:radial-gradient(circle at 38% 50%,#000,transparent 68%);pointer-events:none; }
        .pw-eyebrow { display:flex;align-items:center;gap:11px;margin:0 0 17px;color:var(--accent);font-size:.7rem;font-weight:850;letter-spacing:.18em;text-transform:uppercase; }
        .pw-eyebrow::before { content:"";width:28px;height:1px;background:currentColor;box-shadow:0 0 12px currentColor; }
        .pw-hero h1 { margin:0;color:#f4f6f7;font-size:clamp(4.5rem,8.4vw,8rem);font-weight:900;letter-spacing:-.075em;line-height:.86; }
        .pw-hero-outline { color:transparent;-webkit-text-stroke:2px color-mix(in srgb,var(--accent) 85%,#fff); }
        .pw-hero-line { max-width:690px;margin:26px 0 0;color:#c8ced1;font-size:clamp(1.05rem,2vw,1.5rem);font-weight:680;line-height:1.35;letter-spacing:-.025em; }
        .pw-hero-chips { display:flex;flex-wrap:wrap;gap:8px;margin-top:25px; }
        .pw-hero-chips span { display:inline-flex;align-items:center;gap:8px;padding:8px 11px;border:1px solid var(--line);border-radius:999px;background:rgba(13,16,18,.72);color:#aab2b6;font-size:.68rem;font-weight:750; }
        .pw-hero-chips i { width:6px;height:6px;border-radius:50%;background:var(--accent);box-shadow:0 0 9px var(--accent); }
        .pw-hero-proof { display:grid;gap:10px; }
        .pw-hero-proof article { position:relative;min-height:126px;padding:20px 21px;border:1px solid var(--line);border-radius:21px;background:linear-gradient(135deg,rgba(17,21,23,.94),rgba(10,12,14,.90));transition:border-color .2s,transform .2s; }
        .pw-hero-proof article:hover { border-color:color-mix(in srgb,var(--accent) 34%,transparent);transform:translateX(-4px); }
        .pw-hero-proof article>span { position:absolute;right:20px;top:19px;color:var(--accent);font-size:.58rem;font-weight:900;letter-spacing:.13em;text-transform:uppercase; }
        .pw-hero-proof strong { display:block;max-width:65%;color:#fff;font-size:1.3rem;overflow-wrap:anywhere; }
        .pw-hero-proof p { max-width:280px;margin:17px 0 0;color:#7f898e;font-size:.72rem;line-height:1.5; }
        .pw-workspace { position:relative; }
        .pw-workspace-bar { position:sticky;top:91px;z-index:70;display:grid;grid-template-columns:minmax(260px,.9fr) minmax(440px,1.1fr);align-items:center;gap:10px;margin-bottom:20px;padding:8px;border:1px solid var(--line);border-radius:25px;background:rgba(8,10,11,.88);box-shadow:0 18px 60px rgba(0,0,0,.27);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px); }
        .pw-search { display:flex;min-width:0;align-items:center;gap:10px;padding:0 13px; }
        .pw-search svg { width:18px;height:18px;flex:0 0 18px;fill:none;stroke:#697177;stroke-width:2;stroke-linecap:round; }
        .pw-search .s-box { width:100%;min-height:46px;margin:0;padding:0;border:0;border-radius:0;background:transparent;color:var(--text);font-size:.86rem; }
        .pw-search .s-box::placeholder { color:#5f686d; }
        .tabs { display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:5px;margin:0;padding:0;border-radius:18px;background:rgba(255,255,255,.035); }
        .tab { display:flex;min-width:0;min-height:46px;align-items:center;justify-content:center;gap:7px;padding:8px 10px;border-radius:15px;color:#d0d5d8;font-size:.78rem;font-weight:800;transition:color .2s,background .2s,transform .2s; }
        .tab span { color:var(--accent);font-size:.55rem;font-weight:900;letter-spacing:.08em; }
        .tab-icon { display:grid;width:15px;height:15px;flex:0 0 15px;place-items:center; }
        .tab-icon svg { width:100%;height:100%;fill:none;stroke:currentColor;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round; }
        .tab b { overflow:hidden;font-weight:800;text-overflow:ellipsis;white-space:nowrap; }
        .tab:hover { color:#fff; }
        .tab.active { background:var(--accent);color:var(--accent-contrast);box-shadow:0 10px 28px color-mix(in srgb,var(--accent) 14%,transparent); }
        .tab.active span { color:var(--accent-contrast);opacity:.88; }
        .notif { position:relative;z-index:60;margin:0 0 16px;border-radius:17px;background:rgba(48,209,88,.10);box-shadow:0 14px 45px rgba(0,0,0,.18); }
        #v-cracked.list, #v-handshakes.list { display:grid;grid-template-columns:repeat(2,minmax(0,1fr));align-items:start;gap:12px;overflow:visible;border-radius:0;background:transparent; }
        #v-cracked>.si, #v-handshakes>.si { overflow:hidden;border:1px solid var(--line);border-radius:21px;background:linear-gradient(145deg,rgba(20,23,26,.94),rgba(11,13,15,.94));transition:border-color .2s,transform .2s,background .2s;content-visibility:auto;contain-intrinsic-size:auto 92px; }
        #v-cracked>.si>.row { min-height:112px;padding:18px 19px;border:0; }
        #v-cracked>.si:hover, #v-handshakes>.si:hover { border-color:color-mix(in srgb,var(--accent) 38%,transparent);background:linear-gradient(145deg,color-mix(in srgb,var(--accent) 5%,#14171a),#0d0f11);transform:translateY(-2px); }
        #v-handshakes>.si>.row { min-height:112px;padding:18px 19px;border:0; }
        #v-cracked .tit, #v-handshakes .tit { max-width:100%;font-size:1rem;overflow-wrap:anywhere; }
        .badge { border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.045);color:#8d969b;font-size:.53rem;letter-spacing:.07em; }
        .pwd { color:var(--accent); }
        .subs { padding:0 10px 10px;border:0;background:rgba(0,0,0,.18); }
        .sub-row { gap:14px;padding:12px 10px;border-top:1px solid var(--line);border-bottom:0; }
        .capture-row { display:block; }
        .capture-file-head { display:flex;align-items:flex-start;justify-content:space-between;gap:10px; }
        .capture-file-info { min-width:0; }
        .capture-file-name { overflow:hidden;color:#eef2f3;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.7rem;font-weight:800;text-overflow:ellipsis;white-space:nowrap; }
        .best-capture-badge{display:inline-flex;margin-left:7px;padding:2px 6px;border:1px solid color-mix(in srgb,var(--accent) 38%,transparent);border-radius:999px;background:color-mix(in srgb,var(--accent) 10%,transparent);color:var(--accent);font-family:Inter,system-ui,sans-serif;font-size:8px;letter-spacing:.08em;vertical-align:1px}
        .capture-other-list{margin:9px 0 0;border:1px solid var(--line);border-radius:13px;background:rgba(255,255,255,.018);overflow:hidden}
        .capture-other-list>summary{display:flex;align-items:center;justify-content:space-between;padding:11px 12px;color:var(--sub);font-size:11px;font-weight:850;cursor:pointer;list-style:none}
        .capture-other-list>summary::-webkit-details-marker{display:none}
        .capture-other-list>summary b{min-width:25px;padding:3px 7px;border-radius:999px;background:rgba(255,255,255,.07);color:var(--text);text-align:center}
        .capture-other-body{padding:0 8px 8px}
        .capture-other-body .capture-row{margin-top:7px;opacity:.82}
        .capture-file-bssid { overflow:hidden;color:#dce1e3;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.68rem;text-overflow:ellipsis;white-space:nowrap; }
        .capture-file-meta { margin-top:2px;color:#727c81;font-size:.56rem; }
        .capture-file-info .quality-badge { display:inline-flex;margin-top:4px;padding:3px 6px;font-size:.48rem; }
        .capture-file-delete { display:grid;width:34px;height:34px;flex:0 0 34px;place-items:center;padding:0;border:1px solid rgba(255,69,58,.28);border-radius:10px;background:rgba(255,69,58,.08);color:#ff7169;cursor:pointer; }
        .capture-file-delete:hover { border-color:rgba(255,69,58,.58);background:rgba(255,69,58,.14); }
        .capture-file-delete svg { width:16px;height:16px;fill:none;stroke:currentColor;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round; }
        .network-expanded-tools { display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;padding:10px;border-top:1px solid var(--line); }
        .network-expanded-action { display:flex;min-width:0;min-height:48px;align-items:center;justify-content:center;gap:9px;padding:8px 12px;border:1px solid var(--line);border-radius:13px;background:rgba(255,255,255,.035);color:#dce2e4;font-size:.66rem;font-weight:850;cursor:pointer;transition:border-color .2s,background .2s,color .2s,transform .2s; }
        .network-expanded-action:hover { border-color:color-mix(in srgb,var(--accent) 42%,transparent);background:color-mix(in srgb,var(--accent) 7%,transparent);color:var(--accent);transform:translateY(-1px); }
        .network-expanded-action svg { width:16px;height:16px;flex:0 0 16px;fill:none;stroke:currentColor;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round; }
        .network-expanded-tools > :only-child { grid-column:1/-1; }
        .credential-expanded { margin:10px;padding:12px;border:1px solid color-mix(in srgb,var(--accent) 24%,var(--line));border-radius:14px;background:color-mix(in srgb,var(--accent) 5%,rgba(255,255,255,.02)); }
        .credential-label { color:#7f898e;font-size:.5rem;font-weight:900;letter-spacing:.12em;text-transform:uppercase; }
        .credential-value { margin-top:5px;color:var(--accent);font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.9rem;font-weight:800;overflow-wrap:anywhere;user-select:text; }
        .credential-actions { display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:10px; }
        .capture-actions { display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:6px;margin-top:9px;padding-top:9px;border-top:1px solid var(--line); }
        .capture-action { display:flex;min-width:0;min-height:48px;box-sizing:border-box;flex-direction:column;align-items:center;justify-content:center;gap:3px;padding:5px 3px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.035);color:#dbe1e3;text-align:center;text-decoration:none;cursor:pointer; }
        .capture-action:hover { border-color:color-mix(in srgb,var(--accent) 42%,transparent);color:var(--accent); }
        .capture-action svg { width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round; }
        .capture-action span { font-size:.48rem;font-weight:900;letter-spacing:.02em; }
        .capture-action.accent { border-color:color-mix(in srgb,var(--accent) 28%,transparent);color:var(--accent); }
        .capture-action.danger { border-color:rgba(255,69,58,.22);color:#ff7169; }
        .btn-grp { flex-wrap:wrap;justify-content:flex-end;gap:5px; }
        .btn-xs { margin:0;padding:6px 9px;border:1px solid var(--line);background:rgba(255,255,255,.045);color:var(--accent); }
        .icon-btn { display:grid;min-width:34px;height:34px;place-items:center;padding:0;border:1px solid var(--line);border-radius:50%;background:rgba(255,255,255,.035);font-size:14px;transition:border-color .2s,background .2s,transform .2s; }
        .icon-btn:hover { border-color:color-mix(in srgb,var(--accent) 45%,transparent);background:color-mix(in srgb,var(--accent) 8%,transparent);transform:translateY(-1px); }
        .icon-btn svg, .arr svg { width:15px;height:15px;fill:none;stroke:currentColor;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round; }
        .btn-whitelist, .btn-add { color:var(--accent); }
        .arr { display:grid;width:34px;height:34px;place-items:center;margin-left:7px;border:1px solid var(--line);border-radius:50%;background:rgba(255,255,255,.025);color:#899398;cursor:pointer;transition:transform .2s,color .2s,border-color .2s; }
        .si.open .arr { border-color:color-mix(in srgb,var(--accent) 35%,transparent);color:var(--accent);transform:rotate(90deg); }
        #v-cracked>.newfpv-credit, #v-handshakes>.newfpv-credit { grid-column:1/-1; }
        #v-other { grid-template-columns:repeat(2,minmax(0,1fr));align-items:start;gap:14px; }
        #v-other:not(.hidden) { display:grid; }
        #v-other>.cleanup-card{order:1}
        #v-other>.identity-card{order:2}
        #v-other>.operations-card{order:3}
        #v-other>.ohc-card{order:4}
        #v-other>.wpa-card{order:5}
        #v-other>.whitelist-card{order:6}
        #v-other>.activity-card{grid-column:1/-1;order:7}
        #v-other>.conflict-card{grid-column:1/-1;order:8}
        #v-other>.newfpv-credit{order:9}
        .mobile-profile-card { display:none; }
        .card { height:100%;margin:0;padding:22px;border:1px solid var(--line);border-radius:23px;background:linear-gradient(145deg,rgba(20,23,26,.94),rgba(11,13,15,.94));box-shadow:none; }
        .card h3 { letter-spacing:-.025em; }
        .btn { border-radius:999px;background:var(--accent);color:var(--accent-contrast);font-size:.82rem;transition:transform .2s,box-shadow .2s,background .2s; }
        .btn:hover { transform:translateY(-2px);box-shadow:0 14px 38px color-mix(in srgb,var(--accent) 15%,transparent); }
        .whitelist-input { border-color:var(--line);background:#0b0d0f; }
        .whitelist-input:focus { border-color:color-mix(in srgb,var(--accent) 58%,transparent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 8%,transparent); }
        .whitelist-submit { border-color:color-mix(in srgb,var(--accent) 35%,transparent);background:color-mix(in srgb,var(--accent) 8%,transparent);color:var(--accent); }
        .newfpv-credit { --credit-accent:var(--accent);min-width:300px;padding:15px 16px 15px 19px;border-radius:19px; }
        .newfpv-credit small { font-size:10px; }
        .newfpv-credit strong { font-size:16px; }
        .newfpv-credit i { width:38px;height:38px;flex-basis:38px; }
        .newfpv-credit svg { width:17px;height:17px; }
        #v-other>.newfpv-credit { grid-column:1/-1; }
        .view-map .pw-nav-wrap, .view-map .pw-workspace-bar { position:relative;top:auto; }
        .map-shell { height:calc(100vh - 150px);min-height:680px;border:1px solid var(--line);border-radius:25px;background:#090b0c;box-shadow:0 24px 70px rgba(0,0,0,.30); }
        .map-stage { background-color:#0a0c0d;background-image:linear-gradient(rgba(255,255,255,.022) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.022) 1px,transparent 1px),radial-gradient(circle at 72% 18%,color-mix(in srgb,var(--accent) 8%,transparent),transparent 35%);background-size:64px 64px,64px 64px,auto; }
        .map-stage:after { background:linear-gradient(180deg,rgba(5,7,8,.04),rgba(5,7,8,.23)); }
        .map-glass { border-color:var(--line);background:rgba(8,11,12,.88);box-shadow:0 18px 55px rgba(0,0,0,.38); }
        .map-topbar { gap:9px; }
        .map-search-wrap { min-height:52px;padding:2px 14px;border:1px solid var(--line);transition:border-color .2s,box-shadow .2s; }
        .map-search-wrap:focus-within { border-color:color-mix(in srgb,var(--accent) 58%,transparent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 9%,transparent),0 18px 55px rgba(0,0,0,.38); }
        .map-search { color:var(--text);font-size:.86rem; }
        .map-search::placeholder { color:#687177; }
        .map-gps-dot { width:52px;height:52px;flex:0 0 52px;border:1px solid var(--line);background:rgba(8,11,12,.92);color:#7e898f;box-shadow:0 18px 55px rgba(0,0,0,.38); }
        .map-gps-dot.browser { color:var(--accent); }
        .map-gps-pop { padding:16px 17px;border:1px solid var(--line);border-radius:20px;background:rgba(8,11,12,.95);box-shadow:0 24px 65px rgba(0,0,0,.48); }
        .map-point { border-color:var(--accent);background:#f6f8f8;color:#071012;box-shadow:0 8px 22px color-mix(in srgb,var(--accent) 24%,transparent); }
        .map-point.me { border-color:#f4f6f7;background:var(--accent);color:var(--accent-contrast);box-shadow:0 0 0 10px color-mix(in srgb,var(--accent) 18%,transparent),0 8px 20px rgba(0,0,0,.28); }
        .map-empty { border:1px solid var(--line);background:rgba(8,11,12,.91);color:#b9c0c4; }
        .map-dock { gap:5px;padding:6px;border:1px solid var(--line);background:rgba(8,11,12,.92); }
        .map-dock-btn { min-height:42px;padding:10px 15px;color:#cbd1d4;font-size:.72rem;letter-spacing:.015em;transition:background .2s,color .2s,transform .2s; }
        .map-dock-btn:hover { color:#fff;transform:translateY(-1px); }
        .map-dock-btn.active, .map-dock-btn.green.active, .map-dock-btn.blue.active { background:var(--accent);color:var(--accent-contrast);box-shadow:0 8px 24px color-mix(in srgb,var(--accent) 17%,transparent); }
        .map-sheet { border:1px solid var(--line-strong);border-bottom:0;border-radius:28px 28px 0 0;background:linear-gradient(155deg,rgba(18,22,24,.985),rgba(8,10,11,.99));box-shadow:0 -24px 70px rgba(0,0,0,.52); }
        .map-handle { background:var(--accent);box-shadow:0 0 13px color-mix(in srgb,var(--accent) 50%,transparent); }
        .map-title { color:#f4f6f7;font-size:clamp(2rem,4vw,3.15rem);font-weight:900;letter-spacing:-.055em; }
        .map-sub { color:#8f999e;font-size:.82rem; }
        .map-close, .map-back { border:1px solid var(--line);background:rgba(255,255,255,.035);color:#d6dcdf; }
        .map-close:hover, .map-back:hover { border-color:color-mix(in srgb,var(--accent) 45%,transparent);color:var(--accent); }
        .map-metric { border:1px solid var(--line);border-radius:18px;background:linear-gradient(145deg,rgba(255,255,255,.038),rgba(255,255,255,.014)); }
        .map-metric-label { color:#7f898e;font-size:.61rem;letter-spacing:.1em; }
        .map-metric-value { color:#f4f6f7; }
        .map-status { border:1px solid var(--line);border-radius:17px;background:rgba(255,255,255,.025);color:#c1c8cc; }
        .map-chip { border-color:var(--line);background:rgba(255,255,255,.035); }
        .map-action { min-height:52px;border:1px solid color-mix(in srgb,var(--accent) 30%,transparent);border-radius:999px;background:var(--accent);color:var(--accent-contrast);transition:transform .2s,box-shadow .2s,border-color .2s; }
        .map-action:hover { transform:translateY(-2px);box-shadow:0 12px 32px color-mix(in srgb,var(--accent) 14%,transparent); }
        .map-action.soft, .map-action.cyan { border-color:color-mix(in srgb,var(--accent) 25%,transparent);background:color-mix(in srgb,var(--accent) 8%,#0c0f11);color:var(--accent); }
        .map-action.red { border-color:rgba(255,69,58,.24);background:rgba(255,69,58,.09);color:#ff756d; }
        .map-list-item { border:1px solid var(--line);border-radius:18px;background:linear-gradient(145deg,rgba(255,255,255,.045),rgba(255,255,255,.018));transition:border-color .2s,transform .2s; }
        .map-list-item:hover { border-color:color-mix(in srgb,var(--accent) 38%,transparent);transform:translateY(-1px); }
        .map-toast { background:var(--accent);color:var(--accent-contrast); }
        /* Compact map workspace */
        .map-shell { border-radius:18px; }
        .map-topbar { top:12px;left:12px;right:12px;gap:7px; }
        .map-filter-toggle { position:relative;display:flex;min-height:40px;flex:0 0 auto;align-items:center;gap:8px;padding:0 11px;border:1px solid var(--line);border-radius:14px;background:rgba(8,11,12,.9);color:#cbd2d5;font-size:.66rem;font-weight:850;cursor:pointer;box-shadow:0 18px 55px rgba(0,0,0,.3); }
        .map-filter-toggle input { position:absolute;opacity:0;pointer-events:none; }
        .map-filter-track { position:relative;width:31px;height:18px;border-radius:999px;background:rgba(255,255,255,.12);transition:background .2s; }
        .map-filter-track::after { content:"";position:absolute;left:3px;top:3px;width:12px;height:12px;border-radius:50%;background:#8b969b;transition:transform .2s,background .2s,box-shadow .2s; }
        .map-filter-toggle input:checked + .map-filter-track { background:color-mix(in srgb,var(--accent) 25%,transparent); }
        .map-filter-toggle input:checked + .map-filter-track::after { background:var(--accent);box-shadow:0 0 9px var(--accent);transform:translateX(13px); }
        .map-search-wrap { min-height:40px;padding:0 11px;border-radius:14px; }
        .map-search { min-height:38px;padding:0 3px;font-size:.76rem; }
        .map-gps-dot { width:40px;height:40px;flex-basis:40px; }
        #gpsStatusDot { display:none!important; }
        .map-gps-dot:before { width:10px;height:10px;box-shadow:0 0 0 4px color-mix(in srgb,currentColor 18%,transparent); }
        .map-gps-pop { top:59px;right:12px;left:12px;max-width:285px;padding:10px 12px;border-radius:14px;font-size:.69rem;line-height:1.3; }
        .map-gps-pop b { margin-bottom:2px;font-size:.76rem; }
        .map-empty { top:68px;left:12px;right:12px;padding:11px;border-radius:14px;font-size:.72rem; }
        .map-point { min-width:28px;height:28px;padding:0 6px;border-width:4px;font-size:.68rem; }
        .map-point.me { width:19px;height:19px;border-width:4px;box-shadow:0 0 0 7px color-mix(in srgb,var(--accent) 16%,transparent),0 6px 15px rgba(0,0,0,.28); }
        .map-dock { bottom:13px;gap:3px;padding:4px;border-radius:15px; }
        .map-dock-btn { min-height:32px;padding:6px 11px;border-radius:11px;font-size:.63rem;letter-spacing:0; }
        .map-sheet { min-height:0;max-height:72%;padding:25px 16px 14px;border-radius:20px 20px 0 0; }
        .map-handle { top:8px;width:34px;height:4px; }
        .map-title-row { gap:9px;margin-bottom:10px; }
        .map-title-main { min-width:0;flex:1;text-align:left; }
        .map-title { font-size:1.38rem;line-height:1.05;letter-spacing:-.035em; }
        .map-sub { margin-top:4px;font-size:.68rem;line-height:1.35; }
        .map-close { width:34px;height:34px;font-size:21px; }
        .map-back { min-height:34px;padding:6px 10px;font-size:.68rem; }
        .map-metrics { gap:6px;margin-bottom:9px; }
        .map-metric { padding:8px 6px;border-radius:12px; }
        .map-metric-label { font-size:.49rem;letter-spacing:.075em; }
        .map-metric-value { margin-top:3px;font-size:.95rem; }
        .map-secret { margin-top:7px;padding:10px;border-radius:13px;font-size:.72rem; }
        .map-copy { padding:7px 9px;border-radius:9px;font-size:.64rem; }
        .map-password { margin-top:4px;font-size:1.2rem; }
        .map-status { margin-top:7px;padding:8px 10px;border-radius:12px;font-size:.67rem;line-height:1.35; }
        .map-chips { gap:5px;margin-top:7px; }
        .map-chip { min-height:23px;padding:3px 7px;font-size:.58rem; }
        .map-chip:before { width:5px;height:5px; }
        .map-actions { gap:6px;margin-top:8px; }
        .map-actions.three { grid-template-columns:minmax(0,1fr) minmax(0,1fr) 40px; }
        .map-action { min-height:38px;padding:7px 9px;border-radius:12px;font-size:.66rem;line-height:1.2; }
        .map-action.trash { font-size:17px; }
        .trash-icon { width:15px;height:17px; }
        .map-list { gap:6px;margin-top:7px; }
        .map-list-item { padding:9px 10px;border-radius:12px; }
        .map-list-title { font-size:.82rem!important;line-height:1.25; }
        .map-list-sub { margin-top:3px;font-size:.61rem;line-height:1.35; }
        .map-toast { bottom:61px;padding:8px 11px;font-size:.66rem; }
        .map-title-row { position:relative;padding-right:38px; }
        .map-close { position:absolute;top:0;right:0; }
        .map-back { width:34px;padding:0;font-size:0; }
        .map-back::before { content:"←";font-size:15px;line-height:1; }
        .map-compact-meta { display:flex;flex-wrap:wrap;gap:5px;margin-top:7px; }
        .map-compact-meta span { padding:5px 7px;border:1px solid var(--line);border-radius:9px;background:rgba(255,255,255,.025);color:#aeb7bb;font-size:.58rem;font-weight:750; }
        .map-icon-actions { display:grid;width:100%;grid-template-columns:repeat(auto-fit,minmax(52px,1fr));gap:6px;margin-top:10px; }
        .map-icon-action { display:grid;width:auto;min-width:0;height:46px;box-sizing:border-box;place-items:center;padding:5px 3px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.035);color:#dce1e3;text-decoration:none;cursor:pointer; }
        .map-icon-action:hover { border-color:color-mix(in srgb,var(--accent) 42%,transparent);color:var(--accent); }
        .map-icon-action svg { width:17px;height:17px;fill:none;stroke:currentColor;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round; }
        .map-icon-action span { display:block;margin-top:2px;font-size:.46rem;font-weight:850;letter-spacing:.02em; }
        .map-icon-action.primary { border-color:color-mix(in srgb,var(--accent) 30%,transparent);background:color-mix(in srgb,var(--accent) 8%,transparent);color:var(--accent); }
        .map-icon-action.danger { border-color:rgba(255,69,58,.22);color:#ff7169; }
        .map-more { margin-top:8px;border:1px solid var(--line);border-radius:11px;background:rgba(255,255,255,.018); }
        .map-more summary { padding:8px 10px;color:#aeb7bb;font-size:.62rem;font-weight:800;cursor:pointer;list-style:none; }
        .map-more summary::-webkit-details-marker { display:none; }
        .map-more summary::after { content:"+";float:right;color:var(--accent); }
        .map-more[open] summary::after { content:"−"; }
        .map-more .map-list { padding:0 6px 6px; }
        .map-overview-link { display:flex;width:100%;align-items:center;justify-content:space-between;gap:10px;margin-top:8px;padding:9px 10px;border:1px solid var(--line);border-radius:11px;background:rgba(255,255,255,.022);color:#cbd2d5;cursor:pointer; }
        .map-overview-link span { display:flex;align-items:center;gap:7px;font-size:.62rem; }
        .map-overview-link svg { width:15px;height:15px;fill:none;stroke:var(--accent);stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round; }
        .map-overview-link strong { color:var(--accent);font-size:.78rem; }
        .map-cluster-list .map-list-item { display:grid;grid-template-columns:minmax(0,1fr) auto;grid-template-rows:auto auto;gap:2px 8px;padding:7px 9px;border-color:var(--line);border-left-width:3px;background:rgba(255,255,255,.025); }
        .map-cluster-list .map-list-item.green { border-left-color:#30d158; }
        .map-cluster-list .map-list-item.blue { border-left-color:var(--accent); }
        .map-cluster-list .map-list-item.red { border-left-color:#ff453a; }
        .map-cluster-list .map-list-title { grid-column:1;grid-row:1;font-size:.72rem!important; }
        .map-cluster-list .map-list-sub { grid-column:1;grid-row:2;font-size:.53rem; }
        .map-cluster-list .map-chip { grid-column:2;grid-row:1/3;align-self:center;margin:0; }
        .map-desktop-footer { display:none; }
        @media (hover:hover) and (pointer:fine) {
            .card { transition:border-color .2s,transform .2s,background .2s; }
            .card:hover { border-color:color-mix(in srgb,var(--accent) 28%,transparent);background:linear-gradient(145deg,color-mix(in srgb,var(--accent) 4%,#14171a),#0d0f11);transform:translateY(-2px); }
        }
        @media (max-width:920px) {
            .pw-hero { min-height:0;grid-template-columns:1fr;gap:38px;padding-top:75px; }
            .pw-hero-proof { grid-template-columns:repeat(3,minmax(0,1fr)); }
            .pw-hero-proof article { min-height:150px; }
            .pw-workspace-bar { grid-template-columns:1fr; }
            #v-cracked.list, #v-handshakes.list { grid-template-columns:1fr; }
        }
        @media (max-width:700px) {
            body { padding:0 0 calc(88px + env(safe-area-inset-bottom)); }
            body.view-map { height:100svh;overflow:hidden;padding:0; }
            body::after { background-size:64px 64px; }
            .pw-nav-wrap { display:none; }
            .pw-nav { min-height:58px;grid-template-columns:minmax(0,1fr) auto auto auto;gap:8px;padding:6px 7px 6px 15px;border-radius:25px;background:rgba(8,11,12,.92); }
            .pw-nav-meta>span:not(.pw-live-dot), .pw-nav-separator { display:none; }
            .pw-nav-meta { gap:6px; }
            .pw-nav-meta strong { font-size:.61rem; }
            .accent-toggle { width:42px;height:42px;min-height:42px;padding:0;border-radius:50%; }
            .mobile-search-toggle { display:none; }
            .mobile-search-toggle[aria-expanded="true"] { border-color:color-mix(in srgb,var(--accent) 45%,transparent);background:color-mix(in srgb,var(--accent) 8%,transparent);color:var(--accent); }
            .accent-label { display:none; }
            .accent-panel { position:fixed;left:14px;right:14px;top:auto;bottom:calc(82px + env(safe-area-inset-bottom));width:auto;border-radius:24px;animation:accent-mobile-in .24s ease both; }
            @keyframes accent-mobile-in { from { opacity:0;transform:translateY(18px) scale(.98); } to { opacity:1;transform:none; } }
            .pwmenu-main { width:min(calc(100% - 28px),var(--max));padding-bottom:20px; }
            .pw-hero { display:none; }
            .pw-hero::before { left:-55%;top:-10%;width:130vw;height:130vw; }
            .pw-hero::after { mask-image:radial-gradient(circle at 35% 35%,#000,transparent 72%); }
            .pw-eyebrow { margin-bottom:12px;font-size:.59rem; }
            .pw-hero h1 { font-size:clamp(3rem,15.5vw,4.4rem);line-height:.88;white-space:nowrap; }
            .pw-hero-line { margin-top:20px;font-size:1rem;line-height:1.5; }
            .pw-hero-chips { flex-wrap:nowrap;overflow-x:auto;margin:20px -14px 0;padding:0 14px 7px;scrollbar-width:none; }
            .pw-hero-chips::-webkit-scrollbar { display:none; }
            .pw-hero-chips span { flex:0 0 auto; }
            .pw-hero-proof { display:none; }
            .pw-workspace { padding-top:14px; }
            .pw-workspace-bar { position:relative;top:auto;display:block;height:auto;margin:0 0 10px;padding:0;border:0;border-radius:0;background:transparent;box-shadow:none;backdrop-filter:none;-webkit-backdrop-filter:none; }
            .pw-search { position:relative;left:auto;right:auto;top:auto;z-index:1;min-height:43px;padding:0 12px;border:1px solid var(--line-strong);border-radius:14px;background:rgba(8,10,11,.92);box-shadow:none;opacity:1;visibility:visible;transform:none;pointer-events:auto;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px); }
            .pw-search .s-box { min-height:41px;font-size:.76rem; }
            .mobile-search-close { display:none; }
            .tabs { position:fixed;left:50%;bottom:max(9px,env(safe-area-inset-bottom));z-index:150;width:min(calc(100% - 20px),430px);grid-template-columns:repeat(4,1fr);gap:4px;padding:5px;border:1px solid var(--line);border-radius:20px;background:rgba(10,13,14,.94);box-shadow:0 20px 60px rgba(0,0,0,.55);transform:translateX(-50%);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px); }
            .map-placement-label { top:64px;max-width:calc(100% - 32px); }
            .map-placement-controls { bottom:calc(76px + env(safe-area-inset-bottom));border-radius:18px; }
            .tab { min-height:51px;flex-direction:column;gap:1px;padding:5px 3px;border-radius:15px;color:#d7dcde;font-size:.69rem; }
            .tab span { font-size:.49rem; }
            .tab-icon { width:17px;height:17px;flex-basis:17px; }
            #v-cracked.list, #v-handshakes.list { gap:7px; }
            #v-cracked>.si, #v-handshakes>.si { border-radius:14px; }
            #v-cracked>.si>.row, #v-handshakes>.si>.row { min-height:66px;padding:9px 10px; }
            #v-cracked .tit, #v-handshakes .tit { font-size:.82rem; }
            #v-cracked .pwd, #v-handshakes .pwd { font-size:.7rem; }
            #v-cracked .arr, #v-handshakes .arr { width:34px;height:34px;margin-left:5px; }
            .credential-expanded { margin:7px;padding:10px; }
            .credential-value { font-size:.82rem; }
            .network-expanded-tools { padding:7px; }
            .network-expanded-action { min-height:46px;font-size:.64rem; }
            .capture-actions { grid-template-columns:repeat(5,minmax(0,1fr));gap:5px; }
            .capture-action { min-height:49px;border-radius:11px; }
            #v-other:not(.hidden) { grid-template-columns:1fr;gap:10px; }
            .mobile-profile-card { display:block;padding:14px;border:1px solid var(--line);border-radius:18px;background:linear-gradient(145deg,rgba(20,23,26,.96),rgba(10,12,14,.96)); }
            .mobile-profile-top { display:flex;align-items:center;justify-content:space-between;gap:14px; }
            .mobile-profile-top small, .mobile-profile-top strong, .mobile-profile-top>div>span { display:block; }
            .mobile-profile-top small { color:var(--accent);font-size:.52rem;font-weight:900;letter-spacing:.14em;text-transform:uppercase; }
            .mobile-profile-top strong { margin-top:3px;color:#f4f6f7;font-size:1.15rem;letter-spacing:-.03em; }
            .mobile-profile-top>div>span { margin-top:2px;color:#8d979c;font-size:.63rem; }
            .mobile-profile-accent { display:flex;min-height:38px;align-items:center;gap:7px;padding:7px 10px;border:1px solid var(--line);border-radius:12px;background:rgba(255,255,255,.035);color:#d9dee0;font-size:.65rem;font-weight:800;cursor:pointer; }
            .mobile-profile-accent .accent-current { display:block;width:12px;height:12px; }
            .mobile-xp-track { height:4px;overflow:hidden;margin-top:11px;border-radius:999px;background:rgba(255,255,255,.07); }
            .mobile-xp-track i { display:block;height:100%;border-radius:inherit;background:var(--accent);box-shadow:0 0 12px color-mix(in srgb,var(--accent) 55%,transparent); }
            .card { padding:18px;border-radius:20px; }
            .view-map .pw-search, .view-other .pw-search { display:none; }
            .view-map .pw-workspace-bar, .view-other .pw-workspace-bar { height:0;margin:0; }
            .view-map .pw-nav { grid-template-columns:minmax(0,1fr) auto auto; }
            .view-map .pwmenu-page, .view-map .pwmenu-main, .view-map .pw-workspace { width:100%;height:100%;margin:0;padding:0; }
            .map-shell { height:calc(100svh - 28px);min-height:560px;border-radius:15px; }
            .map-stage, .view-map.map-panel-open .map-stage { width:100%;min-height:560px; }
            .view-map .map-shell { position:fixed;inset:0;z-index:10;width:100%;height:100svh;min-height:0;border:0;border-radius:0; }
            .view-map .map-stage, .view-map.map-panel-open .map-stage { height:100%;min-height:0; }
            .map-topbar { top:8px;left:8px;right:8px;gap:6px; }
            .map-filter-toggle { min-height:38px;padding:0 9px;border-radius:12px;font-size:.61rem; }
            .map-filter-track { width:29px;height:17px; }
            .map-filter-track::after { width:11px;height:11px; }
            .map-filter-toggle input:checked + .map-filter-track::after { transform:translateX(12px); }
            .map-search-wrap { min-height:38px;padding:0 9px;border-radius:12px; }
            .map-search { min-height:34px;font-size:.7rem; }
            .map-gps-dot { width:36px;height:36px;flex-basis:36px; }
            .map-gps-pop { top:50px;left:8px;right:8px;padding:9px 10px; }
            .map-sheet { bottom:0;z-index:140;max-height:calc(100% - 52px);padding:25px 12px calc(76px + env(safe-area-inset-bottom));border-radius:22px 22px 0 0; }
            .map-title { font-size:1.16rem; }
            .map-title-row { margin-bottom:8px; }
            .map-close { width:31px;height:31px; }
            .map-metric { padding:7px 4px; }
            .map-metric-value { font-size:.84rem; }
            .map-action { min-height:35px;padding:6px 7px;font-size:.61rem; }
            .map-list-item { padding:8px 9px; }
            .map-title-row { padding-right:35px; }
            .map-close { top:0;right:0; }
            .map-compact-meta span { padding:4px 6px;font-size:.55rem; }
            .map-icon-action { width:auto;height:52px;border-radius:13px; }
            .map-icon-action svg { width:19px;height:19px; }
            .map-icon-action span { font-size:.5rem; }
            .view-map .tabs { left:8px;right:8px;bottom:max(7px,env(safe-area-inset-bottom));width:auto;padding:4px;border-radius:17px;transform:none; }
            .view-map .tab { min-height:43px;font-size:.62rem;border-radius:13px; }
            .view-map .tab span { font-size:.43rem; }
            .newfpv-credit { width:100%;min-width:0; }
        }
        @media (max-width:430px) {
            .pw-brand { font-size:.7rem; }
            .pw-nav-meta strong { max-width:64px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
            .pw-hero h1 { font-size:clamp(2.85rem,15.5vw,3.85rem); }
            .pw-hero-line { max-width:330px;font-size:.9rem; }
            .sub-row { align-items:flex-start;flex-direction:column; }
            .btn-grp { width:100%;justify-content:flex-start; }
            .map-topbar { top:8px;left:8px;right:8px; }
            .map-gps-pop { top:50px;left:8px;right:8px; }
            .map-dock-btn { padding:5px 7px;font-size:.55rem; }
        }
        @media (min-width:701px) {
            .pw-hero { min-height:340px;gap:46px;padding:52px 0 40px; }
            .pw-hero h1 { font-size:clamp(4rem,7vw,6.5rem); }
            .pw-hero-line { margin-top:20px;font-size:clamp(1rem,1.7vw,1.25rem); }
            .pw-hero-chips { margin-top:18px; }
            .pw-hero-proof { gap:7px; }
            .pw-hero-proof article { min-height:96px;padding:15px 16px; }
            .pw-hero-proof article>span { top:14px;right:15px; }
            .pw-hero-proof strong { font-size:1.08rem; }
            .pw-hero-proof p { margin-top:11px;font-size:.65rem; }

            #v-cracked.list, #v-handshakes.list { grid-template-columns:repeat(2,minmax(0,1fr));gap:8px; }
            #v-cracked>.si, #v-handshakes>.si { border-radius:15px; }
            #v-cracked>.si>.row, #v-handshakes>.si>.row { min-height:72px;padding:10px 11px; }
            #v-cracked .tit, #v-handshakes .tit { font-size:.84rem;line-height:1.25; }
            #v-cracked .pwd, #v-handshakes .pwd { font-size:.75rem; }
            #v-cracked .sub, #v-handshakes .sub { margin-top:3px;font-size:.62rem; }
            #v-cracked .icon-btn, #v-handshakes .icon-btn { min-width:29px;width:29px;height:29px;font-size:12px; }
            #v-cracked .badge, #v-handshakes .badge { padding:3px 6px;font-size:.46rem; }
            #v-handshakes .subs { padding:0 7px 7px; }
            #v-handshakes .sub-row { gap:10px;padding:8px 6px; }
            #v-handshakes .btn-xs { padding:5px 7px;font-size:.58rem; }

            .view-map .pw-hero { display:grid; }
            .view-map .pwmenu-main { padding-bottom:70px; }
            .view-map .pw-workspace { padding-top:0; }
            .view-map .pw-workspace-bar { position:sticky;top:91px;display:grid;width:100%;max-width:none;grid-template-columns:minmax(260px,.9fr) minmax(440px,1.1fr);margin:0 0 20px;padding:8px;border:1px solid var(--line);border-radius:25px;background:rgba(8,10,11,.88);box-shadow:0 18px 60px rgba(0,0,0,.27); }
            .view-map .pw-workspace-bar .pw-search { display:flex; }
            .view-map .tabs { gap:5px;width:100%;border-radius:18px;background:rgba(255,255,255,.035); }
            .view-map .tab { min-height:46px;gap:7px;padding:8px 10px;border-radius:15px;font-size:.72rem; }
            .view-map .tab-icon { width:15px;height:15px;flex-basis:15px; }
            .view-map .map-shell { height:calc(100vh - 225px);min-height:480px;border-radius:16px; }
            .view-map .map-stage { width:100%;transition:width .22s ease; }
            .view-map.map-panel-open .map-stage { width:calc(100% - 360px); }
            .view-map .map-topbar { right:12px;width:auto; }
            .view-map .map-search-wrap { display:flex; }
            .view-map .map-gps-pop { right:auto;width:285px;margin:0; }
            .view-map .map-sheet { top:0;right:0;bottom:auto;left:auto;width:350px;max-height:100%;padding:24px 13px 12px;border:1px solid var(--line-strong);border-radius:15px 0 0 15px;animation:mapSlideLeft .2s ease-out; }
            .view-map .map-handle { top:7px; }
            .view-map .map-title { font-size:1.22rem; }
            .view-map .map-dock { bottom:10px; }
            .view-map .map-desktop-footer { display:block;margin-top:8px; }
            .view-map .map-desktop-footer .newfpv-credit { margin:0 auto; }
            @keyframes mapSlideLeft { from { opacity:0;transform:translateX(18px); } to { opacity:1;transform:none; } }
        }
        @media (min-width:1100px) {
            #v-cracked.list, #v-handshakes.list { grid-template-columns:repeat(3,minmax(0,1fr)); }
        }
        @media (prefers-reduced-motion:reduce) {
            html { scroll-behavior:auto; }
            *, *::before, *::after { animation-duration:.01ms!important;transition-duration:.01ms!important; }
        }
    </style>
</head>
<body>
    {% macro newfpv_credit(compact=false) -%}
    <a class="newfpv-credit{% if compact %} compact{% endif %}" href="https://neewfpv.com/" target="_blank" rel="noopener">
        <span><small>Made by</small><strong>New<span class="mark">FPV</span></strong></span>
        <i aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg></i>
    </a>
    {%- endmacro %}
    {% macro capture_row(g, f, best=false) -%}
    <div class="sub-row capture-row{% if best %} best-capture{% endif %}" data-filename="{{ f.filename }}">
        <div class="capture-file-head">
            <div class="capture-file-info">
                <div class="capture-file-name" title="{{ f.filename }}">{{ f.filename }}{% if best %}<span class="best-capture-badge">BEST</span>{% endif %}</div>
                <div class="capture-file-bssid">{{ f.bssid or 'Unknown BSSID' }}</div>
                <div class="capture-file-meta">{{ f.date }} В· {{ f.size }}</div>
                {% if f.quality.grade %}<div class="quality-badge {{ f.quality.grade|lower }}" title="{{ f.quality.summary }}">{{ f.quality.grade }}</div>{% else %}<div class="quality-badge">Pending</div>{% endif %}
            </div>
            <button class="capture-file-delete" onclick='rm({{ f.filename|tojson }})' title="Delete {{ f.filename }}"><svg viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3m-9 0 1 14h10l1-14M10 11v6m4-6v6"></path></svg></button>
        </div>
        <div class="capture-actions">
            <button class="capture-action map-capture-action" onclick='placeHandshakeOnMap({{ f.filename|tojson }}, {{ g.essid|tojson }}, {{ f.bssid|tojson }})'><svg viewBox="0 0 24 24"><path d="M20 10c0 5-8 11-8 11S4 15 4 10a8 8 0 1 1 16 0Z"></path><circle cx="12" cy="10" r="2.5"></circle></svg><span>{{ 'Move' if f.lat is not none and f.lon is not none else 'Map' }}</span></button>
            {% if best %}
            {% if show_wpa %}<button class="capture-action" onclick='upl({{ f.filename|tojson }})'><svg viewBox="0 0 24 24"><path d="M12 3 5 6v5c0 4.6 2.8 8 7 10 4.2-2 7-5.4 7-10V6l-7-3Z"></path><path d="M9 12h6"></path></svg><span>WPA</span></button>{% endif %}
            <button class="capture-action" onclick='sendSingleToOhc({{ f.filename|tojson }})'><svg viewBox="0 0 24 24"><path d="M7 18h10a4 4 0 0 0 .7-7.9A6 6 0 0 0 6.3 8.5 4.8 4.8 0 0 0 7 18Z"></path><path d="m9 13 3-3 3 3m-3-3v6"></path></svg><span>OHC</span></button>
            <a href="/plugins/A_pwmenu/download-22000/{{ f.filename|urlencode }}" class="capture-action accent"><svg viewBox="0 0 24 24"><path d="M8 3 6 21m10-18-2 18M3 9h18M2 15h18"></path></svg><span>22000</span></a>
            <a href="/plugins/A_pwmenu/download/{{ f.filename|urlencode }}" class="capture-action accent"><svg viewBox="0 0 24 24"><path d="M12 3v12m-4-4 4 4 4-4"></path><path d="M5 19h14"></path></svg><span>PCAP</span></a>
            {% endif %}
        </div>
    </div>
    {%- endmacro %}
    <div class="pwmenu-page">

        <header class="pw-nav-wrap">
            <nav class="pw-nav" aria-label="PWMenu navigation">
                <button class="pw-brand" type="button" onclick="tab('cracked')" aria-label="Open cracked passwords">
                    <span class="pw-brand-dot"></span>
                    <span>PWN<span class="pw-brand-mark">MENU</span></span>
                </button>
                <div class="pw-nav-meta">
                    <span class="pw-live-dot"></span>
                    <span>{{ stats.files }} captures</span>
                    <span class="pw-nav-separator"></span>
                    <strong>Level {{ stats.level }}</strong>
                </div>
                <button id="accentToggle" class="accent-toggle accent-trigger" type="button" onclick="toggleAccentPanel(event)" aria-expanded="false" aria-controls="accentPanel">
                    <span class="accent-current"></span>
                    <span class="accent-label">Accent</span>
                </button>
            </nav>
        </header>
        <div id="accentPanel" class="accent-panel hidden" role="dialog" aria-label="Accent color">
                <div class="accent-panel-head">
                    <div><small>Interface</small><strong>Accent color</strong></div>
                    <button type="button" onclick="closeAccentPanel()" aria-label="Close accent picker">&times;</button>
                </div>
                <div class="accent-presets">
                    <button type="button" class="accent-swatch" data-color="#20e4f4" data-name="NewFPV Cyan" style="--swatch:#20e4f4" aria-label="NewFPV Cyan"></button>
                    <button type="button" class="accent-swatch" data-color="#9d63ff" data-name="Violet" style="--swatch:#9d63ff" aria-label="Violet"></button>
                    <button type="button" class="accent-swatch" data-color="#4da3ff" data-name="Electric Blue" style="--swatch:#4da3ff" aria-label="Electric Blue"></button>
                    <button type="button" class="accent-swatch" data-color="#b7ff3c" data-name="Signal Lime" style="--swatch:#b7ff3c" aria-label="Signal Lime"></button>
                    <button type="button" class="accent-swatch" data-color="#ffe72e" data-name="Mistmee Yellow" style="--swatch:#ffe72e" aria-label="Mistmee Yellow"></button>
                    <button type="button" class="accent-swatch" data-color="#ff5b71" data-name="Coral" style="--swatch:#ff5b71" aria-label="Coral"></button>
                </div>
                <label class="accent-custom">
                    <span><small>Custom</small><strong id="accentName">NewFPV Cyan</strong></span>
                    <input id="customAccent" type="color" value="#20e4f4" aria-label="Custom accent color">
                </label>
        </div>

        <main class="pwmenu-main">
            <section class="pw-hero" aria-labelledby="pwmenuTitle">
                <div class="pw-hero-copy">
                    <p class="pw-eyebrow">NewFPV / Pwnagotchi</p>
                    <h1 id="pwmenuTitle">PWN<span class="pw-hero-outline">MENU</span></h1>
                    <p class="pw-hero-line">Capture intelligence, passwords and map data in one field console.</p>
                    <div class="pw-hero-chips">
                        <span><i></i>{{ stats.total }} networks</span>
                        <span><i></i>{{ stats.cracked }} cracked</span>
                        <span><i></i>{{ stats.gps_points }} map points</span>
                    </div>
                </div>
                <aside class="pw-hero-proof" aria-label="PWMenu status">
                    <article><span>01 / progress</span><strong>{{ stats.percent }}%</strong><p>of captured networks have a known password</p></article>
                    <article><span>02 / identity</span><strong>{{ stats.rank }}</strong><p>Level {{ stats.level }} &middot; {{ stats.xp }} / {{ stats.next_xp }} XP</p></article>
                    <article><span>03 / queue</span><strong>{{ ohc_status.pending }}</strong><p>capture file(s) waiting in the persistent OHC queue</p></article>
                </aside>
            </section>

            <section class="pw-workspace" aria-label="Password workspace">
                <div class="pw-workspace-bar">
                    <button id="mobileSearchToggle" class="mobile-search-toggle" type="button" onclick="toggleMobileSearch(event)" aria-expanded="false" aria-controls="workspaceSearch" aria-label="Open search">
                        <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"></circle><path d="m20 20-3.4-3.4"></path></svg>
                    </button>
                    <div id="workspaceSearch" class="pw-search" role="search" aria-label="Search current section">
                        <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="7"></circle><path d="m20 20-3.4-3.4"></path></svg>
                        <input type="text" id="s" class="s-box" onkeyup="flt()" placeholder="Search networks, passwords and captures...">
                        <button class="mobile-search-close" type="button" onclick="closeMobileSearch()" aria-label="Close search">&times;</button>
                    </div>
                    <div class="tabs" role="tablist" aria-label="PWMenu sections">
                        <button class="tab active" onclick="tab('cracked')" id="b-cracked" role="tab"><span class="tab-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"></circle><path d="m11 12 8-8m-3 3 2 2m-5 1 2 2"></path></svg></span><b>Cracked</b></button>
                        <button class="tab" onclick="tab('handshakes')" id="b-handshakes" role="tab"><span class="tab-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M4.9 9.9a10 10 0 0 1 14.2 0M7.8 12.8a6 6 0 0 1 8.4 0m-5.6 2.8a2 2 0 0 1 2.8 0"></path><circle cx="12" cy="19" r="1"></circle></svg></span><b>Handshakes</b></button>
                        <button class="tab" onclick="tab('map')" id="b-map" role="tab"><span class="tab-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><path d="M20 10c0 5-8 11-8 11S4 15 4 10a8 8 0 1 1 16 0Z"></path><circle cx="12" cy="10" r="2.5"></circle></svg></span><b>Map</b></button>
                        <button class="tab" onclick="tab('other')" id="b-other" role="tab"><span class="tab-icon" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="1.5"></circle><circle cx="12" cy="12" r="1.5"></circle><circle cx="19" cy="12" r="1.5"></circle></svg></span><b>Other</b></button>
                    </div>
                </div>

        {% if notif %}
        <div id="nt" class="notif {{ 'err' if ntype == 'error' else '' }}"><b>{{ notif }}</b></div>
        {% endif %}
        <!-- PWMENU_NOTIFICATION -->

        {% if health_issues %}
        <details class="health-panel">
            <summary>
                <span><i></i><b>System attention</b></span>
                <strong>{{ health_issues|length }}</strong>
            </summary>
            <div class="health-issue-list">
                {% for issue in health_issues %}
                <button class="health-issue {{ issue.kind }}" type="button" onclick="tab({{ issue.tab|tojson }})">
                    <span><b>{{ issue.title }}</b><small>{{ issue.detail }}</small></span>
                    <i>&rsaquo;</i>
                </button>
                {% endfor %}
            </div>
        </details>
        {% endif %}

        <div id="v-cracked" class="list hidden">
            <!-- PWMENU_TAB_CRACKED_START -->
            {% for credential_id, d in cracked.items() %}
            <!-- PWMENU_CARD_CRACKED_{{ loop.index }}_START -->
            <div class="si credential-card" data-kind="credential" data-essid="{{ d.essid }}" data-bssid="{{ d.bssid }}" data-t="{{ d.essid }} {{ d.bssid }} {{ d.password }}">
                <div class="row" onclick="tog('cracked-{{ loop.index }}')">
                    <div style="flex-grow:1;min-width:0">
                        <div class="tit">{{ d.essid }}<span class="badge">{{ d.source }}</span></div>
                        <div class="sub">{{ d.bssid or 'Name-only credential' }}</div>
                    </div>
                    <span class="arr" title="Open credential"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"></path></svg></span>
                </div>
                <div id="s-cracked-{{ loop.index }}" class="subs" data-detail-kind="cracked" data-detail-id="{{ loop.index }}">
                    <!-- PWMENU_DETAIL_CRACKED_{{ loop.index }}_START -->
                    <div class="credential-expanded credential-panel">
                        <div class="credential-label">Password</div>
                        <div class="credential-value">{{ d.password }}</div>
                        <div class="credential-actions">
                            <button class="network-expanded-action" onclick='ed({{ d.essid|tojson }}, {{ d.password|tojson }}, {{ d.source|tojson }}, {{ d.bssid|tojson }})'>Edit password</button>
                            <button class="network-expanded-action" style="color:var(--danger)" onclick='del({{ d.essid|tojson }}, {{ d.password|tojson }}, {{ d.source|tojson }}, {{ d.bssid|tojson }})'>Delete password</button>
                        </div>
                    </div>
                    <!-- PWMENU_DETAIL_CRACKED_{{ loop.index }}_END -->
                </div>
            </div>
            <!-- PWMENU_CARD_CRACKED_{{ loop.index }}_END -->
            {% endfor %}
            {% if not cracked %}<div style="padding:30px;text-align:center;color:var(--sub);">No cracked networks yet.</div>{% endif %}
            {{ newfpv_credit(false) }}
            <!-- PWMENU_TAB_CRACKED_END -->
        </div>

        <div id="v-handshakes" class="list hidden">
            <!-- PWMENU_TAB_HANDSHAKES_START -->
            {% for g in groups %}
            {% set group_index = loop.index %}
            <!-- PWMENU_CARD_HANDSHAKES_{{ loop.index }}_START -->
            <div class="si handshake-card" data-kind="handshake" data-essid="{{ g.essid }}" data-bssid="{{ g.bssid }}" data-t="{{ g.essid }}">
                <div class="row">
                    <div style="flex-grow:1;min-width:0" onclick="tog('handshake-{{ loop.index }}')">
                        <div class="tit {{ g.cls }}">{{ g.essid }} {% if g.count > 1 %}<span class="badge">{{ g.count }}</span>{% endif %}{% if g.map_count > 0 %}<span class="badge location-badge" data-location-badge>MAP</span>{% elif g.gps_count > 0 %}<span class="badge location-badge" data-location-badge>GPS</span>{% endif %}</div>
                        <div class="sub">{{ g.last_seen }}</div>
                    </div>
                    <div style="display:flex;align-items:center;">
                        <span class="arr" onclick="tog('handshake-{{ loop.index }}')" title="Open captures"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"></path></svg></span>
                    </div>
                </div>
                <div id="s-handshake-{{ loop.index }}" class="subs" data-detail-kind="handshake" data-detail-id="{{ loop.index }}">
                    <!-- PWMENU_DETAIL_HANDSHAKE_{{ loop.index }}_START -->
                    {% if g.is_cracked and g.pwd %}
                    <div class="credential-expanded credential-panel">
                        <div class="credential-label">Recovered password</div>
                        <div class="credential-value">{{ g.pwd }}</div>
                        <div class="credential-actions">
                            <button class="network-expanded-action" onclick='ed({{ g.essid|tojson }}, {{ g.pwd|tojson }}, {{ g.src|tojson }}, {{ g.bssid|tojson }})'>Edit password</button>
                            <button class="network-expanded-action" style="color:var(--danger)" onclick='del({{ g.essid|tojson }}, {{ g.pwd|tojson }}, {{ g.src|tojson }}, {{ g.bssid|tojson }})'>Delete password</button>
                        </div>
                    </div>
                    {% endif %}
                    <div class="network-expanded-tools">
                        {% if not g.is_cracked or not g.pwd %}
                        <button class="network-expanded-action password-add-action" onclick='add({{ g.essid|tojson }}, {{ g.bssid|tojson }})' title="Add a recovered password"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="8" cy="15" r="4"></circle><path d="m11 12 7-7m-2 0h4m-2-2v4"></path></svg><span>Add password</span></button>
                        {% endif %}
                        <button class="network-expanded-action" onclick='whitelistAdd({{ g.essid|tojson }}, "handshakes", {{ g.bssid|tojson }})' title="Add this network to the whitelist"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 5 6v5c0 4.6 2.8 8 7 10 4.2-2 7-5.4 7-10V6l-7-3Z"></path><path d="m9 12 2 2 4-4"></path></svg><span>Whitelist</span></button>
                    </div>
                    {% for f in g.files %}
                    {% if f.is_best %}
                    <div class="sub-row capture-row" data-filename="{{ f.filename }}">
                        <div class="capture-file-head">
                            <div class="capture-file-info">
                                <div class="capture-file-name" title="{{ f.filename }}">{{ f.filename }}<span class="best-capture-badge">BEST</span></div>
                                <div class="capture-file-bssid">{{ f.bssid or 'Unknown BSSID' }}</div>
                                <div class="capture-file-meta">{{ f.date }} · {{ f.size }}</div>
                                {% if f.quality.grade %}<div class="quality-badge {{ f.quality.grade|lower }}" title="{{ f.quality.summary }}">{{ f.quality.grade }}</div>{% else %}<div class="quality-badge">Pending</div>{% endif %}
                            </div>
                            <button class="capture-file-delete" onclick='rm({{ f.filename|tojson }})' title="Delete {{ f.filename }}"><svg viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3m-9 0 1 14h10l1-14M10 11v6m4-6v6"></path></svg></button>
                        </div>
                        <div class="capture-actions">
                            <button class="capture-action map-capture-action" onclick='placeHandshakeOnMap({{ f.filename|tojson }}, {{ g.essid|tojson }}, {{ f.bssid|tojson }})'><svg viewBox="0 0 24 24"><path d="M20 10c0 5-8 11-8 11S4 15 4 10a8 8 0 1 1 16 0Z"></path><circle cx="12" cy="10" r="2.5"></circle></svg><span>{{ 'Move' if f.lat is not none and f.lon is not none else 'Map' }}</span></button>
                            {% if show_wpa %}<button class="capture-action" onclick='upl({{ f.filename|tojson }})'><svg viewBox="0 0 24 24"><path d="M12 3 5 6v5c0 4.6 2.8 8 7 10 4.2-2 7-5.4 7-10V6l-7-3Z"></path><path d="M9 12h6"></path></svg><span>WPA</span></button>{% endif %}
                            <button class="capture-action" onclick='sendSingleToOhc({{ f.filename|tojson }})'><svg viewBox="0 0 24 24"><path d="M7 18h10a4 4 0 0 0 .7-7.9A6 6 0 0 0 6.3 8.5 4.8 4.8 0 0 0 7 18Z"></path><path d="m9 13 3-3 3 3m-3-3v6"></path></svg><span>OHC</span></button>
                            <a href="/plugins/A_pwmenu/download-22000/{{ f.filename|urlencode }}" class="capture-action accent"><svg viewBox="0 0 24 24"><path d="M8 3 6 21m10-18-2 18M3 9h18M2 15h18"></path></svg><span>22000</span></a>
                            <a href="/plugins/A_pwmenu/download/{{ f.filename|urlencode }}" class="capture-action accent"><svg viewBox="0 0 24 24"><path d="M12 3v12m-4-4 4 4 4-4"></path><path d="M5 19h14"></path></svg><span>PCAP</span></a>
                        </div>
                    </div>
                    {% endif %}
                    {% endfor %}
                    {% if g.other_files %}
                    <details class="capture-other-list">
                        <summary><span>Other captures</span><b>{{ g.other_files|length }}</b></summary>
                        <div class="capture-other-body">
                            {% for f in g.other_files %}
                            {{ capture_row(g, f, false) }}
                            {% endfor %}
                        </div>
                    </details>
                    {% endif %}
                    <!-- PWMENU_DETAIL_HANDSHAKE_{{ loop.index }}_END -->
                </div>
            </div>
            <!-- PWMENU_CARD_HANDSHAKES_{{ loop.index }}_END -->
            {% endfor %}
            {{ newfpv_credit(false) }}
            <!-- PWMENU_TAB_HANDSHAKES_END -->
        </div>

        <div id="v-map" class="map-shell hidden">
            <!-- PWMENU_TAB_MAP_START -->
            <div class="map-stage" id="mapStage">
                <div class="map-topbar">
                    <label class="map-filter-toggle map-glass" title="Show only cracked networks">
                        <input id="mapCrackedToggle" type="checkbox" onchange="setMapFilter(this.checked ? 'cracked' : 'all')">
                        <span class="map-filter-track"></span><b>Cracked</b>
                    </label>
                    <div class="map-search-wrap map-glass">
                        <input type="text" id="mapSearch" class="map-search" oninput="renderMap()" placeholder="Search networks...">
                    </div>
                    <button id="gpsStatusDot" class="map-gps-dot offline hidden" type="button" tabindex="-1" aria-hidden="true"></button>
                </div>
                <div id="mapPlacementTarget" class="map-placement-target hidden" hidden>
                    <div class="map-placement-pin" aria-hidden="true">
                        <svg viewBox="0 0 64 64"><path d="M32 60S12 43.5 12 25a20 20 0 1 1 40 0C52 43.5 32 60 32 60Z"></path><circle cx="32" cy="25" r="10"></circle><path d="M32 20v10m-5-5h10"></path></svg>
                    </div>
                </div>
                <div id="mapPlacementText" class="map-placement-label hidden" hidden>Move the map, then confirm.</div>
                <div id="mapPlacementControls" class="map-placement-controls hidden" hidden>
                    <button class="map-placement-cancel" type="button" onclick="cancelMapPlacement()" title="Cancel"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 6 12 12M18 6 6 18"></path></svg></button>
                    <button class="map-placement-confirm" type="button" onclick="confirmMapPlacement()" title="Place here"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5 12 4 4L19 6"></path></svg></button>
                </div>
                <div id="gpsStatusPop" class="map-gps-pop hidden"></div>
                <div id="mapEmpty" class="map-empty hidden">
                    <b>No GPS points</b>
                    <div style="margin-top:6px;">{{ stats.no_gps }} networks without coordinates</div>
                </div>
                <div id="yandexMap" class="ymap-real"></div>
                <div id="mapMarkers"></div>
                <div id="mapDock" class="hidden" style="display:none!important" aria-hidden="true"><button id="mapAllBtn"></button><button id="mapCrackedBtn"></button><button id="mapNoGpsBtn"></button></div>
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
                    <button class="map-overview-link" type="button" onclick="showNoGpsList()">
                        <span><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 10c0 5-8 11-8 11S4 15 4 10a8 8 0 1 1 16 0Z"></path><path d="m9 9 6 6m0-6-6 6"></path></svg><b>No GPS networks</b></span>
                        <strong>{{ stats.no_gps }}</strong>
                    </button>
                </div>
                <div id="mapDetails" class="hidden"></div>
            </div>
            <!-- PWMENU_TAB_MAP_END -->
        </div>
        <footer class="map-desktop-footer">{{ newfpv_credit(false) }}</footer>

        <div id="v-other" class="hidden">
            <!-- PWMENU_TAB_OTHER_START -->
            {% set conflicts = conflicts|default([]) %}
            {% set activity_history = activity_history|default({'items': [], 'total': 0, 'nextOffset': 0, 'hasMore': false}) %}
            <div class="card identity-card" aria-label="Pwnagotchi identity and achievements">
                <div class="identity-card-top">
                    <button id="identityDisclosure" class="identity-disclosure" type="button" onclick="toggleIdentityAchievements()" aria-expanded="false" aria-controls="identityAchievements">
                        <span>
                            <small>Identity</small>
                            <strong>{{ stats.rank }}</strong>
                            <span>Level {{ stats.level }} &middot; {{ stats.xp }} / {{ stats.next_xp }} XP</span>
                        </span>
                        <i class="identity-chevron"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"></path></svg></i>
                    </button>
                    <button id="mobileAccentToggle" class="identity-theme accent-trigger" type="button" onclick="toggleAccentPanel(event)" aria-expanded="false" aria-controls="accentPanel">
                        <i class="accent-current"></i><span>Theme</span>
                    </button>
                </div>
                <div class="mobile-xp-track" aria-label="Level progress {{ stats.lvl_percent }} percent"><i style="width:{{ stats.lvl_percent }}%"></i></div>
                <div id="identityAchievements" class="identity-achievements hidden">
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
            </div>
            <div class="card ohc-card" style="padding:15px;text-align:left;">
                <h3 style="margin-top:0;text-align:center;"><a class="external-service-link" href="https://app.onlinehashcrack.com/" target="_blank" rel="noopener noreferrer">OnlineHashCrack ↗</a></h3>
                <button class="btn" style="margin-top:0;background:#ff9f0a;" onclick="sendAllMissingToOhc()">Send all missing to OHC</button>
                <div class="sub" style="margin-top:10px;">
                    Persistent queue: {{ ohc_status.pending }} file(s)
                    {% if ohc_status.retry_in > 0 %} • retry in {{ ohc_status.retry_in }}s{% endif %}
                </div>
                {% if ohc_status.uncrackable %}
                <div class="service-alert"><b>{{ ohc_status.uncrackable }} capture(s) have no extractable WPA/PMKID hash.</b><span>They are excluded before upload and listed in Capture cleanup.</span></div>
                {% endif %}
                {% if not pot_health.ok %}
                <div class="service-alert">
                    <b>OHC password storage needs attention</b>
                    <span>{{ pot_health.credentials }} credential(s), {{ pot_health.duplicates }} duplicate(s), {{ pot_health.invalid }} invalid line(s), {{ pot_health.nul_bytes }} NUL byte(s).</span>
                </div>
                {% endif %}
                <div class="sub" style="margin-top:6px;">Queues one best unresolved PCAP per BSSID. Local history and the latest imported OHC export are excluded before upload.</div>
            </div>

            <div class="card wpa-card" style="padding:15px;text-align:left;">
                <h3 style="margin-top:0;text-align:center;"><a class="external-service-link" href="https://wpa-sec.stanev.org/?submit=" target="_blank" rel="noopener noreferrer">WPA-sec ↗</a></h3>
                <button class="btn" style="margin-top:0;background:#147a45;color:#fff;" onclick="syncWpaSec()">Sync WPA-sec now</button>
                <div class="sub" style="margin-top:10px;">
                    Integrated uploader: {{ wpa_status.submitted }} network(s) remembered
                    {% if wpa_status.pending %} · {{ wpa_status.pending }} queued{% endif %}
                </div>
                <div class="sub" style="margin-top:4px;">
                    {% if wpa_status.results_present %}
                    Results: {{ wpa_status.results_bytes }} bytes · updated {{ wpa_status.results_updated }}
                    {% else %}
                    No downloaded result file yet.
                    {% endif %}
                </div>
                {% if wpa_status.last_upload %}<div class="sub" style="margin-top:4px;">{{ wpa_status.last_upload }}</div>{% endif %}
            </div>

            <div class="card whitelist-card" style="padding:15px;text-align:left;">
                <div class="compact-card-heading">
                    <div><small>Pwnagotchi protection</small><h3>Network whitelist</h3></div>
                    <strong id="whitelistTotal">{{ whitelist|length }}</strong>
                </div>
                <div class="sub">Add an exact network name. Changes are written atomically and applied to the running Pwnagotchi session.</div>
                <form method="POST" action="/plugins/A_pwmenu/whitelist-add" class="whitelist-form" onsubmit="return whitelistFormSubmit(event)">
                    <input type="hidden" name="csrf_token" value="{{ token }}">
                    <input type="hidden" name="return_tab" value="other">
                    <input class="whitelist-input" type="text" name="network" maxlength="128" autocomplete="off" placeholder="Network name" required>
                    <button class="whitelist-submit">Add network</button>
                </form>
                <div id="whitelistListHost">
                <div class="whitelist-compact-list">
                    {% for network in whitelist %}
                    <div class="whitelist-compact-item">
                        <i></i>
                        <span><b>{{ network }}</b><small>Ignored during capture</small></span>
                        <button class="whitelist-remove" type="button" onclick='whitelistRemove({{ network|tojson }})'>Remove</button>
                    </div>
                    {% else %}
                    <div class="whitelist-compact-empty">No active whitelist entries.</div>
                    {% endfor %}
                </div>
                </div>
            </div>

            {% if conflicts %}
            <div class="card conflict-card" style="padding:15px;text-align:left;">
                <div class="compact-card-heading">
                    <div><small>Needs review</small><h3>Conflict center</h3></div>
                    <div class="compact-card-heading-actions">
                        <strong id="conflictTotal">{{ conflicts|length }}</strong>
                        <button class="compact-copy-button" type="button" onclick="copyConflictCenter(this)" title="Copy every conflict" aria-label="Copy every conflict">
                            <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="8" width="11" height="11" rx="2"></rect><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"></path></svg>
                        </button>
                    </div>
                </div>
                <div class="sub">Equivalent punctuation-only aliases are reconciled automatically. Passwords change only after local cryptographic verification.</div>
                <div class="conflict-list">
                    {% for conflict in conflicts %}
                    <div class="conflict-item {{ conflict.kind }}" data-bssid="{{ conflict.bssid }}">
                        <i></i>
                        <span>
                            <b>{{ conflict.title }}</b>
                            <small>{{ conflict.detail }}</small>
                        </span>
                        <div class="conflict-item-actions">
                            <em>{{ conflict.kind }}</em>
                            {% if conflict.repairable %}
                            <button class="conflict-repair" type="button" onclick='repairPasswordConflict(this, {{ conflict.bssid|tojson }})'>Verify &amp; fix</button>
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            {% endif %}

            <div class="card activity-card" style="padding:15px;text-align:left;">
                <div class="compact-card-heading">
                    <div><small>Pwnagotchi + PWMenu</small><h3>Activity history</h3></div>
                    <div class="compact-card-heading-actions">
                        <strong id="activityHistoryTotal">{{ activity_history['total'] }}</strong>
                        <button class="compact-copy-button" type="button" onclick="copyAllActivityHistory(this)" title="Copy complete activity history" aria-label="Copy complete activity history">
                            <svg viewBox="0 0 24 24" aria-hidden="true"><rect x="8" y="8" width="11" height="11" rx="2"></rect><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"></path></svg>
                        </button>
                    </div>
                </div>
                <div id="activityHistoryList" class="activity-history-list">
                    {% for item in activity_history['items'] %}
                    <div class="activity-history-item {{ item.kind }}">
                        <i></i>
                        <span>
                            <b>{{ item.title }}</b>
                            {% if item.detail %}<small>{{ item.detail }}</small>{% endif %}
                        </span>
                        <time>{{ item.time }}<small>{{ item.source }}</small></time>
                    </div>
                    {% else %}
                    <div class="activity-history-empty">Important Pwnagotchi events will appear here.</div>
                    {% endfor %}
                </div>
            </div>

            <div class="card operations-card" style="padding:15px;text-align:left;">
                <div class="compact-card-heading">
                    <div><small>Library</small><h3>Results &amp; transfer</h3></div>
                </div>
                <div class="other-stat-grid">
                    <div class="other-stat primary"><strong>{{ stats.percent }}%</strong><small>Cracked</small></div>
                    <div class="other-stat"><strong>{{ stats.total }}</strong><small>Networks</small></div>
                    <div class="other-stat"><strong>{{ stats.files }}</strong><small>Files</small></div>
                </div>
                <div class="other-action-grid">
                    <a href="/plugins/A_pwmenu/export-passwords" class="other-action primary">Export passwords</a>
                    <a href="/plugins/A_pwmenu/download-zip" class="other-action">Download all PCAPs</a>
                    <a href="/plugins/A_pwmenu/download-uncracked" class="other-action">Download Uncracked</a>
                    <button class="other-action" type="button" onclick="downloadPWMenuBackup()">Download backup</button>
                    <button class="other-action" type="button" onclick="document.getElementById('fi').click()">Import</button>
                    <button class="other-action" type="button" onclick="post('sync-time', {})">Sync device time</button>
                </div>
                <form method="POST" action="/plugins/A_pwmenu/import" enctype="multipart/form-data" id="if">
                    <input type="hidden" name="csrf_token" value="{{ token }}">
                    <input type="file" id="fi" name="file" accept=".json,.csv,.pwmenu-backup,application/zip" hidden onchange="sel(this)">
                    <div id="fn" class="compact-import-state">
                        <span>No import file selected</span>
                        <button id="ib" type="submit">Import selected</button>
                    </div>
                </form>
                <div class="sub" style="margin-top:9px;">Import accepts OHC/Handshake Lab results or a PWMenu backup. A backup contains every PCAP, GPS/MAP point, setting, history record, submission state and recovered password. It is not encrypted.</div>
            </div>

            {% if cleanup_report.count %}
            <div class="card cleanup-card" style="padding:15px;text-align:left;">
                <h3 style="margin-top:0;text-align:center;">Capture Cleanup</h3>
                <div style="font-weight:800;color:{{ 'var(--danger)' if cleanup_report.count else 'var(--green)' }};">
                    {{ cleanup_report.count }} cleanup candidate(s)
                </div>
                <div class="sub" style="margin-top:6px;">{{ cleanup_report.empty_count }} empty header(s), {{ cleanup_report.uncrackable_count }} incomplete capture(s) without a usable WPA/PMKID hash, and {{ cleanup_report.unusable_count }} analyzed unusable capture(s). Every file and signature is checked again immediately before deletion.</div>
                {% if cleanup_report.display_files %}
                <ul class="cleanup-file-list">
                    {% for item in cleanup_report.display_files %}<li><strong>{{ item.name }}</strong><span>{{ item.reason }}</span></li>{% endfor %}
                    {% if cleanup_report.more %}<li><strong>+ {{ cleanup_report.more }} more file(s)</strong></li>{% endif %}
                </ul>
                <form method="POST" action="/plugins/A_pwmenu/clean-captures" onsubmit="return confirm('Permanently remove {{ cleanup_report.count }} reviewed empty, uncrackable, or unusable capture file(s) and their companion metadata?')">
                    <input type="hidden" name="csrf_token" value="{{ token }}">
                    <input type="hidden" name="report_token" value="{{ cleanup_report.token }}">
                    <button class="btn red">Clean Reviewed Captures</button>
                </form>
                {% endif %}
            </div>
            {% endif %}

            {{ newfpv_credit(false) }}
            <!-- PWMENU_TAB_OTHER_END -->
        </div>
            </section>
        </main>
    </div>
    <div id="mapToast" class="map-toast" role="status" aria-live="polite">Done</div>

    <script>
        const csrfToken = '{{ token }}';
        const wpaEnabled = {{ 'true' if show_wpa else 'false' }};
        let mapPoints = {{ map_points|tojson }};
        let noGpsNetworks = {{ no_gps_networks|tojson }};
        const gpsStatus = {{ gps_status|tojson }};
        const whitelistedNetworks = new Set({{ whitelist|tojson }});
        const notificationDurationMs = {{ notification_duration_ms }};
        const backgroundBatchSize = {{ web_background_batch_size|default(12) }};
        const backgroundBatchDelayMs = {{ web_background_batch_delay_ms|default(120) }};
        const foregroundBatchSize = {{ web_foreground_batch_size|default(24) }};
        const foregroundBatchDelayMs = {{ web_foreground_batch_delay_ms|default(50) }};
        let gpsWatchId = null;
        let selectedMapPoint = null;
        let userLocation = null;
        let mapFilter = 'all';
        let yandexMap = null;
        let yandexObjects = null;
        let yandexReady = false;
        let yandexLoader = null;
        let activeMapGroup = null;
        let mapPlacement = null;
        let offlinePlacementCenter = null;
        const pendingMapActions = new Set();
        const accentStorageKey = 'a_pwmenu_accent_v1';

        const t0 = '{{ tab }}';
        initAccentPicker();
        tab(t0);
        startPhoneGps(false);
        updateGpsStatusDot();
        renderMap();
        if(document.getElementById('nt')) setTimeout(() => document.getElementById('nt').style.display='none', notificationDurationMs);

        function post(u, d) {
            const f = document.createElement('form'); f.method='POST'; f.action='/plugins/A_pwmenu/'+u;
            const t = document.createElement('input'); t.type='hidden'; t.name='csrf_token'; t.value=csrfToken; f.appendChild(t);
            for(const k in d) { const i=document.createElement('input'); i.name=k; i.value=d[k]; f.appendChild(i); }
            document.body.appendChild(f); f.submit();
        }

        async function postAsync(u, data) {
            const body = new URLSearchParams();
            body.append('csrf_token', csrfToken);
            Object.entries(data || {}).forEach(([key, value]) => body.append(key, value));
            const response = await fetch('/plugins/A_pwmenu/' + u, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                    'X-PWMenu-Async': '1'
                },
                body: body.toString()
            });
            let payload = null;
            try { payload = await response.json(); } catch(error) {}
            if(!response.ok || !payload) throw new Error(payload && payload.message ? payload.message : `Request failed (${response.status})`);
            return payload;
        }

        async function downloadPWMenuBackup() {
            showToast('Preparing backup...', false);
            const body = new URLSearchParams();
            body.set('csrf_token', csrfToken);
            try {
                const response = await fetch('/plugins/A_pwmenu/backup-export', {
                    method:'POST',
                    credentials:'same-origin',
                    headers:{
                        'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8',
                        'X-PWMenu-Async':'1'
                    },
                    body:body.toString()
                });
                if(!response.ok) {
                    let message = 'Backup creation failed';
                    try {
                        const payload = await response.json();
                        message = payload.message || message;
                    } catch(error) {}
                    throw new Error(message);
                }
                const blob = await response.blob();
                const disposition = response.headers.get('Content-Disposition') || '';
                const match = disposition.match(/filename="?([^";]+)"?/i);
                const filename = match ? match[1] : 'PWMenu-backup.pwmenu-backup';
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = filename;
                document.body.appendChild(link);
                link.click();
                link.remove();
                setTimeout(() => URL.revokeObjectURL(url), 1500);
                showToast('PWMenu backup downloaded', false);
            } catch(error) {
                showToast(error.message || 'Backup creation failed', true);
            }
        }

        async function restorePWMenuBackup(input) {
            const file = input && input.files ? input.files[0] : null;
            if(!file) return;
            if(!confirm('This backup is not encrypted. Restore its settings, state, every handshake, map point and password? PWMenu will restart only its service.')) {
                input.value = '';
                return;
            }
            const body = new FormData();
            body.append('csrf_token', csrfToken);
            body.append('file', file, file.name);
            showToast('Verifying and restoring backup...', false);
            try {
                const response = await fetch('/plugins/A_pwmenu/backup-restore', {
                    method:'POST',
                    credentials:'same-origin',
                    headers:{'X-PWMenu-Async':'1'},
                    body
                });
                const payload = await response.json();
                if(!response.ok || !payload.ok) {
                    throw new Error(payload.message || 'Backup restore failed');
                }
                showToast(payload.message || 'Backup restored', false);
                setTimeout(() => window.location.replace('/plugins/A_pwmenu/?restored=' + Date.now()), 9000);
            } catch(error) {
                showToast(error.message || 'Backup restore failed', true);
            } finally {
                input.value = '';
            }
        }

        async function runMapAction(route, data, pendingMessage) {
            const key = route + ':' + String((data || {}).filenames || '');
            if(pendingMapActions.has(key)) {
                showToast('This action is already in progress', true);
                return;
            }
            pendingMapActions.add(key);
            showToast(pendingMessage || 'Working...', false);
            try {
                const result = await postAsync(route, data);
                showToast(result.message || (result.ok ? 'Done' : 'Action failed'), !result.ok);
            } catch(error) {
                showToast(error.message || 'Request failed', true);
            } finally {
                pendingMapActions.delete(key);
            }
        }

        function accentContrast(hex) {
            const value = String(hex || '').replace('#', '');
            if(!/^[0-9a-f]{6}$/i.test(value)) return '#001013';
            const rgb = [0, 2, 4].map(index => parseInt(value.slice(index, index + 2), 16) / 255);
            const linear = rgb.map(channel => channel <= .03928 ? channel / 12.92 : Math.pow((channel + .055) / 1.055, 2.4));
            const luminance = .2126 * linear[0] + .7152 * linear[1] + .0722 * linear[2];
            return luminance > .42 ? '#001013' : '#ffffff';
        }

        function applyAccent(color, name, persist) {
            if(!/^#[0-9a-f]{6}$/i.test(String(color || ''))) return;
            const normalized = color.toLowerCase();
            document.documentElement.style.setProperty('--accent', normalized);
            document.documentElement.style.setProperty('--accent-contrast', accentContrast(normalized));
            const custom = document.getElementById('customAccent');
            const label = document.getElementById('accentName');
            if(custom) custom.value = normalized;
            if(label) label.textContent = name || normalized.toUpperCase();
            document.querySelectorAll('.accent-swatch').forEach(button => {
                button.classList.toggle('active', button.dataset.color.toLowerCase() === normalized);
            });
            if(persist) {
                try {
                    localStorage.setItem(accentStorageKey, JSON.stringify({color:normalized, name:name || normalized.toUpperCase()}));
                } catch(error) {}
                document.cookie = 'a_pwmenu_accent=' + normalized.slice(1) + '; Max-Age=31536000; Path=/; SameSite=Lax';
            }
        }

        function initAccentPicker() {
            let saved = null;
            try { saved = JSON.parse(localStorage.getItem(accentStorageKey) || 'null'); } catch(error) {}
            if(!saved || !saved.color) {
                const cookieMatch = document.cookie.match(/(?:^|;\\s*)a_pwmenu_accent=([0-9a-f]{6})(?:;|$)/i);
                if(cookieMatch) saved = {color:'#' + cookieMatch[1], name:'Saved ' + cookieMatch[1].toUpperCase()};
            }
            applyAccent(saved && saved.color ? saved.color : '#20e4f4', saved && saved.name ? saved.name : 'NewFPV Cyan', false);
            document.querySelectorAll('.accent-swatch').forEach(button => {
                button.addEventListener('click', () => applyAccent(button.dataset.color, button.dataset.name, true));
            });
            const custom = document.getElementById('customAccent');
            if(custom) {
                custom.addEventListener('input', event => applyAccent(event.target.value, 'Custom ' + event.target.value.toUpperCase(), true));
            }
            document.addEventListener('click', event => {
                const panel = document.getElementById('accentPanel');
                const toggles = Array.from(document.querySelectorAll('.accent-trigger'));
                if(panel && !panel.classList.contains('hidden') && !panel.contains(event.target) && !toggles.some(toggle => toggle.contains(event.target))) closeAccentPanel();
                const search = document.getElementById('workspaceSearch');
                const searchToggle = document.getElementById('mobileSearchToggle');
                if(document.body.classList.contains('mobile-search-open') && search && !search.contains(event.target) && searchToggle && !searchToggle.contains(event.target)) closeMobileSearch();
            });
            document.addEventListener('keydown', event => {
                if(event.key === 'Escape') {
                    closeAccentPanel();
                    closeMobileSearch();
                    if(mapPlacement) cancelMapPlacement();
                }
            });
        }

        function toggleMobileSearch(event) {
            if(event) event.stopPropagation();
            const toggle = document.getElementById('mobileSearchToggle');
            const opening = !document.body.classList.contains('mobile-search-open');
            document.body.classList.toggle('mobile-search-open', opening);
            if(toggle) toggle.setAttribute('aria-expanded', opening ? 'true' : 'false');
            if(opening) setTimeout(() => document.getElementById('s').focus(), 90);
        }

        function closeMobileSearch() {
            document.body.classList.remove('mobile-search-open');
            const toggle = document.getElementById('mobileSearchToggle');
            if(toggle) toggle.setAttribute('aria-expanded', 'false');
        }

        function toggleAccentPanel(event) {
            if(event) event.stopPropagation();
            const panel = document.getElementById('accentPanel');
            const opening = panel.classList.contains('hidden');
            panel.classList.toggle('hidden', !opening);
            document.querySelectorAll('.accent-trigger').forEach(toggle => toggle.setAttribute('aria-expanded', opening ? 'true' : 'false'));
        }

        function closeAccentPanel() {
            const panel = document.getElementById('accentPanel');
            if(panel) panel.classList.add('hidden');
            document.querySelectorAll('.accent-trigger').forEach(toggle => toggle.setAttribute('aria-expanded', 'false'));
        }

        function sel(i) {
            if(i.files[0]) {
                const file = i.files[0];
                if(/[.]pwmenu-backup$/i.test(file.name) || file.type === 'application/zip') {
                    restorePWMenuBackup(i);
                    return;
                }
                const state = document.getElementById('fn');
                const name = state && state.querySelector('span');
                if(name) name.innerText = file.name;
                if(state) state.classList.add('ready');
            }
        }

        function toggleIdentityAchievements() {
            const button = document.getElementById('identityDisclosure');
            const panel = document.getElementById('identityAchievements');
            if(!button || !panel) return;
            const opening = panel.classList.contains('hidden');
            panel.classList.toggle('hidden', !opening);
            button.setAttribute('aria-expanded', opening ? 'true' : 'false');
        }

        function compactBssid(value) {
            const clean = String(value || '').toLowerCase().replace(/[^0-9a-f]/g, '');
            return clean.length === 12 ? clean : '';
        }

        function normalizedEssid(value) {
            return String(value || '').normalize().replace(/[^\\p{L}\\p{N}]+/gu, '').toLowerCase();
        }

        function sameNetwork(aEssid, aBssid, bEssid, bBssid) {
            const aMac = compactBssid(aBssid);
            const bMac = compactBssid(bBssid);
            if(aMac && bMac) return aMac === bMac;
            return normalizedEssid(aEssid) === normalizedEssid(bEssid);
        }

        function passwordPanelHtml(credential) {
            if(!credential || !credential.password) return '';
            return `<div class="credential-expanded credential-panel">
                <div class="credential-label">Recovered password</div>
                <div class="credential-value">${esc(credential.password)}</div>
                <div class="credential-actions">
                    <button class="network-expanded-action" onclick='ed(${jsq(credential.essid)}, ${jsq(credential.password)}, ${jsq(credential.source || '')}, ${jsq(credential.bssid || '')})'>Edit password</button>
                    <button class="network-expanded-action" style="color:var(--danger)" onclick='del(${jsq(credential.essid)}, ${jsq(credential.password)}, ${jsq(credential.source || '')}, ${jsq(credential.bssid || '')})'>Delete password</button>
                </div>
            </div>`;
        }

        function credentialCardHtml(credential) {
            const id = 'dynamic-' + Date.now() + '-' + Math.floor(Math.random() * 10000);
            return `<div class="si credential-card" data-kind="credential" data-essid="${esc(credential.essid)}" data-bssid="${esc(credential.bssid || '')}" data-t="${esc(`${credential.essid} ${credential.bssid || ''} ${credential.password}`)}">
                <div class="row" onclick="tog('${id}')">
                    <div style="flex-grow:1;min-width:0">
                        <div class="tit">${esc(credential.essid)}<span class="badge">${esc(credential.source || 'Manual')}</span></div>
                        <div class="sub">${esc(credential.bssid || 'Name-only credential')}</div>
                    </div>
                    <span class="arr" title="Open credential"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"></path></svg></span>
                </div>
                <div id="s-${id}" class="subs">${passwordPanelHtml(credential)}</div>
            </div>`;
        }

        function updateMapCredential(essid, bssid, credential) {
            const visit = item => {
                if(!item) return;
                if(sameNetwork(item.essid, item.bssid, essid, bssid)) {
                    item.password = credential ? String(credential.password || '') : '';
                    item.is_cracked = !!(credential && credential.password);
                    item.status = item.is_cracked ? 'cracked' : 'handshake';
                }
                (item.members || []).forEach(visit);
                (item.history || []).forEach(visit);
                if(item.members && item.members.length > 1) {
                    item.is_cracked = item.members.some(member => member.is_cracked);
                    item.status = item.is_cracked ? 'cracked' : 'handshake';
                }
            };
            mapPoints.forEach(visit);
            noGpsNetworks.forEach(visit);
            renderMap();
            refreshOpenMapCard();
        }

        function applyPasswordResult(result) {
            const credential = result.credential && result.credential.password
                ? result.credential : null;
            const cards = Array.from(document.querySelectorAll('.si[data-kind]'));
            const matching = cards.filter(card => sameNetwork(
                card.dataset.essid, card.dataset.bssid,
                result.essid, result.bssid
            ));
            const credentialCards = matching.filter(card => card.dataset.kind === 'credential');
            const handshakeCards = matching.filter(card => card.dataset.kind === 'handshake');

            if(credential) {
                if(credentialCards.length) {
                    credentialCards.forEach(card => {
                        card.dataset.essid = credential.essid || result.essid;
                        card.dataset.bssid = credential.bssid || result.bssid || '';
                        card.dataset.t = `${credential.essid} ${credential.bssid || ''} ${credential.password}`;
                        const title = card.querySelector('.tit');
                        if(title) title.innerHTML = `${esc(credential.essid)}<span class="badge">${esc(credential.source || 'Manual')}</span>`;
                        const sub = card.querySelector('.sub');
                        if(sub) sub.textContent = credential.bssid || 'Name-only credential';
                        const panel = card.querySelector('.credential-panel');
                        if(panel) panel.outerHTML = passwordPanelHtml(credential);
                    });
                } else {
                    const list = document.getElementById('v-cracked');
                    if(list) {
                        const credit = list.querySelector('.newfpv-credit');
                        const holder = document.createElement('div');
                        holder.innerHTML = credentialCardHtml(credential);
                        list.insertBefore(holder.firstElementChild, credit || null);
                    }
                }
            } else {
                credentialCards.forEach(card => card.remove());
            }

            handshakeCards.forEach(card => {
                const subs = card.querySelector('.subs');
                if(!subs) return;
                const panel = subs.querySelector('.credential-panel');
                if(credential) {
                    if(panel) panel.outerHTML = passwordPanelHtml(credential);
                    else subs.insertAdjacentHTML('afterbegin', passwordPanelHtml(credential));
                } else if(panel) {
                    panel.remove();
                }
                const tools = subs.querySelector('.network-expanded-tools');
                let addButton = tools && tools.querySelector('.password-add-action');
                if(credential && addButton) addButton.remove();
                if(!credential && tools && !addButton) {
                    tools.insertAdjacentHTML('afterbegin', `<button class="network-expanded-action password-add-action" onclick='add(${jsq(result.essid)}, ${jsq(result.bssid || '')})' title="Add a recovered password">${mapActionIcon('key')}<span>Add password</span></button>`);
                }
            });
            updateMapCredential(result.essid, result.bssid, credential);
        }

        async function passwordAction(route, payload, pendingMessage) {
            showToast(pendingMessage || 'Verifying password...');
            try {
                const result = await postAsync(route, payload);
                applyPasswordResult(result);
                showToast(result.message || (result.ok ? 'Password updated' : 'Password rejected'), !result.ok);
                return result;
            } catch(error) {
                showToast(error.message || 'Password action failed', true);
                return null;
            }
        }

        function add(e,b) {
            const p = prompt("Password for " + e + ":");
            if(p !== null && p !== '') passwordAction(
                'add-password',
                {essid:e, bssid:b || '', password:p},
                'Verifying password against the capture...'
            );
        }
        function whitelistAdd(network, returnTab, bssid) {
            if(confirm('Add "' + network + '" to the whitelist?')) {
                const payload = {network:network, bssid:bssid || '', return_tab:returnTab || 'other'};
                updateWhitelistAsync('whitelist-add', payload);
            }
        }
        function whitelistRemove(network, returnTab) {
            if(confirm('Remove "' + network + '" from the whitelist?')) {
                updateWhitelistAsync('whitelist-remove', {network:network, return_tab:returnTab || 'other'});
            }
        }

        function syncWhitelist(values) {
            whitelistedNetworks.clear();
            (values || []).forEach(name => whitelistedNetworks.add(String(name)));
        }

        function whitelistItemHtml(network) {
            return `<div class="whitelist-compact-item"><i></i><span><b>${esc(network)}</b><small>Ignored during capture</small></span><button class="whitelist-remove" type="button" onclick='whitelistRemove(${jsq(network)})'>Remove</button></div>`;
        }

        function renderWhitelistList(values) {
            const host = document.getElementById('whitelistListHost');
            if(!host) return;
            const names = (values || []).map(String);
            const total = document.getElementById('whitelistTotal');
            if(total) total.textContent = String(names.length);
            if(!names.length) {
                host.innerHTML = '<div class="whitelist-compact-list"><div class="whitelist-compact-empty">No active whitelist entries.</div></div>';
                return;
            }
            host.innerHTML = `<div class="whitelist-compact-list">${names.map(whitelistItemHtml).join('')}</div>`;
        }

        function whitelistFormSubmit(event) {
            event.preventDefault();
            const form = event.currentTarget;
            const input = form.querySelector('[name="network"]');
            const name = input ? input.value.trim() : '';
            if(name) updateWhitelistAsync('whitelist-add', {network:name, return_tab:'other'}).then(() => form.reset());
            return false;
        }

        function refreshOpenMapCard() {
            if(activeMapGroup && selectedMapPoint === activeMapGroup) showMapGroup(activeMapGroup);
            else if(selectedMapPoint) showMapPoint(selectedMapPoint, !!activeMapGroup);
        }

        async function updateWhitelistAsync(route, data) {
            showToast('Saving whitelist...');
            try {
                const result = await postAsync(route, data);
                syncWhitelist(result.whitelist);
                renderWhitelistList(result.whitelist);
                refreshOpenMapCard();
                showToast(result.message || (result.ok ? 'Whitelist updated' : 'No changes'));
            } catch(error) {
                showToast(error.message || 'Whitelist update failed', true);
            }
        }

        function memberHasExcellentQuality(member) {
            if(member && member.quality && member.quality.grade === 'Excellent') return true;
            return (member && member.history || []).some(item => item && item.quality && item.quality.grade === 'Excellent');
        }

        function excellentGroupNetworks(group) {
            const names = (group && group.members || [])
                .filter(memberHasExcellentQuality)
                .map(member => String(member.essid || '').trim())
                .filter(Boolean);
            return [...new Set(names)];
        }

        async function whitelistExcellentGroup(group) {
            const names = excellentGroupNetworks(group).filter(name => !whitelistedNetworks.has(name));
            if(!names.length) return;
            if(confirm(`Add ${names.length} Excellent-quality network(s) from this group to the whitelist?`)) {
                await updateWhitelistAsync('whitelist-add-excellent', {networks:JSON.stringify(names)});
            }
        }
        function ed(e,o,s,b) {
            const p = prompt("Edit " + e + ":", o);
            if(p !== null && p !== o) passwordAction(
                'update-password',
                {essid:e, bssid:b || '', old_password:o, password:p, source:s || ''},
                'Verifying the new password...'
            );
        }
        function del(e, p, s, b) {
            if(confirm("Delete password for "+e+"?")) {
                passwordAction(
                    'delete-password',
                    {essid:e, bssid:b || '', password:p, source:s || ''},
                    'Deleting password...'
                );
            }
        }
        function rm(f) { if(confirm("Delete file "+f+"?")) post('delete-file', {filename:f}); }
        function upl(f) {
            if(wpaEnabled) runMapAction('wpa-sec-upload', {filename:f}, 'Queueing WPA-sec upload...');
        }

        function syncWpaSec() {
            runMapAction('wpa-sec-sync', {}, 'Starting WPA-sec synchronization...');
        }

        function findMapMemberById(pointId) {
            let found = null;
            const visit = item => {
                if(!item || found) return;
                if(String(item.id || '') === String(pointId || '')) {
                    found = item;
                    return;
                }
                (item.members || []).forEach(visit);
                (item.history || []).forEach(visit);
            };
            mapPoints.forEach(visit);
            return found;
        }

        function placeHandshakeOnMap(filename, essid, bssid) {
            mapPlacement = {
                filename:String(filename || ''),
                essid:String(essid || ''),
                bssid:String(bssid || ''),
                saving:false
            };
            const label = mapPlacement.essid || mapPlacement.filename;
            const text = document.getElementById('mapPlacementText');
            const stage = document.getElementById('mapStage');
            if(text) text.textContent = `Move the map under the pin, then place ${label}.`;
            setMapPlacementUiVisible(true);
            if(stage) stage.classList.add('placing');
            hideMapPoint();
            tab('map');
            setTimeout(focusMapPlacement, 120);
            showToast('Move the map and press the check mark');
        }

        function setMapPlacementUiVisible(visible) {
            ['mapPlacementTarget', 'mapPlacementText', 'mapPlacementControls'].forEach(id => {
                const element = document.getElementById(id);
                if(!element) return;
                element.hidden = !visible;
                element.classList.toggle('hidden', !visible);
            });
        }

        function cancelMapPlacement(showMessage = true) {
            mapPlacement = null;
            offlinePlacementCenter = null;
            const stage = document.getElementById('mapStage');
            setMapPlacementUiVisible(false);
            if(stage) stage.classList.remove('placing');
            if(showMessage) showToast('Handshake placement cancelled');
            renderMap();
        }

        function placementInitialPoint() {
            if(!mapPlacement) return null;
            const current = findMapMemberById(mapPlacement.filename);
            if(current && Number.isFinite(Number(current.lat)) && Number.isFinite(Number(current.lon))) {
                return {lat:Number(current.lat), lon:Number(current.lon)};
            }
            if(userLocation) return {lat:Number(userLocation.lat), lon:Number(userLocation.lon)};
            if(mapPoints.length) return {lat:Number(mapPoints[0].lat), lon:Number(mapPoints[0].lon)};
            return {lat:55.751244, lon:37.618423};
        }

        function focusMapPlacement() {
            if(!mapPlacement) return;
            const point = placementInitialPoint();
            if(!point) return;
            offlinePlacementCenter = point;
            if(yandexMap) {
                const zoom = Math.max(Number(yandexMap.getZoom() || 0), 16);
                yandexMap.setCenter([point.lat, point.lon], zoom, {duration:220});
            }
            renderMap();
        }

        function placementCenter() {
            if(yandexReady && yandexMap) {
                const center = yandexMap.getCenter();
                if(center && center.length === 2) {
                    return {lat:Number(center[0]), lon:Number(center[1])};
                }
            }
            return offlinePlacementCenter || placementInitialPoint();
        }

        function confirmMapPlacement() {
            if(!mapPlacement || mapPlacement.saving) return;
            const center = placementCenter();
            if(!center) {
                showToast('Map center is unavailable', true);
                return;
            }
            saveHandshakeMapPoint(center.lat, center.lon);
        }

        function mapItemCoordinates(item) {
            if(!item) return null;
            const lat = Number(item.lat);
            const lon = Number(item.lon);
            const hasDirect = item.lat !== null && item.lat !== undefined && item.lat !== ''
                && item.lon !== null && item.lon !== undefined && item.lon !== '';
            if(hasDirect && Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180) {
                return {lat, lon};
            }
            const coordinates = [];
            const collect = member => {
                if(!member) return;
                const memberLat = Number(member.lat);
                const memberLon = Number(member.lon);
                const hasCoordinates = member.lat !== null && member.lat !== undefined && member.lat !== ''
                    && member.lon !== null && member.lon !== undefined && member.lon !== '';
                if(hasCoordinates && Number.isFinite(memberLat) && Number.isFinite(memberLon) && Math.abs(memberLat) <= 90 && Math.abs(memberLon) <= 180) {
                    coordinates.push({lat:memberLat, lon:memberLon});
                    return;
                }
                (member.members || []).forEach(collect);
                (member.history || []).forEach(collect);
            };
            (item.members || []).forEach(collect);
            (item.history || []).forEach(collect);
            if(!coordinates.length) return null;
            return {
                lat:coordinates.reduce((sum, point) => sum + point.lat, 0) / coordinates.length,
                lon:coordinates.reduce((sum, point) => sum + point.lon, 0) / coordinates.length
            };
        }

        function placeHandshakeInSelectedGroup() {
            if(!mapPlacement || !selectedMapPoint) return;
            const coordinates = mapItemCoordinates(selectedMapPoint);
            if(!coordinates) {
                showToast('This group has no valid map coordinates', true);
                return;
            }
            saveHandshakeMapPoint(coordinates.lat, coordinates.lon);
        }

        function applyMapPlacementToHandshake(placement) {
            if(!placement) return;
            document.querySelectorAll('#v-handshakes .handshake-card').forEach(card => {
                const cardBssid = String(card.dataset.bssid || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
                const placedBssid = String(placement.bssid || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
                const sameNetwork = cardBssid && placedBssid
                    ? cardBssid === placedBssid
                    : String(card.dataset.essid || '') === String(placement.essid || '');
                if(!sameNetwork) return;

                const title = card.querySelector('.tit');
                if(title) {
                    let badge = title.querySelector('[data-location-badge]');
                    if(!badge) {
                        badge = document.createElement('span');
                        badge.className = 'badge location-badge';
                        badge.dataset.locationBadge = '';
                        title.appendChild(document.createTextNode(' '));
                        title.appendChild(badge);
                    }
                    badge.textContent = 'MAP';
                }

                card.querySelectorAll('.capture-row[data-filename]').forEach(row => {
                    if(String(row.dataset.filename || '') !== String(placement.filename || '')) return;
                    const label = row.querySelector('.map-capture-action span');
                    if(label) label.textContent = 'Move';
                });
            });
        }

        async function saveHandshakeMapPoint(lat, lon) {
            if(!mapPlacement || mapPlacement.saving) return;
            const latitude = Number(lat);
            const longitude = Number(lon);
            if(lat === null || lat === undefined || lat === '' || lon === null || lon === undefined || lon === ''
                || !Number.isFinite(latitude) || !Number.isFinite(longitude) || Math.abs(latitude) > 90 || Math.abs(longitude) > 180) {
                showToast('Map coordinates are invalid', true);
                return;
            }
            mapPlacement.saving = true;
            const placement = Object.assign({}, mapPlacement);
            const placementName = placement.essid || placement.filename;
            showToast(`Adding ${placementName} to the map...`);
            try {
                const result = await postAsync('capture-map-set', {
                    filename:placement.filename,
                    lat:String(latitude),
                    lon:String(longitude)
                });
                if(!result.ok) throw new Error(result.message || 'Location was rejected');
                if(result.map_points) mapPoints = result.map_points;
                if(result.no_gps_networks) noGpsNetworks = result.no_gps_networks;
                applyMapPlacementToHandshake(placement);
                cancelMapPlacement(false);
                const point = findMapMemberById(result.point_id || placement.filename);
                if(point) showMapPoint(point);
                showToast(`Added ${placementName} to the map`);
            } catch(error) {
                if(mapPlacement) mapPlacement.saving = false;
                showToast(error.message || 'Could not save handshake location', true);
            }
        }

        function esc(v) {
            return String(v || '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
        }

        function jsq(v) {
            const slash = String.fromCharCode(92);
            return JSON.stringify(String(v || ''))
                .replace(/'/g, slash + 'u0027')
                .replace(/</g, slash + 'u003c')
                .replace(/>/g, slash + 'u003e');
        }

        async function copyText(v, successMessage='Copied') {
            const text = String(v || '');
            if(!text) return false;
            let copied = false;
            if(navigator.clipboard && navigator.clipboard.writeText) {
                try {
                    await navigator.clipboard.writeText(text);
                    copied = true;
                } catch(error) {}
            }
            if(!copied) {
                const t = document.createElement('textarea');
                t.value = text;
                t.setAttribute('readonly', '');
                t.style.position = 'fixed';
                t.style.opacity = '0';
                document.body.appendChild(t);
                t.select();
                try { copied = document.execCommand('copy'); } catch(error) {}
                document.body.removeChild(t);
            }
            showToast(copied ? successMessage : 'Could not copy text', !copied);
            return copied;
        }

        async function copyConflictCenter(button) {
            const rows = Array.from(document.querySelectorAll('.conflict-item'));
            if(!rows.length) {
                showToast('No conflicts to copy');
                return;
            }
            const lines = ['Conflict center', ''];
            rows.forEach(row => {
                const kind = String(row.querySelector('em')?.textContent || 'conflict').trim().toUpperCase();
                const title = String(row.querySelector('b')?.textContent || '').trim();
                const detail = String(row.querySelector('small')?.textContent || '').trim();
                lines.push(`- [${kind}] ${title}`);
                if(detail) lines.push(`  ${detail}`);
            });
            if(button) button.disabled = true;
            try {
                await copyText(lines.join('\\n'), `Copied ${rows.length} conflict(s)`);
            } finally {
                if(button) button.disabled = false;
            }
        }

        async function repairPasswordConflict(button, bssid) {
            if(!button || button.disabled) return;
            const row = button.closest('.conflict-item');
            const detail = row && row.querySelector('small');
            if(detail && !detail.dataset.originalDetail) {
                detail.dataset.originalDetail = detail.textContent || '';
            }
            button.disabled = true;
            button.classList.add('loading');
            button.textContent = 'Checking...';
            if(detail) detail.textContent = 'Starting local verification...';
            showToast(
                'Password verification started. It will continue in the background.',
                false,
                Math.max(notificationDurationMs, 5000)
            );
            try {
                const started = await postAsync(
                    'repair-password-conflict',
                    {bssid:bssid || ''}
                );
                const jobBssid = started.bssid || bssid || '';
                let result = started;
                for(let attempt = 0; attempt < 720; attempt += 1) {
                    if(result.status === 'done') break;
                    if(result.status === 'error') {
                        throw new Error(
                            result.message || 'Password verification failed'
                        );
                    }
                    if(detail) {
                        const progress = result.total
                            ? ` (${result.current || 0}/${result.total})`
                            : '';
                        detail.textContent = (
                            result.message
                            || 'Local verification is running...'
                        ) + progress;
                    }
                    await new Promise(resolve => setTimeout(resolve, 1250));
                    const response = await fetch(
                        '/plugins/A_pwmenu/api/repair-password-conflict/'
                        + encodeURIComponent(jobBssid),
                        {
                            credentials:'same-origin',
                            headers:{'Accept':'application/json'}
                        }
                    );
                    result = await response.json();
                    if(!response.ok || !result.ok) {
                        throw new Error(
                            result.message
                            || 'Could not read verification status'
                        );
                    }
                }
                if(result.status !== 'done') {
                    throw new Error(
                        'Local verification is still running. Reopen this '
                        + 'network later to check the result.'
                    );
                }
                if(row) row.remove();
                const remaining = document.querySelectorAll(
                    '.conflict-item'
                ).length;
                const total = document.getElementById('conflictTotal');
                if(total) total.textContent = String(remaining);
                const card = document.querySelector('.conflict-card');
                if(card && remaining === 0) card.remove();
                showToast(result.message || 'Password conflict repaired');
            } catch(error) {
                button.disabled = false;
                button.classList.remove('loading');
                button.textContent = 'Retry';
                if(detail) detail.textContent = (
                    error.message || detail.dataset.originalDetail
                );
                showToast(
                    error.message || 'Password conflict was not changed',
                    true
                );
            }
        }

        async function copyAllActivityHistory(button) {
            if(button) button.disabled = true;
            try {
                const response = await fetch(
                    '/plugins/A_pwmenu/api/history?limit=200',
                    {
                        credentials:'same-origin',
                        headers:{'Accept':'application/json'}
                    }
                );
                const payload = await response.json();
                if(!response.ok || !payload.ok) {
                    throw new Error(
                        payload.message || 'Could not load activity history'
                    );
                }
                const items = payload.items || [];
                if(!items.length) {
                    showToast('No activity to copy');
                    return;
                }
                const lines = ['Activity history', ''];
                items.forEach(item => {
                    const meta = [item.time, item.source].filter(Boolean).join(' · ');
                    lines.push(`- ${meta ? meta + ' — ' : ''}${String(item.title || 'Activity').trim()}`);
                    const detail = String(item.detail || '').trim();
                    if(detail) lines.push(`  ${detail}`);
                });
                await copyText(
                    lines.join('\\n'),
                    `Copied ${items.length} activity event(s)`
                );
            } catch(error) {
                showToast(error.message || 'Could not copy activity history', true);
            } finally {
                if(button) button.disabled = false;
            }
        }

        function showToast(text, isError, duration = notificationDurationMs) {
            const toast = document.getElementById('mapToast');
            if(!toast) return;
            toast.textContent = text || 'Done';
            toast.classList.toggle('error', !!isError);
            toast.classList.add('show');
            clearTimeout(showToast.t);
            showToast.t = setTimeout(() => toast.classList.remove('show'), duration);
        }

        function setMapPanelOpen(open) {
            document.body.classList.toggle('map-panel-open', !!open);
            setTimeout(() => {
                if(yandexMap) yandexMap.container.fitToViewport();
                renderMap();
            }, 60);
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
            runMapAction('ohc-upload-cluster', {filenames: names}, 'Starting OHC upload...');
        }

        function sendClusterToWpa(p) {
            const names = clusterFilenames(p);
            if(!names || !wpaEnabled) return;
            runMapAction('wpa-sec-upload-cluster', {filenames: names}, 'Starting WPA-sec upload...');
        }

        function noGpsFilenames(n) {
            return (n.files || []).map(f => f.filename).filter(Boolean).join(',');
        }

        function sendNoGpsToOhc(n) {
            const names = noGpsFilenames(n);
            if(!names) return;
            runMapAction('ohc-upload-cluster', {filenames: names}, 'Starting OHC upload...');
        }

        function sendNoGpsToWpa(n) {
            const names = noGpsFilenames(n);
            if(!names || !wpaEnabled) return;
            runMapAction('wpa-sec-upload-cluster', {filenames: names}, 'Starting WPA-sec upload...');
        }

        function sendSingleToOhc(filename) {
            if(!filename) return;
            runMapAction('ohc-upload-cluster', {filenames: filename}, 'Starting OHC upload...');
        }

        function sendAllMissingToOhc() {
            if(!confirm('Scan all uncracked captures and send every hash missing from OHC?')) return;
            post('ohc-upload-all-missing', {});
        }

        function sendSingleToWpa(filename) {
            if(!filename || !wpaEnabled) return;
            runMapAction('wpa-sec-upload-cluster', {filenames: filename}, 'Starting WPA-sec upload...');
        }

        function ohcStatusBlock(item) {
            const o = (item && item.ohc) || {};
            if(!o.status) return '<span class="map-chip gray">OHC Not sent</span>';
            if(o.status === 'sent') return '<span class="map-chip green">OHC Sent</span>';
            if(o.status === 'already_reported') return '<span class="map-chip blue">OHC Already exists</span>';
            if(o.status === 'local_cracked') return '<span class="map-chip green">Password known locally</span>';
            if(o.status === 'queued') return '<span class="map-chip yellow">OHC Queued</span>';
            if(o.status === 'failed') return '<span class="map-chip red">OHC Failed</span>';
            if(o.status === 'invalid') return '<span class="map-chip red">OHC Unusable</span>';
            return `<span class="map-chip gray">OHC ${esc(o.status)}</span>`;
        }

        function qualityStatusBlock(item) {
            const q = (item && item.quality) || {};
            const grade = String(q.grade || 'Pending');
            const cls = grade === 'Excellent' ? 'green' : grade === 'Usable' ? 'blue' : grade === 'Partial' ? 'yellow' : grade === 'Unusable' ? 'red' : 'gray';
            const title = q.summary ? ` title="${esc(q.summary)}"` : '';
            return `<span class="map-chip ${cls}"${title}>Quality ${esc(grade)}</span>`;
        }

        function gpsStatusChip(item, missing) {
            if(missing) return '<span class="map-chip gray">GPS Missing</span>';
            const source = String((item && item.source) || '').toLowerCase();
            if(source === 'manual-map' || source === 'map' || source === 'pwmenu-map') {
                return '<span class="map-chip blue">Map</span>';
            }
            if(item && item.gps_stale) {
                const mins = Math.max(1, Math.round((Number(item.gps_age_at_capture || 0)) / 60));
                return `<span class="map-chip yellow">GPS ${mins} min old</span>`;
            }
            return '<span class="map-chip green">GPS Fresh</span>';
        }

        function pointChips(item, missingGps) {
            return `<div class="map-chips">${qualityStatusBlock(item)}${gpsStatusChip(item, missingGps)}</div>`;
        }

        function mapItemClass(item) {
            if(item && ((item.ohc && item.ohc.status === 'invalid') || (item.quality && item.quality.grade === 'Unusable'))) return 'red';
            return item && item.is_cracked ? 'green' : 'blue';
        }

        function mapActionIcon(name) {
            const icons = {
                download: '<svg viewBox="0 0 24 24"><path d="M12 3v12m-4-4 4 4 4-4"></path><path d="M5 19h14"></path></svg>',
                ohc: '<svg viewBox="0 0 24 24"><path d="M7 18h10a4 4 0 0 0 .7-7.9A6 6 0 0 0 6.3 8.5 4.8 4.8 0 0 0 7 18Z"></path><path d="m9 13 3-3 3 3m-3-3v6"></path></svg>',
                wpa: '<svg viewBox="0 0 24 24"><path d="M12 3 5 6v5c0 4.6 2.8 8 7 10 4.2-2 7-5.4 7-10V6l-7-3Z"></path><path d="M9 12h6"></path></svg>',
                key: '<svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"></circle><path d="m11 12 8-8m-3 3 2 2m-5 1 2 2"></path></svg>',
                whitelist: '<svg viewBox="0 0 24 24"><path d="M12 3 5 6v5c0 4.6 2.8 8 7 10 4.2-2 7-5.4 7-10V6l-7-3Z"></path><path d="m9 12 2 2 4-4"></path></svg>',
                trash: '<svg viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3m-9 0 1 14h10l1-14M10 11v6m4-6v6"></path></svg>'
            };
            return icons[name] || '';
        }

        function whitelistAction(networkName, bssid) {
            const allowed = whitelistedNetworks.has(String(networkName || ''));
            const action = allowed
                ? `whitelistRemove(${jsq(networkName)}, "map")`
                : `whitelistAdd(${jsq(networkName)}, "map", ${jsq(bssid || '')})`;
            const title = allowed ? 'Remove from whitelist' : 'Add to whitelist';
            const label = allowed ? 'Remove' : 'Allow';
            return `<button class="map-icon-action ${allowed ? 'danger' : ''}" onclick='${action}' title="${title}">${mapActionIcon('whitelist')}<span>${label}</span></button>`;
        }

        function networkActions(networkName, bssid, filename, password, credentialSource, ohcExpr, wpaExpr) {
            const isCracked = !!password;
            const download = filename ? `<a class="map-icon-action primary" href="/plugins/A_pwmenu/download/${encodeURIComponent(filename)}" title="Download PCAP">${mapActionIcon('download')}<span>PCAP</span></a>` : '';
            const ohc = !isCracked && filename ? `<button class="map-icon-action" onclick='${ohcExpr}' title="Send to OHC">${mapActionIcon('ohc')}<span>OHC</span></button>` : '';
            const wpa = !isCracked && filename && wpaEnabled ? `<button class="map-icon-action" onclick='${wpaExpr}' title="Send to WPA-sec">${mapActionIcon('wpa')}<span>WPA</span></button>` : '';
            const key = isCracked
                ? `<button class="map-icon-action" onclick='ed(${jsq(networkName)}, ${jsq(password)}, ${jsq(credentialSource || '')}, ${jsq(bssid || '')})' title="Edit password">${mapActionIcon('key')}<span>Edit key</span></button>
                   <button class="map-icon-action danger" onclick='del(${jsq(networkName)}, ${jsq(password)}, ${jsq(credentialSource || '')}, ${jsq(bssid || '')})' title="Delete password">${mapActionIcon('trash')}<span>Del key</span></button>`
                : `<button class="map-icon-action" onclick='add(${jsq(networkName)}, ${jsq(bssid || '')})' title="Add and verify password">${mapActionIcon('key')}<span>Add key</span></button>`;
            const captureDelete = filename ? `<button class="map-icon-action danger" title="Delete capture" onclick='rm(${jsq(filename)})'>${mapActionIcon('trash')}<span>Delete</span></button>` : '';
            return `<div class="map-icon-actions">
                ${download}${ohc}${wpa}${key}
                ${whitelistAction(networkName, bssid)}
                ${captureDelete}
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
            const toggle = document.getElementById('mapCrackedToggle');
            if(toggle) toggle.checked = mode === 'cracked';
            document.getElementById('mapAllBtn').classList.toggle('active', mode === 'all');
            document.getElementById('mapCrackedBtn').classList.toggle('active', mode === 'cracked');
            document.getElementById('mapNoGpsBtn').classList.toggle('active', false);
            hideMapPoint();
            renderMap();
        }

        function showMapSummary() {
            setMapPanelOpen(true);
            selectedMapPoint = null;
            document.getElementById('mapSheet').classList.remove('hidden');
            document.getElementById('mapSummary').classList.remove('hidden');
            document.getElementById('mapDetails').classList.add('hidden');
            document.getElementById('mapDock').classList.add('hidden');
        }

        function showNoGpsList() {
            setMapPanelOpen(true);
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
                <button class="map-list-item ${mapItemClass(n)}" onclick="showNoGpsPoint(${idx})">
                    <div class="map-list-title">${esc(n.essid)}</div>
                    <div class="map-list-sub">${esc(n.vendor || 'Unknown vendor')} · ${n.count} capture${n.count === 1 ? '' : 's'}</div>
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
            setMapPanelOpen(true);
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
                </div>` : '';
            const fileRows = (n.files || []).slice(0, 5).map(f => `
                <div class="map-list-item ${mapItemClass(f)}">
                    <div class="map-list-title" style="font-size:15px">${esc(f.filename)}</div>
                    <div class="map-list-sub">${esc(f.date)} - ${esc(f.size)}</div>
                    ${qualityStatusBlock(f)}
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
                <div class="map-compact-meta">
                    <span>${esc(n.count || 1)} capture${Number(n.count || 1) === 1 ? '' : 's'}</span>
                    <span>GPS missing</span>
                    <span>${esc(n.vendor || 'Unknown vendor')}</span>
                </div>
                ${pointChips(n, true)}
                ${pass}
                ${fileRows ? `<details class="map-more"><summary>${n.files.length} capture file${n.files.length === 1 ? '' : 's'}</summary><div class="map-list">${fileRows}</div></details>` : ''}
                ${n.filename ? networkActions(n.essid, n.bssid, n.filename, n.password || '', n.credential_source || '', `sendNoGpsToOhc(noGpsNetworks[${idx}])`, `sendNoGpsToWpa(noGpsNetworks[${idx}])`) : ''}`;
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
                const center = userLocation || {lat:55.751244, lon:37.618423};
                minLat = center.lat - 0.001; maxLat = center.lat + 0.001;
                minLon = center.lon - 0.001; maxLon = center.lon + 0.001;
            }
            if(minLat === maxLat) { minLat -= 0.001; maxLat += 0.001; }
            if(minLon === maxLon) { minLon -= 0.001; maxLon += 0.001; }
            return {minLat, maxLat, minLon, maxLon};
        }

        function offlineMapBounds(points) {
            const bounds = mapBounds(points);
            if(!mapPlacement || !offlinePlacementCenter) return bounds;
            const latSpan = Math.max(bounds.maxLat - bounds.minLat, 0.002);
            const lonSpan = Math.max(bounds.maxLon - bounds.minLon, 0.002);
            return {
                minLat:offlinePlacementCenter.lat - latSpan / 2,
                maxLat:offlinePlacementCenter.lat + latSpan / 2,
                minLon:offlinePlacementCenter.lon - lonSpan / 2,
                maxLon:offlinePlacementCenter.lon + lonSpan / 2
            };
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

        function pointHasUnusable(p) {
            const members = (p && p.members) || [];
            if(members.length > 1) return false;
            return !!(p && ((p.ohc && p.ohc.status === 'invalid') || (p.quality && p.quality.grade === 'Unusable')));
        }

        function pointStatusClass(p) {
            if(pointHasUnusable(p)) return 'unusable';
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
            if(pointHasUnusable(p)) return '#ff453a';
            if(p.status === 'analyzing') return '#ffcc00';
            if(p.status === 'no_result') return '#8e8e93';
            if(p.is_cracked || p.status === 'cracked') return '#30d158';
            return '#1e9bff';
        }

        function loadYandexMaps() {
            if(window.ymaps) return Promise.resolve(window.ymaps);
            if(yandexLoader) return yandexLoader;
            yandexLoader = new Promise((resolve, reject) => {
                const script = document.createElement('script');
                script.src = 'https://api-maps.yandex.ru/2.1/?apikey=&lang=en_US';
                script.async = true;
                script.onload = () => window.ymaps ? resolve(window.ymaps) : reject(new Error('Yandex Maps API unavailable'));
                script.onerror = () => reject(new Error('Yandex Maps API failed to load'));
                document.head.appendChild(script);
            }).catch(error => {
                console.warn('[A_pwmenu] ' + error.message + '; using the offline map.');
                yandexLoader = null;
                return null;
            });
            return yandexLoader;
        }

        function initYandexMap() {
            loadYandexMaps().then(api => {
                if(!api) return;
                api.ready(() => {
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
                        const coordinates = mapItemCoordinates({members:points});
                        showMapGroup({
                            id: 'cluster-' + ids.join('-'),
                            essid: points.length + ' points',
                            count: points.reduce((sum, p) => sum + (parseInt(p.count || 1, 10) || 1), 0),
                            lat: coordinates ? coordinates.lat : null,
                            lon: coordinates ? coordinates.lon : null,
                            members: members
                        });
                    }
                });
                yandexReady = true;
                document.getElementById('yandexMap').classList.add('ready');
                setTimeout(() => yandexMap.container.fitToViewport(), 50);
                if(mapPlacement) setTimeout(focusMapPlacement, 80);
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
            const stage = document.getElementById('mapStage');
            if(!box) return;
            const pts = filteredMapPoints();
            const empty = document.getElementById('mapEmpty');
            box.innerHTML = '';
            empty.classList.toggle('hidden', pts.length > 0 || !!userLocation || !!mapPlacement);
            if(stage) {
                stage.onclick = event => {
                    if(!mapPlacement || yandexReady) return;
                    if(event.target.closest('button, input, a, .map-sheet, .map-placement-target, .map-placement-controls, .map-placement-label')) return;
                    const rect = stage.getBoundingClientRect();
                    if(!rect.width || !rect.height) return;
                    const bounds = offlineMapBounds(pts);
                    const x = Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width));
                    const y = Math.max(0, Math.min(1, (event.clientY - rect.top) / rect.height));
                    const lon = bounds.minLon + x * (bounds.maxLon - bounds.minLon);
                    const lat = bounds.maxLat - y * (bounds.maxLat - bounds.minLat);
                    offlinePlacementCenter = {lat, lon};
                    renderMap();
                };
            }
            if(pts.length === 0 && !userLocation && !mapPlacement) return;

            if(renderYandexMap(pts)) return;

            const b = offlineMapBounds(pts);
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
            setMapPanelOpen(true);
            selectedMapPoint = p;
            document.getElementById('mapSheet').classList.remove('hidden');
            document.getElementById('mapDock').classList.add('hidden');
            document.getElementById('mapSummary').classList.add('hidden');
            const d = document.getElementById('mapDetails');
            d.classList.remove('hidden');
            const backButton = activeMapGroup ? '<button class="map-back" onclick="showMapGroup(activeMapGroup)">Back</button>' : '<button class="map-back" onclick="hideMapPoint()">Back</button>';
            const placementAction = mapPlacement
                ? `<button class="map-action cyan map-placement-card-action" onclick="placeHandshakeInSelectedGroup()">Add ${esc(mapPlacement.essid || mapPlacement.filename)} here</button>`
                : '';
            const pass = p.password ? `
                <div class="map-secret">
                    <div class="map-secret-row">
                        <div style="min-width:0">
                            <div class="map-metric-label" style="color:#8effb8">Access Key</div>
                            <div id="pw-${esc(p.id)}" class="map-password" onclick='revealPassword(${jsq('pw-' + p.id)})' title="Tap to reveal">${esc(p.password)}</div>
                        </div>
                        <button class="map-copy" onclick='copyText(${jsq(p.password)})'>Copy</button>
                    </div>
                </div>` : '';
            const history = (p.history || []).slice(1, 5).map(h => `
                <div class="map-list-item ${mapItemClass(h)}">
                    <div class="map-list-title" style="font-size:15px">${esc(h.date)}</div>
                    <div class="map-list-sub">${esc(h.filename)} - ${Math.round(h.accuracy || 0)}m</div>
                    ${qualityStatusBlock(h)}
                </div>`).join('');
            d.innerHTML = `
                <div class="map-title-row">
                    ${backButton}
                    <div class="map-title-main">
                        <div class="map-title">${esc(p.essid)}</div>
                        <div class="map-sub">${esc(p.bssid || 'no bssid')}</div>
                    </div>
                    <button class="map-close" onclick="hideMapPoint()">&times;</button>
                </div>
                <div class="map-compact-meta">
                    <span>${esc(p.captures || 1)} capture${Number(p.captures || 1) === 1 ? '' : 's'}</span>
                    <span>${esc(p.encryption || 'WPA2')}</span>
                    <span>${esc(p.vendor || 'Unknown vendor')}</span>
                </div>
                ${pointChips(p, false)}
                ${placementAction}
                ${pass}
                ${history ? `<details class="map-more"><summary>${p.history.length} nearby captures</summary><div class="map-list">${history}</div></details>` : ''}
                ${networkActions(p.essid, p.bssid, p.filename, p.password || '', p.credential_source || '', `sendSingleToOhc(${jsq(p.filename)})`, `sendSingleToWpa(${jsq(p.filename)})`)}`;
        }

        function showMapGroup(p) {
            setMapPanelOpen(true);
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
                return `<button class="map-list-item ${mapItemClass(m)}" onclick="showMapPointFromGroup(${idx})">
                    <div class="map-list-title">${esc(m.essid)}</div>
                    <div class="map-list-sub">${esc(m.vendor || 'Unknown vendor')}${gpsAge}</div>
                    ${qualityStatusBlock(m)}
                </button>`;
            }).join('');
            const excellentNames = excellentGroupNetworks(p);
            const excellentPending = excellentNames.filter(name => !whitelistedNetworks.has(name));
            const whitelistGroupAction = excellentPending.length
                ? `<button class="map-icon-action" onclick="whitelistExcellentGroup(activeMapGroup)" title="Add ${excellentPending.length} Excellent-quality network(s) to the whitelist">${mapActionIcon('whitelist')}<span>Allow ${excellentPending.length}</span></button>`
                : `<button class="map-icon-action" disabled title="${excellentNames.length ? 'All Excellent-quality networks are already whitelisted' : 'No Excellent-quality networks in this group'}">${mapActionIcon('whitelist')}<span>${excellentNames.length ? 'Allowed' : 'No Excellent'}</span></button>`;
            const placementAction = mapPlacement
                ? `<button class="map-action cyan map-placement-card-action" onclick="placeHandshakeInSelectedGroup()">Add ${esc(mapPlacement.essid || mapPlacement.filename)} to this group</button>`
                : '';
            p.visibleMembers = visibleMembers;
            d.innerHTML = `
                <div class="map-title-row">
                    <div class="map-title-main">
                        <div class="map-title">${visibleMembers.length} networks</div>
                        <div class="map-sub">Same spot cluster</div>
                    </div>
                    <button class="map-close" onclick="hideMapPoint()">&times;</button>
                </div>
                <div class="map-icon-actions">
                    <a class="map-icon-action primary" href="${clusterDownloadUrl(p)}" title="Download all PCAP files">${mapActionIcon('download')}<span>All</span></a>
                    <button class="map-icon-action" onclick="sendClusterToOhc(activeMapGroup)" title="Send cluster to OHC">${mapActionIcon('ohc')}<span>OHC</span></button>
                    ${wpaEnabled ? `<button class="map-icon-action" onclick="sendClusterToWpa(activeMapGroup)" title="Send cluster to WPA-sec">${mapActionIcon('wpa')}<span>WPA</span></button>` : ''}
                    ${whitelistGroupAction}
                </div>
                ${placementAction}
                <div class="map-list map-cluster-list">${rows || '<div class="map-status">No networks here.</div>'}</div>`;
        }

        function showMapPointFromGroup(idx) {
            if(!selectedMapPoint || !selectedMapPoint.members) return;
            activeMapGroup = selectedMapPoint;
            const members = selectedMapPoint.visibleMembers || selectedMapPoint.members;
            showMapPoint(members[idx], true);
        }

        function hideMapPoint() {
            setMapPanelOpen(false);
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

        function tabView(t) {
            return document.getElementById(t === 'other' ? 'v-other' : 'v-' + t);
        }

        function activeTabName() {
            const active = document.querySelector('.tab.active');
            return active ? active.id.replace('b-', '') : 'cracked';
        }

        function tabLoadingMarkup(tabName) {
            if(tabName === 'map') {
                return '<div class="pwmenu-map-loading" aria-busy="true"><div class="pwmenu-map-loading-core"><i></i></div><b>Loading map...</b><span>Preparing locations and map tiles</span></div>';
            }
            return '<div class="pwmenu-tab-skeleton" aria-busy="true"><i></i><i></i><i></i></div>';
        }

        function tabPageUrl(tabName, pageNumber, query, offset=null, limit=null) {
            const params = new URLSearchParams();
            params.set('page', String(pageNumber || 1));
            if(query) params.set('q', query);
            if(offset !== null) params.set('offset', String(Math.max(0, Number(offset) || 0)));
            if(limit !== null) params.set('limit', String(Math.max(2, Number(limit) || backgroundBatchSize)));
            if(currentSnapshotId) params.set('snapshot', currentSnapshotId);
            return '/plugins/A_pwmenu/api/tab/' +
                encodeURIComponent(tabName) + '?' + params.toString();
        }

        function detailCacheKey(kind, detailId) {
            return String(kind || '') + ':' + String(detailId || '');
        }

        function applyCachedDetail(panel) {
            if(!panel) return false;
            const key = detailCacheKey(
                panel.dataset.detailKind, panel.dataset.detailId
            );
            if(!detailHtmlCache.has(key)) return false;
            panel.innerHTML = detailHtmlCache.get(key);
            panel.dataset.loaded = '1';
            return true;
        }

        function seedCardPlaceholders(tabName) {
            const view = tabView(tabName);
            const state = tabPageState.get(tabName);
            if(!view || !state) return;
            view.querySelectorAll('.pwmenu-card-placeholder').forEach(node => node.remove());
            const missing = Math.max(0, state.total - state.loaded);
            if(!missing) return;
            const fragment = document.createDocumentFragment();
            for(let index=0; index<missing; index+=1) {
                const placeholder = document.createElement('div');
                placeholder.className = 'si pwmenu-card-placeholder';
                placeholder.setAttribute('aria-hidden', 'true');
                placeholder.innerHTML = '<div class="pwmenu-card-placeholder-line wide"></div><div class="pwmenu-card-placeholder-line"></div>';
                fragment.appendChild(placeholder);
            }
            view.appendChild(fragment);
        }

        function installPagePayload(tabName, payload) {
            const view = tabView(tabName);
            const state = tabPageState.get(tabName);
            if(!view || !state) return 0;
            const template = document.createElement('template');
            template.innerHTML = payload.html || '';
            const children = Array.from(template.content.children);
            const cards = children.filter(node => node.classList.contains('si'));
            const extras = children.filter(node => !node.classList.contains('si'));
            cards.forEach(card => {
                const placeholder = view.querySelector('.pwmenu-card-placeholder');
                card.classList.add('pwmenu-card-arrival');
                if(placeholder) placeholder.replaceWith(card);
                else view.appendChild(card);
                window.setTimeout(() => card.classList.remove('pwmenu-card-arrival'), 500);
            });
            extras.forEach(node => view.appendChild(node));
            state.loaded = Math.max(
                state.loaded,
                Number(payload.nextOffset || (state.loaded + cards.length))
            );
            state.nextOffset = Number(payload.nextOffset || state.loaded);
            state.hasMore = !!payload.hasMore;
            state.total = Number(payload.total || state.total);
            const pending = new Set(state.pendingDetailIds || []);
            (payload.detailIds || []).forEach(id => pending.add(String(id)));
            state.pendingDetailIds = Array.from(pending);
            view.querySelectorAll('.subs').forEach(applyCachedDetail);
            return cards.length;
        }

        async function loadMoreTab(tabName, requestedLimit=backgroundBatchSize) {
            const state = tabPageState.get(tabName);
            const view = tabView(tabName);
            if(!state || !view || !state.hasMore || state.loading) return false;
            state.loading = true;
            try {
                const response = await fetch(
                    tabPageUrl(
                        tabName,
                        state.page + 1,
                        state.query,
                        state.nextOffset,
                        requestedLimit
                    ),
                    {credentials:'same-origin', headers:{'Accept':'application/json'}}
                );
                const payload = await response.json();
                if(!response.ok || !payload.ok) {
                    throw new Error(payload.message || 'Could not load more networks');
                }
                if(String(payload.snapshotId || '') !== currentSnapshotId) {
                    state.loading = false;
                    state.hasMore = false;
                    view.querySelectorAll('.pwmenu-card-placeholder').forEach(
                        node => node.classList.add('stale')
                    );
                    showToast(
                        'New captures arrived. Reopen this tab to refresh them',
                        false
                    );
                    return false;
                }
                state.page = Number(payload.page || state.nextPage);
                state.nextPage = payload.nextPage;
                const installed = installPagePayload(tabName, payload);
                state.loading = false;
                if(!state.hasMore) hydratePendingTabDetails(tabName);
                return installed > 0 || !state.hasMore;
            } catch(error) {
                state.loading = false;
                showToast(error.message || 'Could not load more networks', true);
                return false;
            }
        }

        async function scheduleTabBackfill(tabName) {
            if(!['cracked', 'handshakes'].includes(tabName)) return false;
            const existing = tabBackfillTasks.get(tabName);
            if(existing) return existing;
            const generation = tabRequestGeneration.get(tabName);
            const task = (async () => {
                try {
                    while(true) {
                        const state = tabPageState.get(tabName);
                        if(
                            !state
                            || !state.hasMore
                            || tabRequestGeneration.get(tabName) !== generation
                        ) break;
                        const foreground = activeTabName() === tabName;
                        await waitForBrowserIdle(foreground ? 160 : 700);
                        if(tabRequestGeneration.get(tabName) !== generation) break;
                        const loaded = await loadMoreTab(
                            tabName,
                            foreground ? foregroundBatchSize : backgroundBatchSize
                        );
                        if(!loaded) break;
                        await new Promise(resolve => window.setTimeout(
                            resolve,
                            foreground
                                ? foregroundBatchDelayMs
                                : backgroundBatchDelayMs
                        ));
                    }
                    return true;
                } finally {
                    if(tabBackfillTasks.get(tabName) === task) {
                        tabBackfillTasks.delete(tabName);
                    }
                }
            })();
            tabBackfillTasks.set(tabName, task);
            return task;
        }

        async function loadTab(tabName, foreground=false, force=false, requestedQuery=null) {
            if(!['cracked', 'handshakes', 'map', 'other'].includes(tabName)) return false;
            const currentState = tabPageState.get(tabName);
            const query = requestedQuery === null
                ? String((currentState && currentState.query) || '')
                : String(requestedQuery || '').trim();
            if(!force && loadedTabs.has(tabName) && (!currentState || currentState.query === query)) return true;
            if(!force && loadingTabs.has(tabName)) return loadingTabs.get(tabName);
            const view = tabView(tabName);
            if(!view) return false;
            const generation = Number(tabRequestGeneration.get(tabName) || 0) + 1;
            tabRequestGeneration.set(tabName, generation);
            view.innerHTML = tabLoadingMarkup(tabName);
            const task = (async () => {
                try {
                    const response = await fetch(tabPageUrl(tabName, 1, query), {
                        credentials: 'same-origin',
                        headers: {'Accept': 'application/json'}
                    });
                    const payload = await response.json();
                    if(!response.ok || !payload.ok) {
                        throw new Error(payload.message || `Could not load ${tabName}`);
                    }
                    if(tabRequestGeneration.get(tabName) !== generation) return false;
                    view.innerHTML = payload.html || '';
                    const incomingSnapshot = String(payload.snapshotId || currentSnapshotId);
                    if(currentSnapshotId && incomingSnapshot !== currentSnapshotId) {
                        detailHtmlCache.clear();
                    }
                    currentSnapshotId = incomingSnapshot;
                    tabPageState.set(tabName, {
                        page: Number(payload.page || 1),
                        nextPage: payload.nextPage,
                        nextOffset: Number(
                            payload.nextOffset
                            || (payload.detailIds || []).length
                        ),
                        loaded: Number(
                            payload.nextOffset
                            || (payload.detailIds || []).length
                        ),
                        hasMore: !!payload.hasMore,
                        total: Number(payload.total || 0),
                        query: String(payload.query || query),
                        loading: false,
                        pendingDetailIds: [],
                        detailHydrating: false
                    });
                    if(tabName === 'map') {
                        mapPoints = Array.isArray(payload.mapPoints) ? payload.mapPoints : [];
                        noGpsNetworks = Array.isArray(payload.noGpsNetworks) ? payload.noGpsNetworks : [];
                        gpsStatus = payload.gpsStatus || {};
                        updateGpsStatusDot();
                        loadYandexMaps();
                    }
                    loadedTabs.add(tabName);
                    if(tabName === 'cracked' || tabName === 'handshakes') {
                        seedCardPlaceholders(tabName);
                        view.querySelectorAll('.subs').forEach(applyCachedDetail);
                        hydrateTabDetails(tabName, payload.detailIds || []);
                        scheduleTabBackfill(tabName);
                    }
                    if(activeTabName() === tabName && tabName === 'map') {
                        await initYandexMap();
                        if(yandexMap) yandexMap.container.fitToViewport();
                        renderMap();
                    }
                    return true;
                } catch(error) {
                    if(tabRequestGeneration.get(tabName) !== generation) return false;
                    loadedTabs.delete(tabName);
                    view.innerHTML = '<div class="pwmenu-load-error"><b>Could not load this section</b><button type="button">Retry</button></div>';
                    const retry = view.querySelector('button');
                    if(retry) retry.onclick = () => loadTab(tabName, true, true, query);
                    if(foreground) showToast(error.message || 'Section loading failed', true);
                    return false;
                } finally {
                    if(tabRequestGeneration.get(tabName) === generation) {
                        loadingTabs.delete(tabName);
                    }
                }
            })();
            loadingTabs.set(tabName, task);
            return task;
        }

        function waitForBrowserIdle(timeout=1200) {
            return new Promise(resolve => {
                if('requestIdleCallback' in window) {
                    window.requestIdleCallback(() => resolve(), {timeout});
                } else {
                    setTimeout(resolve, Math.min(timeout, 700));
                }
            });
        }

        async function hydrateTabDetails(tabName, detailIds) {
            if(!['cracked', 'handshakes'].includes(tabName)) return false;
            const kind = tabName === 'cracked' ? 'cracked' : 'handshake';
            const ids = Array.from(new Set(
                (detailIds || []).map(String).filter(id => /^\\d{1,6}$/.test(id))
            ));
            ids.forEach(detailId => {
                const panel = document.querySelector(
                    `[data-detail-kind="${kind}"][data-detail-id="${detailId}"]`
                );
                applyCachedDetail(panel);
            });
            const missing = ids.filter(
                detailId => !detailHtmlCache.has(detailCacheKey(kind, detailId))
            );
            if(!missing.length) return true;
            const batchKey = currentSnapshotId + ':' + kind + ':' + missing.join(',');
            if(loadingDetailBatches.has(batchKey)) return loadingDetailBatches.get(batchKey);
            const task = (async () => {
                try {
                    const response = await fetch(
                        '/plugins/A_pwmenu/api/details/' +
                        encodeURIComponent(tabName) + '?snapshot=' +
                        encodeURIComponent(currentSnapshotId) + '&ids=' +
                        encodeURIComponent(missing.join(',')),
                        {
                            credentials: 'same-origin',
                            headers: {'Accept': 'application/json'}
                        }
                    );
                    const payload = await response.json();
                    if(response.status === 409 && payload.reload) return false;
                    if(!response.ok || !payload.ok) {
                        throw new Error(payload.message || 'Could not preload card details');
                    }
                    currentSnapshotId = String(payload.snapshotId || currentSnapshotId);
                    Object.entries(payload.details || {}).forEach(([detailId, fragment]) => {
                        detailHtmlCache.set(
                            detailCacheKey(kind, detailId), fragment
                        );
                        const panel = document.querySelector(
                            `[data-detail-kind="${kind}"][data-detail-id="${detailId}"]`
                        );
                        applyCachedDetail(panel);
                    });
                    return true;
                } catch(error) {
                    return false;
                } finally {
                    loadingDetailBatches.delete(batchKey);
                }
            })();
            loadingDetailBatches.set(batchKey, task);
            return task;
        }

        async function hydratePendingTabDetails(tabName) {
            const state = tabPageState.get(tabName);
            if(!state || state.detailHydrating) return false;
            state.detailHydrating = true;
            try {
                while((state.pendingDetailIds || []).length) {
                    await waitForBrowserIdle(
                        activeTabName() === tabName ? 260 : 850
                    );
                    const ids = state.pendingDetailIds.splice(0, 50);
                    await hydrateTabDetails(tabName, ids);
                }
                return true;
            } finally {
                state.detailHydrating = false;
            }
        }

        async function scheduleBackgroundPreload() {
            if(bootstrap.backgroundPreload === false) return;
            await loadTab(t0, true);
            scheduleTabBackfill(t0);
            loadYandexMaps();
            const queue = ['handshakes', 'map', 'cracked', 'other'].filter(name => name !== t0);
            for(const name of queue) {
                await waitForBrowserIdle(name === 'map' ? 500 : 850);
                await loadTab(name, false);
            }
        }

        function tab(t) {
            closeMobileSearch();
            document.body.classList.remove('view-cracked', 'view-handshakes', 'view-map', 'view-other');
            document.body.classList.add('view-' + t);
            document.querySelectorAll('.list, #v-other, #v-map').forEach(e=>e.classList.add('hidden'));
            const view = tabView(t);
            if(!view) return;
            view.classList.remove('hidden');
            if(t!=='other' && t!=='map') view.classList.add('list');
            document.querySelectorAll('.tab').forEach(e=>{
                e.classList.remove('active');
                e.setAttribute('aria-selected', 'false');
            });
            const activeButton = document.getElementById('b-'+t);
            if(activeButton) {
                activeButton.classList.add('active');
                activeButton.setAttribute('aria-selected', 'true');
            }
            const searchValue = (
                t === 'cracked' || t === 'handshakes'
            ) ? String(document.getElementById('s').value || '').trim() : null;
            loadTab(t, true, false, searchValue).then(() => {
                if(t !== activeTabName()) return;
                if(t === 'cracked' || t === 'handshakes') {
                    scheduleTabBackfill(t);
                }
                if(t === 'map') {
                    startPhoneGps(false);
                    initYandexMap();
                    setTimeout(() => {
                        if(yandexMap) yandexMap.container.fitToViewport();
                        renderMap();
                    }, 80);
                }
            });
        }

        async function tog(id) {
            let target = document.getElementById('s-'+id);
            if(!target) return;
            const opening = target.style.display !== 'block';
            document.querySelectorAll('#v-cracked .subs, #v-handshakes .subs').forEach(panel => {
                panel.style.display = 'none';
                const card = panel.closest('.si');
                if(card) card.classList.remove('open');
            });
            if(opening) {
                target.style.display = 'block';
                const card = target.closest('.si');
                if(card) card.classList.add('open');
                requestAnimationFrame(() => card && card.scrollIntoView({block:'center', behavior:'smooth'}));
                applyCachedDetail(target);
                if(target.dataset.loaded !== '1') {
                    target.innerHTML = '<div class="pwmenu-detail-loading">Loading...</div>';
                    if(target.dataset.loading === '1') return;
                    target.dataset.loading = '1';
                    try {
                        const detailKind = target.dataset.detailKind;
                        const detailId = target.dataset.detailId;
                        const url = '/plugins/A_pwmenu/api/detail/' +
                            encodeURIComponent(detailKind) + '/' +
                            encodeURIComponent(detailId) + '?snapshot=' +
                            encodeURIComponent(currentSnapshotId);
                        const response = await fetch(url, {
                            credentials: 'same-origin',
                            headers: {'Accept': 'application/json'}
                        });
                        const payload = await response.json();
                        if(response.status === 409 && payload.reload) {
                            currentSnapshotId = String(payload.snapshotId || '');
                            const sourceTab = detailKind === 'cracked' ? 'cracked' : 'handshakes';
                            loadedTabs.delete(sourceTab);
                            detailHtmlCache.clear();
                            const state = tabPageState.get(sourceTab);
                            await loadTab(
                                sourceTab, true, true,
                                state ? state.query : ''
                            );
                            return tog(id);
                        }
                        if(!response.ok || !payload.ok) {
                            throw new Error(payload.message || 'Could not load details');
                        }
                        currentSnapshotId = String(payload.snapshotId || currentSnapshotId);
                        detailHtmlCache.set(
                            detailCacheKey(detailKind, detailId),
                            payload.html || ''
                        );
                        target.innerHTML = payload.html || '';
                        target.dataset.loaded = '1';
                    } catch(error) {
                        target.innerHTML = '<div class="pwmenu-detail-loading">Could not load details. Tap again to retry.</div>';
                        showToast(error.message || 'Could not load details', true);
                        return;
                    } finally {
                        target = document.getElementById('s-'+id) || target;
                        delete target.dataset.loading;
                    }
                }
            }
        }

        function flt() {
            const raw = document.getElementById('s').value;
            let active = activeTabName();
            if(active === 'other') return;
            if(active === 'map') {
                const mapSearch = document.getElementById('mapSearch');
                if(mapSearch) mapSearch.value = raw;
                renderMap();
                return;
            }
            clearTimeout(tabSearchTimer);
            tabSearchTimer = setTimeout(() => {
                const state = tabPageState.get(active);
                const query = String(raw || '').trim();
                if(state && state.query === query) return;
                loadTab(active, true, true, query);
            }, 240);
        }
    </script>
</body>
</html>
"""
