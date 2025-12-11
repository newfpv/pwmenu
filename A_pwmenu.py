import os
import logging
import glob
import json
import csv
import io
import datetime
import re
import zipfile
import subprocess
import requests
import socket
import time
import pwnagotchi.plugins as plugins
from flask import render_template_string, send_file, make_response

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
    __version__ = '1.0.0'
    __license__ = 'GPL3'
    __description__ = 'Ultimate Password Manager'

    def __init__(self):
        self.ready = False
        self.handshake_dirs = ['/root/handshakes/', '/home/pi/handshakes/']
        self.potfile_ohc = '/root/handshakes/onlinehashcrack.cracked.potfile'
        self.potfile_manual = '/root/handshakes/manual.potfile'
        self.data_file = '/root/handshakes/.a_pwmenu_data.json'
        self.last_sync = 0

    def on_loaded(self):
        logging.info("[A_pwmenu] Loaded.")
        self._ensure_file(self.potfile_ohc)
        self._ensure_file(self.potfile_manual)
        self._load_data()
        self.options.setdefault('time_sync_interval', 1800)
        self.ready = True

    def on_ui_update(self, ui):
        if not self.ready:
            return
        
        try:
            interval = int(self.options.get('time_sync_interval', 1800))
        except:
            interval = 1800
            
        if time.time() - self.last_sync > interval:
            if self._sync_time_now(silent=True):
                self.last_sync = time.time()

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

                if path == 'add-password':
                    self._add_manual_password(request.form.get('essid'), request.form.get('bssid'), request.form.get('password'))
                    return self._render_page(notification="Password added", notif_type="success")
                
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
                        c = self._process_import(f.read().decode('utf-8', errors='ignore'), f.filename)
                        return self._render_page(notification=f"Imported {c} passwords", notif_type="success", active_tab='other')
                    except Exception as e:
                        return self._render_page(notification=f"Import Error: {e}", notif_type="error", active_tab='other')

            if path == 'download-zip':
                return self._serve_zip()
            if path == 'export-passwords':
                return self._serve_password_list()
            if path.startswith('download-22000/'):
                return self._serve_22000(path.replace('download-22000/', ''))
            if path.startswith('download/'):
                return self._serve_file(path.replace('download/', ''))

            if path == '/' or not path:
                return self._render_page()
            return "Not found"
        except Exception as e: 
            logging.error(f"[A_pwmenu] Critical: {e}")
            return self._render_page(notification=f"System Error: {e}", notif_type="error")

    def _sync_time_now(self, silent=False):
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            cmd = "date -s \"$(curl -s --head http://google.com | grep ^Date: | sed 's/Date: //g')\""
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if not silent:
                logging.info("[A_pwmenu] Time synchronized.")
            return True
        except:
            return False

    def _render_page(self, notification=None, notif_type=None, active_tab='cracked'):
        cracked = self._get_cracked_data()
        groups = self._scan_and_group_files(cracked)
        ach = self._update_achievements(groups, cracked)
        
        t_nets = len(groups)
        c_nets = len([g for g in groups if g['is_cracked']])
        pct = int((c_nets / t_nets * 100)) if t_nets > 0 else 0
        
        stats = {
            'cracked': c_nets, 'total': t_nets, 'percent': pct,
            'files': sum(len(g['files']) for g in groups),
            'level': ach['level'], 'xp': ach['xp'], 'next_xp': ach['next_xp'], 'rank': ach['rank'],
            'lvl_percent': ach['lvl_percent']
        }

        tok = generate_csrf() if generate_csrf else ""
        show_wpa = bool(self.options.get('wpa_sec_key'))

        html = render_template_string(self._get_html(), 
            groups=groups, cracked=cracked, notif=notification, ntype=notif_type, 
            tab=active_tab, stats=stats, ach=ach['badges'], token=tok,
            show_wpa=show_wpa
        )
        
        r = make_response(html)
        r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return r

    def _handle_wpa_upload(self, req):
        try:
            socket.create_connection(("1.1.1.1", 53), timeout=5)
        except OSError:
            return "No Internet Connection", True

        fname = req.form.get('filename')
        key = self.options.get('wpa_sec_key')
        if not key:
            return "WPA-Sec Key missing in config", True
        
        path = None
        for d in self.handshake_dirs:
            fp = os.path.join(d, fname)
            if os.path.exists(fp):
                path = fp
                break
        if not path:
            return "File not found", True
        
        try:
            with open(path, 'rb') as f:
                r = requests.post('https://wpa-sec.stanev.org/?api_key=' + key, files={'file': f}, timeout=30)
            
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
        p = None
        for d in self.handshake_dirs:
            fp = os.path.join(d, name)
            if os.path.exists(fp):
                p = fp
                break
        
        if not p:
            return "Not found"
        
        # FIX: Correct extension
        out = f"/tmp/{name.replace('.pcap', '')}.hc22000"
        try:
            subprocess.run(f"/usr/bin/hcxpcapngtool -o {out} {p}", shell=True, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            if os.path.exists(out) and os.path.getsize(out) > 0:
                return send_file(out, as_attachment=True, download_name=f"{os.path.basename(out)}")
            else:
                tok = generate_csrf() if generate_csrf else ""
                return f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8"><title>Error</title>
                    <style>body{{background:#1c1c1e;color:#fff;font-family:sans-serif;text-align:center;padding:50px;}} button{{background:#ff453a;color:#fff;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-weight:bold;}}</style>
                </head>
                <body>
                    <h2 style="color:#ff453a">Conversion Failed</h2>
                    <p>File <b>{name}</b> contains no valid PMKID/EAPOL.</p>
                    <form method="POST" action="/plugins/A_pwmenu/delete-file">
                        <input type="hidden" name="csrf_token" value="{tok}">
                        <input type="hidden" name="filename" value="{name}">
                        <button type="submit">Delete Invalid File</button>
                    </form>
                    <br><a href="/plugins/A_pwmenu/" style="color:#0a84ff">Back</a>
                </body>
                </html>
                """
        except Exception as e:
            return f"Error: {e}"

    def _load_data(self):
        self.data = {'xp': 0, 'badges': [], 'history_cracked': 0, 'history_captured': 0}
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file) as f:
                    self.data.update(json.load(f))
            except:
                pass

    def _save_data(self):
        try:
            with open(self.data_file, 'w') as f:
                json.dump(self.data, f)
        except:
            pass

    def _update_achievements(self, groups, cracked):
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
            self.data['xp'] += 200
            self._save_data()
        except: pass

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
        found = False
        for d in self.handshake_dirs:
            p = os.path.join(d, fname)
            if os.path.exists(p):
                os.remove(p)
                found = True
            h = os.path.join(d, fname.replace('.pcap','.hc22000'))
            if os.path.exists(h):
                os.remove(h)

            h2 = os.path.join(d, fname.replace('.pcap','.22000'))
            if os.path.exists(h2):
                os.remove(h2)
        return found

    def _clean_broken_handshakes(self):
        d_cnt=0
        t_cnt=0
        for d in self.handshake_dirs:
            if not os.path.exists(d): continue
            for f in glob.glob(os.path.join(d, '*.pcap')):
                t_cnt += 1
                try:
                    tmp = f"/tmp/chk_{os.path.basename(f)}.hc22000"
                    subprocess.run(f"/usr/bin/hcxpcapngtool -o {tmp} {f}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    valid = os.path.exists(tmp) and os.path.getsize(tmp) > 0
                    if os.path.exists(tmp):
                        os.remove(tmp)
                    if not valid:
                        os.remove(f)
                        base = f.replace('.pcap', '')
                        for ext in ['.hc22000', '.22000']:
                             h = base + ext
                             if os.path.exists(h): os.remove(h)
                        d_cnt += 1
                except: pass
        return d_cnt, t_cnt

    def _nuke_all_handshakes(self):
        c = 0
        
        for d in self.handshake_dirs:
            if not os.path.exists(d): continue
            for f in glob.glob(os.path.join(d, '*.pcap')):
                try:
                    os.remove(f)
                    c += 1
                except: pass
            for f in glob.glob(os.path.join(d, '*.hc22000')):
                try: os.remove(f)
                except: pass
            for f in glob.glob(os.path.join(d, '*.22000')):
                try: os.remove(f)
                except: pass

        try:
            with open(self.potfile_manual, 'w') as f: f.write("")
            with open(self.potfile_ohc, 'w') as f: f.write("")
        except: pass
            
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
            self.data['xp'] += c * 100
            self._save_data()
        return c

    def _imp_json(self, data):
        c=0
        ex=self._read_pot(self.potfile_ohc)
        with open(self.potfile_ohc, 'a') as f:
            for t in data:
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
        except: pass
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
        m = io.BytesIO()
        with zipfile.ZipFile(m, 'w', zipfile.ZIP_DEFLATED) as z:
            for d in self.handshake_dirs:
                if not os.path.exists(d): continue
                for f in glob.glob(os.path.join(d, '*.pcap')):
                    z.write(f, os.path.basename(f))
        m.seek(0)
        return send_file(m, mimetype='application/zip', as_attachment=True, download_name='handshakes.zip')

    def _serve_password_list(self):
        c = self._get_cracked_data()
        t = "\n".join([f"{e}:{d['password']}" for e, d in c.items()])
        m = io.BytesIO(t.encode('utf-8'))
        return send_file(m, mimetype='text/plain', as_attachment=True, download_name='passwords.txt')

    def _serve_file(self, name):
        for d in self.handshake_dirs:
            fp = os.path.join(d, name)
            if os.path.exists(fp):
                return send_file(fp, as_attachment=True, download_name=name)
        return "Not found"

    def _ensure_file(self, p):
        try:
            if not os.path.exists(os.path.dirname(p)):
                os.makedirs(os.path.dirname(p))
            if not os.path.exists(p):
                open(p, 'w').close()
        except: pass

    def _scan_and_group_files(self, cracked):
        grps = {}
        try:
            tz_offset = int(self.options.get('timezone', 0))
        except:
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
                                    'pwd': cracked[es]['password'] if isc else '', 'src': cracked[es]['source'] if isc else ''}
                    
                    date_str = get_local_time(st.st_mtime, tz_offset)

                    grps[es]['files'].append({
                        'filename': fn, 'bssid': bs, 'size': f"{round(st.st_size/1024,1)}KB", 
                        'date': date_str,
                        'ts': st.st_mtime
                    })
                    if st.st_mtime > grps[es]['ts']:
                        grps[es]['ts'] = st.st_mtime
                except: pass
        res = list(grps.values())
        for g in res:
            g['files'].sort(key=lambda x: x['ts'], reverse=True)
            g['last_seen'] = g['files'][0]['date']
            g['count'] = len(g['files'])
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
                except: pass
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
                    except: pass
        return d

    def _get_html(self):
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>A_pwmenu</title>
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
                        <div class="tit {{ g.cls }}">{{ g.essid }} {% if g.count > 1 %}<span class="badge">{{ g.count }}</span>{% endif %}</div>
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
                            {% if show_wpa %}<button class="btn-xs" onclick="upl('{{ f.filename }}')">WPA</button>{% endif %}
                            <a href="/plugins/A_pwmenu/download-22000/{{ f.filename }}" class="btn-xs hc">22000</a>
                            <a href="/plugins/A_pwmenu/download/{{ f.filename }}" class="btn-xs">PCAP</a>
                            <button class="btn-xs" onclick="rm('{{ f.filename }}')" style="color:var(--danger)">×</button>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            {% endfor %}
        </div>

        <div id="v-other" class="hidden">
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
        
        const t0 = '{{ tab }}';
        tab(t0);
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

        function tab(t) {
            document.querySelectorAll('.list, #v-other').forEach(e=>e.classList.add('hidden'));
            document.getElementById(t==='other'?'v-other':'v-'+t).classList.remove('hidden');
            if(t!=='other') document.getElementById('v-'+t).classList.add('list');
            document.querySelectorAll('.tab').forEach(e=>e.classList.remove('active'));
            document.getElementById('b-'+t).classList.add('active');
            flt();
        }
        
        function tog(id) {
            let s = document.getElementById('s-'+id);
            s.style.display = s.style.display==='block' ? 'none' : 'block';
        }
        
        function flt() {
            let v = document.getElementById('s').value.toUpperCase();
            if(document.getElementById('b-other').classList.contains('active')) return;
            let act = document.querySelector('.tab.active').id.replace('b-','v-');
            document.getElementById(act).querySelectorAll('.si').forEach(el=>{
                el.style.display = el.getAttribute('data-t').toUpperCase().includes(v) ? '' : 'none';
            });
        }
    </script>
</body>
</html>
"""