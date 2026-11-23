"""
Wi-Fi Encryption Analyzer - live server version (Windows)
-----------------------------------------------------------
Runs a small local web server on your own PC (127.0.0.1 only - never
reachable from outside your machine) that repeatedly reads REAL data
about your Wi-Fi connection via Windows' built-in `netsh` command, and
serves it to a browser page that refreshes itself automatically.

Leave this terminal window open while you use the report - closing it,
or pressing Ctrl+C in it, stops the live updates. No third-party
libraries required.

What this can honestly verify from a normal scan:
  - Encryption protocol and cipher (WPA3 / WPA2 / WEP / Open)
  - Signal strength, channel, band
  - Channel congestion across nearby networks
  - A same-SSID / different-security heuristic for possible rogue APs
  - A "safe to connect" verdict built from the above

What it CANNOT verify (and will label "not assessed" rather than guess):
  - Passphrase strength (would require attempting to crack the key)
  - Router admin credentials (requires logging into the router itself)
  - Real man-in-the-middle detection (requires packet capture in
    monitor mode, which most built-in Wi-Fi adapters don't support)

Run it only against networks you own or have permission to inspect.

USAGE:
    python wifi_scan_report.py

Requires Python 3, and only works on Windows (uses `netsh`).
"""

import subprocess
import re
import json
import sys
import csv
import datetime
import webbrowser
import http.server
import socketserver
from pathlib import Path

REFRESH_SECONDS = 6
PAGE_HTML = ""  # filled in by main() before the server starts

LOG_PATH = Path(__file__).resolve().parent / "connection_log.csv"
LOG_FIELDS = ["timestamp", "ssid", "bssid", "encryption", "cipher", "band", "channel", "signal", "risk", "verdict"]
_last_logged_key = None


def _load_last_logged_key():
    """On startup, read the last logged row so a restart doesn't duplicate it."""
    global _last_logged_key
    if not LOG_PATH.exists():
        return
    try:
        with LOG_PATH.open("r", newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        if rows:
            last = rows[-1]
            _last_logged_key = (last.get("ssid"), last.get("bssid"))
    except Exception:
        pass


def log_connection(entry):
    """Append a row only when the connected network actually changes -
    this is the persistent evidence trail, not a snapshot that resets."""
    global _last_logged_key
    key = (entry["ssid"], entry["bssid"])
    if key == _last_logged_key:
        return
    _last_logged_key = key
    is_new_file = not LOG_PATH.exists()
    with LOG_PATH.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=LOG_FIELDS)
        if is_new_file:
            writer.writeheader()
        writer.writerow({
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ssid": entry["ssid"],
            "bssid": entry["bssid"],
            "encryption": entry["encryption"],
            "cipher": entry["cipher"],
            "band": entry["band"],
            "channel": entry["channel"],
            "signal": entry["signal"],
            "risk": entry["risk"],
            "verdict": entry["verdict"]["label"],
        })


def read_history(limit=200):
    if not LOG_PATH.exists():
        return []
    with LOG_PATH.open("r", newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    return list(reversed(rows))[:limit]


def run_cmd(args):
    result = subprocess.run(
        args, capture_output=True, text=True, encoding="utf-8", errors="ignore"
    )
    return result.stdout


def parse_kv_lines(text):
    """Parse simple 'Key   : Value' lines into a dict, keyed by stripped label."""
    data = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if key:
            data[key] = value
    return data


def get_current_connection():
    text = run_cmd(["netsh", "wlan", "show", "interfaces"])
    if "There is no wireless interface" in text or not text.strip():
        return None
    parsed = parse_kv_lines(text)
    if parsed.get("State", "").lower() != "connected" and "SSID" not in parsed:
        return None
    return parsed


def get_visible_networks():
    """Parse `netsh wlan show networks mode=Bssid` into a list of
    {ssid, auth, cipher, bssids: [{bssid, signal, channel}]} dicts."""
    text = run_cmd(["netsh", "wlan", "show", "networks", "mode=Bssid"])
    networks = []
    current_net = None
    current_bssid = None

    def flush_bssid():
        if current_net is not None and current_bssid:
            current_net["bssids"].append(current_bssid)

    def flush_net():
        flush_bssid()
        if current_net is not None:
            networks.append(current_net)

    for raw_line in text.splitlines():
        line = raw_line.strip()

        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            flush_net()
            current_net = {"ssid": m.group(1).strip() or "(hidden)", "auth": "", "cipher": "", "bssids": []}
            current_bssid = None
            continue

        m = re.match(r"^Authentication\s*:\s*(.*)$", line)
        if m and current_net is not None and current_bssid is None:
            current_net["auth"] = m.group(1).strip()
            continue

        m = re.match(r"^Encryption\s*:\s*(.*)$", line)
        if m and current_net is not None and current_bssid is None:
            current_net["cipher"] = m.group(1).strip()
            continue

        m = re.match(r"^BSSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            flush_bssid()
            current_bssid = {"bssid": m.group(1).strip(), "signal": "", "channel": ""}
            continue

        m = re.match(r"^Signal\s*:\s*(.*)$", line)
        if m and current_bssid is not None:
            current_bssid["signal"] = m.group(1).strip()
            continue

        m = re.match(r"^Channel\s*:\s*(.*)$", line)
        if m and current_bssid is not None:
            current_bssid["channel"] = m.group(1).strip()
            continue

    flush_net()
    return networks


def band_for_channel(channel):
    try:
        ch = int(channel)
    except (TypeError, ValueError):
        return "Unknown"
    if 1 <= ch <= 14:
        return "2.4 GHz"
    if 32 <= ch <= 177:
        return "5 GHz"
    return "6 GHz / other"


def classify_risk(auth, cipher):
    a = (auth or "").lower()
    c = (cipher or "").lower()
    if "wpa3" in a:
        return "secure", "Secure", (
            "WPA3 is the current standard. It resists offline password-guessing "
            "even if traffic is captured."
        )
    if a in ("open", "") or "open" in a:
        return "risk", "High risk", (
            "This network has no encryption. Anything sent over it can be read "
            "by anyone nearby with basic tools."
        )
    if "wep" in a or "wep" in c:
        return "risk", "High risk", (
            "WEP was deprecated in 2004. Its key can typically be recovered from "
            "a few minutes of captured traffic."
        )
    if "wpa2" in a:
        if "tkip" in c:
            return "attention", "Needs attention", (
                "WPA2 is in use, but with the older TKIP cipher instead of AES/CCMP, "
                "which is weaker and being phased out."
            )
        return "ok", "Acceptable", (
            "WPA2 with AES/CCMP is still considered reasonably secure, though WPA3 "
            "offers stronger protection against offline password-guessing."
        )
    if "wpa" in a:
        return "attention", "Needs attention", "Original WPA is outdated; WPA2 or WPA3 is recommended."
    return "unknown", "Unknown", "Unrecognized authentication type reported by the adapter."


def compute_verdict(risk, rogue_detected, mitm_detected):
    reasons = []
    if risk == "risk":
        reasons.append("Encryption is weak or missing (see Overview tab).")
    if rogue_detected:
        reasons.append("A possible rogue access point was detected under this name.")
    if mitm_detected:
        reasons.append("Signs of man-in-the-middle activity were observed.")
    if risk == "attention" and not reasons:
        reasons.append("Encryption works but isn't best practice (see Overview tab).")

    if not reasons:
        return {"level": "safe", "label": "Safe to connect",
                "reasons": ["Encryption is current and no threats were detected in this scan."]}
    if risk == "risk" or rogue_detected or mitm_detected:
        return {"level": "avoid", "label": "Avoid connecting", "reasons": reasons}
    return {"level": "caution", "label": "Connect with caution", "reasons": reasons}


def build_network_entries(current, visible):
    current_ssid = current.get("SSID") if current else None
    current_bssid = (current.get("AP BSSID") or current.get("BSSID")) if current else None

    entries = []
    channel_tally = {}

    # Tally 2.4 GHz channel usage from every visible access point up front.
    for net in visible:
        for b in net["bssids"]:
            ch = b["channel"]
            if band_for_channel(ch) == "2.4 GHz" and ch:
                channel_tally[ch] = channel_tally.get(ch, 0) + 1

    def rogue_check(ssid):
        same_name = [n for n in visible if n["ssid"] == ssid]
        if len(same_name) <= 1:
            return False, "Only one set of access points broadcasting this name was found, all with matching security settings."
        auths = set(n["auth"] for n in same_name if n["auth"])
        ciphers = set(n["cipher"] for n in same_name if n["cipher"])
        if len(auths) > 1 or len(ciphers) > 1:
            return True, (
                f"Multiple access points are broadcasting the name '{ssid}' with "
                f"DIFFERENT security settings ({', '.join(auths)}). This is a common "
                f"sign of a fake 'evil twin' hotspot, not just a mesh/extender setup."
            )
        return False, (
            f"Multiple access points broadcast the name '{ssid}' but with matching "
            f"security settings, which usually just means a mesh network or repeater. "
            f"Worth confirming with the network owner if this is unexpected."
        )

    def make_entry(entry_id, ssid, bssid, is_current, auth, cipher, channel, signal):
        risk, risk_label, proto_note = classify_risk(auth, cipher)
        rogue_detected, rogue_note = rogue_check(ssid)
        return {
            "id": entry_id,
            "ssid": ssid,
            "bssid": bssid or "?",
            "isCurrent": is_current,
            "encryption": auth or "Unknown",
            "cipher": cipher or "Unknown",
            "band": band_for_channel(channel),
            "channel": channel or "?",
            "signal": signal or "?",
            "risk": risk,
            "riskLabel": risk_label,
            "protoNote": proto_note,
            "passphrase": {
                "status": "na",
                "note": "Not assessed. Passphrase strength can't be read from a scan; checking it would mean attempting to crack the key, which is only appropriate on a network you own."
            },
            "defaultLogin": {
                "status": "na",
                "note": "Not assessed. This requires logging into the router's own admin page, not a Wi-Fi scan."
            },
            "ports": {
                "status": "na", "list": [],
                "note": "Not assessed. Checking open ports requires directly scanning the router, which needs separate, explicit permission."
            },
            "rogueAp": {"detected": rogue_detected, "note": rogue_note},
            "mitm": {
                "assessed": False,
                "detected": False,
                "note": "Not assessed. Real MITM detection requires packet capture in monitor mode, which this scan does not perform."
            },
            "verdict": compute_verdict(risk, rogue_detected, False),
        }

    # Build the connected network's card directly from `netsh wlan show
    # interfaces` (ground truth for what you're actually connected to),
    # rather than trying to re-find it in the separate networks scan -
    # that second list can lag behind on multi-AP systems (like a
    # library's mesh) and silently fail to match.
    if current_ssid:
        entries.append(make_entry(
            "current-" + re.sub(r"[^a-zA-Z0-9]", "", (current_ssid or "") + (current_bssid or ""))[:20],
            current_ssid, current_bssid, True,
            current.get("Authentication", ""), current.get("Cipher", ""),
            current.get("Channel", ""), current.get("Signal", ""),
        ))

    # Then list the other nearby networks from the scan, skipping the
    # exact BSSID already represented above so it isn't duplicated.
    for net in visible:
        ssid = net["ssid"]
        auth = net["auth"]
        cipher = net["cipher"]
        for b in net["bssids"]:
            if current_bssid and b["bssid"].lower() == current_bssid.lower():
                continue
            entries.append(make_entry(
                re.sub(r"[^a-zA-Z0-9]", "", ssid + b["bssid"])[:24] or "net",
                ssid, b["bssid"], False, auth, cipher, b["channel"], b["signal"],
            ))

    entries.sort(key=lambda e: (not e["isCurrent"], -_signal_num(e["signal"])))
    return entries[:15], channel_tally


def _signal_num(signal_str):
    m = re.search(r"(\d+)", signal_str or "")
    return int(m.group(1)) if m else 0


def get_default_gateway():
    """Best-effort: find the default gateway IP for the active Wi-Fi adapter
    via ipconfig. Falls back to the first gateway found anywhere."""
    text = run_cmd(["ipconfig"])
    blocks = re.split(r"\r?\n\r?\n+", text)
    for block in blocks:
        if "Wi-Fi" in block or "Wireless" in block:
            m = re.search(r"Default Gateway[ .]*:\s*([\d.]+)", block)
            if m and m.group(1):
                return m.group(1)
    m = re.search(r"Default Gateway[ .]*:\s*([\d.]+)", text)
    return m.group(1) if m else None


def get_arp_table():
    """Parse `arp -a` into {ip: mac}. This only reads your own PC's local
    ARP cache - it doesn't send anything to, or capture traffic from,
    anyone else's device."""
    text = run_cmd(["arp", "-a"])
    table = {}
    for line in text.splitlines():
        m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+\w+", line)
        if m:
            table[m.group(1)] = m.group(2).lower().replace("-", ":")
    return table


_gateway_mac_history = {}


def check_mitm(gateway_ip):
    """A real, passive MITM heuristic: if the MAC address answering for the
    default gateway changes mid-session, that's a genuine (though not
    certain - reconnecting can also cause it) sign of ARP spoofing."""
    if not gateway_ip:
        return {"assessed": False, "detected": False,
                "note": "No default gateway was detected, so the ARP check couldn't run."}
    mac = get_arp_table().get(gateway_ip)
    if not mac:
        return {"assessed": False, "detected": False,
                "note": f"Gateway {gateway_ip} hasn't appeared in the local ARP table yet."}
    prev = _gateway_mac_history.get(gateway_ip)
    _gateway_mac_history[gateway_ip] = mac
    if prev and prev != mac:
        return {"assessed": True, "detected": True,
                "note": (f"The MAC address answering for your gateway ({gateway_ip}) changed "
                         f"from {prev} to {mac} during this session. That's a real sign of "
                         f"possible ARP spoofing, though reconnecting to Wi-Fi can also cause it.")}
    return {"assessed": True, "detected": False,
            "note": (f"Your gateway ({gateway_ip}) has consistently answered from the same "
                     f"MAC address ({mac}) since this scanner started, with no ARP anomalies detected.")}


COMMON_ROUTER_PORTS = [21, 22, 23, 80, 443, 2323, 5000, 7547, 8080, 8443, 49152]


def scan_gateway_ports(ip, timeout=0.5):
    """Connect-scan a small list of commonly risky ports on your OWN
    gateway only. This never accepts an arbitrary target - only the
    detected default gateway can be scanned (enforced by the caller)."""
    import socket
    results = []
    for port in COMMON_ROUTER_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, port))
            is_open = True
        except Exception:
            is_open = False
        finally:
            s.close()
        results.append({"port": port, "open": is_open})
    return results


def scan_now():
    current = get_current_connection()
    visible = get_visible_networks()
    if current is None:
        return [], {}, None
    entries, tally = build_network_entries(current, visible)
    cur_entry = next((e for e in entries if e["isCurrent"]), None)
    gateway_ip = get_default_gateway()
    if cur_entry:
        mitm_result = check_mitm(gateway_ip)
        cur_entry["mitm"] = mitm_result
        cur_entry["verdict"] = compute_verdict(cur_entry["risk"], cur_entry["rogueAp"]["detected"], mitm_result["detected"])
        log_connection(cur_entry)
    return entries, tally, gateway_ip


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Wi-Fi Encryption Analysis - Live</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
:root{--bg:#0F1720;--panel:#16212C;--panel-raised:#1D2C3A;--border:#263847;--text:#E8EEF4;--text-muted:#8CA0B4;--accent:#4FA8FF;--success:#45D6A0;--warning:#F0B94A;--danger:#F26B62;--sans:'Inter',sans-serif;--head:'Space Grotesk',var(--sans);--mono:'JetBrains Mono',ui-monospace,monospace;}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.5;padding:2.5rem 1.5rem 4rem;}
.wrap{max-width:920px;margin:0 auto;}
header h1{font-family:var(--head);font-weight:600;font-size:1.7rem;margin:0 0 .4rem;}
header p{color:var(--text-muted);font-size:.95rem;max-width:65ch;margin:0 0 1rem;}
.livebar{display:flex;align-items:center;gap:.6rem;margin-bottom:1.5rem;font-size:.8rem;color:var(--text-muted);}
.livedot{width:7px;height:7px;border-radius:50%;background:var(--success);display:inline-block;animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{opacity:1;}50%{opacity:.3;}}
.noNetMsg{display:none;background:var(--panel);border:1px solid var(--border);border-left:3px solid var(--warning);border-radius:6px;padding:.8rem 1rem;margin-bottom:1.5rem;font-size:.85rem;color:var(--text-muted);}
.chips{display:flex;gap:.5rem;overflow-x:auto;padding-bottom:.5rem;margin-bottom:1.5rem;}
.chip{flex:0 0 auto;background:var(--panel);border:1px solid var(--border);color:var(--text-muted);font-size:.85rem;padding:.55rem 1rem;border-radius:6px;cursor:pointer;white-space:nowrap;}
.chip:hover{border-color:var(--accent);}
.chip.active{background:var(--panel-raised);border-color:var(--accent);color:var(--text);}
.chip .dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:7px;position:relative;top:-1px;}
.chip .tag{font-size:.68rem;color:var(--accent);margin-left:6px;}
.summary{background:var(--panel);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:6px;padding:1.1rem 1.3rem;margin-bottom:1.5rem;display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:1rem;}
.summary .id h2{font-family:var(--head);font-size:1.15rem;font-weight:600;margin:0 0 .2rem;}
.summary .id .bssid{font-family:var(--mono);font-size:.78rem;color:var(--text-muted);}
.badge{font-size:.78rem;font-weight:500;padding:.3rem .7rem;border-radius:4px;white-space:nowrap;}
.badge.secure{background:rgba(69,214,160,.12);color:var(--success);}
.badge.ok{background:rgba(79,168,255,.12);color:var(--accent);}
.badge.attention{background:rgba(240,185,74,.12);color:var(--warning);}
.badge.risk{background:rgba(242,107,98,.12);color:var(--danger);}
.badge.neutral{background:rgba(140,160,180,.14);color:var(--text-muted);}
.verdict{border-radius:6px;padding:1rem 1.2rem;margin-bottom:1.5rem;border:1px solid var(--border);}
.verdict.safe{background:rgba(69,214,160,.08);border-color:rgba(69,214,160,.35);}
.verdict.caution{background:rgba(240,185,74,.08);border-color:rgba(240,185,74,.35);}
.verdict.avoid{background:rgba(242,107,98,.08);border-color:rgba(242,107,98,.35);}
.verdict .vlabel{font-family:var(--head);font-weight:600;font-size:1.05rem;margin-bottom:.35rem;}
.verdict.safe .vlabel{color:var(--success);}
.verdict.caution .vlabel{color:var(--warning);}
.verdict.avoid .vlabel{color:var(--danger);}
.verdict ul{margin:.3rem 0 0;padding-left:1.1rem;font-size:.85rem;color:var(--text-muted);}
.meta-row{display:flex;gap:1.6rem;font-family:var(--mono);font-size:.8rem;color:var(--text-muted);flex-wrap:wrap;}
.meta-row span b{color:var(--text);font-weight:500;}
.tabs{display:flex;gap:1.6rem;border-bottom:1px solid var(--border);margin-bottom:1.5rem;flex-wrap:wrap;}
.tab{background:none;border:none;color:var(--text-muted);font-size:.92rem;padding:.7rem .1rem;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;}
.tab.active{color:var(--text);border-bottom-color:var(--accent);}
.panel{display:none;}
.panel.active{display:block;}
.card{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:1.3rem 1.4rem;margin-bottom:1rem;}
.card h3{font-family:var(--head);font-size:1rem;font-weight:600;margin:0 0 .5rem;}
.card p{color:var(--text-muted);font-size:.9rem;margin:0;}
.proto-line{display:flex;align-items:baseline;gap:.7rem;margin-bottom:.8rem;flex-wrap:wrap;}
.proto-line .proto{font-family:var(--head);font-size:1.5rem;font-weight:600;}
.fact-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);border-radius:6px;overflow:hidden;margin-top:1rem;}
.fact{background:var(--panel);padding:.9rem 1rem;}
.fact .label{font-size:.75rem;color:var(--text-muted);margin-bottom:.3rem;}
.fact .value{font-family:var(--mono);font-size:.92rem;}
.check-row{display:flex;align-items:flex-start;gap:.8rem;padding:.9rem 0;border-bottom:1px solid var(--border);}
.check-row:last-child{border-bottom:none;}
.check-icon{flex:0 0 auto;width:20px;height:20px;margin-top:2px;}
.check-body .title{font-size:.92rem;font-weight:500;margin-bottom:.2rem;}
.check-body .desc{font-size:.85rem;color:var(--text-muted);}
.threat-card{display:flex;gap:1rem;align-items:flex-start;}
.threat-icon{flex:0 0 auto;width:22px;height:22px;margin-top:2px;}
.chart-wrap{position:relative;height:220px;margin:1rem 0 .5rem;}
.rec-note{font-size:.88rem;color:var(--text-muted);border-left:3px solid var(--accent);padding:.2rem 0 .2rem .9rem;margin-top:1rem;}
.data-table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:.8rem;margin-top:.8rem;}
.data-table td{padding:.3rem .5rem;border-bottom:1px solid var(--border);}
.btn{background:var(--panel-raised);border:1px solid var(--border);color:var(--text);padding:.5rem 1rem;border-radius:6px;cursor:pointer;font-size:.85rem;}
.btn:hover{border-color:var(--accent);}
footer{margin-top:2.5rem;padding-top:1.2rem;border-top:1px solid var(--border);font-size:.8rem;color:var(--text-muted);max-width:75ch;}
</style></head>
<body><div class="wrap">
<header>
<h1>Wi-Fi encryption analysis - live</h1>
<p>Real data read from this PC's Wi-Fi adapter, re-scanned automatically every few seconds by a small local server this script runs on your own machine. Nothing leaves your computer.</p>
</header>
<div class="livebar"><span class="livedot"></span><span id="liveStatus">Live &bull; starting&hellip;</span></div>
<div class="noNetMsg" id="noNetMsg">No active Wi-Fi connection was found in the last scan. Showing the most recent data below.</div>
<div class="chips" id="chips"></div>
<div class="summary" id="summary"></div>
<div class="verdict" id="verdict"></div>
<div class="tabs">
<button class="tab active" data-tab="overview">Overview</button>
<button class="tab" data-tab="vulns">Vulnerabilities</button>
<button class="tab" data-tab="threats">Threats</button>
<button class="tab" data-tab="channels">Channels</button>
<button class="tab" data-tab="history">History</button>
</div>
<div class="panel active" id="panel-overview"></div>
<div class="panel" id="panel-vulns"></div>
<div class="panel" id="panel-threats"></div>
<div class="panel" id="panel-channels"></div>
<div class="panel" id="panel-history"></div>
<footer>This page polls a local server (started by wifi_scan_report.py) every few seconds for a fresh scan. Close that terminal window, or press Ctrl+C in it, to stop live updates.</footer>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<script>
const ICONS = {
  check: '<svg viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="9" stroke="#45D6A0" stroke-width="1.4"/><path d="M6 10.2l2.5 2.5L14 7" stroke="#45D6A0" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  warn: '<svg viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="9" stroke="#F0B94A" stroke-width="1.4"/><path d="M10 6v5" stroke="#F0B94A" stroke-width="1.6" stroke-linecap="round"/><circle cx="10" cy="13.6" r="0.9" fill="#F0B94A"/></svg>',
  danger: '<svg viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="9" stroke="#F26B62" stroke-width="1.4"/><path d="M7 7l6 6M13 7l-6 6" stroke="#F26B62" stroke-width="1.6" stroke-linecap="round"/></svg>',
  neutral: '<svg viewBox="0 0 20 20" fill="none"><circle cx="10" cy="10" r="9" stroke="#8CA0B4" stroke-width="1.4"/><path d="M7 10h6" stroke="#8CA0B4" stroke-width="1.6" stroke-linecap="round"/></svg>'
};
let networks = __NETWORKS_JSON__;
let channelTally = __CHANNEL_JSON__;
let gatewayIp = __GATEWAY_JSON__;
let activeId = networks.length ? networks[0].id : null;
let chartInstance = null;

function riskBadgeClass(r){return {secure:'secure',ok:'ok',attention:'attention',risk:'risk',unknown:'neutral'}[r]||'neutral';}
function dotColor(r){return {secure:'var(--success)',ok:'var(--accent)',attention:'var(--warning)',risk:'var(--danger)',unknown:'var(--text-muted)'}[r]||'var(--text-muted)';}
function statusIcon(s){if(['ok','strong'].includes(s))return ICONS.check;if(['warn','weak'].includes(s))return ICONS.warn;if(['fail','default','none'].includes(s))return ICONS.danger;return ICONS.neutral;}

function renderChips(){
  document.getElementById('chips').innerHTML = networks.map(n=>`
    <button class="chip ${n.id===activeId?'active':''}" data-id="${n.id}">
      <span class="dot" style="background:${dotColor(n.risk)}"></span>${n.ssid}${n.isCurrent?'<span class="tag">connected</span>':''}
    </button>`).join('');
  document.querySelectorAll('.chip').forEach(b=>b.addEventListener('click',()=>{activeId=b.dataset.id;renderAll();}));
}
function renderSummary(n){
  document.getElementById('summary').innerHTML = `
    <div class="id"><h2>${n.ssid}</h2><div class="bssid">${n.bssid}</div></div>
    <div class="meta-row"><span>band <b>${n.band}</b></span><span>channel <b>${n.channel}</b></span><span>signal <b>${n.signal}</b></span></div>
    <div class="badge ${riskBadgeClass(n.risk)}">${n.riskLabel}</div>`;
}
function renderVerdict(n){
  const el = document.getElementById('verdict');
  el.className = 'verdict ' + n.verdict.level;
  el.innerHTML = `<div class="vlabel">${n.verdict.label}</div><ul>${n.verdict.reasons.map(r=>`<li>${r}</li>`).join('')}</ul>`;
}
function renderOverview(n){
  document.getElementById('panel-overview').innerHTML = `
    <div class="card"><div class="proto-line"><span class="proto">${n.encryption}</span><span class="badge ${riskBadgeClass(n.risk)}">${n.riskLabel}</span></div>
    <p>${n.protoNote}</p>
    <div class="fact-grid">
      <div class="fact"><div class="label">Cipher</div><div class="value">${n.cipher}</div></div>
      <div class="fact"><div class="label">Band</div><div class="value">${n.band}</div></div>
      <div class="fact"><div class="label">Channel</div><div class="value">${n.channel}</div></div>
      <div class="fact"><div class="label">Signal</div><div class="value">${n.signal}</div></div>
    </div></div>`;
}
function renderVulns(n){
  const panel = document.getElementById('panel-vulns');
  const isCurrent = n.isCurrent;

  const routerBlock = !isCurrent
    ? `<div class="desc">Only assessed for the network you're currently connected to.</div>`
    : `<div class="desc" id="routerDesc">${gatewayIp ? `Detected router address: <span style="font-family:var(--mono)">${gatewayIp}</span>` : 'Detecting your router\u2019s address\u2026'}</div>
       <div style="margin-top:.6rem;display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;">
         ${gatewayIp ? `<a class="btn" style="text-decoration:none;" href="http://${gatewayIp}" target="_blank" rel="noopener">Open router admin page</a>
         <label style="font-size:.82rem;color:var(--text-muted);"><input type="checkbox" id="routerConfirm"> I checked \u2014 it's not using default login</label>` : ''}
       </div>
       <div class="rec-note" style="margin-top:.6rem;">This tool won't attempt real logins automatically \u2014 that would mean guessing your router's password for you, which crosses into actual intrusion testing. You confirm this one yourself.</div>`;

  const portsBlock = !isCurrent
    ? `<div class="desc">Only assessed for the network you're currently connected to.</div>`
    : `<div class="desc">Scans your own router (${gatewayIp || 'detecting\u2026'}) for common risky open ports. Only run this if this router is genuinely yours \u2014 don't run it on a network you're just a guest on (like a library or caf\u00e9).</div>
       <div style="margin-top:.6rem;display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;">
         <label style="font-size:.82rem;color:var(--text-muted);"><input type="checkbox" id="ownNetworkConfirm"> This router belongs to me</label>
         <button class="btn" id="scanPortsBtn" type="button" disabled>Scan my router</button>
       </div>
       <div id="portsResult" style="margin-top:.6rem;"></div>`;

  panel.innerHTML = `
    <div class="card">
      <div class="check-row"><div class="check-icon">${statusIcon(n.passphrase.status)}</div><div class="check-body"><div class="title">Passphrase strength</div><div class="desc">${n.passphrase.note}</div></div></div>
      <div class="check-row"><div class="check-icon" id="routerIcon">${ICONS.neutral}</div><div class="check-body" style="flex:1;"><div class="title">Router admin credentials</div>${routerBlock}</div></div>
      <div class="check-row"><div class="check-icon" id="portsIcon">${ICONS.neutral}</div><div class="check-body" style="flex:1;"><div class="title">Open logical ports (on your router)</div>${portsBlock}</div></div>
    </div>`;

  if(!isCurrent) return;

  const routerConfirm = document.getElementById('routerConfirm');
  if(routerConfirm){
    routerConfirm.addEventListener('change', ()=>{
      const icon = document.getElementById('routerIcon');
      if(routerConfirm.checked){
        icon.innerHTML = ICONS.check;
        if(!document.getElementById('routerSelfNote')){
          document.getElementById('routerDesc').insertAdjacentHTML('afterend',
            '<div class="desc" id="routerSelfNote" style="color:var(--success);margin-top:.3rem;">Self-confirmed by you \u2014 not verified by an automated scan.</div>');
        }
      } else {
        icon.innerHTML = ICONS.neutral;
        const note = document.getElementById('routerSelfNote');
        if(note) note.remove();
      }
    });
  }

  const ownConfirm = document.getElementById('ownNetworkConfirm');
  const scanBtn = document.getElementById('scanPortsBtn');
  if(ownConfirm && scanBtn){
    ownConfirm.addEventListener('change', ()=>{ scanBtn.disabled = !ownConfirm.checked; });
    scanBtn.addEventListener('click', async ()=>{
      scanBtn.disabled = true;
      scanBtn.textContent = 'Scanning\u2026';
      const resultEl = document.getElementById('portsResult');
      resultEl.innerHTML = '';
      try{
        const res = await fetch('/portscan?confirm=1', {cache:'no-store'});
        const data = await res.json();
        const icon = document.getElementById('portsIcon');
        if(data.error){
          icon.innerHTML = ICONS.neutral;
          resultEl.innerHTML = `<div class="desc" style="color:var(--warning);">${data.error}</div>`;
        } else {
          const openPorts = data.results.filter(r=>r.open);
          icon.innerHTML = openPorts.length ? ICONS.danger : ICONS.check;
          resultEl.innerHTML = openPorts.length
            ? `<div class="desc" style="color:var(--danger);">Open: ${openPorts.map(p=>p.port).join(', ')} \u2014 consider closing these in your router's settings if you don't need them.</div>`
            : `<div class="desc" style="color:var(--success);">None of the commonly risky ports checked were found open.</div>`;
        }
      } catch(err){
        resultEl.innerHTML = `<div class="desc" style="color:var(--danger);">Scan failed \u2014 try again.</div>`;
      }
      scanBtn.disabled = false;
      scanBtn.textContent = 'Scan my router';
    });
  }
}
function renderThreats(n){
  const mitmIcon = !n.mitm.assessed ? ICONS.neutral : (n.mitm.detected ? ICONS.danger : ICONS.check);
  document.getElementById('panel-threats').innerHTML = `
    <div class="card threat-card"><div class="threat-icon">${n.rogueAp.detected?ICONS.danger:ICONS.check}</div><div><h3>Rogue access point</h3><p>${n.rogueAp.note}</p></div></div>
    <div class="card threat-card"><div class="threat-icon">${mitmIcon}</div><div><h3>Man-in-the-middle activity</h3><p>${n.mitm.note}</p></div></div>`;
}
function renderChannels(n){
  const panel = document.getElementById('panel-channels');
  const labels = Object.keys(channelTally).sort((a,b)=>a-b);
  const data = labels.map(l=>channelTally[l]);
  if(n.band !== '2.4 GHz' || labels.length===0){
    panel.innerHTML = `<div class="card"><h3>Channel data</h3><p>${labels.length===0?'No 2.4 GHz networks were seen in this scan to compare against.':'This network runs outside 2.4 GHz, so congestion here mainly affects the 2.4 GHz networks below.'}</p><div class="chart-wrap"><canvas id="channelChart" role="img" aria-label="Bar chart of networks detected per 2.4 GHz channel"></canvas></div></div>`;
  } else {
    const quiet = ['1','6','11'].filter(c=>c!==n.channel).sort((a,b)=>(channelTally[a]||0)-(channelTally[b]||0));
    panel.innerHTML = `<div class="card"><h3>Channel ${n.channel} congestion</h3><p>${channelTally[n.channel]||0} access points were seen sharing channel ${n.channel} in this scan.</p>
      <div class="chart-wrap"><canvas id="channelChart" role="img" aria-label="Bar chart of networks detected per 2.4 GHz channel, this network's channel highlighted"></canvas></div>
      <div class="rec-note">Channels 1, 6, and 11 are the only non-overlapping 2.4 GHz channels. Channel ${quiet[0]} has the least traffic nearby right now.</div></div>`;
  }
  if(chartInstance){chartInstance.destroy();}
  const ctx = document.getElementById('channelChart');
  const colors = labels.map(l=> l===n.channel ? '#4FA8FF' : '#2A3D4F');
  chartInstance = new Chart(ctx,{type:'bar',data:{labels,datasets:[{data,backgroundColor:colors,borderRadius:4,maxBarThickness:28}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
      scales:{x:{grid:{display:false},ticks:{color:'#8CA0B4'},title:{display:true,text:'Channel',color:'#8CA0B4'}},
      y:{beginAtZero:true,ticks:{color:'#8CA0B4',stepSize:1},grid:{color:'#1F2E3B'}}}}});
}
function renderAll(){
  if(!activeId){return;}
  const n = networks.find(x=>x.id===activeId) || networks[0];
  renderChips();renderSummary(n);renderVerdict(n);renderOverview(n);renderVulns(n);renderThreats(n);renderChannels(n);
}

async function fetchScan(){
  try{
    const res = await fetch('/scan', {cache:'no-store'});
    const data = await res.json();
    document.getElementById('liveStatus').textContent = 'Live \u2022 updated ' + new Date().toLocaleTimeString();
    if(data.entries && data.entries.length){
      document.getElementById('noNetMsg').style.display = 'none';
      const prevId = activeId;
      networks = data.entries;
      channelTally = data.tally;
      gatewayIp = data.gatewayIp || gatewayIp;
      const stillThere = networks.find(n=>n.id===prevId);
      const current = networks.find(n=>n.isCurrent);
      activeId = stillThere ? prevId : (current ? current.id : networks[0].id);
      renderAll();
    } else {
      document.getElementById('noNetMsg').style.display = 'block';
    }
  } catch(err){
    document.getElementById('liveStatus').textContent = 'Live \u2022 waiting for local server\u2026';
  }
}

function renderHistoryTable(rows){
  const panel = document.getElementById('panel-history');
  if(!rows.length){
    panel.innerHTML = `<div class="card"><h3>Connection history</h3><p>No history recorded yet. A row is added automatically the first time this scanner detects you've connected to a different network than before.</p></div>`;
    return;
  }
  const body = rows.map(r=>`<tr><td>${r.timestamp}</td><td>${r.ssid}</td><td>${r.encryption}</td><td><span class="badge ${riskBadgeClass(r.risk)}">${r.verdict}</span></td></tr>`).join('');
  panel.innerHTML = `<div class="card"><h3>Connection history</h3>
    <p>A row is added automatically every time this tool detects you've joined a different network \u2014 a persistent record of exactly when and what you were connected to, stored in connection_log.csv next to the script (not just a badge that disappears when you switch networks).</p>
    <table class="data-table" style="margin-top:1rem;">
      <tr><td><b>Time</b></td><td><b>Network</b></td><td><b>Encryption</b></td><td><b>Verdict</b></td></tr>
      ${body}
    </table></div>`;
}
async function fetchHistory(){
  try{
    const res = await fetch('/history', {cache:'no-store'});
    const data = await res.json();
    renderHistoryTable(data.history || []);
  }catch(err){ /* history is non-critical; ignore transient failures */ }
}
async function livePoll(){
  await fetchScan();
  await fetchHistory();
}

document.querySelectorAll('.tab').forEach(tab=>{
  tab.addEventListener('click',()=>{
    document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById('panel-'+tab.dataset.tab).classList.add('active');
  });
});

renderAll();
livePoll();
setInterval(livePoll, __REFRESH_MS__);
</script></body></html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # keep the terminal quiet during polling

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = PAGE_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/scan":
            entries, tally, gateway_ip = scan_now()
            body = json.dumps({"entries": entries, "tally": tally, "gatewayIp": gateway_ip}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/portscan"):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(self.path).query)
            if q.get("confirm", [""])[0] != "1":
                self.send_response(400)
                self.end_headers()
                return
            gw = get_default_gateway()
            if not gw:
                body = json.dumps({"error": "No default gateway was detected."}).encode("utf-8")
            else:
                results = scan_gateway_ports(gw)
                body = json.dumps({"gatewayIp": gw, "results": results}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/history":
            body = json.dumps({"history": read_history()}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def main():
    global PAGE_HTML

    if sys.platform != "win32":
        print("This script uses Windows' netsh command and won't work on this OS.")
        return

    _load_last_logged_key()
    entries, tally, gateway_ip = scan_now()
    if not entries:
        print("No active Wi-Fi connection was found. Connect to a network and try again.")
        return

    PAGE_HTML = (
        HTML_TEMPLATE
        .replace("__NETWORKS_JSON__", json.dumps(entries))
        .replace("__CHANNEL_JSON__", json.dumps(tally))
        .replace("__GATEWAY_JSON__", json.dumps(gateway_ip))
        .replace("__REFRESH_MS__", str(REFRESH_SECONDS * 1000))
    )

    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    url = f"http://127.0.0.1:{port}/"

    print("Wi-Fi Encryption Analyzer - live server (build: bssid-fix-2)")
    print(f"Live report running at {url}")
    print(f"Refreshing every {REFRESH_SECONDS} seconds. Keep this window open.")
    print("Press Ctrl+C here to stop.")
    webbrowser.open(url)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
