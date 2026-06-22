"""
snort_monitor.py
================
Reads Snort alerts in real-time.
Two modes:
  simulate=True  — generates realistic alerts (no Snort/root needed)
  simulate=False — reads from live Snort process on Windows interface
"""
import os, re, time, queue, random, threading, subprocess, platform
from datetime import datetime

_ROOT     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR   = os.path.join(_ROOT, "logs")
SNORT_BIN = r"C:\Snort\bin\snort.exe"
SNORT_CONF= r"C:\Snort\etc\snort.conf"

_RE_RULE  = re.compile(r'\[\*\*\]\s*\[?(\d+:\d+:\d+)?\]?\s*(.+?)\s*\[\*\*\]')
_RE_PRIO  = re.compile(r'\[Priority:\s*(\d+)\]')
_RE_HDR   = re.compile(
    r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}[.\d]*)\s+'
    r'([\d.]+)(?::(\d+))?\s*->\s*([\d.]+)(?::(\d+))?')

# Simulation templates — realistic UNSW-NB15 attack types
TEMPLATES = [
    ("ICMP Ping Detected",         "ICMP", 0,   3, "Normal"),
    ("ICMP Flood Detected",        "ICMP", 0,   2, "DoS"),
    ("TCP SYN Flood Detected",     "TCP",  80,  1, "DoS"),
    ("TCP Port Scan Detected",     "TCP",  445, 2, "Reconnaissance"),
    ("NULL Scan Detected",         "TCP",  22,  2, "Reconnaissance"),
    ("FIN Scan Detected",          "TCP",  443, 2, "Reconnaissance"),
    ("XMAS Scan Detected",         "TCP",  23,  2, "Reconnaissance"),
    ("HTTP SQL Injection Attempt", "TCP",  80,  1, "Exploits"),
    ("HTTP XSS Attempt",           "TCP",  80,  1, "Exploits"),
    ("HTTP Directory Traversal",   "TCP",  80,  2, "Exploits"),
    ("FTP Brute Force Attempt",    "TCP",  21,  1, "Backdoor"),
    ("SSH Brute Force Attempt",    "TCP",  22,  1, "Backdoor"),
    ("DNS Amplification Attack",   "UDP",  53,  2, "DoS"),
    ("UDP Flood Detected",         "UDP",  0,   1, "DoS"),
    ("Telnet Connection Detected", "TCP",  23,  3, "Normal"),
]

SRCS = ["203.0.113.42","198.51.100.7","45.33.32.156",
        "185.220.101.5","91.108.56.180","172.16.5.10","10.0.0.45"]
DSTS = ["192.168.16.1","192.168.16.10","192.168.16.100"]


class SnortMonitor:
    def __init__(self, interface="5", simulate=True):
        self.interface = interface
        self.simulate  = simulate
        self._queue    = queue.Queue(maxsize=1000)
        self._stop     = threading.Event()
        self._thread   = None
        self._buf      = []
        os.makedirs(LOG_DIR, exist_ok=True)

    def start(self):
        self._stop.clear()
        fn = self._sim_loop if self.simulate else self._live_loop
        self._thread = threading.Thread(target=fn, daemon=True)
        self._thread.start()
        mode = "SIMULATE" if self.simulate else "LIVE iface={}".format(self.interface)
        print("[snort] Started — {}".format(mode))

    def stop(self):
        self._stop.set()

    def get_alert(self, timeout=0.2):
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    # ── Live Snort ─────────────────────────────────────────────────────────────
    def _live_loop(self):
        cmd = [SNORT_BIN, "-A", "console", "-q",
               "-i", str(self.interface),
               "-c", SNORT_CONF,
               "-l", LOG_DIR]
        print("[snort] Running: {}".format(" ".join(cmd)))
        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
                close_fds=(platform.system() != "Windows"))
            for line in self._proc.stdout:
                if self._stop.is_set(): break
                self._ingest(line.rstrip())
        except FileNotFoundError:
            print("[snort] ERROR: Snort not found. Falling back to simulate mode.")
            self._sim_loop()
        except PermissionError:
            print("[snort] ERROR: Run as Administrator for live capture.")

    def _ingest(self, line):
        if not line.strip():
            if self._buf:
                a = self._parse(self._buf)
                if a: self._put(a)
                self._buf = []
        else:
            if _RE_RULE.search(line) and self._buf:
                a = self._parse(self._buf)
                if a: self._put(a)
                self._buf = []
            self._buf.append(line)

    def _parse(self, lines):
        a = dict(ts=datetime.now().strftime("%H:%M:%S"),
                 rule_id="unknown", msg="Unknown", priority=3,
                 src_ip="0.0.0.0", src_port=0,
                 dst_ip="0.0.0.0", dst_port=0,
                 proto="TCP", category="")
        for line in lines:
            m = _RE_RULE.search(line)
            if m: a["rule_id"]=m.group(1) or "?"; a["msg"]=m.group(2).strip()
            m = _RE_PRIO.search(line)
            if m: a["priority"]=int(m.group(1))
            m = _RE_HDR.search(line)
            if m:
                a["src_ip"]  = m.group(2)
                a["src_port"]= int(m.group(3)) if m.group(3) else 0
                a["dst_ip"]  = m.group(4)
                a["dst_port"]= int(m.group(5)) if m.group(5) else 0
            for p in ("TCP","UDP","ICMP"):
                if line.strip().startswith(p): a["proto"]=p
        if a["msg"] == "Unknown": return None
        a["category"] = _cat(a["msg"])
        return a

    def _put(self, alert):
        try: self._queue.put_nowait(alert)
        except queue.Full: pass

    # ── Simulator ──────────────────────────────────────────────────────────────
    def _sim_loop(self):
        atk = [t for t in TEMPLATES if t[4] != "Normal"]
        nrm = [t for t in TEMPLATES if t[4] == "Normal"]
        while not self._stop.is_set():
            t = random.choice(atk) if random.random() < 0.72 else random.choice(nrm)
            msg, proto, dp, pri, cat = t
            dp = dp or random.randint(1024, 65535)
            self._put({
                "ts"      : datetime.now().strftime("%H:%M:%S"),
                "rule_id" : "sim",
                "msg"     : msg,
                "priority": pri,
                "src_ip"  : random.choice(SRCS),
                "src_port": random.randint(1024, 65535),
                "dst_ip"  : random.choice(DSTS),
                "dst_port": dp,
                "proto"   : proto,
                "category": cat,
            })
            time.sleep(random.uniform(0.6, 2.2))


_CAT_KW = {
    "syn flood":"DoS","icmp flood":"DoS","udp flood":"DoS","amplif":"DoS",
    "port scan":"Reconnaissance","null scan":"Reconnaissance",
    "fin scan":"Reconnaissance","xmas scan":"Reconnaissance",
    "sql":"Exploits","xss":"Exploits","traversal":"Exploits",
    "brute":"Backdoor","backdoor":"Backdoor",
    "telnet":"Normal","icmp ping":"Normal","ping":"Normal",
}

def _cat(msg):
    ml = msg.lower()
    for k, v in _CAT_KW.items():
        if k in ml: return v
    return "Generic"