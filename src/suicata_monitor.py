# """
# suricata_monitor.py
# ===================
# Real-time Suricata alert monitor — rule-based detection path.

# Reads Suricata eve.json DIRECTLY from WSL via:
#     \\wsl$\<distro>\var\log\suricata\eve.json

# For every new alert event:
#     1. Parse Suricata alert fields (signature, category, proto, ports)
#     2. Build ANN feature vector from alert metadata
#     3. Run ANN classifier → attack probability
#     4. Push ("suricata", alert, result) onto shared results queue

# Runs as a background thread alongside zeek_monitor.py.
# Final verdict merged by monitor_manager.py.

# WSL SETUP (run these in WSL before starting):
#     sudo suricata -i eth0

# STANDALONE USAGE (Windows VS Code terminal):
#     python src/suricata_monitor.py

# CALLED FROM monitor_manager.py:
#     from src.suricata_monitor import _tail_eve
# """

# import os
# import sys
# import json
# import time
# import queue
# import threading
# import subprocess

# # ── WSL path config ───────────────────────────────────────────────────────────
# WSL_DISTRO = os.environ.get("WSL_DISTRO", "Ubuntu")
# _WSL_ROOT  = "\\\\wsl$\\{}".format(WSL_DISTRO)

# SURICATA_LOG = os.environ.get(
#     "WSL_SURICATA_LOG",
#     os.path.join(_WSL_ROOT, "var", "log", "suricata", "eve.json")
# )

# POLL_INTERVAL = 0.5


# # ── WSL user auto-detection ───────────────────────────────────────────────────

# def detect_wsl_user():
#     user = os.environ.get("WSL_USER", "")
#     if user:
#         return user
#     try:
#         r = subprocess.run(
#             ["wsl", "-d", WSL_DISTRO, "--", "whoami"],
#             capture_output=True, text=True, timeout=5
#         )
#         return r.stdout.strip() or "user"
#     except Exception:
#         return "user"


# # ── Startup check ─────────────────────────────────────────────────────────────

# def check_wsl_accessible():
#     wsl_root = "\\\\wsl$\\{}".format(WSL_DISTRO)
#     if not os.path.exists(wsl_root):
#         print("[suricata] ERROR: Cannot reach WSL at {}".format(wsl_root))
#         print("           Make sure WSL is running:  wsl -d {}".format(WSL_DISTRO))
#         print("           Run `wsl -l` in CMD to list distros.")
#         print("           Or set:  set WSL_DISTRO=<your-distro-name>")
#         return False
#     if not os.path.exists(SURICATA_LOG):
#         print("[suricata] ERROR: eve.json not found: {}".format(SURICATA_LOG))
#         print("           Start Suricata in WSL:  sudo suricata -i eth0")
#         print("           Or set:  set WSL_SURICATA_LOG=<path>")
#         return False
#     print("[suricata] WSL distro : {}".format(WSL_DISTRO))
#     print("[suricata] Log path   : {}".format(SURICATA_LOG))
#     return True


# # ── eve.json line parser ───────────────────────────────────────────────────────

# def _parse_eve_alert(raw_line):
#     """
#     Parse one JSON line from Suricata eve.json.
#     Returns normalised alert dict or None if not an alert event.

#     Suricata eve.json alert fields used:
#         timestamp
#         alert.signature   → msg
#         alert.category    → category
#         alert.severity    → priority  (1=high 2=medium 3=low)
#         proto             → proto
#         src_ip, src_port
#         dest_ip, dest_port
#     """
#     try:
#         ev = json.loads(raw_line)
#     except json.JSONDecodeError:
#         return None

#     if ev.get("event_type") != "alert":
#         return None

#     ab = ev.get("alert", {})
#     return {
#         "timestamp" : ev.get("timestamp", ""),
#         "msg"       : ab.get("signature", "Suricata Alert"),
#         "category"  : ab.get("category",  ""),
#         "priority"  : int(ab.get("severity", 3)),
#         "proto"     : ev.get("proto", "TCP").upper(),
#         "src_ip"    : ev.get("src_ip",    ""),
#         "src_port"  : int(ev.get("src_port",  0)),
#         "dst_ip"    : ev.get("dest_ip",   ""),
#         "dst_port"  : int(ev.get("dest_port", 0)),
#         "source"    : "Suricata",
#     }


# # ── eve.json tailer ───────────────────────────────────────────────────────────

# def _tail_eve(predictor, result_queue, stop_event):
#     """
#     Tail Suricata eve.json from WSL path.
#     For each new alert line:
#         1. Parse alert fields
#         2. Run ANN classifier (Suricata-driven feature vector)
#         3. Push ("suricata", alert, result) onto result_queue

#     Args:
#         predictor    : loaded AIPredictor instance
#         result_queue : queue.Queue shared with zeek_monitor
#         stop_event   : threading.Event — set to stop the loop
#     """
#     print("[suricata] Tailing: {}".format(SURICATA_LOG))

#     try:
#         fh  = open(SURICATA_LOG, "r", errors="replace")
#         pos = fh.seek(0, 2)   # seek to end — only new alerts
#     except Exception as e:
#         print("[suricata] Cannot open eve.json: {}".format(e))
#         return

#     while not stop_event.is_set():
#         line = fh.readline()

#         if not line:
#             # Log rotation check
#             try:
#                 if os.path.getsize(SURICATA_LOG) < pos:
#                     fh.close()
#                     fh  = open(SURICATA_LOG, "r", errors="replace")
#                     pos = 0
#                     print("[suricata] eve.json rotated — reopened.")
#             except OSError:
#                 pass
#             time.sleep(POLL_INTERVAL)
#             continue

#         pos   = fh.tell()
#         alert = _parse_eve_alert(line.strip())
#         if alert is None:
#             continue

#         # Run ANN only (Suricata-driven features)
#         try:
#             import numpy as np
#             ann_vec  = predictor._build_ann_vector(alert)
#             ann_prob = float(predictor._ann.predict(ann_vec, verbose=0).ravel()[0])
#             ann_label = 1 if ann_prob >= 0.5 else 0

#             result = {
#                 "ann_label" : ann_label,
#                 "ann_conf"  : round(ann_prob, 4),
#                 "ae_label"  : None,
#                 "ae_mse"    : None,
#                 "threshold" : round(predictor._threshold, 6),
#                 "combined"  : ann_label,
#                 "source"    : "ANN(Suricata)",
#             }
#             result_queue.put(("suricata", alert, result))

#         except Exception as ex:
#             print("[suricata] ANN inference error: {}".format(ex))

#     fh.close()
#     print("[suricata] Monitor stopped.")


# # ── Standalone display helper ─────────────────────────────────────────────────

# def _print_standalone(alert, result):
#     verdict = "ATTACK" if result["combined"] else "NORMAL"
#     print("=" * 62)
#     print("  Time     : {}".format(alert.get("timestamp", "")))
#     print("  Alert    : {}".format(alert.get("msg", "")))
#     print("  Category : {}".format(alert.get("category", "")))
#     print("  Proto    : {}  {}:{} → {}:{}".format(
#         alert.get("proto",""),
#         alert.get("src_ip",""),  alert.get("src_port",""),
#         alert.get("dst_ip",""),  alert.get("dst_port",""),
#     ))
#     print("  ANN      : {} (conf={:.2%})".format(
#         "ATTACK" if result["ann_label"] else "NORMAL",
#         result["ann_conf"],
#     ))
#     print("  ► VERDICT: {}".format(verdict))
#     print("=" * 62)


# # ── Standalone entry point ────────────────────────────────────────────────────

# def start_monitor(predictor=None):
#     """Run suricata_monitor standalone (without zeek_monitor)."""
#     if not check_wsl_accessible():
#         sys.exit(1)

#     if predictor is None:
#         sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
#         from src.ai_predictor import AIPredictor
#         predictor = AIPredictor()
#         predictor.load()

#     rq         = queue.Queue()
#     stop_event = threading.Event()

#     print("[suricata] Standalone mode — Ctrl+C to stop\n")

#     t = threading.Thread(
#         target=_tail_eve,
#         args=(predictor, rq, stop_event),
#         daemon=True
#     )
#     t.start()

#     try:
#         while True:
#             try:
#                 _, alert, result = rq.get(timeout=1.0)
#                 _print_standalone(alert, result)
#             except queue.Empty:
#                 continue
#     except KeyboardInterrupt:
#         stop_event.set()
#         t.join(timeout=3)
#         print("\n[suricata] Stopped.")


# if __name__ == "__main__":
#     start_monitor()