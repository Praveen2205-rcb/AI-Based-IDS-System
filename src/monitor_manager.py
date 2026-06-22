# """
# monitor_manager.py
# ==================
# Launches both monitors as threads and merges their results.

#     Thread 1 — suricata_monitor  (ANN path)
#         Tails \\wsl$\Ubuntu\var\log\suricata\eve.json
#         Runs ANN classifier on every Suricata alert
#         Pushes ("suricata", alert, result) onto shared queue

#     Thread 2 — zeek_monitor  (AE path)
#         Tails \\wsl$\Ubuntu\home\<user>\conn.log
#         Maps real Zeek fields → exact UNSW-NB15 features
#         Runs Autoencoder on every new connection
#         Pushes ("zeek", alert, result) onto shared queue

# MERGE LOGIC:
#     Each source produces its own verdict independently.
#     The manager reads from the shared queue and prints a unified output.

#     Suricata event  → shows ANN label + confidence
#     Zeek event      → shows AE label + MSE
#     If a Suricata alert and a Zeek connection share the same
#     (src_ip, dst_ip, dst_port) within a 5-second window,
#     they are MERGED into one combined verdict:
#         ATTACK if ANN == 1  OR  AE MSE > threshold

# USAGE:
#     python src/monitor_manager.py          # loads models from disk
#     or called from main.py after training:
#         from src.monitor_manager import start_all
#         start_all(predictor)
# """

# import os
# import sys
# import time
# import queue
# import threading
# import subprocess

# # ── WSL distro + user detection ───────────────────────────────────────────────
# WSL_DISTRO = os.environ.get("WSL_DISTRO", "Ubuntu")

# def _detect_wsl_user():
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

# # ── Correlation window ────────────────────────────────────────────────────────
# CORRELATE_WINDOW_SEC = 5.0   # max seconds between Suricata + Zeek events
#                               # for them to be merged into one verdict

# # ── Display helpers ───────────────────────────────────────────────────────────
# _BAR = "=" * 64

# def _verdict_str(combined):
#     return "ATTACK" if combined else "NORMAL"

# def _print_suricata(alert, result):
#     print(_BAR)
#     print("  [SURICATA]  {}".format(alert.get("timestamp", "")))
#     print("  Alert    : {}".format(alert.get("msg", "")))
#     print("  Category : {}".format(alert.get("category", "")))
#     print("  Proto    : {}  {}:{} → {}:{}".format(
#         alert.get("proto",""),
#         alert.get("src_ip",""),  alert.get("src_port",""),
#         alert.get("dst_ip",""),  alert.get("dst_port",""),
#     ))
#     print("  ANN      : {} (conf={:.2%})  ← rule-based path".format(
#         "ATTACK" if result["ann_label"] else "NORMAL",
#         result["ann_conf"],
#     ))
#     print("  AE       : waiting for Zeek data ...")
#     print("  ► VERDICT: {}  (ANN only)".format(_verdict_str(result["combined"])))
#     print(_BAR)

# def _print_zeek(alert, result):
#     print(_BAR)
#     print("  [ZEEK]      {}".format(alert.get("timestamp", "")))
#     print("  Conn     : {} {} {}:{} → {}:{}".format(
#         alert.get("proto",""), alert.get("state",""),
#         alert.get("src_ip",""),  alert.get("src_port",""),
#         alert.get("dst_ip",""),  alert.get("dst_port",""),
#     ))
#     print("  Features : dur={:.4f}s  {}B/{}pkt → {}B/{}pkt  svc={}".format(
#         alert.get("dur",0),
#         alert.get("sbytes",0), alert.get("spkts",0),
#         alert.get("dbytes",0), alert.get("dpkts",0),
#         alert.get("service","-"),
#     ))
#     print("  AE       : {} (MSE={:.6f} | thr={:.6f})  ← anomaly path".format(
#         "ANOMALY" if result["ae_label"] else "NORMAL",
#         result["ae_mse"],
#         result["threshold"],
#     ))
#     print("  ANN      : no Suricata alert matched")
#     print("  ► VERDICT: {}  (AE only)".format(_verdict_str(result["combined"])))
#     print(_BAR)

# def _print_merged(s_alert, s_result, z_alert, z_result):
#     ann_label = s_result["ann_label"]
#     ae_label  = z_result["ae_label"]
#     combined  = 1 if (ann_label == 1 or ae_label == 1) else 0

#     print(_BAR)
#     print("  [MERGED]    Suricata + Zeek correlated")
#     print("  Alert    : {}".format(s_alert.get("msg","")))
#     print("  Proto    : {}  {}:{} → {}:{}".format(
#         s_alert.get("proto",""),
#         s_alert.get("src_ip",""),  s_alert.get("src_port",""),
#         s_alert.get("dst_ip",""),  s_alert.get("dst_port",""),
#     ))
#     print("  Zeek     : dur={:.4f}s  {}B/{}pkt → {}B/{}pkt  svc={}".format(
#         z_alert.get("dur",0),
#         z_alert.get("sbytes",0), z_alert.get("spkts",0),
#         z_alert.get("dbytes",0), z_alert.get("dpkts",0),
#         z_alert.get("service","-"),
#     ))
#     print("  ANN      : {} (conf={:.2%})  ← Suricata features".format(
#         "ATTACK" if ann_label else "NORMAL",
#         s_result["ann_conf"],
#     ))
#     print("  AE       : {} (MSE={:.6f} | thr={:.6f})  ← Zeek features".format(
#         "ANOMALY" if ae_label else "NORMAL",
#         z_result["ae_mse"],
#         z_result["threshold"],
#     ))
#     print("  ► VERDICT: {}  (ANN={} | AE={})".format(
#         _verdict_str(combined),
#         "ATTACK" if ann_label else "NORMAL",
#         "ANOMALY" if ae_label else "NORMAL",
#     ))
#     print(_BAR)

# # ── Correlation cache ─────────────────────────────────────────────────────────

# class _CorrelationCache:
#     """
#     Holds unmatched Suricata and Zeek events for a short window.
#     When both sources produce an event for the same flow
#     (src_ip, dst_ip, dst_port) within CORRELATE_WINDOW_SEC,
#     they are merged into a single combined verdict.
#     """
#     def __init__(self, window=CORRELATE_WINDOW_SEC):
#         self._window     = window
#         self._suricata   = {}   # key → (alert, result, timestamp)
#         self._zeek       = {}
#         self._lock       = threading.Lock()

#     def _flow_key(self, alert):
#         return (
#             alert.get("src_ip",  ""),
#             alert.get("dst_ip",  ""),
#             str(alert.get("dst_port", "")),
#         )

#     def _evict_old(self, store):
#         now = time.time()
#         return {k: v for k, v in store.items()
#                 if now - v[2] < self._window}

#     def add_suricata(self, alert, result):
#         """
#         Try to match with a pending Zeek event.
#         Returns (merged, s_alert, s_result, z_alert, z_result) if matched,
#         else (False, alert, result, None, None).
#         """
#         key = self._flow_key(alert)
#         with self._lock:
#             self._zeek = self._evict_old(self._zeek)
#             if key in self._zeek:
#                 z_alert, z_result, _ = self._zeek.pop(key)
#                 return True, alert, result, z_alert, z_result
#             self._suricata[key] = (alert, result, time.time())
#         return False, alert, result, None, None

#     def add_zeek(self, alert, result):
#         """
#         Try to match with a pending Suricata event.
#         Returns (merged, s_alert, s_result, z_alert, z_result) if matched,
#         else (False, None, None, alert, result).
#         """
#         key = self._flow_key(alert)
#         with self._lock:
#             self._suricata = self._evict_old(self._suricata)
#             if key in self._suricata:
#                 s_alert, s_result, _ = self._suricata.pop(key)
#                 return True, s_alert, s_result, alert, result
#             self._zeek[key] = (alert, result, time.time())
#         return False, None, None, alert, result

# # ── WSL accessibility check ───────────────────────────────────────────────────

# def _check_wsl():
#     wsl_root = "\\\\wsl$\\{}".format(WSL_DISTRO)
#     if not os.path.exists(wsl_root):
#         print("[manager] ERROR: WSL not reachable at {}".format(wsl_root))
#         print("          Run in CMD:  wsl -d {}".format(WSL_DISTRO))
#         print("          Or set:      set WSL_DISTRO=<your-distro>")
#         sys.exit(1)
#     print("[manager] WSL OK — distro: {}".format(WSL_DISTRO))

# # ── Main manager ──────────────────────────────────────────────────────────────

# def start_all(predictor=None):
#     """
#     Start both monitors and begin merging results.

#     Args:
#         predictor : loaded AIPredictor instance.
#                     If None, loads models from disk automatically.
#     """
#     _check_wsl()

#     wsl_user = _detect_wsl_user()
#     print("[manager] WSL user: {}".format(wsl_user))

#     # Load predictor if not provided
#     if predictor is None:
#         sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
#         from src.ai_predictor import AIPredictor
#         predictor = AIPredictor()
#         predictor.load()

#     # Shared queue — both monitors push here
#     result_queue = queue.Queue()
#     stop_event   = threading.Event()
#     cache        = _CorrelationCache()

#     # ── Start Suricata monitor thread ─────────────────────────────────────────
#     from src.suricata_monitor import _tail_eve
#     suricata_thread = threading.Thread(
#         target=_tail_eve,
#         args=(predictor, result_queue, stop_event),
#         name="SuricataMonitor",
#         daemon=True,
#     )
#     suricata_thread.start()
#     print("[manager] SuricataMonitor started")

#     # ── Start Zeek monitor thread ─────────────────────────────────────────────
#     from src.zeek_monitor import start_zeek_monitor
#     zeek_thread, _ = start_zeek_monitor(
#         predictor, result_queue, wsl_user, stop_event
#     )
#     print("[manager] ZeekMonitor started")

#     print("\n[manager] Listening for alerts ... (Ctrl+C to stop)\n")

#     # ── Result merge loop ─────────────────────────────────────────────────────
#     try:
#         while True:
#             try:
#                 source, alert, result = result_queue.get(timeout=1.0)
#             except queue.Empty:
#                 continue

#             if source == "suricata":
#                 merged, sa, sr, za, zr = cache.add_suricata(alert, result)
#                 if merged:
#                     _print_merged(sa, sr, za, zr)
#                 else:
#                     _print_suricata(alert, result)

#             elif source == "zeek":
#                 # Only print Zeek-only events that are anomalies
#                 # (normal Zeek connections are very frequent — skip them)
#                 merged, sa, sr, za, zr = cache.add_zeek(alert, result)
#                 if merged:
#                     _print_merged(sa, sr, za, zr)
#                 elif result["ae_label"] == 1:
#                     # AE detected anomaly but no matching Suricata alert
#                     _print_zeek(alert, result)
#                 # else: normal Zeek connection — silently skip

#     except KeyboardInterrupt:
#         print("\n[manager] Stopping ...")
#         stop_event.set()
#         suricata_thread.join(timeout=3)
#         zeek_thread.join(timeout=3)
#         print("[manager] Stopped.")

# # ── Entry point ───────────────────────────────────────────────────────────────

# if __name__ == "__main__":
#     start_all()