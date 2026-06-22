# """
# zeek_monitor.py
# ===============
# Real-time Zeek log monitor — anomaly-based detection path.

# Reads three Zeek logs directly from WSL:
#     conn.log   — maps to UNSW-NB15 numeric features
#     dns.log    — enriches service field
#     http.log   — enriches trans_depth, response_body_len, ct_flw_http_mthd

# UNSW-NB15 feature columns (exact match to training data):
#     dur, proto, service, state,
#     spkts, dpkts, sbytes, dbytes, rate,
#     sttl, dttl, sload, dload, sloss, dloss,
#     sinpkt, dinpkt, sjit, djit,
#     swin, stcpb, dtcpb, dwin, tcprtt, synack, ackdat,
#     smean, dmean, trans_depth, response_body_len,
#     ct_srv_src, ct_state_ttl, ct_dst_ltm,
#     ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm,
#     is_ftp_login, ct_ftp_cmd, ct_flw_http_mthd,
#     ct_src_ltm, ct_srv_dst, is_sm_ips_ports

# Zeek conn.log → UNSW-NB15 mapping:
#     duration             → dur
#     proto                → proto
#     service              → service  (Zeek field, or port-based lookup)
#     conn_state           → state    (mapped via _STATE_MAP)
#     orig_pkts            → spkts
#     resp_pkts            → dpkts
#     orig_bytes           → sbytes
#     resp_bytes           → dbytes
#     (orig+resp pkts)/dur → rate
#     orig_ttl             → sttl
#     resp_ttl             → dttl
#     orig_bytes/dur       → sload
#     resp_bytes/dur       → dload
#     orig_ip_bytes-orig_bytes → sloss
#     resp_ip_bytes-resp_bytes → dloss
#     dur/orig_pkts        → sinpkt
#     dur/resp_pkts        → dinpkt
#     orig_jitter_inpkt    → sjit
#     resp_jitter_inpkt    → djit
#     orig_wnd_scale       → swin
#     orig_base_seq        → stcpb
#     resp_base_seq        → dtcpb
#     resp_wnd_scale       → dwin
#     rtt                  → tcprtt
#     syn_ack_rtt          → synack
#     ack_dat_rtt          → ackdat
#     orig_bytes/orig_pkts → smean
#     resp_bytes/resp_pkts → dmean
#     http.log entries     → trans_depth, response_body_len, ct_flw_http_mthd
# """

# import os
# import time
# import queue
# import threading
# import numpy as np

# # ── WSL path config ───────────────────────────────────────────────────────────
# WSL_DISTRO = os.environ.get("WSL_DISTRO", "Ubuntu")
# _WSL_ROOT  = "\\\\wsl$\\{}".format(WSL_DISTRO)

# def _wsl(rel):
#     return os.path.join(_WSL_ROOT, rel)

# def wsl_log_paths(wsl_user):
#     home = "home\\{}".format(wsl_user)
#     return {
#         "conn" : os.environ.get("WSL_ZEEK_CONN",  _wsl("{}\\conn.log".format(home))),
#         "dns"  : os.environ.get("WSL_ZEEK_DNS",   _wsl("{}\\dns.log".format(home))),
#         "http" : os.environ.get("WSL_ZEEK_HTTP",  _wsl("{}\\http.log".format(home))),
#     }

# POLL_INTERVAL    = 0.5
# DNS_REFRESH_SEC  = 20
# HTTP_REFRESH_SEC = 20

# # ── Zeek conn_state → UNSW-NB15 state ────────────────────────────────────────
# _STATE_MAP = {
#     "SF"  : "FIN", "S1": "CON", "S0": "INT", "REJ": "RST",
#     "RSTO": "RST", "RSTR":"RST","SH" : "INT", "SHR": "INT",
#     "OTH" : "CON", "S2" : "CON","S3" : "CON",
# }

# # ── Port → service ────────────────────────────────────────────────────────────
# _PORT_SVC = {
#     21:"ftp", 20:"ftp-data", 22:"ssh", 25:"smtp", 53:"dns",
#     80:"http", 110:"pop3", 443:"ssl", 6667:"irc", 161:"snmp", 67:"dhcp",
# }

# # ── Normalisation (UNSW-NB15 approximate mean/scale) ─────────────────────────
# _NORM = {
#     "dur"              : (0.5,     5.0),
#     "spkts"            : (5.0,    20.0),
#     "dpkts"            : (3.0,    15.0),
#     "sbytes"           : (500.0, 5000.0),
#     "dbytes"           : (300.0, 3000.0),
#     "rate"             : (8.0,    30.0),
#     "sttl"             : (64.0,   30.0),
#     "dttl"             : (64.0,   30.0),
#     "sload"            : (0.0,  5000.0),
#     "dload"            : (0.0,  3000.0),
#     "sloss"            : (0.0,    10.0),
#     "dloss"            : (0.0,    10.0),
#     "sinpkt"           : (0.0,    50.0),
#     "dinpkt"           : (0.0,    50.0),
#     "sjit"             : (0.0,   100.0),
#     "djit"             : (0.0,   100.0),
#     "swin"             : (128.0, 128.0),
#     "dwin"             : (128.0, 128.0),
#     "stcpb"            : (0.0,    1e9),
#     "dtcpb"            : (0.0,    1e9),
#     "tcprtt"           : (0.0,     1.0),
#     "synack"           : (0.0,     1.0),
#     "ackdat"           : (0.0,     1.0),
#     "smean"            : (100.0, 500.0),
#     "dmean"            : (100.0, 500.0),
#     "trans_depth"      : (0.0,    10.0),
#     "response_body_len": (0.0, 10000.0),
#     "ct_srv_src"       : (1.0,     5.0),
#     "ct_state_ttl"     : (1.0,     5.0),
#     "ct_dst_ltm"       : (1.0,     5.0),
#     "ct_src_dport_ltm" : (1.0,     5.0),
#     "ct_dst_sport_ltm" : (1.0,     5.0),
#     "ct_dst_src_ltm"   : (1.0,     5.0),
#     "ct_src_ltm"       : (1.0,     5.0),
#     "ct_srv_dst"       : (1.0,     5.0),
# }

# def _z(val, mean, scale):
#     if scale == 0: return 0.0
#     return float(np.clip((float(val) - mean) / scale, -3.0, 3.0))

# def _f(row, key, default=0.0):
#     v = row.get(key, "-")
#     try:    return float(v) if v not in ("-","","(empty)") else default
#     except: return default

# # ── Zeek log parsers ──────────────────────────────────────────────────────────

# def _parse_zeek_tsv(path):
#     rows, fields = [], []
#     if not os.path.exists(path): return rows
#     try:
#         with open(path, "r", errors="replace") as f:
#             for line in f:
#                 line = line.strip()
#                 if line.startswith("#fields"):
#                     fields = line.split("\t")[1:]; continue
#                 if line.startswith("#") or not fields: continue
#                 parts = line.split("\t")
#                 if len(parts) >= len(fields):
#                     rows.append(dict(zip(fields, parts)))
#     except Exception as e:
#         print("[zeek] Parse error {}: {}".format(path, e))
#     return rows

# def _build_dns_index(path):
#     index = {}
#     for row in _parse_zeek_tsv(path):
#         src = row.get("id.orig_h","")
#         if src:
#             index.setdefault(src,[]).append({
#                 "query": row.get("query",""),
#                 "qtype": row.get("qtype_name",""),
#                 "rcode": row.get("rcode_name",""),
#             })
#     return index

# def _build_http_index(path):
#     index = {}
#     for row in _parse_zeek_tsv(path):
#         key = (row.get("id.orig_h",""), row.get("id.resp_h",""), row.get("id.resp_p","80"))
#         index.setdefault(key,[]).append({
#             "method"  : row.get("method",""),
#             "uri"     : row.get("uri",""),
#             "status"  : row.get("status_code",""),
#             "body_len": _f(row,"resp_body_len"),
#         })
#     return index

# # ── conn.log row → exact UNSW-NB15 feature dict ───────────────────────────────

# def _conn_to_features(row, dns_index, http_index, conn_counts):
#     """
#     Map one Zeek conn.log row to the exact UNSW-NB15 feature set.
#     All numeric values are z-score normalised using _NORM constants.
#     """
#     src_ip   = row.get("id.orig_h","")
#     dst_ip   = row.get("id.resp_h","")
#     src_port = int(_f(row,"id.orig_p"))
#     dst_port = int(_f(row,"id.resp_p"))
#     proto    = row.get("proto","tcp").lower()
#     zeek_svc = row.get("service","-").lower().strip()

#     # ── Numeric fields ────────────────────────────────────────────────────────
#     dur    = _f(row,"duration")
#     sbytes = _f(row,"orig_bytes")
#     dbytes = _f(row,"resp_bytes")
#     spkts  = _f(row,"orig_pkts")
#     dpkts  = _f(row,"resp_pkts")

#     orig_ip = _f(row,"orig_ip_bytes", sbytes)
#     resp_ip = _f(row,"resp_ip_bytes", dbytes)
#     sloss   = max(orig_ip - sbytes, 0.0)
#     dloss   = max(resp_ip - dbytes, 0.0)

#     rate   = (spkts + dpkts) / max(dur, 1e-9)
#     sload  = sbytes / max(dur, 1e-9)
#     dload  = dbytes / max(dur, 1e-9)
#     sinpkt = dur    / max(spkts, 1e-9)
#     dinpkt = dur    / max(dpkts, 1e-9)
#     sjit   = _f(row,"orig_jitter_inpkt")
#     djit   = _f(row,"resp_jitter_inpkt")
#     swin   = _f(row,"orig_wnd_scale",0)  if proto=="tcp" else 0.0
#     dwin   = _f(row,"resp_wnd_scale",0)  if proto=="tcp" else 0.0
#     stcpb  = _f(row,"orig_base_seq",0)
#     dtcpb  = _f(row,"resp_base_seq",0)
#     tcprtt = _f(row,"rtt")
#     synack = _f(row,"syn_ack_rtt")
#     ackdat = _f(row,"ack_dat_rtt")
#     smean  = sbytes / max(spkts, 1.0)
#     dmean  = dbytes / max(dpkts, 1.0)
#     sttl   = _f(row,"orig_ttl", 64)
#     dttl   = _f(row,"resp_ttl", 64)

#     # ── State & service ───────────────────────────────────────────────────────
#     state   = _STATE_MAP.get(row.get("conn_state","OTH"), "CON")
#     service = zeek_svc if zeek_svc and zeek_svc != "-" else _PORT_SVC.get(dst_port,"-")

#     # ── HTTP enrichment ───────────────────────────────────────────────────────
#     http_entries      = http_index.get((src_ip, dst_ip, str(dst_port)), [])
#     trans_depth       = float(len(http_entries))
#     response_body_len = sum(e["body_len"] for e in http_entries)
#     ct_flw_http_mthd  = float(len([e for e in http_entries
#                                    if e["method"] in ("GET","POST","PUT","DELETE")]))

#     # ── FTP flags ─────────────────────────────────────────────────────────────
#     is_ftp_login = 1.0 if dst_port == 21 else 0.0
#     ct_ftp_cmd   = 0.0

#     # ── ct_* connection count features ───────────────────────────────────────
#     def _ct(key):
#         conn_counts[key] = conn_counts.get(key, 0) + 1
#         return float(min(conn_counts[key], 255))

#     ct_srv_src       = _ct(("srv_src",   src_ip,  service))
#     ct_state_ttl     = _ct(("state_ttl", state,   int(sttl)))
#     ct_dst_ltm       = _ct(("dst_ltm",   dst_ip))
#     ct_src_dport_ltm = _ct(("src_dport", src_ip,  dst_port))
#     ct_dst_sport_ltm = _ct(("dst_sport", dst_ip,  src_port))
#     ct_dst_src_ltm   = _ct(("dst_src",   dst_ip,  src_ip))
#     ct_src_ltm       = _ct(("src_ltm",   src_ip))
#     ct_srv_dst       = _ct(("srv_dst",   dst_ip,  service))
#     is_sm_ips_ports  = 1.0 if (src_ip == dst_ip or src_port == dst_port) else 0.0

#     # ── Build normalised feature dict ─────────────────────────────────────────
#     n = _NORM
#     feat = {
#         "dur"              : _z(dur,               *n["dur"]),
#         "spkts"            : _z(spkts,             *n["spkts"]),
#         "dpkts"            : _z(dpkts,             *n["dpkts"]),
#         "sbytes"           : _z(sbytes,            *n["sbytes"]),
#         "dbytes"           : _z(dbytes,            *n["dbytes"]),
#         "rate"             : _z(rate,              *n["rate"]),
#         "sttl"             : _z(sttl,              *n["sttl"]),
#         "dttl"             : _z(dttl,              *n["dttl"]),
#         "sload"            : _z(sload,             *n["sload"]),
#         "dload"            : _z(dload,             *n["dload"]),
#         "sloss"            : _z(sloss,             *n["sloss"]),
#         "dloss"            : _z(dloss,             *n["dloss"]),
#         "sinpkt"           : _z(sinpkt,            *n["sinpkt"]),
#         "dinpkt"           : _z(dinpkt,            *n["dinpkt"]),
#         "sjit"             : _z(sjit,              *n["sjit"]),
#         "djit"             : _z(djit,              *n["djit"]),
#         "swin"             : _z(swin,              *n["swin"]),
#         "stcpb"            : _z(stcpb,             *n["stcpb"]),
#         "dtcpb"            : _z(dtcpb,             *n["dtcpb"]),
#         "dwin"             : _z(dwin,              *n["dwin"]),
#         "tcprtt"           : _z(tcprtt,            *n["tcprtt"]),
#         "synack"           : _z(synack,            *n["synack"]),
#         "ackdat"           : _z(ackdat,            *n["ackdat"]),
#         "smean"            : _z(smean,             *n["smean"]),
#         "dmean"            : _z(dmean,             *n["dmean"]),
#         "trans_depth"      : _z(trans_depth,       *n["trans_depth"]),
#         "response_body_len": _z(response_body_len, *n["response_body_len"]),
#         "ct_srv_src"       : _z(ct_srv_src,        *n["ct_srv_src"]),
#         "ct_state_ttl"     : _z(ct_state_ttl,      *n["ct_state_ttl"]),
#         "ct_dst_ltm"       : _z(ct_dst_ltm,        *n["ct_dst_ltm"]),
#         "ct_src_dport_ltm" : _z(ct_src_dport_ltm,  *n["ct_src_dport_ltm"]),
#         "ct_dst_sport_ltm" : _z(ct_dst_sport_ltm,  *n["ct_dst_sport_ltm"]),
#         "ct_dst_src_ltm"   : _z(ct_dst_src_ltm,    *n["ct_dst_src_ltm"]),
#         "is_ftp_login"     : is_ftp_login,
#         "ct_ftp_cmd"       : ct_ftp_cmd,
#         "ct_flw_http_mthd" : _z(ct_flw_http_mthd,  *n["trans_depth"]),
#         "ct_src_ltm"       : _z(ct_src_ltm,        *n["ct_src_ltm"]),
#         "ct_srv_dst"       : _z(ct_srv_dst,        *n["ct_srv_dst"]),
#         "is_sm_ips_ports"  : is_sm_ips_ports,
#         # categorical (for one-hot encoding in vector builder)
#         "_proto"   : proto,
#         "_service" : service,
#         "_state"   : state,
#         "_src_ip"  : src_ip,
#         "_dst_ip"  : dst_ip,
#         "_src_port": src_port,
#         "_dst_port": dst_port,
#         # raw values for display only
#         "_raw": {
#             "dur":dur, "sbytes":int(sbytes), "dbytes":int(dbytes),
#             "spkts":int(spkts), "dpkts":int(dpkts),
#             "sttl":int(sttl),   "dttl":int(dttl),
#             "state":state,      "service":service,
#         },
#     }
#     return feat

# # ── Feature dict → numpy vector ───────────────────────────────────────────────

# def _to_vector(feat, feat_cols, dim):
#     vec     = np.zeros(dim, dtype=np.float32)
#     proto   = feat.get("_proto",   "tcp")
#     service = feat.get("_service", "-")
#     state   = feat.get("_state",   "CON")

#     if feat_cols:
#         for i, col in enumerate(feat_cols):
#             if i >= dim: break
#             if   col in feat:              vec[i] = float(feat[col])
#             elif col.startswith("proto_"): vec[i] = 1.0 if col=="proto_{}".format(proto)   else 0.0
#             elif col.startswith("service_"):vec[i]= 1.0 if col=="service_{}".format(service)else 0.0
#             elif col.startswith("state_"): vec[i] = 1.0 if col=="state_{}".format(state)   else 0.0
#     else:
#         ordered = [
#             "dur","spkts","dpkts","sbytes","dbytes","rate",
#             "sttl","dttl","sload","dload","sloss","dloss",
#             "sinpkt","dinpkt","sjit","djit",
#             "swin","stcpb","dtcpb","dwin","tcprtt","synack","ackdat",
#             "smean","dmean","trans_depth","response_body_len",
#             "ct_srv_src","ct_state_ttl","ct_dst_ltm",
#             "ct_src_dport_ltm","ct_dst_sport_ltm","ct_dst_src_ltm",
#             "is_ftp_login","ct_ftp_cmd","ct_flw_http_mthd",
#             "ct_src_ltm","ct_srv_dst","is_sm_ips_ports",
#         ]
#         idx = 0
#         for col in ordered:
#             if idx < dim: vec[idx] = float(feat.get(col,0.0)); idx+=1
#         for p in ["tcp","udp","icmp","arp","ospf","other"]:
#             if idx < dim: vec[idx] = 1.0 if p==proto else 0.0; idx+=1
#         for s in ["-","dhcp","dns","ftp","ftp-data","http","irc",
#                   "pop3","radius","smtp","snmp","ssh","ssl","other"]:
#             if idx < dim: vec[idx] = 1.0 if s==service else 0.0; idx+=1
#         for st in ["CON","ECO","FIN","INT","PAR","REQ","RST","other"]:
#             if idx < dim: vec[idx] = 1.0 if st==state else 0.0; idx+=1

#     return vec.reshape(1,-1)

# # ── conn.log tailer ───────────────────────────────────────────────────────────

# def _tail_conn_log(paths, predictor, result_queue, stop_event):
#     conn_path = paths["conn"]
#     if not os.path.exists(conn_path):
#         print("[zeek] WARNING: conn.log not found: {}".format(conn_path))
#         print("       Start Zeek in WSL:  sudo /opt/zeek/bin/zeek -C -i eth0")
#         return

#     print("[zeek] Tailing  : {}".format(conn_path))
#     print("[zeek] DNS log  : {}".format(paths["dns"]))
#     print("[zeek] HTTP log : {}".format(paths["http"]))

#     dns_index   = _build_dns_index(paths["dns"])
#     http_index  = _build_http_index(paths["http"])
#     conn_counts = {}
#     last_dns    = time.time()
#     last_http   = time.time()
#     fields      = []
#     dim         = predictor._dim or 194
#     feat_cols   = predictor._feat_cols

#     try:
#         fh  = open(conn_path,"r",errors="replace")
#         pos = fh.seek(0,2)
#     except Exception as e:
#         print("[zeek] Cannot open conn.log: {}".format(e)); return

#     while not stop_event.is_set():
#         line = fh.readline()

#         if not line:
#             now = time.time()
#             if now - last_dns  > DNS_REFRESH_SEC:
#                 dns_index  = _build_dns_index(paths["dns"]);  last_dns  = now
#             if now - last_http > HTTP_REFRESH_SEC:
#                 http_index = _build_http_index(paths["http"]); last_http = now
#             try:
#                 if os.path.getsize(conn_path) < pos:
#                     fh.close(); fh=open(conn_path,"r",errors="replace")
#                     pos=0; fields=[]
#                     print("[zeek] conn.log rotated — reopened.")
#             except OSError: pass
#             time.sleep(POLL_INTERVAL)
#             continue

#         pos  = fh.tell()
#         line = line.strip()
#         if line.startswith("#fields"):
#             fields = line.split("\t")[1:]; continue
#         if line.startswith("#") or not fields: continue
#         parts = line.split("\t")
#         if len(parts) < len(fields): continue

#         row  = dict(zip(fields, parts))
#         feat = _conn_to_features(row, dns_index, http_index, conn_counts)
#         raw  = feat.pop("_raw", {})

#         try:
#             vec      = _to_vector(feat, feat_cols, dim)
#             recon    = predictor._ae.predict(vec, verbose=0)
#             ae_mse   = float(np.mean((vec - recon) ** 2))
#             ae_label = 1 if ae_mse > predictor._threshold else 0

#             alert = {
#                 "timestamp": row.get("ts",""),
#                 "src_ip"   : feat.get("_src_ip",""),
#                 "dst_ip"   : feat.get("_dst_ip",""),
#                 "src_port" : feat.get("_src_port",0),
#                 "dst_port" : feat.get("_dst_port",0),
#                 "proto"    : feat.get("_proto","").upper(),
#                 "service"  : raw.get("service","-"),
#                 "state"    : raw.get("state",""),
#                 "msg"      : "Zeek: {} {} dur={:.4f}s {}B→{}B".format(
#                                  feat.get("_proto","").upper(),
#                                  feat.get("_state",""),
#                                  raw.get("dur",0),
#                                  raw.get("sbytes",0),
#                                  raw.get("dbytes",0)),
#                 "category" : "",
#                 "source"   : "Zeek",
#                 "dur"      : raw.get("dur",0),
#                 "sbytes"   : raw.get("sbytes",0),
#                 "dbytes"   : raw.get("dbytes",0),
#                 "spkts"    : raw.get("spkts",0),
#                 "dpkts"    : raw.get("dpkts",0),
#                 "sttl"     : raw.get("sttl",64),
#                 "dttl"     : raw.get("dttl",64),
#             }
#             result = {
#                 "ann_label": None,
#                 "ann_conf" : None,
#                 "ae_label" : ae_label,
#                 "ae_mse"   : round(ae_mse, 6),
#                 "threshold": round(predictor._threshold, 6),
#                 "combined" : ae_label,
#                 "source"   : "AE(Zeek)",
#             }
#             result_queue.put(("zeek", alert, result))

#         except Exception as ex:
#             print("[zeek] AE inference error: {}".format(ex))

#     fh.close()
#     print("[zeek] Monitor stopped.")

# # ── Public start function ─────────────────────────────────────────────────────

# def start_zeek_monitor(predictor, result_queue, wsl_user, stop_event=None):
#     """
#     Start the Zeek monitor as a background daemon thread.

#     Args:
#         predictor    : loaded AIPredictor instance
#         result_queue : queue.Queue shared with suricata_monitor
#         wsl_user     : WSL username (auto-detected by monitor_manager)
#         stop_event   : threading.Event (created if None)

#     Returns:
#         (thread, stop_event)
#     """
#     if stop_event is None:
#         stop_event = threading.Event()
#     paths  = wsl_log_paths(wsl_user)
#     thread = threading.Thread(
#         target=_tail_conn_log,
#         args=(paths, predictor, result_queue, stop_event),
#         name="ZeekMonitor",
#         daemon=True,
#     )
#     thread.start()
#     return thread, stop_event