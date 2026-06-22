"""
main.py  —  IDS Final: Train → Evaluate → Real-Time Monitor
============================================================
Single command does everything:
  Phase 1  Train ANN + Autoencoder on UNSW-NB15 + SMOTE
  Phase 2  Evaluate and save reports/plots
  Phase 3  Real-time Snort monitoring with trained models

USAGE:
  python main.py                    # train then monitor (simulate)
  python main.py --no-monitor       # train + evaluate only
  python main.py --skip-training    # monitor only (models must exist)
  python main.py --live --iface 5   # live Snort on interface 5 (Admin)
"""
import os, sys, json, time, signal, threading, argparse, warnings, platform
warnings.filterwarnings("ignore")

_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_ROOT, "src"))

import numpy as np
import tensorflow as tf
tf.get_logger().setLevel("ERROR")
np.random.seed(42); tf.random.set_seed(42)

from load_data         import load_datasets
from preprocess        import preprocess
from smote_processing  import apply_smote
from ann_model         import train_ann, predict_ann, load_ann
from autoencoder_model import train_autoencoder, predict_autoencoder, load_autoencoder
from evaluate          import (compute_metrics, save_report,
                               plot_confusion_matrices, plot_learning_curves,
                               plot_reconstruction_errors, compare_models)
from snort_monitor     import SnortMonitor
from ai_predictor      import AIPredictor

LOG_DIR  = os.path.join(_ROOT, "logs")
PRED_LOG = os.path.join(LOG_DIR, "predictions.jsonl")
os.makedirs(LOG_DIR, exist_ok=True)

R="\033[91m"; G="\033[92m"; Y="\033[93m"; C="\033[96m"
D="\033[2m";  B="\033[1m";  E="\033[0m"
def c(t,x): return x+t+E
def banner(s,w=66): print("\n"+"="*w+"\n  "+s+"\n"+"="*w)

CONFIG = dict(ANN_EPOCHS=60, AE_EPOCHS=60, BATCH=512, SAVE=True, N=40)


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 1+2 — TRAINING + EVALUATION
# ══════════════════════════════════════════════════════════════════════════════
def run_training():
    print(c("""
╔══════════════════════════════════════════════════════════════╗
║     IDS FINAL  —  PHASE 1: TRAINING + EVALUATION           ║
║   UNSW-NB15  →  SMOTE  →  ANN + AE  →  Reports            ║
╚══════════════════════════════════════════════════════════════╝
""", C))
    banner("STEP 1 — Load datasets")
    df_tr, df_te = load_datasets()

    banner("STEP 2 — Preprocess  (saves scaler_params.npy + feature_columns.npy)")
    data = preprocess(df_tr, df_te)
    X_tr = data["X_train"]; X_te = data["X_test"]
    y_tr = data["y_train_bin"]; y_te = data["y_test_bin"]
    y_tc = data["y_test_cat"]; cls  = data["attack_classes"]
    fc   = data["feature_columns"]

    banner("STEP 3 — SMOTE  (training only)")
    X_bal, y_bal = apply_smote(X_tr, y_tr, feature_columns=fc)

    banner("STEP 4 — Train ANN on SMOTE-balanced data")
    ann, ann_h = train_ann(X_bal, y_bal,
                           epochs=CONFIG["ANN_EPOCHS"],
                           batch_size=CONFIG["BATCH"],
                           save=CONFIG["SAVE"])

    banner("STEP 5 — Train Autoencoder (normal traffic only)")
    ae, ae_h, ae_thr = train_autoencoder(X_tr, y_tr,
                                         epochs=CONFIG["AE_EPOCHS"],
                                         batch_size=CONFIG["BATCH"],
                                         save=CONFIG["SAVE"])

    banner("STEP 6 — Evaluate")
    ypa, proba = predict_ann(ann, X_te)
    am = compute_metrics(y_te, ypa)
    save_report("ann", am, y_te, ypa,
                extra="ANN  |  SMOTE-balanced  |  Threshold 0.5")

    ype, errs = predict_autoencoder(ae, X_te, ae_thr)
    em = compute_metrics(y_te, ype)
    save_report("autoencoder", em, y_te, ype,
                extra="Autoencoder  |  normal-only training  |  "
                      "threshold {:.6f}".format(ae_thr))

    banner("STEP 7 — Save plots")
    plot_confusion_matrices(am["confusion_matrix"], em["confusion_matrix"])
    plot_learning_curves(ann_h, ae_h)
    plot_reconstruction_errors(errs, y_te, ae_thr)
    compare_models(am, em)

    # Print sample predictions
    import pandas as pd
    lm={0:"Normal",1:"Attack"}
    rows=[{"Actual":lm[int(y_te[i])],"Category":cls[int(y_tc[i])],
           "ANN":lm[int(ypa[i])],"Conf":"{:.3f}".format(float(proba[i])),
           "AE":lm[int(ype[i])],"MSE":"{:.5f}".format(float(errs[i])),
           "ANN_OK":"OK" if y_te[i]==ypa[i] else "MISS",
           "AE_OK":"OK"  if y_te[i]==ype[i] else "MISS"}
          for i in range(min(CONFIG["N"],len(y_te)))]
    df=pd.DataFrame(rows)
    pd.set_option("display.max_columns",None)
    pd.set_option("display.width",160)
    print("\n  Sample predictions (first {} rows):\n".format(CONFIG["N"]))
    print(df.to_string(index=True))

    print(c("\n  TRAINING COMPLETE. Models saved to models/\n", G))
    return ann, ae, ae_thr


# ══════════════════════════════════════════════════════════════════════════════
#  PHASE 3 — REAL-TIME MONITORING
# ══════════════════════════════════════════════════════════════════════════════
def run_monitor(ann_model, ae_model, ae_thr, simulate, iface):
    print(c("""
╔══════════════════════════════════════════════════════════════╗
║     IDS FINAL  —  PHASE 3: REAL-TIME SNORT MONITORING      ║
║   Snort  →  Feature extraction  →  ANN + AE  →  Verdict    ║
╚══════════════════════════════════════════════════════════════╝
""", C))

    # Load predictor
    pred = AIPredictor()
    pred.load(ann_model=ann_model, ae_model=ae_model, threshold=ae_thr)

    # Start Snort monitor
    mon = SnortMonitor(interface=iface, simulate=simulate)
    mon.start()

    mode = "SIMULATE" if simulate else "LIVE interface {}".format(iface)
    print(c("  Mode      : {}".format(mode), C))
    print(c("  Threshold : {:.6f}".format(pred._threshold), C))
    print(c("  Press Ctrl-C to stop\n", Y))

    stats  = dict(total=0, atk=0, nrm=0)
    stop   = threading.Event()

    def _shutdown(sig=None, frame=None):
        stop.set(); mon.stop()
        print(c("\n  Stopped — Total:{} Attacks:{} Normal:{}".format(
            stats["total"], stats["atk"], stats["nrm"]), Y))
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print("{:<9} {:<28} {:<40} {}".format("TIME","VERDICT","SNORT ALERT","ANN | AE"))
    print("─" * 105)

    while not stop.is_set():
        alert = mon.get_alert(timeout=0.4)
        if not alert: continue

        result = pred.predict(alert)
        stats["total"] += 1
        if result["combined"]:
            stats["atk"] += 1
        else:
            stats["nrm"] += 1

        _log(alert, result)
        _print_row(alert, result)


def _log(a, r):
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(PRED_LOG, "a") as f:
        f.write(json.dumps({
            "ts":a.get("ts"), "src":"{}:{}".format(a.get("src_ip"),a.get("src_port")),
            "dst":"{}:{}".format(a.get("dst_ip"),a.get("dst_port")),
            "proto":a.get("proto"), "msg":a.get("msg"),
            "ann":r["ann_label"], "conf":r["ann_conf"],
            "ae":r["ae_label"], "mse":r["ae_mse"],
            "verdict":"ATTACK" if r["combined"] else "NORMAL",
            "category":a.get("category",""),
        })+"\n")


def _print_row(a, r):
    is_atk = r["combined"]
    ts  = a.get("ts","")
    msg = a.get("msg","")[:38]
    cat = a.get("category","")
    ann = c("ATTACK",R) if r["ann_label"] else c("normal",G)
    ae  = c("ANOMALY",R) if r["ae_label"] else c("normal",G)
    st  = c("▶ ATTACK [{:<14}]".format(cat), R+B) if is_atk else c("✓ NORMAL", G)
    print("{} {} | {:<40} | ANN:{} ({:.0f}%)  AE:{} (MSE {:.4f})".format(
        c(ts,D), st, c(msg, Y if is_atk else D),
        ann, r["ann_conf"]*100, ae, r["ae_mse"]))


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    p = argparse.ArgumentParser(description="IDS Final — Train + Monitor")
    p.add_argument("--skip-training", action="store_true",
                   help="Skip training, load saved models")
    p.add_argument("--no-monitor", action="store_true",
                   help="Train and evaluate only, do not start monitor")
    p.add_argument("--live", action="store_true",
                   help="Use live Snort (requires Admin + Snort installed)")
    p.add_argument("--iface", default="5",
                   help="Snort interface index (default 5 = Intel Wi-Fi 6E)")
    args = p.parse_args()

    simulate = not args.live
    ann = ae = thr = None

    if not args.skip_training:
        ann, ae, thr = run_training()
    else:
        print(c("[main] Loading saved models from models/ ...", Y))
        try:
            ann = load_ann()
            ae, thr = load_autoencoder()
            print(c("[main] Models loaded OK.", G))
        except FileNotFoundError as e:
            print(c("[ERROR] {}".format(e), R))
            print("Run without --skip-training first to train the models.")
            sys.exit(1)

    if args.no_monitor:
        print(c("[main] --no-monitor: done.", Y))
        return

    print(c("\n[main] Starting real-time monitor ...", C))
    time.sleep(0.5)
    run_monitor(ann, ae, thr, simulate, args.iface)


if __name__ == "__main__":
    main()