"""
server.py  —  IDS Final Web Server
Dashboard HTML is fully embedded — no external files needed.

USAGE:
  python main.py --no-monitor     # train first (once)
  python server.py                # start server, browser opens automatically
  python server.py --live --iface 5   # live Snort (Admin required)
"""
import os,sys,json,threading,argparse,webbrowser
_ROOT=os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0,os.path.join(_ROOT,"src"))
import numpy as np
try:
    from flask import Flask,jsonify
    from flask_socketio import SocketIO,emit
except ImportError:
    sys.exit("\n[ERROR] Run: pip install flask flask-socketio eventlet\n")
from snort_monitor import SnortMonitor
from ai_predictor  import AIPredictor
from ann_model     import load_ann
from autoencoder_model import load_autoencoder

app=Flask(__name__)
socketio=SocketIO(app,cors_allowed_origins="*",async_mode="threading")
state=dict(running=False,simulate=True,iface="5",total=0,attacks=0,normal=0,
           monitor=None,predictor=None,stop_evt=threading.Event())

DASHBOARD_HTML=open(os.path.join(os.path.dirname(os.path.abspath(__file__)),"dashboard_live.html"),encoding="utf-8").read() if os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)),"dashboard_live.html")) else "<h1>dashboard_live.html not found</h1>"

@app.route("/")
def index():
    return DASHBOARD_HTML

@app.route("/status")
def status_route():
    pred=state["predictor"]
    return jsonify({"running":state["running"],"total":state["total"],
        "attacks":state["attacks"],"normal":state["normal"],
        "threshold":round(pred._threshold,6) if pred else 0,
        "models_ok":pred._ready if pred else False})

@socketio.on("connect")
def on_connect():
    pred=state["predictor"]
    emit("system_status",{"models_ok":pred._ready if pred else False,
        "threshold":round(pred._threshold,6) if pred else 0})
    print("[server] Browser connected.")

@socketio.on("disconnect")
def on_disconnect(): print("[server] Browser disconnected.")

@socketio.on("start_monitor")
def on_start(data):
    if state["running"]: return
    simulate=data.get("simulate",state["simulate"]) if "simulate" in data else state["simulate"]
    iface=data.get("iface",state["iface"])
    state.update(running=True,simulate=simulate,iface=iface)
    state["stop_evt"].clear()
    threading.Thread(target=_loop,args=(simulate,iface),daemon=True).start()
    emit("monitor_started",{"mode":"SIMULATE" if simulate else "LIVE iface={}".format(iface)})

@socketio.on("stop_monitor")
def on_stop(data=None):
    state["running"]=False; state["stop_evt"].set()
    if state["monitor"]: state["monitor"].stop()
    emit("monitor_stopped",{"total":state["total"],"attacks":state["attacks"],"normal":state["normal"]})

@socketio.on("clear_stats")
def on_clear(data=None):
    state["total"]=state["attacks"]=state["normal"]=0
    emit("stats_cleared")

def _loop(simulate,iface):
    mon=SnortMonitor(interface=iface,simulate=simulate)
    pred=state["predictor"]; state["monitor"]=mon; mon.start()
    socketio.emit("terminal",{"cls":"in","msg":"Snort started — "+("SIMULATE" if simulate else "LIVE iface={}".format(iface))})
    while state["running"] and not state["stop_evt"].is_set():
        alert=mon.get_alert(timeout=0.3)
        if not alert: continue
        result=pred.predict(alert)
        state["total"]+=1
        if result["combined"]: state["attacks"]+=1
        else: state["normal"]+=1
        payload={"ts":alert.get("ts",""),"src_ip":alert.get("src_ip",""),
            "src_port":alert.get("src_port",0),"dst_ip":alert.get("dst_ip",""),
            "dst_port":alert.get("dst_port",0),"proto":alert.get("proto","TCP"),
            "msg":alert.get("msg",""),"priority":alert.get("priority",3),
            "category":alert.get("category",""),"ann_label":result["ann_label"],
            "ann_conf":result["ann_conf"],"ae_label":result["ae_label"],
            "ae_mse":result["ae_mse"],"threshold":result["threshold"],
            "combined":result["combined"],"source":result["source"],
            "total":state["total"],"attacks":state["attacks"],"normal":state["normal"]}
        socketio.emit("new_alert",payload)
        if result["combined"]:
            socketio.emit("terminal",{"cls":"er","msg":"ATTACK [{}] {} | ANN:{:.0f}% | MSE={:.4f}".format(
                alert.get("category",""),alert.get("msg","")[:38],result["ann_conf"]*100,result["ae_mse"])})
        elif state["total"]%4==0:
            socketio.emit("terminal",{"cls":"ok","msg":"normal  {} | ANN:{:.0f}% | MSE={:.4f}".format(
                alert.get("msg","")[:38],result["ann_conf"]*100,result["ae_mse"])})
        os.makedirs(os.path.join(_ROOT,"logs"),exist_ok=True)
        with open(os.path.join(_ROOT,"logs","predictions.jsonl"),"a") as f:
            f.write(json.dumps({"ts":alert.get("ts"),"msg":alert.get("msg"),
                "ann":result["ann_label"],"conf":result["ann_conf"],
                "ae":result["ae_label"],"mse":result["ae_mse"],
                "verdict":"ATTACK" if result["combined"] else "NORMAL",
                "cat":alert.get("category","")})+"\n")
    mon.stop()

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--port",type=int,default=5000)
    p.add_argument("--host",default="127.0.0.1")
    p.add_argument("--live",action="store_true")
    p.add_argument("--iface",default="5")
    p.add_argument("--no-open",action="store_true")
    args=p.parse_args()
    state["simulate"]=not args.live; state["iface"]=args.iface
    print("[server] Loading AI models...")
    pred=AIPredictor()
    try:
        ann=load_ann(); ae,thr=load_autoencoder()
        pred.load(ann_model=ann,ae_model=ae,threshold=thr)
    except FileNotFoundError:
        print("[server] Models not found — run 'python main.py --no-monitor' first.")
        pred.load()
    state["predictor"]=pred
    # read dashboard at runtime
    global DASHBOARD_HTML
    dash=os.path.join(_ROOT,"dashboard_live.html")
    if os.path.exists(dash):
        with open(dash,encoding="utf-8") as f: DASHBOARD_HTML=f.read()
    url="http://{}:{}".format(args.host,args.port)
    print("\n[server] Dashboard: {}\n[server] Ctrl-C to stop.\n".format(url))
    if not args.no_open: threading.Timer(1.5,lambda:webbrowser.open(url)).start()
    socketio.run(app,host=args.host,port=args.port,debug=False,use_reloader=False)

if __name__=="__main__": main()