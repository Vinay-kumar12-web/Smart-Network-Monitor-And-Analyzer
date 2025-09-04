# app.py
from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_file
import threading
import time
import network_monitor as nm  # ensure same folder
import socket
import io, csv
import pandas as pd  # for Excel export
from reportlab.platypus import SimpleDocTemplate, Paragraph
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)
app.secret_key = "replace_this_with_a_better_secret_key"

# Global snapshot
DATA = {
    "usage": {},     # usage_by_ip (KB)
    "devices": [],   # list of device dicts
    "alerts": [],
    "timestamp": None,
    "error": None
}

THRESHOLD_KB = 5
lock = threading.Lock()

# ---- helper
def require_auth():
    return "user" in session

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        # hardcoded admin (change or migrate to DB later)
        if u == "admin" and p == "admin123":
            session["user"] = u
            return redirect(url_for("home"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html", error=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.before_request
def protect_routes():
    # allow login and static files
    if request.endpoint in ("login","static"):
        return
    if not require_auth():
        return redirect(url_for("login"))

# capture action (manual)
def do_capture():
    global DATA
    try:
        usage, devices, alerts = nm.run_capture(threshold_kb=THRESHOLD_KB)
        with lock:
            DATA["usage"] = usage
            DATA["devices"] = devices
            DATA["alerts"] = alerts
            DATA["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
            DATA["error"] = None
    except Exception as e:
        with lock:
            DATA["error"] = str(e)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/data")
def data():
    ipq = request.args.get("ip", "").strip()
    domq = request.args.get("domain", "").strip().lower()
    macq = request.args.get("mac", "").strip().lower()
    hostq = request.args.get("host", "").strip().lower()

    with lock:
        snapshot = {
            "usage": dict(DATA["usage"]),
            "devices": list(DATA["devices"]),
            "alerts": list(DATA["alerts"]),
            "timestamp": DATA.get("timestamp"),
            "error": DATA.get("error")
        }

    if ipq:
        snapshot["usage"] = {k:v for k,v in snapshot["usage"].items() if ipq in k}
        snapshot["devices"] = [d for d in snapshot["devices"] if ipq in d.get("ip","")]
        snapshot["alerts"] = [a for a in snapshot["alerts"] if ipq in a]

    if domq:
        snapshot["devices"] = [d for d in snapshot["devices"] if any(domq in (dm.lower()) for dm in d.get("domains",[]))]
        snapshot["alerts"] = [a for a in snapshot["alerts"] if domq in a.lower()]

    if macq:
        snapshot["devices"] = [d for d in snapshot["devices"] if macq in d.get("mac","").lower()]

    if hostq:
        snapshot["devices"] = [d for d in snapshot["devices"] if hostq in d.get("hostname","").lower()]

    return jsonify(snapshot)

@app.route("/capture", methods=["POST"])
def capture_endpoint():
    do_capture()
    return jsonify({"ok": True, "timestamp": DATA.get("timestamp")})

@app.route("/set-threshold", methods=["POST"])
def set_threshold():
    global THRESHOLD_KB
    try:
        val = request.json.get("threshold")
        THRESHOLD_KB = int(val) if val is not None else THRESHOLD_KB
        return jsonify({"ok": True, "threshold_kb": THRESHOLD_KB})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# ---------------- New Routes ----------------

@app.route("/export")
def export_data():
    etype = request.args.get("type","csv")
    with lock:
        devices = list(DATA["devices"])

    if etype=="csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["ip","mac","hostname","usage_kb","domains"])
        writer.writeheader()
        for d in devices:
            writer.writerow({
                "ip": d.get("ip"),
                "mac": d.get("mac"),
                "hostname": d.get("hostname"),
                "usage_kb": d.get("usage_kb"),
                "domains": ",".join(d.get("domains",[]))
            })
        mem = io.BytesIO(output.getvalue().encode("utf-8"))
        return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="devices.csv")

    elif etype=="xlsx":
        df = pd.DataFrame(devices)
        mem = io.BytesIO()
        df.to_excel(mem, index=False)
        mem.seek(0)
        return send_file(mem, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                         as_attachment=True, download_name="devices.xlsx")

    elif etype=="pdf":
        mem = io.BytesIO()
        doc = SimpleDocTemplate(mem)
        styles = getSampleStyleSheet()
        flow = [Paragraph("Devices Report", styles["Heading1"])]
        for d in devices:
            flow.append(Paragraph(f"{d.get('ip')} - {d.get('hostname')} ({d.get('usage_kb')} KB)", styles["Normal"]))
        doc.build(flow)
        mem.seek(0)
        return send_file(mem, mimetype="application/pdf", as_attachment=True, download_name="devices.pdf")

    return jsonify({"ok": False, "error": "unsupported type"})

@app.route("/block")
def block_device():
    ip = request.args.get("ip")
    # TODO: actually run firewall/iptables command
    return jsonify({"ok": True, "msg": f"Device {ip} blocked (simulation)"})

@app.route("/rename")
def rename_device():
    ip = request.args.get("ip")
    name = request.args.get("name")
    with lock:
        for d in DATA["devices"]:
            if d["ip"] == ip:
                d["hostname"] = name
    return jsonify({"ok": True, "msg": f"Device {ip} renamed to {name}"})

@app.route("/trust")
def trust_device():
    ip = request.args.get("ip")
    with lock:
        for d in DATA["devices"]:
            if d["ip"] == ip:
                d["trusted"] = True
    return jsonify({"ok": True, "msg": f"Device {ip} marked trusted"})
# --------------------------------------------

if __name__ == "__main__":
    print("🚀 Smart Network Monitor running at http://127.0.0.1:5000")
    app.run(debug=True)
