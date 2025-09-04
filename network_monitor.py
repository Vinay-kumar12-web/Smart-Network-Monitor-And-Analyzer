import subprocess
import re
from collections import defaultdict
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket
import requests
import csv
import pandas as pd   # for Excel export
from fpdf import FPDF # for PDF export

# ====== CONFIG ======
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"   # update if needed
INTERFACE = "Wi-Fi"             # hotspot interface name (check with: tshark -D)
CAPTURE_TIME = 5                # seconds (capture duration)
THRESHOLD_KB = 5                # threshold in KB for alert emails

SENDER_EMAIL = "rkyadavpvs512@gmail.com"
APP_PASSWORD = "vhxzwdequmnlwjiy"
RECEIVER_EMAIL = "rkyadavpvs512@gmail.com"

# ====== EXTRA STORAGE ======
ALERT_HISTORY = []
DEVICE_NAMES = {}      # ip -> custom name
TRUSTED_DEVICES = set()

# ====== ALERT SYSTEM ======
def send_email_alert(ip, usage_kb):
    subject = "🚨 Network Usage Alert"
    body = f"Device {ip} has used {usage_kb:.2f} KB which exceeded threshold ({THRESHOLD_KB} KB)."

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print("📩 Email alert sent successfully!")
    except Exception as e:
        print("❌ Failed to send email:", e)


# ====== HELPERS ======
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"

def is_device_online(ip):
    try:
        output = subprocess.check_output(f"ping -n 1 {ip}", shell=True).decode()
        return "TTL=" in output
    except:
        return False

def get_geo(ip):
    """
    Return dict with {city, country, lat, lon}.
    For local IPs, put 0,0 coordinates and Local Network label.
    """
    try:
        if ip.startswith(("192.168.", "10.", "172.")):
            return {"city": "Local Network", "country": "", "lat": 0, "lon": 0}
        res = requests.get(f"http://ipinfo.io/{ip}/json", timeout=3).json()
        loc = res.get("loc", "0,0").split(",")
        return {
            "city": res.get("city", "Unknown"),
            "country": res.get("country", ""),
            "lat": float(loc[0]),
            "lon": float(loc[1])
        }
    except:
        return {"city": "Unknown", "country": "", "lat": 0, "lon": 0}

def get_connected_devices():
    devices = []
    try:
        output = subprocess.check_output("arp -a", shell=True).decode(errors="ignore")
        for line in output.splitlines():
            if "dynamic" in line or "static" in line:
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[0]
                    mac = parts[1]
                    hostname = get_hostname(ip)
                    devices.append({
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname,
                        "domains": [],
                        "usage_kb": 0.0
                    })
    except Exception as e:
        print("⚠️ Could not fetch ARP table:", e)
    return devices


# ====== FILTERS ======
def filter_real_devices(devices):
    filtered = []
    for d in devices:
        ip = d["ip"]
        if ip.startswith(("224.", "239.", "255.")):
            continue
        if d["mac"].lower() in [
            "ff-ff-ff-ff-ff-ff", "01-00-5e-00-00-02",
            "01-00-5e-00-00-16", "01-00-5e-00-00-fb",
            "01-00-5e-00-00-fc", "01-00-5e-7f-ff-fa"
        ]:
            continue
        filtered.append(d)
    return filtered

def filter_lan_only(devices):
    filtered = []
    for d in devices:
        ip = d["ip"]
        if ip.startswith(("10.", "172.", "192.168.")):
            filtered.append(d)
    return filtered


# ====== EXPORT DATA ======
def export_data(devices, fmt="csv", filename="network_data"):
    if not devices:
        return None
    if fmt == "csv":
        with open(f"{filename}.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=devices[0].keys())
            writer.writeheader()
            writer.writerows(devices)
        return f"{filename}.csv"
    elif fmt == "excel":
        df = pd.DataFrame(devices)
        df.to_excel(f"{filename}.xlsx", index=False)
        return f"{filename}.xlsx"
    elif fmt == "pdf":
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=10)
        for d in devices:
            pdf.cell(200, 10, txt=str(d), ln=True)
        pdf.output(f"{filename}.pdf")
        return f"{filename}.pdf"
    return None


# ====== DEVICE MANAGEMENT ======
def block_device(ip):
    try:
        subprocess.run(f'netsh advfirewall firewall add rule name="Block {ip}" dir=out action=block remoteip={ip}', shell=True)
        return True
    except:
        return False

def unblock_device(ip):
    try:
        subprocess.run(f'netsh advfirewall firewall delete rule name="Block {ip}"', shell=True)
        return True
    except:
        return False

def rename_device(ip, new_name):
    DEVICE_NAMES[ip] = new_name

def trust_device(ip):
    TRUSTED_DEVICES.add(ip)

def untrust_device(ip):
    TRUSTED_DEVICES.discard(ip)


# ====== BASE CAPTURE ======
def base_run_capture(capture_time=CAPTURE_TIME, threshold_kb=THRESHOLD_KB):
    device_bytes = defaultdict(int)
    domains_by_ip = defaultdict(set)
    alerts = []

    # traffic capture
    try:
        proc = subprocess.Popen(
            [TSHARK_PATH, "-i", INTERFACE, "-a", f"duration:{capture_time}",
             "-T", "fields", "-e", "ip.src", "-e", "frame.len"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        for line in proc.stdout:
            parts = line.strip().split()
            if len(parts) == 2 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                ip, size = parts
                try:
                    device_bytes[ip] += int(size)
                except:
                    continue
    except Exception as e:
        print("❌ Error while capturing frames:", e)

    # DNS capture
    try:
        proc2 = subprocess.Popen(
            [TSHARK_PATH, "-i", INTERFACE, "-a", f"duration:{capture_time}",
             "-Y", "dns.qry.name", "-T", "fields", "-e", "ip.src", "-e", "dns.qry.name"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
        )
        for line in proc2.stdout:
            parts = line.strip().split()
            if len(parts) == 2:
                ip, domain = parts
                if domain:
                    domains_by_ip[ip].add(domain.strip())
    except Exception as e:
        print("⚠️ DNS capture failed:", e)

    # usage summary
    usage_by_ip = {}
    for ip, b in device_bytes.items():
        kb = b / 1024.0
        usage_by_ip[ip] = kb
        if kb > threshold_kb:
            msg = f"⚠️ {ip} exceeded threshold ({kb:.2f} KB > {threshold_kb} KB)"
            alerts.append(msg)
            send_email_alert(ip, kb)

    # merge with devices
    devices = get_connected_devices()
    ip_to_dev = {d["ip"]: d for d in devices}
    for ip, kb in usage_by_ip.items():
        if ip in ip_to_dev:
            ip_to_dev[ip]["usage_kb"] = round(kb, 2)
            ip_to_dev[ip]["domains"] = list(domains_by_ip.get(ip, []))
        else:
            devices.append({
                "ip": ip,
                "mac": "Unknown",
                "hostname": get_hostname(ip),
                "domains": list(domains_by_ip.get(ip, [])),
                "usage_kb": round(kb, 2)
            })

    devices = filter_real_devices(devices)
    devices = filter_lan_only(devices)

    return usage_by_ip, devices, alerts


# ====== FINAL CAPTURE WITH ENHANCEMENTS ======
def run_capture(capture_time=CAPTURE_TIME, threshold_kb=THRESHOLD_KB):
    usage_by_ip, devices, alerts = base_run_capture(capture_time, threshold_kb)
    for d in devices:
        d["online"] = is_device_online(d["ip"])
        d["geo"] = get_geo(d["ip"])   # full dict now
        d["custom_name"] = DEVICE_NAMES.get(d["ip"], d["hostname"])
        d["trusted"] = d["ip"] in TRUSTED_DEVICES
    ALERT_HISTORY.extend(alerts)
    return usage_by_ip, devices, alerts


# ====== TEST RUN ======
if __name__ == "__main__":
    u, devs, a = run_capture()
    print("\nUsage summary (KB):")
    for ip, kb in u.items():
        print(f"  {ip} -> {kb:.2f} KB")

    print("\nDevices:")
    for d in devs:
        geo = d["geo"]
        print(f"  {d['ip']} {d['hostname']} {d['mac']} -> {d['usage_kb']} KB, "
              f"Domains: {d['domains']}, Online: {d['online']}, "
              f"Geo: {geo['city']}, {geo['country']} ({geo['lat']},{geo['lon']})")

    if a:
        print("\nAlerts:")
        for s in a:
            print(" ", s)
