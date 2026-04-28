import json
from datetime import datetime
import requests
from collections import defaultdict

# 🌍 Get location from IP
def get_location(ip):
    try:
        if ip == "cloudtrail.amazonaws.com":
            return "AWS Internal Service"
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        return f"{res.get('country', 'Unknown')}, {res.get('city', 'Unknown')}"
    except:
        return "Unknown"

# 🕒 Convert UTC time
def convert_time(utc_time):
    try:
        dt = datetime.strptime(utc_time, "%Y-%m-%dT%H:%M:%SZ")
        return dt.strftime("%d-%m-%Y %H:%M:%S")
    except:
        return utc_time

def analyze_log_file(file_path):
    print("\n🔍 Analyzing CloudTrail Logs...\n")

    ip_count = defaultdict(int)

    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        print("❌ ERROR: Log file not found → Check file location")
        return
    except json.JSONDecodeError:
        print("❌ ERROR: Invalid JSON format")
        return

    records = data.get("Records", [])

    # ✅ Dependency Monitoring
    if not records:
        print("❌ ERROR: No logs found → CloudTrail may not be generating logs")
        return

    for event in records:

        # Dependency / Integrity checks
        if "eventTime" not in event:
            print("⚠️ Missing eventTime → log integrity issue")

        if "sourceIPAddress" not in event:
            print("⚠️ Missing IP → incomplete log")

        ip = event.get("sourceIPAddress", "Unknown")
        time = convert_time(event.get("eventTime", ""))
        user = event.get("userIdentity", {}).get("type", "Unknown")
        mfa = event.get("userIdentity", {}).get("sessionContext", {}) \
                   .get("attributes", {}).get("mfaAuthenticated", "false")

        location = get_location(ip)

        ip_count[ip] += 1

        # 🚨 Alerts
        if ip not in ["cloudtrail.amazonaws.com"]:
            print(f"🚨 ALERT: Access from IP {ip}")
            print(f"   📍 Location: {location}")
            print(f"   🕒 Time: {time}")

        if user == "Root":
            print(f"⚠️ WARNING: Root account used at {time}")

        if user == "Root" and mfa == "false":
            print(f"❌ CRITICAL: Root login WITHOUT MFA at {time}")

        print("-" * 50)

    # 📊 IP activity summary
    print("\n📊 Checking for repeated IP activity...\n")
    for ip, count in ip_count.items():
        if count > 5:
            print(f"⚠️ WARNING: IP {ip} made {count} requests")

    print("\n✅ Analysis Complete.\n")


# ▶ Run the script
analyze_log_file("cloudtrail_log.json")