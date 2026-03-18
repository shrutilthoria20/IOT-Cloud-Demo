import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import requests
import datetime
import time
import base64
import json
import ssl

import paho.mqtt.client as mqtt
import firebase_admin
from firebase_admin import credentials, db

from streamlit_autorefresh import st_autorefresh
from streamlit_cookies_manager import EncryptedCookieManager
from streamlit_js_eval import streamlit_js_eval

# ============================================================
# FIREBASE INIT — only for security alert logs
# ============================================================

def init_firebase():
    if not firebase_admin._apps:
        fb = st.secrets["firebase"]
        cred = credentials.Certificate({
            "type":                        fb["type"],
            "project_id":                  fb["project_id"],
            "private_key_id":              fb["private_key_id"],
            "private_key":                 fb["private_key"].replace("\\n", "\n"),
            "client_email":                fb["client_email"],
            "client_id":                   fb["client_id"],
            "auth_uri":                    fb["auth_uri"],
            "token_uri":                   fb["token_uri"],
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": (
                "https://www.googleapis.com/robot/v1/metadata/x509/"
                + fb["client_email"]
            ),
        })
        firebase_admin.initialize_app(cred, {"databaseURL": fb["database_url"]})

init_firebase()

def fb_write_alert(event: dict):
    try:
        db.reference("security_logs").push(event)
    except:
        pass

def fb_get_alerts() -> pd.DataFrame:
    try:
        data = db.reference("security_logs").order_by_key().limit_to_last(200).get()
        if data:
            rows = []
            for _, val in data.items():
                rows.append({
                    "Time":      val.get("timestamp", ""),
                    "Source IP": val.get("source_ip", ""),
                    "Country":   val.get("country", ""),
                    "Username":  val.get("payload", {}).get("username_attempted", ""),
                    "Password":  val.get("payload", {}).get("password_attempted", ""),
                })
            return pd.DataFrame(rows)
    except:
        pass
    return pd.DataFrame()

# ============================================================
# SESSION STATE DEFAULTS
# ============================================================

for k, v in {
    "authenticated": False,
    "unlock_done":   False,
    "menu":          "Main Dashboard",
}.items():
    if k not in st.session_state:
        st.session_state[k] = v

# The proven pattern: one dict in session_state, passed by reference to callbacks
if "data_store" not in st.session_state:
    st.session_state.data_store = {
        "temperature": 0,
        "humidity":    0,
        "motion":      0,
        "connected":   False,
    }

# Local alias — callbacks mutate this dict in-place, Streamlit sees updates on rerun
data_store = st.session_state.data_store

# ============================================================
# MQTT — loop_start() pattern (proven working)
# ============================================================

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("✅ MQTT Connected")
        data_store["connected"] = True
        client.subscribe("iot/sensor")
        client.subscribe("iot/motion")
    else:
        print(f"❌ MQTT Failed rc={rc}")
        data_store["connected"] = False

def on_disconnect(client, userdata, rc):
    data_store["connected"] = False
    print(f"⚠️ MQTT Disconnected rc={rc}")

def on_message(client, userdata, msg):
    try:
        payload = json.loads(msg.payload.decode())
        print(f"[MQTT] {msg.topic} → {payload}")
        if msg.topic == "iot/sensor":
            data_store["temperature"] = payload.get("temperature", 0)
            data_store["humidity"]    = payload.get("humidity",    0)
        elif msg.topic == "iot/motion":
            data_store["motion"] = payload.get("motion", 0)
    except Exception as e:
        print(f"[MQTT] Parse error: {e}")

if "mqtt_started" not in st.session_state:
    cfg = st.secrets["hivemq"]

    client = mqtt.Client(client_id="StreamlitBridge", protocol=mqtt.MQTTv311)
    client.username_pw_set(cfg["user"], cfg["password"])
    client.tls_set(cert_reqs=ssl.CERT_REQUIRED)   # same as your working code

    client.on_connect    = on_connect
    client.on_disconnect = on_disconnect
    client.on_message    = on_message

    client.connect(cfg["server"], int(cfg["port"]))
    client.loop_start()   # paho's own background thread — no manual threading needed

    st.session_state.mqtt_started = True

# ============================================================
# HONEYPOT — brute force → Firebase
# ============================================================

def get_country_from_ip(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if r.get("status") == "success":
            return r["country"]
    except:
        pass
    return "Unknown"

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = {}

def check_bruteforce(ip, username, password):
    attempts = st.session_state.failed_attempts
    attempts[ip] = attempts.get(ip, 0) + 1
    if attempts[ip] >= 5:
        fb_write_alert({
            "timestamp":   datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "source_ip":   ip or "unknown",
            "country":     get_country_from_ip(ip or "0.0.0.0"),
            "attack_type": "Brute Force Login",
            "device_type": "HMI Dashboard",
            "payload": {
                "username_attempted": username,
                "password_attempted": password,
            },
        })
        attempts[ip] = 0

# ============================================================
# COOKIES
# ============================================================

cookies = EncryptedCookieManager(prefix="iot_hmi", password="super_secret_key")
if not cookies.ready():
    st.stop()

if cookies.get("auth") == "true":
    st.session_state.authenticated = True

# ============================================================
# PAGE CONFIG + CSS
# ============================================================

st.set_page_config(page_title="IoT HMI", layout="wide")

if st.session_state.unlock_done:
    st_autorefresh(interval=2000, key="refresh")

st.markdown("""
<style>
@keyframes blink { 0%{opacity:1} 50%{opacity:0} 100%{opacity:1} }
.alarm    { color:red; font-size:28px; font-weight:bold; animation:blink 1s infinite; }
.pill-on  { background:#16a34a; color:#fff; padding:2px 10px; border-radius:999px; font-size:12px; }
.pill-off { background:#dc2626; color:#fff; padding:2px 10px; border-radius:999px; font-size:12px; }
</style>
""", unsafe_allow_html=True)

# ============================================================
# LOGIN
# ============================================================

def get_client_ip():
    return streamlit_js_eval(
        js_expressions="""
            fetch('https://api.ipify.org?format=json')
            .then(r => r.json()).then(d => d.ip)
        """,
        key="ip",
    )

def login_screen():
    st.title("🔐 IoT HMI Login")
    _, col, _ = st.columns([1, 2, 1])
    with col:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            ip = get_client_ip()
            if username == "admin" and password == "admin123":
                st.session_state.authenticated = True
                st.session_state.unlock_done   = False
                cookies["auth"] = "true"
                cookies.save()
                st.rerun()
            else:
                check_bruteforce(ip, username, password)
                st.error("Invalid Credentials")

def unlock_animation():
    st.markdown("## 🔓 Unlocking HMI System")
    bar = st.progress(0)
    for i in range(100):
        time.sleep(0.01)
        bar.progress(i + 1)
    st.success("System Unlocked")

if not st.session_state.authenticated:
    login_screen()
    st.stop()

if not st.session_state.unlock_done:
    unlock_animation()
    st.session_state.unlock_done = True
    st.rerun()

# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.image("https://cdn-icons-png.flaticon.com/512/3064/3064197.png", width=80)
st.sidebar.title("⚙ Control Panel")

pill  = "pill-on"     if data_store["connected"] else "pill-off"
label = "MQTT ● Live" if data_store["connected"] else "MQTT ✕ Offline"
st.sidebar.markdown(f'<span class="{pill}">{label}</span>', unsafe_allow_html=True)
st.sidebar.markdown("---")

for btn, page in {
    "🏠 Main Dashboard":         "Main Dashboard",
    "🌡 Temperature Monitoring":  "Temperature Monitoring",
    "🚨 Motion Detection":        "Motion Detection",
    "📷 Camera Monitoring":       "Camera Monitoring",
    "📜 Security Logs":           "Security Logs",
}.items():
    if st.sidebar.button(btn):
        st.session_state.menu = page

if st.sidebar.button("🚪 Logout"):
    st.session_state.authenticated = False
    st.session_state.unlock_done   = False
    cookies["auth"] = "false"
    cookies.save()
    st.rerun()

menu = st.session_state.menu
st.caption(f"System Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# ============================================================
# HELPERS
# ============================================================

def gauge_chart(value, title, color):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={"text": title},
        gauge={
            "axis":  {"range": [0, 100]},
            "bar":   {"color": color},
            "steps": [{"range": [0, 100], "color": "#eeeeee"}],
        },
    ))
    fig.update_layout(height=250)
    return fig

def play_alarm():
    st.warning("🔊 Alarm Triggered")
    try:
        with open("/home/ubuntuIoT/Downloads/beep-01a.wav", "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        st.markdown(
            f'<audio autoplay loop>'
            f'<source src="data:audio/wav;base64,{b64}" type="audio/wav">'
            f'</audio>',
            unsafe_allow_html=True,
        )
    except:
        st.info("Alarm audio not available in cloud mode.")

# ============================================================
# PAGES
# ============================================================

if menu == "Main Dashboard":
    st.title("🛡 IoT Device Control Panel")

    col1, col2, col3 = st.columns(3)
    col1.metric("Temperature", f"{data_store['temperature']} °C")
    col2.metric("Humidity",    f"{data_store['humidity']} %")
    col3.metric("Motion",      "Detected" if data_store["motion"] == 1 else "Clear")

    st.subheader("System Status")
    if data_store["connected"]:
        st.success("HiveMQ Cloud : Connected — receiving live sensor data")
    else:
        st.error("HiveMQ Cloud : Disconnected")
    st.success("HMI Dashboard : Active")
    st.info("ℹ️ Sensor data is live in memory only. Brute-force alerts are persisted to Firebase.")

    # Debug — remove once confirmed working
    st.write("📊 Live data_store:", data_store)

# --------------------------------------------------------

elif menu == "Temperature Monitoring":
    st.title("🌡 Temperature Monitoring")

    temp = data_store["temperature"]
    hum  = data_store["humidity"]

    col1, col2 = st.columns(2)
    with col1:
        st.plotly_chart(gauge_chart(temp, "Temperature", "blue"),   use_container_width=True)
    with col2:
        st.plotly_chart(gauge_chart(hum,  "Humidity",    "orange"), use_container_width=True)

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("LED Status")
        threshold = st.session_state.get("threshold", 29)
        if temp >= threshold:
            st.markdown("<h2 style='color:red;'>● LED ON</h2>",   unsafe_allow_html=True)
        else:
            st.markdown("<h2 style='color:gray;'>● LED OFF</h2>", unsafe_allow_html=True)
    with col2:
        st.subheader("Temperature Threshold")
        threshold = st.slider("Set Threshold", 0, 100, 29)
        st.session_state.threshold = threshold

# --------------------------------------------------------

elif menu == "Motion Detection":
    st.title("🚨 Motion Detection Panel")

    motion_detected = data_store["motion"] == 1

    st.subheader("Attack Mode")
    if st.toggle("Enable Attack Mode"):
        motion_detected = not motion_detected

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Alarm System")
        play_alarm() if motion_detected else st.success("No Alarm")
    with col2:
        st.subheader("LED")
        if motion_detected:
            st.markdown("<h2 style='color:red;'>● LED ON</h2>",   unsafe_allow_html=True)
        else:
            st.markdown("<h2 style='color:gray;'>● LED OFF</h2>", unsafe_allow_html=True)

    st.subheader("Motion Status")
    if motion_detected:
        st.markdown("<div class='alarm'>🚨 INTRUSION DETECTED 🚨</div>", unsafe_allow_html=True)
    else:
        st.success("No Motion")

# --------------------------------------------------------

elif menu == "Security Logs":
    st.title("📜 Honeypot Security Events")
    st.caption("Brute-force login attempts — 5 failed logins from same IP triggers an alert saved to Firebase")

    df = fb_get_alerts()

    if not df.empty:
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Alerts", len(df))
        col2.metric("Unique IPs",   df["Source IP"].nunique())
        col3.metric("Countries",    df["Country"].nunique())

        st.dataframe(df, use_container_width=True)

        if df["Country"].nunique() > 1:
            st.subheader("Attacks by Country")
            st.bar_chart(df["Country"].value_counts())
    else:
        st.info("No alerts yet. Trigger 5+ failed logins from the same IP to generate one.")

# --------------------------------------------------------

elif menu == "Camera Monitoring":
    st.title("📷 Camera Monitoring System")

    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown("""
        <iframe src="http://10.210.122.122:8888/camera"
        width="100%" height="500" frameborder="0" allowfullscreen></iframe>
        """, unsafe_allow_html=True)
    with col2:
        st.subheader("Camera Status")
        try:
            r = requests.get("http://10.210.122.122:8888/camera", timeout=3)
            st.success("Camera : Online") if r.ok else st.error("Camera : Offline")
        except:
            st.error("Camera : Offline")
        st.markdown("**Resolution** : 768x432")
        st.markdown("**FPS** : 25")
        st.markdown("**Protocol** : RTSP / HTTP")

    st.divider()
    st.subheader("Camera Controls")
    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("🔴 Start Recording"):  st.success("Recording Started")
    with c2:
        if st.button("⏹ Stop Recording"):    st.warning("Recording Stopped")
    with c3:
        if st.button("📸 Capture Snapshot"): st.info("Snapshot Captured")
