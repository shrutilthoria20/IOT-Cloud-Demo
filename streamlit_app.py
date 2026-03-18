import streamlit as st
import plotly.graph_objects as go
import pandas as pd
from streamlit_autorefresh import st_autorefresh
from streamlit_cookies_manager import EncryptedCookieManager
import datetime
import time
import base64
import json

# MQTT
import paho.mqtt.client as mqtt
import ssl

# ---------------- CONFIG ---------------- #
BROKER = st.secrets["BROKER"]
USERNAME = st.secrets["USERNAME"]
PASSWORD = st.secrets["PASSWORD"]
PORT = 8883
TOPIC = "iot/sensor"

# ---------------- GLOBAL MQTT DATA ---------------- #
global_data = {
    "temperature": 0,
    "humidity": 0,
    "motion": 0
}

global_status = {"connected": False}

# ---------------- MQTT CALLBACKS ---------------- #
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        global_status["connected"] = True
        client.subscribe(TOPIC)
        print("✅ MQTT Connected")
    else:
        print("❌ MQTT Failed:", rc)

def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        print("DATA:", data)

        global_data["temperature"] = data.get("temperature", 0)
        global_data["humidity"] = data.get("humidity", 0)
        global_data["motion"] = data.get("motion", 0)

    except Exception as e:
        print("Error:", e)

# ---------------- INIT MQTT ---------------- #
if "mqtt_client" not in st.session_state:
    client = mqtt.Client(client_id="dashboard")
    client.username_pw_set(USERNAME, PASSWORD)
    client.tls_set(cert_reqs=ssl.CERT_REQUIRED)

    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(BROKER, PORT)
    client.loop_start()

    st.session_state.mqtt_client = client

# ---------------- COOKIES ---------------- #
cookies = EncryptedCookieManager(prefix="iot_hmi", password="secret")

if not cookies.ready():
    st.stop()

# ---------------- SESSION ---------------- #
if "authenticated" not in st.session_state:
    st.session_state.authenticated = cookies.get("auth") == "true"

if "menu" not in st.session_state:
    st.session_state.menu = "Main Dashboard"

# ---------------- UI CONFIG ---------------- #
st.set_page_config(page_title="IoT HMI", layout="wide")
st_autorefresh(interval=2000, key="refresh")

# ---------------- LOGIN ---------------- #
def login():
    st.title("🔐 IoT Login")

    user = st.text_input("Username")
    pwd = st.text_input("Password", type="password")

    if st.button("Login"):
        if user == "admin" and pwd == "admin123":
            st.session_state.authenticated = True
            cookies["auth"] = "true"
            cookies.save()
            st.rerun()
        else:
            st.error("Invalid credentials")

if not st.session_state.authenticated:
    login()
    st.stop()

# ---------------- SIDEBAR ---------------- #
st.sidebar.title("⚙ Control Panel")

menu = st.sidebar.radio("Navigate", [
    "Main Dashboard",
    "Temperature Monitoring",
    "Motion Detection"
])

# ---------------- DATA ---------------- #
temperature = global_data["temperature"]
humidity = global_data["humidity"]
motion = global_data["motion"]

# ---------------- MAIN DASHBOARD ---------------- #
if menu == "Main Dashboard":

    st.title("🛡 IoT Dashboard")

    col1, col2, col3 = st.columns(3)
    col1.metric("Temperature", f"{temperature} °C")
    col2.metric("Humidity", f"{humidity} %")
    col3.metric("Motion", "Detected" if motion else "No Motion")

    st.markdown("---")

    if global_status["connected"]:
        st.success("✅ Connected to HiveMQ")
    else:
        st.error("❌ MQTT Disconnected")

# ---------------- TEMPERATURE ---------------- #
elif menu == "Temperature Monitoring":

    st.title("🌡 Temperature Monitoring")

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=temperature,
        title={'text': "Temperature"},
        gauge={'axis': {'range': [0, 100]}}
    ))

    st.plotly_chart(fig, use_container_width=True)

# ---------------- MOTION ---------------- #
elif menu == "Motion Detection":

    st.title("🚨 Motion Detection")

    if motion:
        st.error("🚨 INTRUSION DETECTED")
        st.audio("https://www.soundjay.com/buttons/beep-01a.mp3")
    else:
        st.success("No Motion")
