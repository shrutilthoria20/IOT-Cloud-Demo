import streamlit as st
import paho.mqtt.client as mqtt
import ssl
import json
from streamlit_autorefresh import st_autorefresh
import os

# ---------------- CONFIG ---------------- #
BROKER = os.getenv("BROKER")
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")
PORT = 8883
TOPIC = "iot/sensor"



st.set_page_config(page_title="IoT Dashboard")
st.title("📡 IoT Sensor Dashboard")

# Auto refresh
st_autorefresh(interval=2000, key="refresh")

# ---------------- GLOBAL STORAGE (IMPORTANT) ---------------- #
# This block ensures data is NOT reset on rerun
if "data_store" not in st.session_state:
    st.session_state.data_store = {
        "temperature": 0,
        "humidity": 0,
        "connected": False
    }

data_store = st.session_state.data_store

# ---------------- MQTT CALLBACKS ---------------- #
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("✅ Connected")
        data_store["connected"] = True
        client.subscribe(TOPIC)
    else:
        print("❌ Failed:", rc)

def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
        print("DATA:", data)

        # ✅ Update ONLY global dict (NOT session_state directly)
        data_store["temperature"] = data.get("temperature", 0)
        data_store["humidity"] = data.get("humidity", 0)

    except Exception as e:
        print("Error:", e)

# ---------------- INIT MQTT ONLY ONCE ---------------- #
if "mqtt_started" not in st.session_state:

    client = mqtt.Client(client_id="streamlit_client")
    client.username_pw_set(USERNAME, PASSWORD)
    client.tls_set(cert_reqs=ssl.CERT_REQUIRED)

    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(BROKER, PORT)
    client.loop_start()

    st.session_state.mqtt_started = True

# ---------------- UI ---------------- #
col1, col2 = st.columns(2)

with col1:
    st.metric("🌡 Temperature", f"{data_store['temperature']} °C")

with col2:
    st.metric("💧 Humidity", f"{data_store['humidity']} %")

st.markdown("---")

if data_store["connected"]:
    st.success("✅ Connected to HiveMQ")
else:
    st.error("❌ Disconnected")

# Debug
st.write("📊 Live Data:", data_store)