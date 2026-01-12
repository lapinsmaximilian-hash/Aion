# Aion_app.py
Creates an Alexa for all aspects of life 
# ==========================
# 🧠 AION — Digital Twin + Device Interaction
# ==========================

import streamlit as st
import sqlite3
import uuid
from datetime import datetime, timedelta
import bcrypt
from cryptography.fernet import Fernet
import random

# ==========================
# 🔹 SYMBOLIC LANGUAGE LAYER
# ==========================

RUNE_MAP = {
    "a": "ᚨ", "b": "ᛒ", "c": "ᚲ", "d": "ᛞ", "e": "ᛖ",
    "f": "ᚠ", "g": "ᚷ", "h": "ᚺ", "i": "ᛁ", "j": "ᛃ",
    "k": "ᚲ", "l": "ᛚ", "m": "ᛗ", "n": "ᚾ", "o": "ᛟ",
    "p": "ᛈ", "q": "求", "r": "ᚱ", "s": "ᛋ", "t": "ᛏ",
    "u": "ᚢ", "v": "ᚡ", "w": "ᚹ", "x": "行", "y": "ᛦ",
    "z": "ᛉ"
}

def encode_runes(text: str) -> str:
    return "".join(RUNE_MAP.get(c.lower(), c) for c in text)

# ==========================
# 🔹 ENCRYPTION LAYER
# ==========================

FERNET_KEY = Fernet.generate_key()
cipher = Fernet(FERNET_KEY)

def encrypt(data: str) -> bytes:
    return cipher.encrypt(data.encode())

def decrypt(token: bytes) -> str:
    return cipher.decrypt(token).decode()

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

# ==========================
# 🔹 DATABASE SETUP
# ==========================

DB = "aion.db"
conn = sqlite3.connect(DB, check_same_thread=False)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT,
    password BLOB,
    interaction_mode TEXT DEFAULT 'No Interaction'
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS devices (
    id TEXT,
    user_id TEXT,
    name TEXT,
    type TEXT,
    trust REAL,
    last_seen TEXT,
    usage_seconds INTEGER DEFAULT 0,
    app_usage TEXT DEFAULT ''
)
""")
conn.commit()

# ==========================
# 🔹 DIGITAL TWIN
# ==========================

class DigitalTwin:
    def __init__(self):
        self.stress = 0.5
        self.focus = 0.5

    def update_heart_rate(self, hr: int):
        if hr > 100:
            self.stress = min(1.0, self.stress + 0.1)
        else:
            self.stress = max(0.0, self.stress - 0.05)

    def passive_feedback(self, brightness: int, volume: int):
        # Suggest lowering brightness or volume if unhealthy
        suggestions = []
        if brightness > 80:
            suggestions.append("Consider lowering brightness for eye health")
        if volume > 70:
            suggestions.append("Consider reducing volume to prevent hearing strain")
        return suggestions

if "twin" not in st.session_state:
    st.session_state.twin = DigitalTwin()

# ==========================
# 🔹 STREAMLIT APP
# ==========================

st.set_page_config(
    page_title="AION",
    layout="centered",
    initial_sidebar_state="collapsed"
)

st.markdown(
    """
    <style>
    button { width: 100%; height: 3em; font-size: 1.1em; }
    </style>
    """,
    unsafe_allow_html=True
)

st.title("🧠 AION — Digital Twin & Device Interaction")

# -------------------------
# AUTHENTICATION
# -------------------------

st.sidebar.header("🔐 Login / Register")
username = st.sidebar.text_input("Name")
password = st.sidebar.text_input("Password", type="password")

if st.sidebar.button("Login / Create"):
    cur.execute("SELECT id,password,interaction_mode FROM users WHERE name=?", (username,))
    row = cur.fetchone()

    if row:
        if verify_password(password, row[1]):
            st.session_state.user = row[0]
            st.session_state.mode = row[2]
        else:
            st.error("Access denied.")
            st.stop()
    else:
        uid = str(uuid.uuid4())
        cur.execute(
            "INSERT INTO users VALUES (?,?,?,?)",
            (uid, username, hash_password(password), 'No Interaction')
        )
        conn.commit()
        st.session_state.user = uid
        st.session_state.mode = 'No Interaction'

# -------------------------
# INTERACTION MODE SELECTION
# -------------------------

st.sidebar.subheader("⚙️ Interaction Mode")
mode = st.sidebar.radio(
    "Choose AION Behavior",
    ["No Interaction", "Passive Suggestions", "Active Modifications"],
    index=["No Interaction", "Passive Suggestions", "Active Modifications"].index(st.session_state.mode)
)

if mode != st.session_state.mode:
    st.session_state.mode = mode
    cur.execute(
        "UPDATE users SET interaction_mode=? WHERE id=?",
        (mode, st.session_state.user)
    )
    conn.commit()
    st.success(f"Interaction mode set to {mode}")

# -------------------------
# MOBILE-FRIENDLY TABS
# -------------------------

tabs = st.tabs(["🧠 State", "📡 Devices", "➕ Add Device", "📊 Usage Stats"])

with tabs[0]:
    st.subheader("❤️ Cognitive State")
    st.metric("Stress", f"{st.session_state.twin.stress:.2f}")
    st.progress(st.session_state.twin.stress)
    st.subheader("⚡ Focus Level")
    st.metric("Focus", f"{st.session_state.twin.focus:.2f}")
    st.progress(st.session_state.twin.focus)

    # Example: passive suggestions
    if st.session_state.mode == "Passive Suggestions":
        brightness = st.slider("Phone Brightness (simulated)", 0, 100, 70)
        volume = st.slider("Average Volume (simulated)", 0, 100, 60)
        suggestions = st.session_state.twin.passive_feedback(brightness, volume)
        for s in suggestions:
            st.warning(s)

with tabs[1]:
    st.subheader("📡 Your Devices")
    cur.execute(
        "SELECT name,type,trust,last_seen FROM devices WHERE user_id=?",
        (st.session_state.user,)
    )
    rows = cur.fetchall()
    if not rows:
        st.info("No devices marked yet.")
    for d in rows:
        st.markdown(f"**{d[0]}** ({d[1]}) — Trust {d[2]:.2f} — Last Seen {d[3]}")

with tabs[2]:
    with st.form("add_device_form"):
        name = st.text_input("Device Name")
        dtype = st.selectbox("Connection Type", ["Bluetooth", "Wi-Fi", "Manual"])
        if st.form_submit_button("Mark Device"):
            cur.execute(
                "INSERT INTO devices VALUES (?,?,?,?,?,?,?,?)",
                (
                    str(uuid.uuid4()),
                    st.session_state.user,
                    encode_runes(name),
                    dtype,
                    0.5,
                    datetime.now().isoformat(),
                    0,
                    ""
                )
            )
            conn.commit()
            st.success("Device marked in AION language ✅")

with tabs[3]:
    st.subheader("📊 Device Usage Over Time")
    cur.execute(
        "SELECT name,usage_seconds FROM devices WHERE user_id=?",
        (st.session_state.user,)
    )
    rows = cur.fetchall()
    if not rows:
        st.info("No usage recorded yet.")
    for d in rows:
        seconds = d[1]
        days = seconds // (3600*24)
        weeks = days // 7
        months = days // 30
        years = days // 365
        st.markdown(f"**{d[0]}** — {days}d | {weeks}w | {months}m | {years}y")

# -------------------------
# ACTIVE MODIFICATIONS SIMULATION
# -------------------------

if st.session_state.mode == "Active Modifications":
    st.info("Active device control enabled (simulated)")
    # Example gesture control
    st.subheader("👆 Gesture Control")
    taps = st.slider("Simulated Tap Count", 0, 3, 0)
    if taps == 1:
        st.success("Single tap detected → Exit app (simulated)")
    elif taps == 2:
        st.success("Double tap detected → Enter app (simulated)")
    elif taps >= 3:
        st.success("Triple tap → Custom action (simulated)")

