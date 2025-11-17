import os
import pandas as pd
import streamlit as st
import plotly.express as px
from datetime import datetime, timezone
from streamlit_autorefresh import st_autorefresh

# -----------------------------
# AUTO-REFRESH EVERY 5 SECONDS
# -----------------------------
# This returns the number of times the page has refreshed
count = st_autorefresh(interval=5 * 1000, limit=None, key="threatstats_autorefresh")

# -----------------------------
# BASE DIR + LOG FILE (absolute)
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs", "scans.csv")

st.title("📊 Threat Stats — Auto-Refreshing")

# -----------------------------
# LOAD LOGS SAFELY
# -----------------------------
try:
    logs = pd.read_csv(LOG_FILE)
except Exception:
    logs = pd.DataFrame({'timestamp': [], 'url': [], 'label': [], 'score': []})

# -----------------------------
# SAFE TIMESTAMP PARSING
# -----------------------------
if not logs.empty:
    logs['timestamp'] = pd.to_datetime(logs['timestamp'], utc=True, errors='coerce')
    logs = logs.dropna(subset=['timestamp'])

# -----------------------------
# RECENT SCANS TABLE
# -----------------------------
st.subheader("Recent scans")
if logs.empty:
    st.info("No scans yet. Run a scan in the Analyzer.")
else:
    st.dataframe(logs.sort_values("timestamp", ascending=False).head(50))

# -----------------------------
# SAMPLE DISTRIBUTION PIE CHART
# -----------------------------
st.subheader("Sample distribution")
if logs.empty:
    sample = pd.DataFrame({'Category': ['Safe', 'Suspicious', 'Malicious'], 'Count':[120, 35, 22]})
    fig = px.pie(sample, names='Category', values='Count', title='Detected Threats Overview')
else:
    agg = logs['label'].value_counts().rename_axis('label').reset_index(name='Count')
    agg['label'] = agg['label'].map({0: 'Safe', 1: 'Malicious'}).fillna('Unknown')
    fig = px.pie(agg, names='label', values='Count', title='Detected Threats Overview')

st.plotly_chart(fig, use_container_width=True)

# -----------------------------
# LAST UPDATE
# -----------------------------
st.caption(f"Data last updated at {datetime.now(timezone.utc).isoformat()}")
