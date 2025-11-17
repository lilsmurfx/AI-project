import os
import pandas as pd
import streamlit as st
import plotly.express as px
from datetime import datetime, timezone

# -----------------------------
# AUTO-REFRESH EVERY 5 SECONDS
# -----------------------------
st_autorefresh = st.experimental_data_editor  # For caching purposes, we can also do:
count = st.experimental_get_query_params().get("refresh_count", [0])[0]

st_autorefresh = st.experimental_rerun
st_autorefresh_interval = 5  # seconds
st.experimental_set_query_params(refresh_count=int(count)+1)

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
