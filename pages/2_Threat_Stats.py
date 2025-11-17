import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timezone

st.title('📊 Threat Stats')

# -----------------------------
# SAFE LOG LOADING
# -----------------------------
try:
    logs = pd.read_csv('logs/scans.csv')

    # Ensure required columns exist
    required_cols = {'timestamp', 'url', 'label', 'score'}
    if not required_cols.issubset(logs.columns):
        raise ValueError("Malformed logs file")

except Exception:
    logs = pd.DataFrame({'timestamp': [], 'url': [], 'label': [], 'score': []})

# -----------------------------
# SAFE TIMESTAMP PARSING
# -----------------------------
if not logs.empty:
    logs['timestamp'] = pd.to_datetime(
        logs['timestamp'],
        utc=True,
        errors='coerce'       # <-- prevents crashes
    )
    logs = logs.dropna(subset=['timestamp'])  # <-- remove bad rows safely


# -----------------------------
# RECENT SCANS TABLE
# -----------------------------
st.subheader('Recent scans')
if logs.empty:
    st.info('No scans yet. Run a scan in the Analyzer.')
else:
    st.dataframe(
        logs.sort_values('timestamp', ascending=False).head(50)
    )


# -----------------------------
# CHART: SAMPLE DISTRIBUTION
# -----------------------------
st.subheader('Sample distribution')

if logs.empty:
    # fallback dummy data
    sample = pd.DataFrame({
        'Category': ['Safe', 'Suspicious', 'Malicious'],
        'Count': [120, 35, 22]
    })
    fig = px.pie(sample, names='Category', values='Count',
                 title='Detected Threats Overview')

else:
    # Count labels safely
    agg = logs['label'].value_counts().rename_axis('label').reset_index(name='Count')
    agg['label'] = agg['label'].map({0: 'Safe', 1: 'Malicious'}).fillna('Unknown')

    fig = px.pie(agg, names='label', values='Count',
                 title='Detected Threats Overview')

# Plot chart
st.plotly_chart(fig, width='stretch')


# -----------------------------
# TIMESTAMP
# -----------------------------
st.caption(f"Data last updated at {datetime.now(timezone.utc).isoformat()}")
