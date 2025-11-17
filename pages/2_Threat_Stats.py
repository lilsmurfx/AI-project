import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timezone  # <- for UTC timestamps

st.title('📊 Threat Stats')

# Load logs safely
try:
    logs = pd.read_csv('logs/scans.csv')
except Exception:
    logs = pd.DataFrame({'timestamp': [], 'url': [], 'label': [], 'score': []})

# Recent scans table
st.subheader('Recent scans')
if logs.empty:
    st.info('No scans yet. Use the Analyzer to run a URL check.')
else:
    # Convert timestamps to UTC-aware datetime for display
    logs['timestamp'] = pd.to_datetime(logs['timestamp'], utc=True)
    st.dataframe(logs.sort_values('timestamp', ascending=False).head(50))

# Sample distribution pie chart
st.subheader('Sample distribution')
if logs.empty:
    sample = pd.DataFrame({'Category': ['Safe','Suspicious','Malicious'], 'Count':[120,35,22]})
    fig = px.pie(sample, names='Category', values='Count', title='Detected Threats Overview')
else:
    agg = logs['label'].value_counts().rename_axis('label').reset_index(name='Count')
    agg['label'] = agg['label'].map({0:'Safe',1:'Malicious'})
    fig = px.pie(agg, names='label', values='Count', title='Detected Threats Overview')

# Display chart with updated syntax
st.plotly_chart(fig, width='stretch')  # <- replaced use_container_width=True

# Optional: last update timestamp
st.caption(f"Data last updated at {datetime.now(timezone.utc).isoformat()}")
