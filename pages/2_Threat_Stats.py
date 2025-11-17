import streamlit as st
import pandas as pd
import plotly.express as px

st.title('📊 Threat Stats')
try:
    logs = pd.read_csv('logs/scans.csv')
except Exception:
    logs = pd.DataFrame({'timestamp': [], 'url': [], 'label': [], 'score': []})

st.subheader('Recent scans')
if logs.empty:
    st.info('No scans yet. Use the Analyzer to run a URL check.')
else:
    st.dataframe(logs.sort_values('timestamp', ascending=False).head(50))

st.subheader('Sample distribution')
if logs.empty:
    sample = pd.DataFrame({'Category':['Safe','Suspicious','Malicious'], 'Count':[120,35,22]})
    fig = px.pie(sample, names='Category', values='Count', title='Detected Threats Overview')
else:
    agg = logs['label'].value_counts().rename_axis('label').reset_index(name='Count')
    agg['label'] = agg['label'].map({0:'Safe',1:'Malicious'})
    fig = px.pie(agg, names='label', values='Count', title='Detected Threats Overview')
st.plotly_chart(fig, width='stretch')  # if it was True
