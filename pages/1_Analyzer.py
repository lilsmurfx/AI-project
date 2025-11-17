import streamlit as st
import joblib, os, pandas as pd
from feature_extractor import extract_url_features
import plotly.express as px
from datetime import datetime, timezone
import tldextract
import requests
import socket
import ssl
import json

# --------------------------
# --- CONFIGURATION
# --------------------------
JSONWHOIS_API_KEY = "sQtu6yuc5cfrJN"
IPINFO_TOKEN = "YOUR_IPINFO_TOKEN"  # optional
GSB_API_KEY = "YOUR_GOOGLE_SAFEBROWSING_API_KEY"
PHISHTANK_API = "https://checkurl.phishtank.com/checkurl/"
SSL_LABS_API = "https://api.ssllabs.com/api/v3/analyze?host={}"

# --------------------------
# --- UTILITY FUNCTIONS
# --------------------------

def get_whois_info(domain):
    """JSONWHOIS + fallback for .co.ke"""
    try:
        # Use JSONWHOIS for generic domains
        url = f"https://jsonwhoisapi.com/api/v1/whois?identifier={domain}"
        headers = {"Authorization": f"Token token={JSONWHOIS_API_KEY}"}
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            creation_date = data.get('registry_data', {}).get('creation_date')
            if creation_date:
                creation_date = datetime.fromisoformat(creation_date).replace(tzinfo=timezone.utc)
                domain_age_days = (datetime.now(timezone.utc) - creation_date).days
            else:
                domain_age_days = None
            return data, domain_age_days
        return None, None
    except:
        # Fallback for .co.ke using KeNIC (placeholder, implement real API if available)
        if domain.endswith(".co.ke"):
            return {"registrar": "KeNIC"}, None
        return None, None

def get_ip_info(domain):
    """Get IP and geolocation using free API"""
    try:
        r = requests.get(f"https://ipinfo.io/{domain}/json?token={IPINFO_TOKEN}", timeout=5)
        return r.json()
    except:
        return None

def check_url_phishtank(url):
    """PhishTank API placeholder"""
    try:
        r = requests.get(f"{PHISHTANK_API}?url={url}", timeout=5)
        if r.status_code == 200:
            return "✅ Safe (PhishTank placeholder)"
        return "⚠️ Possibly malicious (PhishTank)"
    except:
        return "PhishTank check failed"

def check_url_gsb(url):
    """Google Safe Browsing API"""
    try:
        gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
        payload = {
            "client": {"clientId": "govsec-ai", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        r = requests.post(gsb_url, json=payload, timeout=5)
        data = r.json()
        if data.get("matches"):
            return "⚠️ Malicious (Google Safe Browsing)"
        return "✅ Safe (Google Safe Browsing)"
    except:
        return "GSB check failed"

def check_ssl(domain):
    """Check SSL via SSL Labs API"""
    try:
        r = requests.get(SSL_LABS_API.format(domain), timeout=5)
        data = r.json()
        status = data.get("status")
        if status == "READY":
            endpoints = data.get("endpoints", [])
            if endpoints:
                grade = endpoints[0].get("grade")
                return f"✅ Valid (Grade {grade})"
        return "⚠️ SSL Invalid / Not Ready"
    except:
        return "SSL check failed"

@st.cache_resource
def load_model_and_vectorizer():
    model_path = 'model/phishing_model.pkl'
    vectorizer_path = 'model/vectorizer.pkl'
    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        vec = joblib.load(vectorizer_path)
        model = joblib.load(model_path)
        return model, vec
    return None, None

# --------------------------
# --- STREAMLIT UI
# --------------------------

st.title('🔍 Analyzer')
model, vec = load_model_and_vectorizer()

if model is None:
    st.warning('Model files not found. Run `train_model.py` locally and push model/ files.')
    st.stop()

url_input = st.text_input('Enter a website URL to analyze', '')

if st.button('Analyze URL') and url_input:

    # --- ML Prediction ---
    feats = extract_url_features(url_input)
    X = vec.transform([feats])
    pred = int(model.predict(X)[0])
    prob = float(model.predict_proba(X)[0][pred])

    # --- Logs ---
    os.makedirs('logs', exist_ok=True)
    log_path = 'logs/scans.csv'
    df_log = pd.DataFrame([{
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'url': url_input,
        'label': pred,
        'score': prob
    }])
    if os.path.exists(log_path):
        df_log.to_csv(log_path, mode='a', header=False, index=False)
    else:
        df_log.to_csv(log_path, index=False)

    # --- Risk Display ---
    st.subheader('ML Prediction')
    if pred == 1:
        st.error(f"⚠️ High Risk (Confidence {prob:.2f})")
    else:
        st.success(f"✅ Safe (Confidence {prob:.2f})")

    # --- Feature Breakdown ---
    st.subheader('Feature Breakdown')
    df = pd.DataFrame([feats]).T.reset_index()
    df.columns = ['feature', 'value']
    st.dataframe(df)

    # --- ML Pie Chart ---
    fig = px.pie(names=['Risk','Confidence'], values=[prob, 1-prob], hole=0.6)
    st.plotly_chart(fig, width='stretch')

    # --- Real-time Enhancements ---
    st.subheader('🔎 Real-time URL Analysis')
    domain = tldextract.extract(url_input).registered_domain

    # WHOIS & domain age
    whois_data, domain_age_days = get_whois_info(domain)
    st.write("WHOIS info:", whois_data if whois_data else "Unavailable")
    if domain_age_days: st.write(f"Domain age: {domain_age_days} days")

    # SSL
    ssl_status = check_ssl(domain)
    st.write(f"SSL certificate: {ssl_status}")

    # IP + Geolocation
    ip_info = get_ip_info(domain)
    if ip_info:
        st.write(f"IP Address: {ip_info.get('ip')}")
        st.write(f"Location: {ip_info.get('city')}, {ip_info.get('region')}, {ip_info.get('country')}")
    else:
        st.write("IP / geolocation info unavailable")

    # URL Reputation
    phishtank_status = check_url_phishtank(url_input)
    gsb_status = check_url_gsb(url_input)
    st.write(f"PhishTank: {phishtank_status}")
    st.write(f"Google Safe Browsing: {gsb_status}")

    # --- Composite Risk Score ---
    score_components = []
    if pred == 1: score_components.append(2)
    if domain_age_days is not None and domain_age_days < 180: score_components.append(1)
    if "Safe" not in phishtank_status: score_components.append(2)
    if "Safe" not in gsb_status: score_components.append(2)
    if "Valid" not in ssl_status: score_components.append(1)
    composite_risk = min(sum(score_components), 8)
    risk_labels = {0:'Low',1:'Low',2:'Medium',3:'Medium',4:'High',5:'High',6:'Critical',7:'Critical',8:'Critical'}
    st.metric("Composite Risk Score", f"{risk_labels[composite_risk]} ({composite_risk}/8)")
