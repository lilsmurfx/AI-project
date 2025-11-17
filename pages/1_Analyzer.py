import streamlit as st
import joblib, os, pandas as pd
from feature_extractor import extract_url_features
import plotly.express as px
from datetime import datetime, timezone
import tldextract
import requests
import socket
import ssl
from PIL import Image
from io import BytesIO

# --------------------------
# --- CONFIGURATION
# --------------------------
JSONWHOIS_API_KEY = "sQtu6yuc5cfrJN"
IPINFO_TOKEN = None  # Optional: add token for ipinfo.io
GSB_API_KEY = None   # Optional: Google Safe Browsing API key
PHISHTANK_API = "https://checkurl.phishtank.com/checkurl/"
SCREENSHOT_API = "https://api.screenshotapi.net/screenshot?token=YOUR_API_KEY&url={}"

# --------------------------
# --- UTILITY FUNCTIONS
# --------------------------
def get_whois_info(domain):
    try:
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
    except:
        pass
    if domain.endswith(".ke") or domain.endswith(".co.ke"):
        return {"registrar": "KeNIC (fallback)"}, None
    return None, None

def get_ip_info(domain):
    try:
        url = f"https://ipinfo.io/{domain}/json"
        if IPINFO_TOKEN:
            url += f"?token={IPINFO_TOKEN}"
        r = requests.get(url, timeout=5)
        return r.json()
    except:
        return None

def check_url_phishtank(url):
    try:
        r = requests.get(f"{PHISHTANK_API}?url={url}", timeout=5)
        if r.status_code == 200:
            return "✅ Safe (PhishTank placeholder)"
        return "⚠️ Possibly malicious (PhishTank)"
    except:
        return "PhishTank check failed"

def check_url_gsb(url):
    if not GSB_API_KEY:
        return "GSB check not configured"
    try:
        gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
        payload = {
            "client": {"clientId": "govsec-ai", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries":[{"url":url}]
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
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
        return "✅ Valid"
    except:
        return "⚠️ Invalid / Not found"

def get_screenshot(url):
    try:
        r = requests.get(SCREENSHOT_API.format(url), timeout=10)
        img = Image.open(BytesIO(r.content))
        return img
    except:
        return None

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
# Page config
st.set_page_config(
    page_title="GovSec AI Analyzer 🇰🇪",
    page_icon="🇰🇪",
    layout="wide",
)

# Sidebar
st.sidebar.title("🇰🇪 KE GovSec AI")
st.sidebar.markdown(
    """
    **Navigation:**  
    - Analyzer  
    - Threat Stats  
    - About
    """
)

# Dark/light toggle
theme = st.sidebar.radio("Theme:", ["Light","Dark"])
if theme=="Dark":
    st.markdown("<style>body{background-color:#0B3D91;color:white;}</style>", unsafe_allow_html=True)

# Main Analyzer UI
st.title("🔍 Phishing & Impersonation Analyzer")

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

    # Logs
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

    # --- Card Layout ---
    st.subheader("🔐 ML Prediction")
    col1, col2, col3 = st.columns(3)
    col1.metric("Risk Level", "High Risk" if pred==1 else "Safe", f"{prob:.2f} confidence")
    
    # Feature breakdown
    col2.dataframe(pd.DataFrame([feats]).T.reset_index().rename(columns={0:'value','index':'feature'}))
    
    # ML Pie Chart
    fig = px.pie(names=['Risk','Confidence'], values=[prob, 1-prob], hole=0.6)
    col3.plotly_chart(fig, use_container_width=True)

    # --- Real-time URL Analysis Cards ---
    st.subheader("🔎 Real-time URL Analysis")
    domain = tldextract.extract(url_input).registered_domain
    whois_data, domain_age = get_whois_info(domain)
    ssl_status = check_ssl(domain)
    ip_info = get_ip_info(domain)
    phishtank_status = check_url_phishtank(url_input)
    gsb_status = check_url_gsb(url_input)

    col1, col2, col3 = st.columns(3)
    col1.metric("Domain Age (days)", domain_age if domain_age else "N/A")
    col1.write("WHOIS:", whois_data if whois_data else "Unavailable")
    col2.metric("SSL Certificate", ssl_status)
    col2.metric("IP Address", ip_info.get('ip') if ip_info else "N/A")
    col2.write("Location:", f"{ip_info.get('city')}, {ip_info.get('region')}, {ip_info.get('country')}" if ip_info else "N/A")
    col3.metric("PhishTank", phishtank_status)
    col3.metric("Google Safe Browsing", gsb_status)

    # Screenshot preview
    img = get_screenshot(url_input)
    if img:
        st.subheader("🖼️ Website Screenshot")
        st.image(img, use_column_width=True)

    # --- Composite Risk Score ---
    score = 0
    if pred==1: score+=2
    if domain_age and domain_age<180: score+=1
    if "Safe" not in phishtank_status: score+=2
    if "Safe" not in gsb_status: score+=2
    if "Valid" not in ssl_status: score+=1
    composite_labels={0:'Low',1:'Low',2:'Medium',3:'Medium',4:'High',5:'High',6:'Critical',7:'Critical',8:'Critical'}
    st.subheader("📊 Composite Risk Score")
    st.metric("Score", f"{composite_labels[min(score,8)]} ({min(score,8)}/8)")
