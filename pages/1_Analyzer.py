import os
import streamlit as st
import pandas as pd
import joblib
import plotly.express as px
from datetime import datetime, timezone
from feature_extractor import extract_url_features
import tldextract
import requests
import socket
import ssl
from PIL import Image
from io import BytesIO
from streamlit_autorefresh import st_autorefresh

# ==================================================
# AUTO-REFRESH SETTINGS
# ==================================================
st_autorefresh(interval=5 * 1000, limit=None, key="auto_refresh")  # Refresh every 5 sec

# ==================================================
# BASE DIR + LOG FILE
# ==================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "scans.csv")

# ==================================================
# UTILITY FUNCTIONS
# ==================================================
def safe_append_to_csv(path, df):
    file_exists = os.path.exists(path)
    df.to_csv(path, mode="a", index=False, header=not file_exists)

def safe_request(url, method="GET", timeout=5, **kwargs):
    try:
        if method == "POST":
            r = requests.post(url, timeout=timeout, **kwargs)
        else:
            r = requests.get(url, timeout=timeout, **kwargs)
        return r if r.status_code == 200 else None
    except:
        return None

def load_model_and_vectorizer():
    try:
        model = joblib.load(os.path.join(BASE_DIR, "model/phishing_model.pkl"))
        vec = joblib.load(os.path.join(BASE_DIR, "model/vectorizer.pkl"))
        return model, vec
    except:
        return None, None

def get_whois_info(domain):
    try:
        url = f"https://jsonwhoisapi.com/api/v1/whois?identifier={domain}"
        headers = {"Authorization": f"Token token=sQtu6yuc5cfrJN"}
        r = safe_request(url, headers=headers)
        if r:
            data = r.json()
            creation = data.get("registry_data", {}).get("creation_date") or data.get("created_at")
            if creation:
                cdate = datetime.fromisoformat(creation).replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - cdate).days
                return data, age
    except:
        pass
    if domain.endswith(".ke") or domain.endswith(".co.ke"):
        return {"registrar": "KeNIC (fallback)"}, None
    return None, None

def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            s.getpeercert()
        return "✅ Valid"
    except:
        return "⚠️ Invalid or missing certificate"

# ==================================================
# STREAMLIT UI
# ==================================================
st.title("🔍 Analyzer + Threat Stats")

# --------- Load or Upload Model ---------
model, vec = load_model_and_vectorizer()
if model is None or vec is None:
    st.warning("❌ ML model or vectorizer missing.")
    st.info("Please upload your `phishing_model.pkl` and `vectorizer.pkl` files.")
    uploaded_model = st.file_uploader("Upload phishing_model.pkl", type="pkl")
    uploaded_vec = st.file_uploader("Upload vectorizer.pkl", type="pkl")
    if uploaded_model and uploaded_vec:
        os.makedirs(os.path.join(BASE_DIR, "model"), exist_ok=True)
        model_path = os.path.join(BASE_DIR, "model/phishing_model.pkl")
        vec_path = os.path.join(BASE_DIR, "model/vectorizer.pkl")
        with open(model_path, "wb") as f:
            f.write(uploaded_model.getbuffer())
        with open(vec_path, "wb") as f:
            f.write(uploaded_vec.getbuffer())
        st.success("✅ Files uploaded! Reload the page.")
    st.stop()

# --------- URL Input & Analysis ---------
url_input = st.text_input("Enter website URL")
if st.button("Analyze URL") and url_input:
    if "://" not in url_input:
        url_input = "http://" + url_input
    feats = extract_url_features(url_input)
    X = vec.transform([feats])
    pred = int(model.predict(X)[0])
    prob = float(max(model.predict_proba(X)[0]))

    # Save scan
    row = pd.DataFrame([{
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": url_input,
        "label": pred,
        "score": prob
    }])
    safe_append_to_csv(LOG_FILE, row)

    # Display ML prediction
    st.subheader("ML Prediction")
    st.write("**Prediction:**", "Safe" if pred == 0 else "High-Risk")
    st.write(f"**Confidence:** {prob:.2f}")

    # Feature breakdown
    st.subheader("Feature Breakdown")
    df = pd.DataFrame([feats]).T.reset_index()
    df.columns = ["Feature", "Value"]
    st.dataframe(df)

# --------- Threat Stats ---------
st.subheader("📊 Recent Threat Stats")
try:
    logs = pd.read_csv(LOG_FILE)
    logs['timestamp'] = pd.to_datetime(logs['timestamp'], utc=True, errors='coerce')
    logs = logs.dropna(subset=['timestamp'])
except:
    logs = pd.DataFrame(columns=['timestamp','url','label','score'])

if logs.empty:
    st.info("No scans yet.")
else:
    st.dataframe(logs.sort_values("timestamp", ascending=False).head(50))
    # Pie chart
    agg = logs['label'].value_counts().rename_axis('label').reset_index(name='Count')
    agg['label'] = agg['label'].map({0: 'Safe', 1: 'Malicious'}).fillna('Unknown')
    fig = px.pie(agg, names='label', values='Count', title='Detected Threats Overview')
    st.plotly_chart(fig, use_container_width=True)

st.caption(f"Data last updated at {datetime.now(timezone.utc).isoformat()}")
