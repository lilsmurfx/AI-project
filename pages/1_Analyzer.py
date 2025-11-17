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

# ==================================================
# BASE DIR + LOG FILE
# ==================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "scans.csv")

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

# --------------------------
# WHOIS / SSL / Screenshot
# --------------------------
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

def get_screenshot(url):
    return None  # Placeholder: integrate your screenshot API here

# --------------------------
# LOAD MODEL
# --------------------------
@st.cache_resource
def load_model_and_vectorizer():
    try:
        model = joblib.load(os.path.join(BASE_DIR, "model/phishing_model.pkl"))
        vec = joblib.load(os.path.join(BASE_DIR, "model/vectorizer.pkl"))
        return model, vec
    except:
        return None, None

# ==================================================
# STREAMLIT UI
# ==================================================
st.title("🔍 Analyzer — AI Threat Intelligence")

model, vec = load_model_and_vectorizer()
if model is None or vec is None:
    st.error("❌ ML model or vectorizer missing in `model/` folder. Please add `phishing_model.pkl` and `vectorizer.pkl`.")
    st.stop()

url_input = st.text_input("Enter website URL")
if st.button("Analyze URL") and url_input:
    if "://" not in url_input:
        url_input = "http://" + url_input

    # ML Prediction
    feats = extract_url_features(url_input)
    X = vec.transform([feats])
    pred = int(model.predict(X)[0])
    prob = float(max(model.predict_proba(X)[0]))

    st.subheader("ML Prediction")
    st.write("**Prediction:**", "Safe" if pred == 0 else "High-Risk")
    st.write(f"**Confidence:** {prob:.2f}")

    # Save scan
    row = pd.DataFrame([{
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": url_input,
        "label": pred,
        "score": prob
    }])
    safe_append_to_csv(LOG_FILE, row)

    # Feature breakdown
    st.subheader("Feature Breakdown")
    df = pd.DataFrame([feats]).T.reset_index()
    df.columns = ["Feature", "Value"]
    st.dataframe(df)

    # Pie chart
    fig = px.pie(
        names=["Risk Probability", "Safe Probability"],
        values=[prob, 1 - prob],
        hole=0.5
    )
    st.plotly_chart(fig, use_container_width=True)

    # Threat intelligence
    st.subheader("🔎 Real-Time Threat Intelligence")
    domain = tldextract.extract(url_input).registered_domain
    whois_data, domain_age = get_whois_info(domain)
    st.write("**WHOIS:**", whois_data or "Unavailable")
    if domain_age:
        st.write(f"**Domain Age:** {domain_age} days")
    st.write("**SSL Certificate:**", check_ssl(domain))

    # Screenshot placeholder
    img = get_screenshot(url_input)
    if img:
        st.subheader("Website Screenshot")
        st.image(img, use_column_width=True)

    # Composite Risk
    score = 0
    score += 2 if pred == 1 else 0
    score += 1 if domain_age and domain_age < 180 else 0
    labels = {0: "Low",1:"Low",2:"Medium",3:"Medium",4:"High",5:"High",6:"Critical",7:"Critical",8:"Critical"}
    st.metric("Final Composite Risk Level", f"{labels[min(score,8)]} ({min(score,8)}/8)")
