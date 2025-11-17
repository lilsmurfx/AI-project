import streamlit as st
import joblib, os, pandas as pd, requests, socket, ssl
from feature_extractor import extract_url_features
from datetime import datetime, timezone
import plotly.express as px
import tldextract
from PIL import Image
from io import BytesIO

# =====================================================
#                 CONFIG (Safe Defaults)
# =====================================================
JSONWHOIS_API_KEY = "sQtu6yuc5cfrJN"     # Replace with env var in production
IPINFO_TOKEN = None
GSB_API_KEY = None
PHISHTANK_API = "https://checkurl.phishtank.com/checkurl/"
SCREENSHOT_API = "https://api.screenshotapi.net/screenshot?token=YOUR_API_KEY&url={}"

# =====================================================
#                   SAFE HELPERS
# =====================================================

def safe_request(url, method="GET", timeout=5, **kwargs):
    """Safe HTTP request wrapper to prevent crashes."""
    try:
        if method == "POST":
            r = requests.post(url, timeout=timeout, **kwargs)
        else:
            r = requests.get(url, timeout=timeout, **kwargs)

        if r.status_code == 200:
            return r
    except:
        return None
    return None


def get_whois_info(domain: str):
    """Fetch WHOIS with JSONWHOIS + fallback for .ke."""
    try:
        url = f"https://jsonwhoisapi.com/api/v1/whois?identifier={domain}"
        headers = {"Authorization": f"Token token={JSONWHOIS_API_KEY}"}
        r = safe_request(url, headers=headers)
        if r:
            data = r.json()

            creation = (
                data.get("registry_data", {}).get("creation_date") or
                data.get("created_at")
            )

            if creation:
                try:
                    creation_date = datetime.fromisoformat(creation).replace(tzinfo=timezone.utc)
                    age = (datetime.now(timezone.utc) - creation_date).days
                except:
                    age = None
            else:
                age = None

            return data, age
    except:
        pass

    # Fallback for Kenya domains
    if domain.endswith(".ke") or domain.endswith(".co.ke"):
        return {"registrar": "KeNIC (fallback)"}, None

    return None, None


def get_ip_info(domain):
    """Get IP + geolocation (safe)."""
    url = f"https://ipinfo.io/{domain}/json"
    if IPINFO_TOKEN:
        url += f"?token={IPINFO_TOKEN}"
    r = safe_request(url)
    return r.json() if r else None


def check_url_phishtank(url):
    """PhishTank placeholder check with safe fallback."""
    r = safe_request(f"{PHISHTANK_API}?url={url}")
    if r:
        return "✅ Safe (PhishTank placeholder)"
    return "⚠️ Possibly malicious (PhishTank)"


def check_url_gsb(url):
    """Google Safe Browsing placeholder (safe)."""
    if not GSB_API_KEY:
        return "GSB not configured"

    body = {
        "client": {"clientId": "govsec-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":[{"url":url}]
        }
    }

    r = safe_request(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
        method="POST",
        json=body
    )

    if r and r.json().get("matches"):
        return "⚠️ Malicious (Google Safe Browsing)"
    return "✅ Safe (Google Safe Browsing)"


def check_ssl(domain):
    """Check SSL certificate validity."""
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
    """Return screenshot image safely."""
    r = safe_request(SCREENSHOT_API.format(url), timeout=10)
    if not r:
        return None
    try:
        return Image.open(BytesIO(r.content))
    except:
        return None


@st.cache_resource
def load_model_and_vectorizer():
    """Load ML model safely with fallbacks."""
    try:
        model = joblib.load("model/phishing_model.pkl")
        vec = joblib.load("model/vectorizer.pkl")
        return model, vec
    except:
        return None, None


# =====================================================
#                 STREAMLIT UI
# =====================================================
st.title("🔍 Analyzer — AI Threat Intelligence")

model, vec = load_model_and_vectorizer()
if model is None:
    st.error("❌ Model not found. Upload model/phishing_model.pkl + vectorizer.pkl.")
    st.stop()

url_input = st.text_input("Enter a website URL to analyze", "")

# =====================================================
#                ANALYZE URL BUTTON
# =====================================================
if st.button("Analyze URL") and url_input:

    # URL sanity check
    if "://" not in url_input:
        url_input = "http://" + url_input

    # =====================================================
    #                  ML Prediction
    # =====================================================
    try:
        feats = extract_url_features(url_input)
        X = vec.transform([feats])
        pred = int(model.predict(X)[0])
        prob = float(max(model.predict_proba(X)[0]))
    except Exception as e:
        st.error("❌ Feature extraction or model prediction failed.")
        st.stop()

    label = "Safe" if pred == 0 else "High-Risk"
    color = "success" if pred == 0 else "error"

    st.subheader("ML Prediction")
    st.write(f"**Prediction:** {label}")
    st.write(f"**Confidence:** {prob:.2f}")

    # =====================================================
    #                 Log the Scan
    # =====================================================
    os.makedirs("logs", exist_ok=True)
    row = pd.DataFrame([{
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": url_input,
        "label": pred,
        "score": prob
    }])

    log_file = "logs/scans.csv"
    if os.path.exists(log_file):
        row.to_csv(log_file, mode="a", header=False, index=False)
    else:
        row.to_csv(log_file, index=False)

    # =====================================================
    #                 Feature Breakdown
    # =====================================================
    st.subheader("Feature Breakdown")
    df = pd.DataFrame([feats]).T.reset_index()
    df.columns = ["Feature", "Value"]
    st.dataframe(df)

    # Pie chart
    fig = px.pie(
        names=["Risk Probability", "Safe Probability"],
        values=[prob, 1 - prob],
        hole=0.5,
    )
    st.plotly_chart(fig, use_container_width=True)

    # =====================================================
    #            REAL-TIME THREAT INTELLIGENCE
    # =====================================================
    st.subheader("🔎 Real-Time Threat Intelligence")

    domain = tldextract.extract(url_input).registered_domain

    # WHOIS
    whois_data, domain_age = get_whois_info(domain)
    st.write("**WHOIS:**", whois_data or "Unavailable")
    if domain_age:
        st.write(f"**Domain Age:** {domain_age} days")

    # SSL
    st.write("**SSL Certificate:**", check_ssl(domain))

    # IP + GEO
    ip_info = get_ip_info(domain)
    if ip_info:
        st.write(f"**IP:** {ip_info.get('ip')}")
        st.write(f"**Location:** {ip_info.get('city')}, {ip_info.get('region')}, {ip_info.get('country')}")
    else:
        st.write("IP / Geolocation unavailable")

    # Reputation
    st.write("**PhishTank:**", check_url_phishtank(url_input))
    st.write("**Google Safe Browsing:**", check_url_gsb(url_input))

    # =====================================================
    #                SCREENSHOT
    # =====================================================
    img = get_screenshot(url_input)
    if img:
        st.subheader("Website Screenshot")
        st.image(img, use_container_width=True)

    # =====================================================
    #           Composite Risk Scoring System
    # =====================================================
    score = 0
    score += 2 if pred == 1 else 0
    score += 1 if (domain_age and domain_age < 180) else 0
    score += 2 if "Safe" not in check_url_phishtank(url_input) else 0
    score += 2 if "Safe" not in check_url_gsb(url_input) else 0
    score += 1 if "Valid" not in check_ssl(domain) else 0

    risk_levels = {
        0: "Low", 1: "Low",
        2: "Medium", 3: "Medium",
        4: "High", 5: "High",
        6: "Critical", 7: "Critical", 8: "Critical"
    }

    final_score = min(score, 8)

    st.metric("Final Composite Risk Level", f"{risk_levels[final_score]} ({final_score}/8)")

