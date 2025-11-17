import streamlit as st
import joblib, os, pandas as pd
from feature_extractor import extract_url_features
import plotly.express as px
from datetime import datetime, timezone
import socket
import ssl
import tldextract
import requests

# --- WHOIS API function ---
def get_whois_info(domain):
    try:
        api_key = "sQtu6yuc5cfrJN"  # Your JSONWHOIS API key
        url = f"https://jsonwhoisapi.com/api/v1/whois?identifier={domain}"
        headers = {"Authorization": f"Token token={api_key}"}
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            creation_date = data.get('registry_data', {}).get('creation_date')
            if creation_date:
                creation_date = datetime.fromisoformat(creation_date).replace(tzinfo=timezone.utc)
                domain_age_days = (datetime.now(timezone.utc) - creation_date).days
            else:
                domain_age_days = None
            return data, domain_age_days
        else:
            return None, None
    except Exception:
        return None, None


@st.cache_resource
def load_model_and_vectorizer():
    model_path = 'model/phishing_model.pkl'
    vectorizer_path = 'model/vectorizer.pkl'
    if os.path.exists(model_path) and os.path.exists(vectorizer_path):
        vec = joblib.load(vectorizer_path)
        model = joblib.load(model_path)
        return model, vec
    return None, None


st.title('🔍 Analyzer')
model, vec = load_model_and_vectorizer()

if model is None:
    st.warning('Model files not found. Please run `python train_model.py` locally and push model/ files to the repo.')
    st.stop()

url_input = st.text_input('Enter a website URL to analyze', '')

if st.button('Analyze URL'):
    if not url_input:
        st.error('Please enter a URL')
    else:
        # --- ML prediction ---
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
        if pred == 1:
            st.error(f"⚠️ **High Risk:** This website is likely malicious. (Confidence {prob:.2f})")
        else:
            st.success(f"✅ **Safe:** This website appears legitimate. (Confidence {prob:.2f})")

        # --- Feature Breakdown ---
        st.subheader('Feature breakdown')
        df = pd.DataFrame([feats]).T.reset_index()
        df.columns = ['feature', 'value']
        st.dataframe(df)

        # --- ML Pie Chart ---
        fig = px.pie(names=['Risk','Confidence'], values=[prob, 1-prob], hole=0.6)
        st.plotly_chart(fig, width='stretch')

        # --- Real-time Phishing Enhancements ---
        st.subheader('🔎 Real-time URL Analysis')

        # Domain extraction
        domain = tldextract.extract(url_input).registered_domain

        # WHOIS & domain age via API
        whois_data, domain_age_days = get_whois_info(domain)
        if domain_age_days is not None:
            st.write(f"Domain age: {domain_age_days} days")
        else:
            st.write("WHOIS info not available")

        # SSL certificate check
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(3.0)
                s.connect((domain, 443))
                cert = s.getpeercert()
                ssl_valid = True
            st.write("SSL certificate: ✅ Valid")
        except Exception:
            ssl_valid = False
            st.write("SSL certificate: ⚠️ Invalid or not found")

        # IP Geolocation
        try:
            ip_addr = socket.gethostbyname(domain)
            st.write(f"IP Address: {ip_addr}")
            st.write("Geolocation: Use a free IP API for full details")
        except Exception as e:
            st.write(f"IP resolution failed: {e}")

        # URL reputation check placeholder
        try:
            response = requests.get(f"https://checkurl.phishtank.com/checkurl/?url={url_input}")
            if response.status_code == 200:
                st.write("URL reputation check: ✅ Safe (example API placeholder)")
            else:
                st.write("URL reputation check unavailable")
        except Exception:
            st.write("URL reputation check failed")

        # --- Composite Risk Score ---
        score_components = []
        if pred == 1:
            score_components.append(1)
        if ssl_valid == False:
            score_components.append(1)
        if domain_age_days is not None and domain_age_days < 180:
            score_components.append(1)
        composite_risk = min(sum(score_components), 3)
        risk_labels = {0:'Low', 1:'Medium', 2:'High', 3:'Critical'}
        st.metric("Composite Risk Score", f"{risk_labels[composite_risk]} ({composite_risk}/3)")
