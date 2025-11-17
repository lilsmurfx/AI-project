import streamlit as st
import joblib, os, pandas as pd
from feature_extractor import extract_url_features
import plotly.express as px
from datetime import datetime, timezone  # <- use timezone-aware datetime

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
        feats = extract_url_features(url_input)
        X = vec.transform([feats])
        pred = int(model.predict(X)[0])
        prob = float(model.predict_proba(X)[0][pred])

        os.makedirs('logs', exist_ok=True)
        log_path = 'logs/scans.csv'
        df_log = pd.DataFrame([{
            'timestamp': datetime.now(timezone.utc).isoformat(),  # <- fixed
            'url': url_input,
            'label': pred,
            'score': prob
        }])
        if os.path.exists(log_path):
            df_log.to_csv(log_path, mode='a', header=False, index=False)
        else:
            df_log.to_csv(log_path, index=False)

        if pred == 1:
            st.error(f"⚠️ **High Risk:** This website is likely malicious. (Confidence {prob:.2f})")
        else:
            st.success(f"✅ **Safe:** This website appears legitimate. (Confidence {prob:.2f})")

        st.subheader('Feature breakdown')
        df = pd.DataFrame([feats]).T.reset_index()
        df.columns = ['feature', 'value']
        st.dataframe(df)

        fig = px.pie(names=['Risk','Confidence'], values=[prob, 1-prob], hole=0.6)
        st.plotly_chart(fig, width='stretch')  # already fixed
