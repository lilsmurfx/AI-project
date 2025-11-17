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
import numpy as np

# For screenshot-based AI
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import torch
from torchvision import transforms
from torchvision.models import vit_b_16

# --------------------------
# --- CONFIG
# --------------------------
JSONWHOIS_API_KEY = "sQtu6yuc5cfrJN"
IPINFO_TOKEN = "YOUR_IPINFO_TOKEN"
GSB_API_KEY = "YOUR_GOOGLE_SAFEBROWSING_API_KEY"
PHISHTANK_API = "https://checkurl.phishtank.com/checkurl/"
SSL_LABS_API = "https://api.ssllabs.com/api/v3/analyze?host={}"

# --------------------------
# --- SCREENSHOT & AI MODEL
# --------------------------
@st.cache_resource
def load_vit_model():
    model = vit_b_16(pretrained=True)
    model.eval()
    return model

def capture_screenshot(url):
    """Use Selenium to capture website screenshot"""
    options = Options()
    options.headless = True
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    driver = webdriver.Chrome(options=options)
    driver.set_window_size(1280, 800)
    driver.get(url)
    png = driver.get_screenshot_as_png()
    driver.quit()
    img = Image.open(BytesIO(png))
    return img

def predict_screenshot_risk(img, model):
    """Return 'Safe' or 'Suspicious' based on screenshot"""
    transform = transforms.Compose([
        transforms.Resize((224, 224)),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.485,0.456,0.406], std=[0.229,0.224,0.225])
    ])
    x = transform(img).unsqueeze(0)
    with torch.no_grad():
        outputs = model(x)
        probs = torch.nn.functional.softmax(outputs, dim=1)
        # Simplified: if top prob < 0.5 => suspicious
        top_prob = probs.max().item()
        return "✅ Safe" if top_prob > 0.5 else "⚠️ Suspicious"

# --------------------------
# --- LOAD ML MODEL
# --------------------------
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
st.title('🔍 Analyzer (ML + Screenshot AI)')

model, vec = load_model_and_vectorizer()
vit_model = load_vit_model()

if model is None:
    st.warning('Model files missing. Run `train_model.py` locally and push model files.')
    st.stop()

url_input = st.text_input('Enter website URL to analyze', '')

if st.button('Analyze URL') and url_input:
    
    # --- ML Prediction ---
    feats = extract_url_features(url_input)
    X = vec.transform([feats])
    pred = int(model.predict(X)[0])
    prob = float(model.predict_proba(X)[0][pred])
    
    st.subheader('ML Prediction')
    if pred == 1:
        st.error(f"⚠️ High Risk (Confidence {prob:.2f})")
    else:
        st.success(f"✅ Safe (Confidence {prob:.2f})")
    
    # --- Screenshot Analysis ---
    st.subheader('🖼 Screenshot-based Analysis')
    try:
        img = capture_screenshot(url_input)
        st.image(img, caption="Website Screenshot", use_column_width=True)
        screenshot_risk = predict_screenshot_risk(img, vit_model)
        if "Safe" in screenshot_risk:
            st.success(f"Screenshot AI: {screenshot_risk}")
        else:
            st.error(f"Screenshot AI: {screenshot_risk}")
    except Exception as e:
        st.warning(f"Screenshot analysis failed: {e}")
