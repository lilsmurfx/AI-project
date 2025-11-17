import pandas as pd
from sklearn.feature_extraction import DictVectorizer
from sklearn.ensemble import GradientBoostingClassifier
import joblib
from feature_extractor import extract_url_features
import os

os.makedirs('model', exist_ok=True)

# Load dataset or create a small sample (for demo only)
if not os.path.exists('data/training_data.csv'):
    sample = pd.DataFrame({
        'url': [
            'https://ecitizen.go.ke/login',
            'http://secure-account-login.xyz/verify',
            'https://www.kenya.go.ke',
            'http://update-account-online.click/login',
            'https://portal.kenya.go.ke/account',
            'http://signin-bank-verify.online/auth'
        ],
        'label': [0,1,0,1,0,1]
    })
    sample.to_csv('data/training_data.csv', index=False)
    print('Wrote sample data to data/training_data.csv')

# Training
import pandas as pd

df = pd.read_csv('data/training_data.csv')
X_dicts = [extract_url_features(u) for u in df['url'].astype(str).tolist()]
y = df['label'].values
vec = DictVectorizer(sparse=False)
X = vec.fit_transform(X_dicts)
clf = GradientBoostingClassifier(n_estimators=200, random_state=42)
clf.fit(X, y)
joblib.dump(vec, 'model/vectorizer.pkl')
joblib.dump(clf, 'model/phishing_model.pkl')
print('Saved model and vectorizer to model/')
