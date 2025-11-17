import re
from urllib.parse import urlparse

# tldextract is recommended in requirements; if unavailable, the extractor falls back to simple parsing.
try:
    import tldextract
    _HAS_TLDEXTRACT = True
except Exception:
    _HAS_TLDEXTRACT = False

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "account", "update", "verify", "confirm", "bank", "support", "signin"
]

IP_ADDR_RE = re.compile(r"^(?:\\d{1,3}\\.){3}\\d{1,3}$")

def has_ip(domain):
    return bool(IP_ADDR_RE.match(domain))

def extract_url_features(url: str):
    url = (url or "").strip()
    if not url:
        return {}
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    path = parsed.path or ""

    if _HAS_TLDEXTRACT:
        ext = tldextract.extract(domain)
        tld = ext.suffix or ""
        subdomain = ext.subdomain or ""
        registrable = ext.domain or ""
    else:
        # naive fallback
        parts = domain.split('.')
        tld = parts[-1] if len(parts) > 1 else ''
        registrable = parts[-2] if len(parts) > 1 else parts[0]
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''

    features = {}
    features["url_length"] = len(url)
    features["num_dots"] = domain.count('.')
    features["has_https"] = int(parsed.scheme.lower() == 'https')
    features["num_subdirs"] = max(0, path.count('/'))
    features["tld_length"] = len(tld)
    features["subdomain_length"] = len(subdomain)
    features["domain_length"] = len(registrable)
    features["has_ip"] = int(has_ip(registrable))
    features["num_hyphens"] = domain.count('-')
    lower = url.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        features[f"kw_{kw}"] = int(kw in lower)
    suspicious_tlds = {"xyz", "top", "click", "online", "tk", "ru"}
    features["suspicious_tld"] = int(tld in suspicious_tlds)
    features["path_len"] = len(path)
    features["num_query"] = 1 if parsed.query else 0
    return features
