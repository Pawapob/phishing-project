import re
from urllib.parse import urlparse
import tldextract
import pandas as pd

def create_features_from_url(url, feature_cols):
    feats = {col: 0 for col in feature_cols}
    parsed = urlparse(url)
    host = parsed.netloc.lower() or parsed.path.lower()
    ext = tldextract.extract(host)
    domain = ext.domain + "." + ext.suffix if ext.suffix else ext.domain

    simple = {
        "UrlLength": len(url),
        "length_url": len(url),
        "NumDots": host.count("."),
        "nb_dots": host.count("."),
        "NumDash": host.count("-"),
        "nb_hyphens": host.count("-"),
        "nb_slash": url.count("/"),
        "NumUnderscore": url.count("_"),
        "NumPercent": url.count("%"),
        "NumHash": url.count("#"),
        "NumQueryComponents": url.count("&"),
        "NumNumericChars": sum(c.isdigit() for c in url),
        "IpAddress": int(bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', host))),
        "ip": int(bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', host))),
        "NoHttps": int(not url.lower().startswith("https")),
        "https_token": int("https" in url.lower()),
        "http_in_path": int("http" in parsed.path.lower()),
        "HostnameLength": len(host),
        "length_hostname": len(host),
        "nb_subdomains": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "SubdomainLevel": len(ext.subdomain.split(".")) if ext.subdomain else 0
    }

    for k,v in simple.items():
        if k in feats:
            feats[k] = v

    tokens = ['login','secure','update','verify','account','signin','wp-login']
    if "NumSensitiveWords" in feats:
        feats["NumSensitiveWords"] = sum(int(t in url.lower()) for t in tokens)

    if "prefix_suffix" in feats:
        feats["prefix_suffix"] = int("-" in domain)

    brand_list = ["google","bank","paypal","facebook","apple","youtube","bangkokbank"]
    if "brand_in_path" in feats:
        feats["brand_in_path"] = sum(b in parsed.path.lower() for b in brand_list)
    if "brand_in_subdomain" in feats:
        feats["brand_in_subdomain"] = sum(b in ext.subdomain.lower() for b in brand_list)

    return pd.DataFrame([feats])
