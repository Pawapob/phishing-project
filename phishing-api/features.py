import re
import math
from urllib.parse import urlparse
import tldextract
import pandas as pd

#คำเสี่ยงที่ Hacker ชอบใช้ 
SENSITIVE_TOKENS = [
    'login', 'secure', 'update', 'verify', 'account', 'signin', 'wp-login', 'confirm',
    'banking', 'paypal', 'limited', 'suspend', 'client', 'payment', 'bill', 'invoice',
    'admin', 'service', 'bonus', 'free', 'gift', 'netflix', 'apple', 'google', 'hotmail',
    'yahoo', 'support', 'protect', 'secure', 'safe'
]

#นามสกุลโดเมนเสี่ยง
RISKY_TLDS = {'xyz', 'top', 'club', 'online', 'vip', 'tk', 'ml', 'ga', 'cf', 'gq', 'men', 'loan', 'date', 'win', 'cn', 'ru'}
#คำมั่วของตัวอัการ
def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s: freq[c] = freq.get(c, 0) + 1
    L = len(s)
    return -sum((f/L) * math.log2(f/L) for f in freq.values())
#ลิ้งตัวย่อ
def is_shortened(url: str) -> int:
    shorteners = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                 r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                 r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                 r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                 r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                 r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co"
    return int(bool(re.search(shorteners, url, flags=re.IGNORECASE)))
#ฟังก์ชันหลักที่สกัดฟีเจอร์
def extract_basic_features(url: str) -> dict:
    parsed = urlparse(url)
    host = (parsed.netloc or parsed.path or "").lower()
    ext = tldextract.extract(host)
    path = parsed.path or ''
    
    feats = {}
    #ข้อมูลพื้นฐานวัดความประหลาดของ UR
    feats['url_length'] = len(url)
    feats['hostname_length'] = len(host)
    feats['num_dots'] = host.count('.')
    feats['num_hyphens'] = host.count('-')
    feats['num_slash'] = url.count('/')
    feats['num_query'] = url.count('?') + url.count('&')
    feats['num_digits'] = sum(c.isdigit() for c in url)
    
   
    feats['has_ip'] = int(bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', host)))  #ช้ IP ตรง ๆ แทนโดเมน 
    feats['no_https'] = int(not url.lower().startswith('https')) #ไม่มี HTTPS
    feats['is_shortened'] = is_shortened(url) 
    feats['has_punycode'] = 1 if "xn--" in host else 0 #มี punycode ในโดเมน
    feats['is_risky_tld'] = 1 if ext.suffix in RISKY_TLDS else 0 #นามสกุลโดเมนเสี่ยง
    
    #วัดความมั่วของ hostname และ path
    feats['entropy_host'] = shannon_entropy(host)
    feats['entropy_path'] = shannon_entropy(path)
    
    #จำนวนระดับของ subdomain
    feats['subdomain_levels'] = len([d for d in ext.subdomain.split('.') if d]) if ext.subdomain else 0
    
    #นับคำเสี่ยงใน URL ยิ่งเยอะ ยิ่งน่าสงสัย
    feats['num_sensitive_tokens'] = sum(int(t in url.lower()) for t in SENSITIVE_TOKENS)
    
    return feats
#ฟังก์ชันสร้าง DataFrame ให้โมเดล
def create_features_from_url(url: str, numeric_feature_names: list):
    """
    สร้าง DataFrame 1 แถวจาก url เพื่อเตรียมส่งให้ Model
    """
    ex = extract_basic_features(url)
    # คืนค่าเป็น DataFrame ที่เรียงคอลัมน์ตามที่ Model ต้องการ
    ordered_row = {k: ex.get(k, 0) for k in numeric_feature_names}
    return pd.DataFrame([ordered_row])