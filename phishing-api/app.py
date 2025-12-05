import os
import joblib
import logging
import tldextract
from fastapi import FastAPI, Request, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from features import create_features_from_url
from scipy.sparse import hstack, csr_matrix
from urllib.parse import urlparse

API_KEY = os.getenv("API_KEY", "")
# Threshold เปลี่ยนตามใจ
PHISH_THRESHOLD = float(os.getenv("PHISH_THRESHOLD", 0.46)) 
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")

# ---------------- 1. Trusted Domains (WhiteList) ----------------
# เว็บพวกนี้ ให้ผ่านตลอด (0.01%)
TRUSTED_ROOTS = {
    # --- Search & Social Media ---
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com', 
    'twitter.com', 'x.com', 'tiktok.com', 'linkedin.com', 'pinterest.com',
    'reddit.com', 'line.me', 'whatsapp.com', 'telegram.org', 'discord.com',
    
    # --- Tech & Cloud Services ---
    'microsoft.com', 'live.com', 'office.com', 'sharepoint.com',
    'apple.com', 'icloud.com', 'dropbox.com', 'zoom.us',
    'github.com', 'gitlab.com', 'stackoverflow.com',
    'adobe.com', 'canva.com', 'wetransfer.com',
    
    # --- Streaming & Entertainment ---
    'netflix.com', 'spotify.com', 'twitch.tv', 'viutv.com', 'iq.com',
    'steamcommunity.com', 'steampowered.com', 'roblox.com', 'epicgames.com',
    'spotify.com', # เคสพิเศษที่เคยเจอ
    
    # --- E-Commerce & Shopping (Thai & Global) ---
    'amazon.com', 'ebay.com', 'aliexpress.com', 'alibaba.com',
    'shopee.co.th', 'lazada.co.th', 'kaidee.com', 'wongnai.com',
    
    # --- Banking & Finance (Thai) - เน้นที่ไม่ได้ลงท้ายด้วย .or.th/.go.th ---
    'scb.co.th', 'kasikornbank.com', 'bangkokbank.com', 'krungthai.com', 'ktb.co.th',
    'bay.co.th', 'krungsri.com', # กรุงศรี
    'ttbbank.com', 'tmbbank.com', # TTB
    'uob.co.th', 'cimbthai.com', 'lhbank.co.th',
    'truemoney.com', 'paypal.com',
    
    # --- Logistics (ขนส่ง) ---
    'thailandpost.co.th', 'kerryexpress.com', 'flash-express.com', 'jtexpress.co.th',
    
    # --- Service & Travel ---
    'grab.com', 'foodpanda.co.th', 'lineman.line.me',
    'agoda.com', 'booking.com', 'traveloka.com', 'trip.com',
    'airasia.com', 'thaiairways.com',
    
    # --- Telecom (ค่ายมือถือ/เน็ต) ---
    'ais.co.th', 'dtac.co.th', 'true.th', 'ntplc.co.th', '3bb.co.th',
    
    # --- News & Portal (Thai) ---
    'wikipedia.org', 'pantip.com', 'sanook.com', 'kapook.com', 'mthai.com',
    'thairath.co.th', 'dailynews.co.th', 'matichon.co.th', 'khaosod.co.th',
    'bangkokpost.com', 'workpointtv.com', 'one31.net',
    
    # --- TLDs ที่เชื่อถือได้ (Government/Education/Organization) ---
    # เนื่องจากเรามี logic เช็ค suffix ด้านล่างอยู่แล้ว (.ac.th, .go.th, .or.th)
    # รายชื่อพวกนี้ใส่กันเหนียวไว้สำหรับโดเมนหลัก
    'ac.th', 'go.th', 'or.th', 'mi.th'

# ---------------- 2. Targeted Brands (Blacklist Logic) ----------------
# กฎ: ถ้าเจอคำพวกนี้ใน URL แต่ Root Domain ไม่ใช่เจ้าของตัวจริง = ฟิชชิ่งแน่นอน (99.9%)
# Format: "คำที่เจอใน URL": "โดเมนเจ้าของตัวจริง"
}
BRAND_MAP = {
    # --- Social & Global Tech ---
    'facebook': 'facebook.com',
    'instagram': 'instagram.com',
    'twitter': 'twitter.com',
    'tiktok': 'tiktok.com',
    'line': 'line.me',
    'whatsapp': 'whatsapp.com',
    'google': 'google.com',
    'gmail': 'google.com',
    'youtube': 'youtube.com',
    'microsoft': 'microsoft.com',
    'apple': 'apple.com',
    'icloud': 'icloud.com',
    'netflix': 'netflix.com',
    'spotify': 'spotify.com',
    'amazon': 'amazon.com',
    'paypal': 'paypal.com',
    'dropbox': 'dropbox.com',

    # --- Shopping (Thai) ---
    'shopee': 'shopee.co.th',
    'lazada': 'lazada.co.th',
    'kaidee': 'kaidee.com',

    # --- Banking (Thai) ---
    'kbank': 'kasikornbank.com',     # กสิกร
    'kasikorn': 'kasikornbank.com',
    'scb': 'scb.co.th',              # ไทยพาณิชย์
    'siamcommercial': 'scb.co.th',
    'ktb': 'ktb.co.th',              # กรุงไทย
    'krungthai': 'krungthai.com',
    'bangkokbank': 'bangkokbank.com',# กรุงเทพ
    'bualuang': 'bangkokbank.com',
    'krungsri': 'krungsri.com',      # กรุงศรี
    'ttb': 'ttbbank.com',            # ทีทีบี
    'tmb': 'tmbbank.com',
    'uob': 'uob.co.th',              # ยูโอบี
    'cimb': 'cimbthai.com',          # ซีไอเอ็มบี
    'gsb': 'gsb.or.th',              # ออมสิน
    'truemoney': 'truemoney.com',    # ทรูมันนี่

    # --- Telecom (Thai) ---
    'ais': 'ais.co.th',
    'dtac': 'dtac.co.th',
    'true': 'true.th',               # ทรู (ใช้โดเมนใหม่ true.th หรือ truecorp.co.th)
    'truemove': 'true.th',
    '3bb': '3bb.co.th',
    'ntplc': 'ntplc.co.th',

    # --- Logistics (Thai) ---
    'thailandpost': 'thailandpost.co.th',
    'kerry': 'kerryexpress.com',
    'flash': 'flash-express.com',
    'jtexpress': 'jtexpress.co.th',
    'ninjavan': 'ninjavan.co',

    # --- Service & Others ---
    'grab': 'grab.com',
    'foodpanda': 'foodpanda.co.th',
    'agoda': 'agoda.com',
    'booking': 'booking.com',
    'traveloka': 'traveloka.com',
    'airasia': 'airasia.com'
}

def analyze_url_logic(url):
    """
    ฟังก์ชันรวม Logic ทั้งหมด: Whitelist -> Impersonation -> AI
    """
    try:
        extracted = tldextract.extract(url)
        root_domain = f"{extracted.domain}.{extracted.suffix}".lower()
        full_domain_str = f"{extracted.subdomain}.{root_domain}".lower() # เช่น facebook.com.scam.site
        
        # Step 1: Check Whitelist (เว็บจริง ให้ผ่านเลย)
        if root_domain in TRUSTED_ROOTS:
            return 0.01, "legit", "Trusted Domain"
        if extracted.suffix in ['ac.th', 'go.th', 'or.th']:
            return 0.01, "legit", "Trusted TLD"

        # Step 2: Check Impersonation (ดักพวกแอบอ้าง)
        # วนลูปเช็คว่ามีชื่อแบรนด์ดังใน URL ไหม
        for brand_keyword, official_domain in BRAND_MAP.items():
            # ถ้าเจอชื่อแบรนด์ใน URL (เช่นมีคำว่า facebook) 
            # แต่ Root Domain ไม่ใช่ของจริง (ไม่ใช่ facebook.com)
            if brand_keyword in full_domain_str and root_domain != official_domain:
                return 0.99, "phishing", f"Impersonating {brand_keyword}"

        # Step 3: ถ้าไม่เข้าเงื่อนไขบน ส่งให้ AI ตัดสิน
        return None, None, None # ส่งต่อให้ AI

    except Exception as e:
        logger.error(f"Domain analysis error: {e}")
        return None, None, None

#เมื่อมี log ใด ๆส่งหน้า uvicorn print ออก console ให้ดู
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phish-api")

app = FastAPI(title="Phishing URL Detection API (Final+)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# ---------------- Load Model ----------------
MODEL_PATH = "model/phishing_model_xgb_calibrated.pkl"
TFIDF_PATH = "model/phishing_tfidf_v1.pkl"
SCALER_PATH = "model/phishing_scaler_v1.pkl"
FEATURES_NUM_PATH = "model/phishing_num_features_v1.pkl"

model = None
tfidf = None
scaler = None
numeric_features = None

if os.path.exists(MODEL_PATH) and os.path.exists(TFIDF_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        tfidf = joblib.load(TFIDF_PATH)
        scaler = joblib.load(SCALER_PATH)
        numeric_features = joblib.load(FEATURES_NUM_PATH)
        logger.info("Models loaded successfully.")
    except:
        logger.error("Failed to load models.")

# ---------------- Main Logic ----------------
class PredictRequest(BaseModel):
    url: str

def _predict_process(url: str):
    # 1. ใช้ Logic กรองก่อน (Whitelist / Blacklist)
    prob, label, reason = analyze_url_logic(url)
    if prob is not None:
        logger.info(f"Logic matched: {url} -> {label} ({reason})")
        return prob, label

    # 2. ถ้าไม่เจอ ให้ AI ทำงาน
    if not model:
        raise HTTPException(status_code=503, detail="AI Model unavailable")

    X_num_df = create_features_from_url(url, numeric_features)
    X_num = scaler.transform(X_num_df.fillna(0))
    X_num_sp = csr_matrix(X_num)

    p = urlparse(url)
    text = (p.path or '') + '?' + (p.query or '')
    X_tfidf = tfidf.transform([text])

    X = hstack([X_num_sp, X_tfidf])
    
    # AI Predict
    prob = float(model.predict_proba(X)[0][1])
    label = "phishing" if prob > PHISH_THRESHOLD else "legit"
    
    return prob, label

# ---------------- Routes ----------------
@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/")
def root():
    index_path = os.path.join("static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Phishing API Running"}

@app.post("/predict")
async def predict(request: Request, payload: PredictRequest | None = None):
    url = payload.url if payload else request.query_params.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="No URL provided")

    try:
        prob, label = _predict_process(url)
        return JSONResponse({
            "url": url,
            "probability": prob,
            "label": label,
            "threshold": PHISH_THRESHOLD
        })
    except Exception as e:
        logger.exception("Error")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/predict-get")
def predict_get(url: str = Query(...)):
    try:
        prob, label = _predict_process(url)
        return JSONResponse({
            "url": url,
            "probability": prob,
            "label": label,
            "threshold": PHISH_THRESHOLD
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))