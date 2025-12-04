# app.py - Final Logic with Anti-Impersonation
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

# ---------------- config ----------------
API_KEY = os.getenv("API_KEY", "")
# Threshold ค่าเดิม
PHISH_THRESHOLD = float(os.getenv("PHISH_THRESHOLD", 0.46)) 
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")

# ---------------- 1. Trusted Domains (WhiteList) ----------------
# เว็บพวกนี้ ให้ผ่านตลอด (0.01%)
TRUSTED_ROOTS = {
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'microsoft.com', 'live.com', 'office.com', 'netflix.com', 'amazon.com',
    'shopee.co.th', 'lazada.co.th', 'scb.co.th', 'kasikornbank.com', 'bangkokbank.com',
    'ktb.co.th', 'krungthai.com', 'wikipedia.org', 'pantip.com', 'sanook.com',
    'ac.th', 'go.th', 'or.th'
}

# ---------------- 2. Targeted Brands (Blacklist Logic) ----------------
# กฎ: ถ้าเจอคำพวกนี้ใน URL แต่ Root Domain ไม่ใช่เจ้าของตัวจริง = ฟิชชิ่งแน่นอน (99.9%)
# Format: "คำที่เจอ": "โดเมนเจ้าของตัวจริง"
BRAND_MAP = {
    'facebook': 'facebook.com',
    'instagram': 'instagram.com',
    'twitter': 'twitter.com',
    'paypal': 'paypal.com',
    'netflix': 'netflix.com',
    'microsoft': 'microsoft.com',
    'apple': 'apple.com',
    'icloud': 'icloud.com',
    'google': 'google.com',
    'kbank': 'kasikornbank.com',
    'scb': 'scb.co.th',
    'krungthai': 'krungthai.com'
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

# ---------------- init ----------------
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