# app.py
import os
import joblib
import logging
from fastapi import FastAPI, Request, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from features import create_features_from_url

# ---------------- config ----------------
# อ่านค่า environment (ตั้งค่า .env หรือ export ก่อนรัน)
API_KEY = os.getenv("API_KEY", "")             # ถ้าว่าง = ไม่มีการตรวจ API key
PHISH_THRESHOLD = float(os.getenv("PHISH_THRESHOLD", 0.60))
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*")  # คั่นด้วยคอมม่า ถ้าไม่ต้องการ "*"

# ---------------- init ----------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phish-api")

app = FastAPI(title="Phishing URL Detection API")

# CORS
allow_origins = ["*"] if ALLOWED_ORIGINS == "*" else [o.strip() for o in ALLOWED_ORIGINS.split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# serve static files (index.html under /static/)
if os.path.isdir("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# ---------------- load model ----------------
MODEL_PATH = "model/rf_phishing_model.pkl"
FEATURES_PATH = "model/feature_columns.pkl"

if not os.path.exists(MODEL_PATH) or not os.path.exists(FEATURES_PATH):
    logger.error("Model or feature_columns not found in 'model/' folder.")
    raise RuntimeError("Missing model files. Ensure model/rf_phishing_model.pkl and model/feature_columns.pkl exist.")

model = joblib.load(MODEL_PATH)
feature_cols = joblib.load(FEATURES_PATH)
logger.info(f"Loaded model from {MODEL_PATH} and {len(feature_cols)} feature columns.")

# ---------------- request model ----------------
class PredictRequest(BaseModel):
    url: str

def _check_api_key(x_api_key: str | None):
    if API_KEY:
        if x_api_key != API_KEY:
            logger.warning("Unauthorized access attempt (invalid API key).")
            raise HTTPException(status_code=401, detail="Invalid API key")

def _predict_from_url(url: str):
    # สร้างฟีเจอร์
    X = create_features_from_url(url, feature_cols)

    # ตรวจ shape
    expected_cols = len(feature_cols)
    if X.shape[1] != expected_cols:
        msg = f"Feature mismatch: model expects {expected_cols} columns but got {X.shape[1]}"
        logger.error(msg)
        raise HTTPException(status_code=500, detail=msg)

    # predict
    prob = float(model.predict_proba(X)[0][1])
    label = "phishing" if prob > PHISH_THRESHOLD else "legit"
    return prob, label

# ---------------- routes ----------------
@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/")
def root():
    # ถ้ามี static/index.html ให้ serve หน้าแทน JSON
    index_path = os.path.join("static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Phishing API running"}

@app.post("/predict")
async def predict(request: Request, payload: PredictRequest | None = None, x_api_key: str | None = Header(None)):
    # API key check (ถ้ามีตั้งค่า)
    _check_api_key(x_api_key)

    # รับ url จาก body หรือ query param
    url = None
    if payload and getattr(payload, "url", None):
        url = payload.url
    else:
        url = request.query_params.get("url")

    if not url:
        raise HTTPException(status_code=400, detail="No url provided. Use JSON body {\"url\":\"...\"} or ?url=...")

    try:
        prob, label = _predict_from_url(url)
        logger.info(f"predict url={url} prob={prob:.4f} label={label}")
        return JSONResponse({
            "url": url,
            "probability": prob,
            "label": label,
            "threshold": PHISH_THRESHOLD
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Prediction error")
        raise HTTPException(status_code=500, detail="Internal processing error: " + str(e))

# --- เพิ่ม GET สำหรับทดสอบสะดวก (เช่น พิมพ์ใน browser หรือใช้ vite proxy GET) ---
@app.get("/predict-get")
def predict_get(url: str = Query(None), x_api_key: str | None = Header(None)):
    """
    Endpoint สำหรับทดสอบ: /predict-get?url=...
    ใช้ GET เพื่อความสะดวกตอนทดสอบผ่าน browser address bar.
    (สำหรับ production ถ้าต้องการป้องกัน ให้เอาออก หรือ require API_KEY)
    """
    # API key check (ถ้ามีตั้งค่า)
    _check_api_key(x_api_key)

    if not url:
        raise HTTPException(status_code=400, detail="No url provided. Use ?url=...")

    try:
        prob, label = _predict_from_url(url)
        logger.info(f"predict-get url={url} prob={prob:.4f} label={label}")
        return JSONResponse({
            "url": url,
            "probability": prob,
            "label": label,
            "threshold": PHISH_THRESHOLD
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Prediction error (GET)")
        raise HTTPException(status_code=500, detail="Internal processing error: " + str(e))
