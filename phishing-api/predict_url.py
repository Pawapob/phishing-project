# predict_url.py (safe dual-mode: v1 pipeline + legacy fallback)
import joblib
import hashlib
import pandas as pd
import os
from urllib.parse import urlparse
from scipy.sparse import csr_matrix, hstack
from features import create_features_from_url

# ---------------- helper ----------------
def md5(path):
    if not os.path.exists(path):
        return "FILE NOT FOUND"
    with open(path,'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

# ---------------- model paths ----------------
# v1 artifacts
MODEL_V1_PATH = "model/phishing_model_v1.pkl"
TFIDF_V1_PATH = "model/phishing_tfidf_v1.pkl"
SCALER_V1_PATH = "model/phishing_scaler_v1.pkl"
FEATURES_NUM_V1_PATH = "model/phishing_num_features_v1.pkl"

# legacy model
LEGACY_MODEL_PATH = "model/rf_phishing_model.pkl"
LEGACY_FEATURES_PATH = "model/feature_columns.pkl"

# ---------------- auto-load logic ----------------
use_v1 = False
model = None
tfidf = None
scaler = None
numeric_features = None
feature_cols = None

print("Checking model files...")
print("Model v1 MD5:", md5(MODEL_V1_PATH))
print("Legacy model MD5:", md5(LEGACY_MODEL_PATH))

# Try v1 first
if (
    os.path.exists(MODEL_V1_PATH)
    and os.path.exists(TFIDF_V1_PATH)
    and os.path.exists(SCALER_V1_PATH)
    and os.path.exists(FEATURES_NUM_V1_PATH)
):
    try:
        model = joblib.load(MODEL_V1_PATH)
        tfidf = joblib.load(TFIDF_V1_PATH)
        scaler = joblib.load(SCALER_V1_PATH)
        numeric_features = joblib.load(FEATURES_NUM_V1_PATH)
        use_v1 = True
        print("Loaded Model v1 (numeric + tfidf pipeline)")
        print("Numeric feature count:", len(numeric_features))
    except Exception as e:
        print("Failed loading v1:", e)
        print("Falling back to legacy model...")
        use_v1 = False

# If v1 not loaded → fallback to legacy
if not use_v1:
    model = joblib.load(LEGACY_MODEL_PATH)
    feature_cols = joblib.load(LEGACY_FEATURES_PATH)
    print("Loaded legacy RandomForest model")
    print("Legacy feature count:", len(feature_cols))

print("Mode:", "v1" if use_v1 else "legacy")
print("--------------------------------------")

# ---------------- predict function ----------------
def predict_url(url, threshold=0.6, show_features=False):
    if use_v1:
        # ------------ V1 pipeline (numeric + scaled + tfidf) ------------
        # numeric features
        X_num_df = create_features_from_url(url, numeric_features)

        if X_num_df.shape[1] != len(numeric_features):
            raise ValueError(
                f"Numeric feature mismatch (v1): DF has {X_num_df.shape[1]}, expected {len(numeric_features)}"
            )

        # scale numeric
        X_num = scaler.transform(X_num_df.fillna(0))
        X_num_sp = csr_matrix(X_num)

        # tfidf
        p = urlparse(url)
        text = (p.path or "") + "?" + (p.query or "")
        X_tfidf = tfidf.transform([text])

        # combined
        X = hstack([X_num_sp, X_tfidf])

        prob = model.predict_proba(X)[0][1]
        label = int(prob > threshold)

        if show_features:
            pd.set_option("display.max_rows", 999)
            print("\n=== numeric features (v1) ===")
            print(X_num_df.T)

        print(url)
        print("prob:", f"{prob*100:.2f}%", "=>", "Phishing" if label else "Legit")
        return prob, label

    else:
        # ------------ Legacy pipeline ------------
        X = create_features_from_url(url, feature_cols)

        if X.shape[1] != len(feature_cols):
            raise ValueError(
                f"Legacy feature mismatch: DF cols={X.shape[1]}, expected={len(feature_cols)}"
            )

        if show_features:
            pd.set_option("display.max_rows", 999)
            print("=== legacy feature vector ===")
            print(X.T)

        prob = model.predict_proba(X)[0][1]
        label = int(prob > threshold)

        print(url)
        print("prob:", f"{prob*100:.2f}%", "=>", "Phishing" if label else "Legit")
        return prob, label

# ---------------- example run ----------------
if __name__ == "__main__":
    predict_url("https://www.youtube.com/", threshold=0.6, show_features=False)
