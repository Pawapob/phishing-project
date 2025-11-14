# predict_url.py
import joblib
import hashlib
import pandas as pd
import os
from features import create_features_from_url   # ต้องมีไฟล์ features.py ในโฟลเดอร์เดียวกัน

# --- helper: md5 check (เช็คว่าไฟล์โมเดลที่ใช้ตรงกับที่มึงคิด) ---
def md5(path):
    with open(path,'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

print("Model file md5:", md5("model/rf_phishing_model.pkl"))
print("Feature columns file md5:", md5("model/feature_columns.pkl"))

# --- โหลดโมเดล + feature list (ต้องมาจากไฟล์เดียวกับ Colab) ---
model = joblib.load("model/rf_phishing_model.pkl")
feature_cols = joblib.load("model/feature_columns.pkl")
print("จำนวน feature ที่โมเดลต้องการ:", len(feature_cols))

# --- debug: แสดง 20 ฟีเจอร์แรกของ feature_cols ---
print("feature_cols[:20]:", feature_cols[:20])

# --- ฟังก์ชัน predict ตามที่มึงต้องการ ---
def predict_url(url, threshold=0.6, show_features=False):
    # สร้าง DataFrame ฟีเจอร์จาก URL (ต้องคืน DataFrame shape (1, len(feature_cols)))
    X = create_features_from_url(url, feature_cols)

    # sanity checks
    if X.shape[1] != len(feature_cols):
        raise ValueError(f"Feature mismatch: X has {X.shape[1]} cols but model expects {len(feature_cols)}")

    # debug: ถ้าขอแสดงให้เห็นรายละเอียดฟีเจอร์
    if show_features:
        pd.set_option('display.max_rows', 999)
        print("=== feature vector (name : value) ===")
        print(X.T)

    prob = model.predict_proba(X)[0][1]
    label = int(prob > threshold)

    print(url)
    print("prob:", f"{prob*100:.2f}%", "=>", "Phishing" if label else "Legit")
    return prob, label

# --- ตัวอย่างการรัน (เปลี่ยน threshold ถ้าต้องการ) ---
if __name__ == "__main__":
    # ถ้าต้องการดูฟีเจอร์ ให้ใส่ show_features=True
    predict_url("https://www.youtube.com/", threshold=0.6, show_features=False)
