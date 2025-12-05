
import { useState } from "react";
import "./App.css";


const API_URL = "/predict";

export default function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function handleCheck(e) {
    e && e.preventDefault();
    setError(null);
    setResult(null);

    if (!url.trim()) { 
      setError("❌ กรุณาวาง URL ที่ต้องการตรวจสอบก่อนครับ"); 
      return; 
    }

    setLoading(true);
    try {
      // เรียก API
      const res = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() })
      });

      if (!res.ok) {
        const err = await res.json().catch(()=>({detail:"Connection Error"}));
        throw new Error(err.detail || "Server Error");
      }

      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError(err.message || "เกิดข้อผิดพลาดในการเชื่อมต่อ");
    } finally {
      setLoading(false);
    }
  }

 
  const isPhishing = result?.label?.toLowerCase() === "phishing";
  const probPercent = result ? (result.probability * 100).toFixed(2) : 0;

  return (
    <div className="app-container">
      <div className="cyber-card">
        
        <div className="header-section">
          <h1 className="title">Phishing URL Checker </h1>
          <p className="subtitle">ระบบตรวจสอบ Phishing URL อัจฉริยะ ด้วย Machine Learning</p>
        </div>

        <form onSubmit={handleCheck}>
          <div className="search-box">
            <input
              type="url"
              className="url-input"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com (วางลิงก์ที่นี่)"
              required
            />
          </div>

          <button type="submit" className="scan-btn" disabled={loading}>
            {loading ? <div className="spinner"></div> : "CHECK NOW"}
          </button>
        </form>

        {/* ส่วนแสดง Error */}
        {error && (
          <div style={{
            color: "#fca5a5", 
            marginTop: "1.5rem", 
            fontWeight: 500, 
            background: "rgba(127, 29, 29, 0.4)", 
            padding: "16px", 
            borderRadius: "12px",
            border: "1px solid rgba(248, 113, 113, 0.2)"
          }}>
            {error}
          </div>
        )}

        {/* ส่วนแสดงผลลัพธ์ */}
        {result && (
          <div className={`result-card ${isPhishing ? "phishing" : "legit"}`}>
            
            <div style={{textAlign: "center"}}>
                <div className="status-badge">
                {isPhishing ? "DETECTED PHISHING" : "SAFE TO VISIT"}
                </div>
            </div>

            <div className="result-details">
              <div>
                <strong>URL:</strong> <span style={{wordBreak: "break-all", color: "#e6edf3"}}>{result.url}</span>
              </div>
              
              <div>
                <strong>ความเสี่ยง (Confidence Score):</strong> 
                <span style={{ marginLeft: "8px", fontSize: "1.2em", color: isPhishing ? "#fca5a5" : "#6ee7b7" }}>
                  {probPercent}%
                </span>
              </div>

              <div>
                <strong>AI Analysis:</strong> 
                <span style={{color: "#c9d1d9"}}>
                    {isPhishing 
                    ? "ระบบตรวจพบความผิดปกติที่ตรงกับพฤติกรรมของเว็บหลอกลวง" 
                    : "โครงสร้าง URL ดูปลอดภัยและอยู่ในเกณฑ์ที่ยอมรับได้"}
                </span>
              </div>

              <div style={{fontSize: "0.8em", opacity: 0.6, marginTop: "16px", borderTop: "1px solid rgba(255,255,255,0.1)", paddingTop: "12px", textAlign: "left"}}>
                 Model: XGBoost & TF-IDF (Calibrated) | Threshold: {result.threshold || 0.6}
              </div>
            </div>
          </div>
        )}

      </div>
      
      <p style={{textAlign:"center", color: "#8b949e", fontSize: "0.85rem", marginTop: "32px", opacity: 0.8}}>
        Developed by Pawapob • CS 461 Neural Networks and Deep Learning Final Project
      </p>
    </div>
  );
}