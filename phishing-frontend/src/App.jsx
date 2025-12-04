// src/App.jsx
import { useState } from "react";

const API_URL = import.meta.env.VITE_API_URL || "/predict"; // dev: vite proxy -> localhost:8000

export default function App() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  async function handleCheck(e) {
    e && e.preventDefault();
    setError(null);
    setResult(null);
    if (!url.trim()) { setError("กรอก URL ก่อน"); return; }

    setLoading(true);
    try {
      const res = await fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url.trim() })
      });

      if (!res.ok) {
        const err = await res.json().catch(()=>({detail:"ไม่ทราบสาเหตุ"}));
        throw new Error(err.detail || "Request failed");
      }

      const data = await res.json();
      setResult(data);
    } catch (err) {
      setError(err.message || "เกิดข้อผิดพลาด");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{maxWidth:800, margin:"40px auto", fontFamily: "Inter, Arial, sans-serif", padding:20}}>
      <h1 style={{marginBottom:8}}> Phishing URL Checker</h1>
      <form onSubmit={handleCheck} style={{display:"flex", gap:8}}>
        <input
          value={url}
          onChange={(e)=>setUrl(e.target.value)}
          placeholder="https://example.com"
          style={{flex:1, padding:10, fontSize:16}}
        />
        <button type="submit" style={{padding:"10px 14px", fontSize:16}} disabled={loading}>
          {loading ? "Checking..." : "Check"}
        </button>
      </form>

      {error && <div style={{color:"#b00020", marginTop:12}}>{error}</div>}

      {result && (
          <div style={{marginTop:20, padding:14, borderRadius:8, background:"#f7f7fb", boxShadow:"0 1px 3px rgba(0,0,0,0.06)", color: "#242424"}}>
          <div><strong>URL:</strong> {result.url}</div>
          <div><strong>Label:</strong> <span style={{textTransform:"uppercase"}}>{result.label}</span></div>
          <div><strong>Probability:</strong> {(result.probability*100).toFixed(2)}%</div>
          <div style={{marginTop:8, color:"#555"}}>threshold: {(result.threshold ?? 0.8)}</div>
        </div>
      )}

      <div style={{marginTop:30, fontSize:13, color:"#666"}}>
        Prototype
      </div>
    </div>
  );
}
