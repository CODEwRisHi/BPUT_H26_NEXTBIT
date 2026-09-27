from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from services.risk_scorer import analyze_threat

app = FastAPI(title="Cyber Threat & Phishing Detection API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"status": "online", "message": "Cyber Threat & Phishing Detection Engine Active"}

@app.post("/api/v1/analyze")
def analyze_telemetry(payload: dict):
    source_type = payload.get("source_type")
    content = payload.get("content")
    
    if not content or not source_type:
        raise HTTPException(status_code=400, detail="Both source_type and content are required")
    
    analysis_result = analyze_threat(source_type, content)
    return {
        "status": "success",
        "payload_type": source_type,
        "analysis": analysis_result
    }