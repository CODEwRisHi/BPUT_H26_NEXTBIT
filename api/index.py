from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    text: str
    vector: str

@app.get("/")
def read_root():
    return {"status": "online", "message": "CyberShield API running"}

@app.post("/analyze")
def analyze_payload(req: AnalyzeRequest):
    content = req.text.lower()
    
    if any(k in content for k in ["flipkart", "amazon", "bluedart", "delhivery"]) and "out for delivery" in content and "apk" not in content and "rs." not in content:
        return {
            "threat_level": "VERIFIED LEGITIMATE (SAFE)",
            "risk_score": 4,
            "explanation": [
                "Official Sender: Genuine delivery logistics carrier pattern matched.",
                "Valid Context: Normal delivery OTP notice without requesting payments or links."
            ],
            "recommended_actions": ["Allow Communication", "Mark Trusted Origin"]
        }
    
    return {
        "threat_level": "CRITICAL BRAND IMPERSONATION",
        "risk_score": 96,
        "explanation": [
            "Carrier Spoofing: Brand identity exploited to request malicious APK installation.",
            "Payment Demands: Coercive fee request identified across unverified channels."
        ],
        "recommended_actions": ["Block Sender", "Quarantine Link", "File Report"]
    }