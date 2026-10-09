import os
import time
import json
import logging
from typing import Dict, List, Optional
from enum import Enum
from fastapi import FastAPI, Depends, HTTPException, Security, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from cryptography.fernet import Fernet

from rbac import get_current_user, RequireRole, UserRole, UserContext

# AAA AUDIT LOGGING
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("UmarmathiSecurityAudit")

def audit_log(event_type: str, user_id: str, client_ip: str, details: dict):
    log_entry = {
        "timestamp": time.time(),
        "event_type": event_type,
        "user_id": user_id,
        "client_ip": client_ip,
        "details": details
    }
    logger.info(f"AUDIT_RECORD: {json.dumps(log_entry)}")

FIELD_ENCRYPTION_KEY = os.getenv("FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
cipher_suite = Fernet(FIELD_ENCRYPTION_KEY.encode())

def encrypt_pii(data: str) -> str:
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_pii(encrypted_data: str) -> str:
    return cipher_suite.decrypt(encrypted_data.encode()).decode()

app = FastAPI(
    title="Umarmathi Pivot Point Calculator",
    description="OWASP Top 10 Secured Trading Platform with RBAC",
    version="1.0.0"
)

@app.middleware("http")
async def apply_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[ALLOWED_ORIGIN, "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

class CalculationType(str, Enum):
    STANDARD = "STANDARD"
    FIBONACCI = "FIBONACCI"
    CAMARILLA = "CAMARILLA"

class PivotRequest(BaseModel):
    symbol: str = Field(..., example="XAUUSD")
    high: float = Field(..., gt=0)
    low: float = Field(..., gt=0)
    close: float = Field(..., gt=0)
    open_price: Optional[float] = Field(None, gt=0)
    method: CalculationType = CalculationType.STANDARD

class PivotLevels(BaseModel):
    pivot: float
    r1: float
    r2: float
    r3: float
    s1: float
    s2: float
    s3: float

class AlertCheckRequest(BaseModel):
    symbol: str = Field(..., example="XAUUSD")
    current_price: float = Field(..., gt=0)
    previous_price: float = Field(..., gt=0)
    pivot_levels: PivotLevels

class AlertTriggerResponse(BaseModel):
    triggered: bool
    symbol: str
    message: str
    crossed_level: Optional[str] = None

def calculate_pivots(req: PivotRequest) -> PivotLevels:
    H, L, C = req.high, req.low, req.close
    if req.method == CalculationType.STANDARD:
        P = (H + L + C) / 3.0
        R1 = (2 * P) - L
        S1 = (2 * P) - H
        R2 = P + (H - L)
        S2 = P - (H - L)
        R3 = H + 2 * (P - L)
        S3 = L - 2 * (H - P)
    elif req.method == CalculationType.FIBONACCI:
        P = (H + L + C) / 3.0
        R1 = P + 0.382 * (H - L)
        S1 = P - 0.382 * (H - L)
        R2 = P + 0.618 * (H - L)
        S2 = P - 0.618 * (H - L)
        R3 = P + 1.000 * (H - L)
        S3 = P - 1.000 * (H - L)
    elif req.method == CalculationType.CAMARILLA:
        P = (H + L + C) / 3.0
        R1 = C + (H - L) * 1.1 / 12.0
        S1 = C - (H - L) * 1.1 / 12.0
        R2 = C + (H - L) * 1.1 / 6.0
        S2 = C - (H - L) * 1.1 / 6.0
        R3 = C + (H - L) * 1.1 / 4.0
        S3 = C - (H - L) * 1.1 / 4.0

    return PivotLevels(
        pivot=round(P, 4), r1=round(R1, 4), r2=round(R2, 4), r3=round(R3, 4),
        s1=round(S1, 4), s2=round(S2, 4), s3=round(S3, 4)
    )

@app.get("/")
async def serve_frontend():
    return FileResponse("index.html")

@app.get("/health")
@app.get("/healthz", tags=["System Operational Readiness"])
async def health_check():
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "service": "Umarmathi Pivot Engine"
    }

@app.post("/api/v1/pivots/calculate", response_model=PivotLevels, tags=["Trading Engine"])
async def compute_pivots(
    req: PivotRequest,
    request: Request,
    current_user: UserContext = Depends(get_current_user)
):
    if req.method in [CalculationType.FIBONACCI, CalculationType.CAMARILLA]:
        if UserRole.ANONYMOUS in current_user.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. {req.method.value} calculations require Google authentication."
            )

    client_ip = request.client.host if request.client else "unknown"
    audit_log("PIVOT_CALCULATION", current_user.user_id, client_ip, {"symbol": req.symbol, "method": req.method})
    return calculate_pivots(req)

@app.post("/api/v1/alerts/check", response_model=AlertTriggerResponse, tags=["Automated Alert Engine"])
async def check_price_crossing(
    req: AlertCheckRequest,
    request: Request,
    current_user: UserContext = Depends(get_current_user)
):
    curr = req.current_price
    prev = req.previous_price
    levels = {
        "R3": req.pivot_levels.r3, "R2": req.pivot_levels.r2, "R1": req.pivot_levels.r1,
        "PIVOT": req.pivot_levels.pivot,
        "S1": req.pivot_levels.s1, "S2": req.pivot_levels.s2, "S3": req.pivot_levels.s3,
    }
    
    for level_name, level_val in levels.items():
        if (prev < level_val <= curr) or (prev > level_val >= curr):
            client_ip = request.client.host if request.client else "unknown"
            msg = f"PRICE CROSSING DETECTED: {req.symbol} crossed {level_name} zone ({level_val:.4f}). Current Price: {curr:.4f}"
            audit_log("ALERT_BREACH", current_user.user_id, client_ip, {"symbol": req.symbol, "level": level_name, "price": curr})
            return AlertTriggerResponse(
                triggered=True,
                symbol=req.symbol,
                message=msg,
                crossed_level=level_name
            )
            
    return AlertTriggerResponse(triggered=False, symbol=req.symbol, message="Price within threshold limits.")
