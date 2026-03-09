from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel
import numpy as np
import joblib

app = FastAPI(title="DDoS Detection API")

# load trained DDoS model
model = joblib.load("model.pkl")

# load brute-force model and encoders if present
model_bruteforce = None
username_encoder = None
ip_encoder = None
if Path("model_bruteforce.pkl").exists():
    model_bruteforce = joblib.load("model_bruteforce.pkl")
    username_encoder = joblib.load("username_encoder.pkl")
    ip_encoder = joblib.load("ip_encoder.pkl")


class Packet(BaseModel):

    IPLength: int
    IPHeaderLength: int
    TTL: int
    Protocol: int
    SourcePort: int
    DestPort: int
    SequenceNumber: int
    AckNumber: int
    WindowSize: int
    TCPHeaderLength: int
    TCPLength: int
    TCPStream: int
    TCPUrgentPointer: int
    IPFlags: int
    IPID: int
    IPchecksum: int
    TCPflags: int
    TCPChecksum: int


@app.get("/")
def root():
    return {"message": "DDoS Detection API Running"}


@app.post("/detect")
def detect(packet: Packet):

    features = np.array([[
        packet.IPLength,
        packet.IPHeaderLength,
        packet.TTL,
        packet.Protocol,
        packet.SourcePort,
        packet.DestPort,
        packet.SequenceNumber,
        packet.AckNumber,
        packet.WindowSize,
        packet.TCPHeaderLength,
        packet.TCPLength,
        packet.TCPStream,
        packet.TCPUrgentPointer,
        packet.IPFlags,
        packet.IPID,
        packet.IPchecksum,
        packet.TCPflags,
        packet.TCPChecksum
    ]])

    prediction = model.predict(features)[0]

    if prediction == 1:
        return {
            "attack_detected": True,
            "attack_type": "DDoS"
        }

    return {
        "attack_detected": False,
        "attack_type": "Benign"
    }


class BruteForceRequest(BaseModel):
    """Request body for brute-force detection (same idea as DDoS /detect)."""

    username: str
    hour: int  # 0-23
    day_of_week: int  # 0=Monday .. 6=Sunday
    password_count: int
    foreign_ip: str


@app.post("/detect-bruteforce")
def detect_bruteforce(req: BruteForceRequest):
    """Detect brute-force attack; same response shape as /detect (DDoS)."""
    if model_bruteforce is None:
        return {
            "attack_detected": False,
            "attack_type": "Benign"
        }
    try:
        u = username_encoder.transform([req.username])[0]
    except (ValueError, TypeError):
        u = 0
    try:
        ip = ip_encoder.transform([req.foreign_ip])[0]
    except (ValueError, TypeError):
        ip = 0
    features = np.array([[
        u,
        req.hour,
        req.day_of_week,
        req.password_count,
        ip,
    ]])
    prediction = model_bruteforce.predict(features)[0]

    if prediction == 1:
        return {
            "attack_detected": True,
            "attack_type": "BruteForce"
        }

    return {
        "attack_detected": False,
        "attack_type": "Benign"
    }