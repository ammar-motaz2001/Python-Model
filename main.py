from pathlib import Path
from typing import Union
import logging

from fastapi import FastAPI, Request
from pydantic import BaseModel
import numpy as np
import joblib

app = FastAPI(title="DDoS Detection API")

# logging setup
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "events.log"

logger = logging.getLogger("attack_detector")
logger.setLevel(logging.INFO)

if not logger.handlers:
    file_handler = logging.FileHandler(LOG_FILE)
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

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


class BruteForceRequest(BaseModel):
    """Request body for brute-force detection."""

    username: str
    hour: int  # 0-23
    day_of_week: int  # 0=Monday .. 6=Sunday
    password_count: int
    foreign_ip: str


@app.get("/")
def root():
    return {"message": "DDoS and Brute-force Detection API Running"}


@app.post("/detect")
def detect(payload: Union[Packet, BruteForceRequest], request: Request):
    """
    Single endpoint that can detect either:
    - DDoS attacks from packet-level features
    - Brute-force attacks from login attempt features
    """

    client_ip = request.client.host if request.client else "unknown"

    # DDoS path: body matches Packet schema
    if isinstance(payload, Packet):
        features = np.array([[
            payload.IPLength,
            payload.IPHeaderLength,
            payload.TTL,
            payload.Protocol,
            payload.SourcePort,
            payload.DestPort,
            payload.SequenceNumber,
            payload.AckNumber,
            payload.WindowSize,
            payload.TCPHeaderLength,
            payload.TCPLength,
            payload.TCPStream,
            payload.TCPUrgentPointer,
            payload.IPFlags,
            payload.IPID,
            payload.IPchecksum,
            payload.TCPflags,
            payload.TCPChecksum,
        ]])

        prediction = model.predict(features)[0]

        if prediction == 1:
            logger.info(
                "ddos_detect client_ip=%s src_port=%s dst_port=%s result=DDoS",
                client_ip,
                payload.SourcePort,
                payload.DestPort,
            )
            return {
                "attack_detected": True,
                "attack_type": "DDoS",
            }

        logger.info(
            "ddos_detect client_ip=%s src_port=%s dst_port=%s result=Benign",
            client_ip,
            payload.SourcePort,
            payload.DestPort,
        )
        return {
            "attack_detected": False,
            "attack_type": "Benign",
        }

    # Brute-force path: body matches BruteForceRequest schema
    if model_bruteforce is None:
        return {
            "attack_detected": False,
            "attack_type": "Benign",
        }

    try:
        u = username_encoder.transform([payload.username])[0]
    except (ValueError, TypeError):
        u = 0

    try:
        ip = ip_encoder.transform([payload.foreign_ip])[0]
    except (ValueError, TypeError):
        ip = 0

    features = np.array([[
        u,
        payload.hour,
        payload.day_of_week,
        payload.password_count,
        ip,
    ]])

    prediction = model_bruteforce.predict(features)[0]

    if prediction == 1:
        logger.info(
            "bruteforce_detect client_ip=%s username=%s ip=%s pwd_count=%s result=BruteForce",
            client_ip,
            payload.username,
            payload.foreign_ip,
            payload.password_count,
        )
        return {
            "attack_detected": True,
            "attack_type": "BruteForce",
        }

    logger.info(
        "bruteforce_detect client_ip=%s username=%s ip=%s pwd_count=%s result=Benign",
        client_ip,
        payload.username,
        payload.foreign_ip,
        payload.password_count,
    )
    return {
        "attack_detected": False,
        "attack_type": "Benign",
    }