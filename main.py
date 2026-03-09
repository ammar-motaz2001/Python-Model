from pathlib import Path
from typing import Union, Optional
import json
import logging
from datetime import datetime

from fastapi import FastAPI, Request
from pydantic import BaseModel
import numpy as np
import joblib
import redis

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

# Redis setup (for real-time streaming to frontend)
REDIS_URL = "redis://localhost:6379/0"
redis_client: Optional[redis.Redis]
try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    # ping once so we fail fast if Redis is not running
    redis_client.ping()
except Exception:
    redis_client = None


def publish_event(event: dict) -> None:
    """
    Publish attack events to Redis so the frontend can receive them in real time.
    Channel: \"attack-events\"
    """
    if redis_client is None:
        return
    try:
        payload = {
            **event,
            "timestamp": datetime.utcnow().isoformat(),
        }
        redis_client.publish("attack-events", json.dumps(payload))
    except Exception:
        # avoid breaking the API if Redis is down
        logger.exception("Failed to publish event to Redis")


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
            publish_event(
                {
                    "kind": "ddos",
                    "client_ip": client_ip,
                    "src_port": payload.SourcePort,
                    "dst_port": payload.DestPort,
                    "attack_detected": True,
                    "attack_type": "DDoS",
                },
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
        publish_event(
            {
                "kind": "ddos",
                "client_ip": client_ip,
                "src_port": payload.SourcePort,
                "dst_port": payload.DestPort,
                "attack_detected": False,
                "attack_type": "Benign",
            },
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
        publish_event(
            {
                "kind": "bruteforce",
                "client_ip": client_ip,
                "username": payload.username,
                "foreign_ip": payload.foreign_ip,
                "password_count": payload.password_count,
                "attack_detected": True,
                "attack_type": "BruteForce",
            },
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
    publish_event(
        {
            "kind": "bruteforce",
            "client_ip": client_ip,
            "username": payload.username,
            "foreign_ip": payload.foreign_ip,
            "password_count": payload.password_count,
            "attack_detected": False,
            "attack_type": "Benign",
        },
    )
    return {
        "attack_detected": False,
        "attack_type": "Benign",
    }