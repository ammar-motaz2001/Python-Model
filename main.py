from pathlib import Path
from typing import Annotated, Union, Optional, Tuple
import asyncio
import json
import logging
from datetime import datetime
from io import BytesIO
import base64
import os
import shlex
import subprocess
import ipaddress
import threading

try:
    from dotenv import load_dotenv
except ImportError:  # optional dep; install with: pip install python-dotenv
    def load_dotenv(*_args, **_kwargs) -> bool:
        return False

# Load `.env` before any os.getenv-based config. Try app root next to this file, then CWD (uvicorn).
# Locally: override=True so `.env` wins over an empty `export MONGO_URL=` in the shell.
# On Vercel: override=False so platform env vars are not replaced by a missing `.env`.
_env_root = Path(__file__).resolve().parent
_DOTENV_PATH = _env_root / ".env"
_on_vercel = bool(os.getenv("VERCEL"))
_dotenv_override = not _on_vercel
load_dotenv(_DOTENV_PATH, override=_dotenv_override)
load_dotenv(override=_dotenv_override)

# Before numpy/sklearn: avoid fork/OpenMP issues on serverless (Vercel, Lambda).
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("VECLIB_MAXIMUM_THREADS", "1")
os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")
os.environ.setdefault("JOBLIB_MULTIPROCESSING", "0")

from fastapi import (
    FastAPI,
    Request,
    Query,
    Header,
    HTTPException,
    Body,
    File,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import numpy as np
import joblib
import redis
from bson import ObjectId
from bson.errors import InvalidId
from pymongo import MongoClient

_OPENAPI_TAGS = [
    {
        "name": "Core",
        "description": "Health checks and API status.",
    },
    {
        "name": "Detection",
        "description": (
            "ML-based detection. **`POST /detect`**: classification only. **`POST /automated-actions/detect`**: "
            "same body + **DDoS → isolate** caller IP, **brute-force attack → block** `foreign_ip` when "
            "`password_count` ≥ threshold. **`GET /detect/packet-auto`** / **`POST .../upload`**: DDoS from PCAP + isolate on hit."
        ),
    },
    {
        "name": "Actions",
        "description": "Block/unblock IPs (in-memory + MongoDB) and list blocked IPs.",
    },
    {
        "name": "MongoDB",
        "description": "CRUD-style access to `devices`, `alerts`, and `automated_actions` collections.",
    },
    {
        "name": "WiFi logs",
        "description": (
            "Read or append WiFi/router log files on disk. Configure `WIFI_LOG_PATH`, "
            "`WIFI_LOG_DIR`, `WIFI_LOG_INGEST_KEY` via environment variables."
        ),
    },
    {
        "name": "Stats",
        "description": "Per-IP request counts and action history (in-memory, resets on server restart).",
    },
    {
        "name": "Realtime",
        "description": "Dashboard events via GET backlog and WebSocket stream.",
    },
]

app = FastAPI(
    title="SOC Security API",
    version="1.0.0",
    description="""
## Overview
Security operations API: **DDoS** and **brute-force** classification (trained models),
optional **MongoDB** persistence, **Redis** pub/sub for realtime dashboards, and **WiFi log** file access.

## Swagger UI
- This page documents every endpoint.
- **ReDoc**: `/redoc`

## Environment variables (common)
| Variable | Purpose |
|----------|---------|
| `MONGO_URL` | MongoDB connection string (default `mongodb://localhost:27017`) |
| `MONGO_DB` | Database name (default `soc_security`) |
| `REDIS_URL` | Redis for `attack-events` channel (default `redis://localhost:6379/0`) |
| `WIFI_LOG_PATH` | File read by `GET /logs/wifi` |
| `WIFI_LOG_DIR` | Directory for optional `?file=` basename |
| `WIFI_LOG_INGEST_KEY` | If set, required header `X-WiFi-Log-Key` for `POST /logs/wifi/append` |
| `WIFI_AUTO_PACKET_PATH` | PCAP read by **`GET /detect/packet-auto`** (default `logs/wifi_last.pcap`) |
| `BF_AUTO_BLOCK_THRESHOLD` | Brute-force auto-block when `password_count` ≥ this (default **6**) — see **`POST /automated-actions/detect`** |
| `ENFORCEMENT_ENABLED` | Run real OS/network action commands for block/isolate (`1`=enabled, default disabled) |
| `ENFORCE_*_CMD` | Command templates with `{ip}` (e.g. `ENFORCE_BLOCK_CMD`, `ENFORCE_ISOLATE_CMD`) |
| `CORS_ORIGINS` | Comma-separated allowed browser origins (default `*` for open API) |
| `EVENT_HISTORY_MAXLEN` | Max in-memory realtime events for `GET /events/recent` and `WS /ws/events` |
| `ROOT_REDIRECT_TO_DOCS` | `1` (default): `GET /` on localhost redirects to `/docs`; set `0` for JSON root |
| `SOC_DEBUG_ERRORS` | `0` / `false`: hide raw errors on `POST /detect` (default is to show `ExceptionType: message`) |
| *(local)* | Copy `.env.example` → `.env`; variables are loaded automatically via `python-dotenv`. |
""",
    openapi_tags=_OPENAPI_TAGS,
)

_cors_origins = os.getenv("CORS_ORIGINS", "*").strip()
_cors_list = ["*"] if _cors_origins == "*" else [o.strip() for o in _cors_origins.split(",") if o.strip()]
# Browsers disallow credentials + wildcard origin; disable credentials when using "*"
_cors_credentials = _cors_list != ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_list,
    allow_credentials=_cors_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
)

# logging setup
LOG_DIR = Path(os.getenv("LOG_DIR", "/tmp/logs" if os.getenv("VERCEL") else "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "events.log"

# WiFi logs: point syslog/rsyslog or router export here (see README or env docs)
WIFI_LOG_PATH = Path(os.getenv("WIFI_LOG_PATH", str(LOG_DIR / "wifi.log")))
WIFI_LOG_DIR = Path(os.getenv("WIFI_LOG_DIR", str(LOG_DIR)))
# If set, POST /logs/wifi/append requires header X-WiFi-Log-Key: <value>
WIFI_LOG_INGEST_KEY = os.getenv("WIFI_LOG_INGEST_KEY", "").strip()
# GET /detect/packet-auto reads PCAP from this file (e.g. tcpdump -w logs/wifi_last.pcap)
WIFI_AUTO_PACKET_PATH = Path(
    os.getenv("WIFI_AUTO_PACKET_PATH", str(LOG_DIR / "wifi_last.pcap")),
)
# Brute-force: auto-block foreign_ip when model detects attack and password_count >= this threshold
BF_AUTO_BLOCK_THRESHOLD = max(1, int(os.getenv("BF_AUTO_BLOCK_THRESHOLD", "6")))
ENFORCEMENT_ENABLED = os.getenv("ENFORCEMENT_ENABLED", "0").strip() in {"1", "true", "yes"}
ENFORCE_TIMEOUT_SECONDS = max(1, int(os.getenv("ENFORCE_TIMEOUT_SECONDS", "8")))
ENFORCE_BLOCK_CMD = os.getenv("ENFORCE_BLOCK_CMD", "").strip()
ENFORCE_UNBLOCK_CMD = os.getenv("ENFORCE_UNBLOCK_CMD", "").strip()
ENFORCE_ISOLATE_CMD = os.getenv("ENFORCE_ISOLATE_CMD", "").strip()
ENFORCE_UNISOLATE_CMD = os.getenv("ENFORCE_UNISOLATE_CMD", "").strip()

logger = logging.getLogger("attack_detector")
logger.setLevel(logging.INFO)

if not logger.handlers:
    file_handler = logging.FileHandler(LOG_FILE)
    stream_handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
    )
    file_handler.setFormatter(formatter)
    stream_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

# Redis setup (for real-time streaming to frontend)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
ALERT_QUEUE_STREAM = os.getenv("ALERT_QUEUE_STREAM", "security-alerts")
ALERT_QUEUE_MAXLEN = max(1000, int(os.getenv("ALERT_QUEUE_MAXLEN", "20000")))
EVENT_HISTORY_MAXLEN = max(100, int(os.getenv("EVENT_HISTORY_MAXLEN", "2000")))
redis_client: Optional[redis.Redis]
try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    # ping once so we fail fast if Redis is not running
    redis_client.ping()
except Exception:
    redis_client = None

# MongoDB setup
_DEFAULT_MONGO = "mongodb://localhost:27017"
_mongo_raw = (os.getenv("MONGO_URL") or "").strip()
MONGO_URL = _mongo_raw if _mongo_raw else _DEFAULT_MONGO
MONGO_DB = (os.getenv("MONGO_DB") or "soc_security").strip() or "soc_security"
mongo_client: Optional[MongoClient]
MONGO_LAST_ERROR: Optional[str] = None
db = None
devices_collection = None
alerts_collection = None
actions_collection = None
try:
    mongo_client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=10000)
    mongo_client.admin.command("ping")
    db = mongo_client[MONGO_DB]
    devices_collection = db["devices"]
    alerts_collection = db["alerts"]
    actions_collection = db["automated_actions"]
    MONGO_LAST_ERROR = None
    logger.info("MongoDB connected successfully: %s/%s", MONGO_URL, MONGO_DB)
except Exception as exc:
    mongo_client = None
    MONGO_LAST_ERROR = str(exc).strip()[:300]
    logger.warning("MongoDB not connected (%s): %s", MONGO_URL.split("@")[-1], MONGO_LAST_ERROR)

EVENT_HISTORY: list[dict] = []
EVENT_SEQUENCE = 0
EVENT_LOCK = threading.Lock()


def initialize_mongo() -> None:
    """
    Ensure DB/collections exist on startup.
    Mongo creates databases lazily on first write, so we write bootstrap metadata.
    """
    if db is None:
        return
    now = datetime.utcnow().isoformat()
    existing = set(db.list_collection_names())
    for name in ["devices", "alerts", "automated_actions", "app_meta"]:
        if name not in existing:
            db.create_collection(name)
    db["app_meta"].update_one(
        {"_id": "bootstrap"},
        {"$set": {"initialized_at": now}},
        upsert=True,
    )


try:
    initialize_mongo()
except Exception:
    logger.warning("MongoDB schema init skipped (connection unavailable).")


def publish_event(event: dict) -> None:
    """
    Publish attack events and actions to Redis so the frontend can receive them in real time.
    Channel: "attack-events"
    """
    global EVENT_SEQUENCE
    payload = {
        **event,
        "timestamp": datetime.utcnow().isoformat(),
    }
    with EVENT_LOCK:
        EVENT_SEQUENCE += 1
        payload["seq"] = EVENT_SEQUENCE
        EVENT_HISTORY.append(payload)
        if len(EVENT_HISTORY) > EVENT_HISTORY_MAXLEN:
            del EVENT_HISTORY[: len(EVENT_HISTORY) - EVENT_HISTORY_MAXLEN]

    if redis_client is None:
        return
    try:
        event_json = json.dumps(payload, default=str)
        redis_client.publish("attack-events", event_json)
        # Durable queue for external automation/action services.
        redis_client.xadd(
            ALERT_QUEUE_STREAM,
            {"event_json": event_json},
            maxlen=ALERT_QUEUE_MAXLEN,
            approximate=True,
        )
    except Exception:
        # avoid breaking the API if Redis is down
        logger.exception("Failed to publish event to Redis")


def to_object_id(value: str) -> ObjectId:
    """Parse string id into Mongo ObjectId."""
    return ObjectId(value)


def serialize_doc(doc: Optional[dict]) -> Optional[dict]:
    """Convert Mongo document ObjectId fields to strings."""
    if doc is None:
        return None
    payload = dict(doc)
    payload["id"] = str(payload.pop("_id"))
    if payload.get("device_id") is not None:
        payload["device_id"] = str(payload["device_id"])
    if payload.get("alert_id") is not None:
        payload["alert_id"] = str(payload["alert_id"])
    if payload.get("type") == "firewall":
        payload.setdefault("true_positive_count", 0)
        payload.setdefault("false_positive_count", 0)
    return payload


# GET /alerts sort: critical → high → medium → low, then newest created_at within tier
_ALERT_PRIORITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "midum": 2,
    "midium": 2,
    "low": 3,
}


def _alert_priority_rank(priority: object) -> int:
    if priority is None:
        return 99
    return _ALERT_PRIORITY_RANK.get(str(priority).strip().lower(), 99)


def _alert_list_sort_key(doc: dict) -> tuple:
    rank = _alert_priority_rank(doc.get("priority"))
    neg_epoch = 0.0
    ts_raw = doc.get("created_at")
    if ts_raw:
        try:
            s = str(ts_raw).replace("Z", "+00:00")
            neg_epoch = -datetime.fromisoformat(s).timestamp()
        except (TypeError, ValueError, OSError):
            neg_epoch = 0.0
    return (rank, neg_epoch)


def _batch_device_ip_by_object_id(oids: list) -> dict[str, Optional[str]]:
    """Map device ObjectId string -> IP for batch alert responses."""
    if devices_collection is None:
        return {}
    unique = list({o for o in oids if o is not None})
    if not unique:
        return {}
    out: dict[str, Optional[str]] = {}
    for row in devices_collection.find({"_id": {"$in": unique}}, {"_id": 1, "ip": 1}):
        out[str(row["_id"])] = row.get("ip")
    return out


def serialize_alert_for_response(doc: Optional[dict]) -> Optional[dict]:
    """Like serialize_doc for alerts plus resolved `device_ip` from `devices`."""
    payload = serialize_doc(doc)
    if payload is None:
        return None
    raw_did = None if doc is None else doc.get("device_id")
    if raw_did is not None:
        ip_map = _batch_device_ip_by_object_id([raw_did])
        payload["device_ip"] = ip_map.get(str(raw_did))
    else:
        payload["device_ip"] = None
    return payload


def serialize_alerts_for_list(raw_docs: list[dict]) -> list[dict]:
    """Serialize alert documents with one batched device IP lookup."""
    ip_map = _batch_device_ip_by_object_id([d.get("device_id") for d in raw_docs])
    out: list[dict] = []
    for doc in raw_docs:
        s = serialize_doc(doc)
        if s is None:
            continue
        did = doc.get("device_id")
        s["device_ip"] = ip_map.get(str(did)) if did is not None else None
        out.append(s)
    return out


def ensure_device(ip: str) -> Optional[dict]:
    """Get or create a device record by IP."""
    if devices_collection is None:
        return None
    now = datetime.utcnow().isoformat()
    devices_collection.update_one(
        {"ip": ip},
        {
            "$setOnInsert": {
                "ip": ip,
                "is_blocked": False,
                "is_isolated": False,
                "created_at": now,
                "attack_counts": {"ddos": 0, "brute_force": 0},
                "total_requests": 0,
                "last_seen_at": None,
                "last_detection_type": None,
            },
            "$set": {"updated_at": now},
        },
        upsert=True,
    )
    return devices_collection.find_one({"ip": ip})


def upsert_attack_alert(device_id: ObjectId, attack_type: str) -> Optional[dict]:
    """
    Upsert an open alert for the device and increment attack counters.
    attack_type: ddos | brute_force
    """
    if alerts_collection is None:
        return None
    now = datetime.utcnow().isoformat()
    inc_field = "attack_counts.ddos" if attack_type == "ddos" else "attack_counts.brute_force"
    alerts_collection.update_one(
        {"device_id": device_id, "is_closed": False, "type": "firewall"},
        {
            "$setOnInsert": {
                "title": "Security attack detected",
                "device_id": device_id,
                "priority": "high",
                "type": "firewall",
                "is_closed": False,
                "created_at": now,
                "true_positive_count": 0,
                "false_positive_count": 0,
            },
            "$inc": {inc_field: 1},
            "$set": {"updated_at": now},
        },
        upsert=True,
    )
    return alerts_collection.find_one(
        {"device_id": device_id, "is_closed": False, "type": "firewall"},
    )


def record_alert_tp_fp(
    device_id: ObjectId,
    *,
    attack_kind: str,
    prediction: int,
    password_count: Optional[int] = None,
) -> None:
    """
    Update open firewall alert with model outcome counters.

    - DDoS: TP if model predicts attack (prediction==1); FP if benign.
    - Brute-force: TP if model predicts attack AND password_count >= BF_AUTO_BLOCK_THRESHOLD
      (strong signal); otherwise FP (benign, or weak attempt e.g. 2 tries below threshold).
    """
    if alerts_collection is None:
        return
    if attack_kind == "ddos":
        is_true_positive = prediction == 1
    else:
        is_true_positive = prediction == 1 and (
            password_count is not None and password_count >= BF_AUTO_BLOCK_THRESHOLD
        )
    now = datetime.utcnow().isoformat()
    inc_field = "true_positive_count" if is_true_positive else "false_positive_count"
    # Do not put true_positive_count / false_positive_count in $setOnInsert: same path as $inc
    # causes MongoDB error 40 (path conflict). $inc creates the field from implicit 0 if missing.
    alerts_collection.update_one(
        {"device_id": device_id, "is_closed": False, "type": "firewall"},
        {
            "$setOnInsert": {
                "title": "Security attack detected",
                "device_id": device_id,
                "priority": "high",
                "type": "firewall",
                "is_closed": False,
                "created_at": now,
                "attack_counts": {"ddos": 0, "brute_force": 0},
            },
            "$inc": {inc_field: 1},
            "$set": {"updated_at": now},
        },
        upsert=True,
    )


def create_action_record(
    action: str,
    ip: str,
    reason: Optional[str] = None,
    status: str = "triggered",
    device_id: Optional[ObjectId] = None,
    alert_id: Optional[ObjectId] = None,
) -> Optional[dict]:
    """Insert an automated action record into Mongo."""
    if actions_collection is None:
        return None
    doc = {
        "action": action,
        "ip": ip,
        "reason": reason,
        "status": status,
        "device_id": device_id,
        "alert_id": alert_id,
        "created_at": datetime.utcnow().isoformat(),
    }
    result = actions_collection.insert_one(doc)
    return actions_collection.find_one({"_id": result.inserted_id})


def record_action(ip: str, action: str, reason: Optional[str] = None) -> None:
    """Track actions (block/unblock/etc.) taken on a given IP in memory."""
    entry = {
        "ip": ip,
        "action": action,
        "reason": reason,
        "timestamp": datetime.utcnow().isoformat(),
    }
    history = IP_ACTIONS.setdefault(ip, [])
    history.append(entry)


def _validate_ip_or_raise(ip: str) -> str:
    """Reject malformed IP strings before using them in any command."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid IP address: {ip}") from exc


def persist_device_is_isolated(ip: str, isolated: bool) -> None:
    """Set `devices.is_isolated` by IP (Mongo). Skips invalid IPs and when DB is down."""
    if devices_collection is None:
        return
    try:
        safe = _validate_ip_or_raise(ip)
    except HTTPException:
        return
    ensure_device(safe)
    devices_collection.update_one(
        {"ip": safe},
        {"$set": {"is_isolated": isolated, "updated_at": datetime.utcnow().isoformat()}},
    )


def persist_device_is_blocked(ip: str, blocked: bool) -> None:
    """Set `devices.is_blocked` by IP (Mongo). Skips invalid IPs and when DB is down."""
    if devices_collection is None:
        return
    try:
        safe = _validate_ip_or_raise(ip)
    except HTTPException:
        return
    ensure_device(safe)
    devices_collection.update_one(
        {"ip": safe},
        {"$set": {"is_blocked": blocked, "updated_at": datetime.utcnow().isoformat()}},
    )


def run_enforcement_command(action: str, ip: str) -> dict:
    """
    Execute real infra command for action (if configured).
    Set ENFORCEMENT_ENABLED=1 and ENFORCE_*_CMD env vars.
    """
    command_by_action = {
        "block": ENFORCE_BLOCK_CMD,
        "unblock": ENFORCE_UNBLOCK_CMD,
        "isolate": ENFORCE_ISOLATE_CMD,
        "unisolate": ENFORCE_UNISOLATE_CMD,
    }
    template = command_by_action.get(action, "")
    if not ENFORCEMENT_ENABLED:
        return {
            "enabled": False,
            "attempted": False,
            "applied": False,
            "message": "ENFORCEMENT_ENABLED is off (state only, no real firewall/network change).",
        }
    if not template:
        return {
            "enabled": True,
            "attempted": False,
            "applied": False,
            "message": f"Missing command template for action '{action}'.",
        }

    safe_ip = _validate_ip_or_raise(ip)
    command = template.format(ip=safe_ip)
    try:
        result = subprocess.run(
            shlex.split(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=ENFORCE_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        logger.exception("enforce_action_failed action=%s ip=%s", action, safe_ip)
        return {
            "enabled": True,
            "attempted": True,
            "applied": False,
            "command": command,
            "error": str(exc),
        }

    return {
        "enabled": True,
        "attempted": True,
        "applied": result.returncode == 0,
        "command": command,
        "return_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


# in-memory IP tracking and blocklist
BLOCKED_IPS: set[str] = set()
ISOLATED_IPS: set[str] = set()
CLIENT_IPS: set[str] = set()
CLIENT_IP_COUNTS: dict[str, int] = {}
IP_ACTIONS: dict[str, list[dict]] = {}

# load trained models from app root (cwd differs on Vercel vs local uvicorn)
_MODEL_DIR = Path(__file__).resolve().parent
model = None
_dd_path = _MODEL_DIR / "model.pkl"
if _dd_path.is_file():
    model = joblib.load(_dd_path)

# load brute-force model and encoders if present
model_bruteforce = None
username_encoder = None
ip_encoder = None
_bf_path = _MODEL_DIR / "model_bruteforce.pkl"
if _bf_path.is_file():
    model_bruteforce = joblib.load(_bf_path)
    username_encoder = joblib.load(_MODEL_DIR / "username_encoder.pkl")
    ip_encoder = joblib.load(_MODEL_DIR / "ip_encoder.pkl")


def _load_model_metrics_file() -> dict:
    """Test-set metrics from last training run (model_metrics.json)."""
    path = _MODEL_DIR / "model_metrics.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        logger.warning("Could not parse model_metrics.json")
        return {}


MODEL_METRICS: dict = _load_model_metrics_file()


def _combined_model_accuracy() -> Optional[float]:
    """
    Single test-set accuracy across all models: mean of numeric `accuracy` values in
    `model_metrics.json` for `ddos` and `brute_force` (only entries that exist and are numbers).
    """
    dd = MODEL_METRICS.get("ddos") if isinstance(MODEL_METRICS.get("ddos"), dict) else {}
    bf = MODEL_METRICS.get("brute_force") if isinstance(MODEL_METRICS.get("brute_force"), dict) else {}
    vals: list[float] = []
    for block in (dd, bf):
        a = block.get("accuracy")
        if a is not None and isinstance(a, (int, float)) and not isinstance(a, bool):
            vals.append(float(a))
    if not vals:
        return None
    return round(sum(vals) / len(vals), 6)


def _accuracy_only_response() -> dict:
    return {"accuracy": _combined_model_accuracy()}


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


def parse_raw_bytes_to_packet(raw: bytes) -> Packet:
    """
    Build Packet features from raw bytes: PCAP (first frame) or Ethernet/IP frame with TCP.
    Used by GET /detect/packet-auto and POST /detect/packet-auto/upload.
    """
    if not raw:
        raise HTTPException(status_code=400, detail="Empty body")
    try:
        from scapy.all import Ether, IP, TCP, rdpcap
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="Install scapy: pip install scapy",
        ) from exc

    pkt = None
    try:
        pkts = rdpcap(BytesIO(raw))
        if pkts:
            pkt = pkts[0]
    except Exception:
        pass
    if pkt is None:
        try:
            e = Ether(raw)
            if IP in e and TCP in e:
                pkt = e
        except Exception:
            pass
    if pkt is None:
        try:
            ip_only = IP(raw)
            if IP in ip_only and TCP in ip_only:
                pkt = ip_only
        except Exception:
            pass

    if pkt is None or IP not in pkt or TCP not in pkt:
        raise HTTPException(
            status_code=400,
            detail="Send a PCAP or raw frame with IPv4 + TCP (e.g. tcpdump -w - -c 1)",
        )

    ip = pkt[IP]
    tcp = pkt[TCP]
    ip_total = int(ip.len) if ip.len is not None else len(ip)
    ip_hlen = int(ip.ihl) * 4
    tcp_payload_len = len(tcp.payload) if tcp.payload is not None else 0
    stream = abs(hash((ip.src, ip.dst, int(tcp.sport), int(tcp.dport)))) % (2**31)

    return Packet(
        IPLength=ip_total,
        IPHeaderLength=ip_hlen,
        TTL=int(ip.ttl),
        Protocol=int(ip.proto),
        SourcePort=int(tcp.sport),
        DestPort=int(tcp.dport),
        SequenceNumber=int(tcp.seq),
        AckNumber=int(tcp.ack),
        WindowSize=int(tcp.window),
        TCPHeaderLength=int(tcp.dataofs) * 4,
        TCPLength=tcp_payload_len,
        TCPStream=stream,
        TCPUrgentPointer=int(tcp.urgptr),
        IPFlags=int(ip.flags),
        IPID=int(ip.id),
        IPchecksum=int(ip.chksum) if ip.chksum is not None else 0,
        TCPflags=int(tcp.flags),
        TCPChecksum=int(tcp.chksum) if tcp.chksum is not None else 0,
    )


class BruteForceRequest(BaseModel):
    """Request body for brute-force detection."""

    username: str
    hour: int  # 0-23
    day_of_week: int  # 0=Monday .. 6=Sunday
    password_count: int
    foreign_ip: str


class BlockIpRequest(BaseModel):
    """Action payload for blocking or unblocking an IP."""

    ip: str
    reason: Optional[str] = None


class WiFiLogAppend(BaseModel):
    """Push live WiFi log lines from a collector script (router/syslog/macOS log stream)."""

    line: Optional[str] = None
    lines: Optional[list[str]] = None


class DeviceCreate(BaseModel):
    ip: str
    is_blocked: bool = False
    is_isolated: bool = False


class AlertCreate(BaseModel):
    title: str
    device_id: str
    priority: str
    type: str  # firewall, siem, ids, manual
    is_closed: bool = False
    attack_counts: dict = {"ddos": 0, "brute_force": 0}


class AutomatedActionCreate(BaseModel):
    action: str  # block, unblock, isolate, unisolate
    ip: str
    reason: Optional[str] = None
    status: str = "done"
    device_id: Optional[str] = None
    alert_id: Optional[str] = None


@app.get(
    "/actions/blocked-ips",
    tags=["Actions"],
    summary="List blocked IPs (memory)",
    description=(
        "Returns all IPs currently marked blocked in the **in-memory** set `BLOCKED_IPS`. "
        "For Mongo-backed device state, use `GET /devices`."
    ),
)
def list_blocked_ips():
    """Return the current in-memory list of blocked IPs."""
    return {"blocked_ips": sorted(BLOCKED_IPS)}


@app.post(
    "/devices",
    tags=["MongoDB"],
    summary="Create device",
    description=(
        "Insert a device document: `ip`, `is_blocked`, `is_isolated`, and zeroed `attack_counts`. "
        "Usually devices are also created automatically on first `/detect` via `ensure_device`."
    ),
)
def create_device(payload: DeviceCreate):
    if devices_collection is None:
        return {"error": "MongoDB is not connected"}
    now = datetime.utcnow().isoformat()
    doc = {
        "ip": payload.ip,
        "is_blocked": payload.is_blocked,
        "is_isolated": payload.is_isolated,
        "attack_counts": {"ddos": 0, "brute_force": 0},
        "created_at": now,
        "updated_at": now,
    }
    result = devices_collection.insert_one(doc)
    return serialize_doc(devices_collection.find_one({"_id": result.inserted_id}))


@app.get(
    "/devices",
    tags=["MongoDB"],
    summary="List devices",
    description="Returns all documents from the `devices` collection, newest first.",
)
def list_devices():
    if devices_collection is None:
        return {"error": "MongoDB is not connected"}
    docs = [serialize_doc(doc) for doc in devices_collection.find().sort("created_at", -1)]
    return {"devices": docs}


@app.post(
    "/alerts",
    tags=["MongoDB"],
    summary="Create alert",
    description=(
        "Insert an alert linked to a device (`device_id` as Mongo ObjectId string). "
        "Open firewall-style alerts are also upserted automatically when attacks are detected."
    ),
)
def create_alert(payload: AlertCreate):
    if alerts_collection is None:
        return {"error": "MongoDB is not connected"}
    now = datetime.utcnow().isoformat()
    doc = {
        "title": payload.title,
        "device_id": to_object_id(payload.device_id),
        "priority": payload.priority,
        "type": payload.type,
        "is_closed": payload.is_closed,
        "attack_counts": payload.attack_counts,
        "created_at": now,
        "updated_at": now,
    }
    result = alerts_collection.insert_one(doc)
    return serialize_alert_for_response(
        alerts_collection.find_one({"_id": result.inserted_id}),
    )


@app.get(
    "/alerts",
    tags=["MongoDB"],
    summary="List alerts",
    description=(
        "Returns **`total_alerts`**, **`total_closed`**, and **`alerts`** ordered by **`priority`**: "
        "**critical** → **high** → **medium** → **low** (case-insensitive; unknown values last), "
        "then **newest `created_at`** within each tier. "
        "Open `firewall` alerts include TP/FP counts from detect. "
        "Each alert includes **`device_ip`** when `device_id` resolves in `devices`. "
        "After **`PATCH .../close-as-*`**, the same row shows **`is_closed`**, **`close_verdict`**, "
        "**`closed_at`**."
    ),
)
def list_alerts():
    if alerts_collection is None:
        return {"error": "MongoDB is not connected"}
    total_alerts = alerts_collection.count_documents({})
    total_closed = alerts_collection.count_documents({"is_closed": True})
    raw_docs = list(alerts_collection.find())
    raw_docs.sort(key=_alert_list_sort_key)
    docs = serialize_alerts_for_list(raw_docs)
    return {
        "total_alerts": total_alerts,
        "total_closed": total_closed,
        "alerts": docs,
    }


def _close_alert_with_verdict(alert_id: str, verdict: str) -> dict:
    """
    Persist closure on the alert document (same `alerts` collection as GET /alerts) and
    publish a realtime event so UIs can merge the updated row without guessing.
    """
    if alerts_collection is None:
        return {"error": "MongoDB is not connected"}
    try:
        oid = ObjectId(alert_id)
    except InvalidId as exc:
        raise HTTPException(status_code=422, detail="Invalid alert id") from exc
    existing = alerts_collection.find_one({"_id": oid})
    if existing is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    if existing.get("is_closed"):
        raise HTTPException(status_code=400, detail="Alert is already closed")
    now = datetime.utcnow().isoformat()
    alerts_collection.update_one(
        {"_id": oid},
        {
            "$set": {
                "is_closed": True,
                "close_verdict": verdict,
                "closed_at": now,
                "updated_at": now,
            },
        },
    )
    updated = alerts_collection.find_one({"_id": oid})
    out = serialize_alert_for_response(updated) or {}
    publish_event(
        {
            "kind": "alert",
            "action": "closed",
            "close_verdict": verdict,
            "alert_id": alert_id,
            "alert": out,
        },
    )
    return out


@app.patch(
    "/alerts/{alert_id}/close-as-false-positive",
    tags=["MongoDB"],
    summary="Close alert as false positive",
    description=(
        "Updates the **`alerts`** document: **`is_closed`**, **`close_verdict`: `false_positive`**, "
        "**`closed_at`**. **`GET /alerts`** returns this state after refetch. Publishes "
        "**`kind`: `alert`**, **`action`: `closed`** on **`WS /ws/events`** with full **`alert`** "
        "payload (same shape as list items) for live UI updates."
    ),
)
def close_alert_as_false_positive(alert_id: str):
    return _close_alert_with_verdict(alert_id, "false_positive")


@app.patch(
    "/alerts/{alert_id}/close-as-true-positive",
    tags=["MongoDB"],
    summary="Close alert as true positive",
    description=(
        "Same as close-as-false-positive but **`close_verdict`: `true_positive`**. "
        "Persists to **`alerts`** and broadcasts on **`WS /ws/events`**."
    ),
)
def close_alert_as_true_positive(alert_id: str):
    return _close_alert_with_verdict(alert_id, "true_positive")


@app.post(
    "/automated-actions",
    tags=["MongoDB"],
    summary="Create automated action",
    description=(
        "Manually insert a row in `automated_actions`. Block/unblock from `/actions/*` also writes here."
    ),
)
def create_automated_action(payload: AutomatedActionCreate):
    if actions_collection is None:
        return {"error": "MongoDB is not connected"}
    now = datetime.utcnow().isoformat()
    doc = {
        "action": payload.action,
        "ip": payload.ip,
        "reason": payload.reason,
        "status": payload.status,
        "device_id": to_object_id(payload.device_id) if payload.device_id else None,
        "alert_id": to_object_id(payload.alert_id) if payload.alert_id else None,
        "created_at": now,
    }
    result = actions_collection.insert_one(doc)
    return serialize_doc(actions_collection.find_one({"_id": result.inserted_id}))


@app.get(
    "/automated-actions",
    tags=["MongoDB"],
    summary="List automated actions",
    description="Returns all documents from `automated_actions`, newest first.",
)
def list_automated_actions():
    if actions_collection is None:
        return {"error": "MongoDB is not connected"}
    docs = [serialize_doc(doc) for doc in actions_collection.find().sort("created_at", -1)]
    return {"automated_actions": docs}


@app.post(
    "/actions/block-ip",
    tags=["Actions"],
    summary="Block IP",
    description=(
        "Adds IP to in-memory block list, updates Mongo `devices.is_blocked`, inserts "
        "`automated_actions`, logs, and publishes Redis `attack-events`. "
        "If `ENFORCEMENT_ENABLED=1`, executes real command `ENFORCE_BLOCK_CMD`."
    ),
)
def block_ip(action: BlockIpRequest):
    """Block IP in app state and optionally enforce real infra command."""
    safe_ip = _validate_ip_or_raise(action.ip)
    BLOCKED_IPS.add(safe_ip)
    logger.info("block_ip ip=%s reason=%s", safe_ip, action.reason)
    record_action(safe_ip, "block", action.reason)
    enforcement = run_enforcement_command("block", safe_ip)
    device_doc = ensure_device(safe_ip)
    if devices_collection is not None:
        devices_collection.update_one(
            {"ip": safe_ip},
            {"$set": {"is_blocked": True, "updated_at": datetime.utcnow().isoformat()}},
        )
    if actions_collection is not None:
        action_doc = {
            "action": "block",
            "ip": safe_ip,
            "reason": action.reason,
            "status": (
                "done" if (not enforcement["attempted"] or enforcement["applied"]) else "failed"
            ),
            "device_id": device_doc["_id"] if device_doc else None,
            "alert_id": None,
            "created_at": datetime.utcnow().isoformat(),
            "enforcement": enforcement,
        }
        actions_collection.insert_one(action_doc)
    publish_event(
        {
            "kind": "action",
            "action": "block",
            "ip": safe_ip,
            "reason": action.reason,
            "enforcement_applied": enforcement.get("applied", False),
        },
    )
    return {"ip": safe_ip, "blocked": True, "reason": action.reason, "enforcement": enforcement}


@app.post(
    "/actions/unblock-ip",
    tags=["Actions"],
    summary="Unblock IP",
    description=(
        "Removes IP from in-memory block list, sets `devices.is_blocked=false`, records action, "
        "and publishes Redis event."
    ),
)
def unblock_ip(action: BlockIpRequest):
    """Remove an IP address from the block list."""
    safe_ip = _validate_ip_or_raise(action.ip)
    BLOCKED_IPS.discard(safe_ip)
    logger.info("unblock_ip ip=%s reason=%s", safe_ip, action.reason)
    record_action(safe_ip, "unblock", action.reason)
    enforcement = run_enforcement_command("unblock", safe_ip)
    device_doc = ensure_device(safe_ip)
    if devices_collection is not None:
        devices_collection.update_one(
            {"ip": safe_ip},
            {"$set": {"is_blocked": False, "updated_at": datetime.utcnow().isoformat()}},
        )
    if actions_collection is not None:
        action_doc = {
            "action": "unblock",
            "ip": safe_ip,
            "reason": action.reason,
            "status": (
                "done" if (not enforcement["attempted"] or enforcement["applied"]) else "failed"
            ),
            "device_id": device_doc["_id"] if device_doc else None,
            "alert_id": None,
            "created_at": datetime.utcnow().isoformat(),
            "enforcement": enforcement,
        }
        actions_collection.insert_one(action_doc)
    publish_event(
        {
            "kind": "action",
            "action": "unblock",
            "ip": safe_ip,
            "reason": action.reason,
            "enforcement_applied": enforcement.get("applied", False),
        },
    )
    return {"ip": safe_ip, "blocked": False, "reason": action.reason, "enforcement": enforcement}


@app.post(
    "/actions/isolate-ip",
    tags=["Actions"],
    summary="Isolate IP (network quarantine)",
    description=(
        "Marks IP as **isolated** (in-memory `ISOLATED_IPS`, Mongo `devices.is_isolated`), records "
        "`automated_actions`, and publishes Redis. Use for DDoS-style containment (separate from **block**)."
    ),
)
def isolate_ip(action: BlockIpRequest):
    """Quarantine an IP in state and optionally enforce real isolation command."""
    safe_ip = _validate_ip_or_raise(action.ip)
    ISOLATED_IPS.add(safe_ip)
    logger.info("isolate_ip ip=%s reason=%s", safe_ip, action.reason)
    record_action(safe_ip, "isolate", action.reason)
    enforcement = run_enforcement_command("isolate", safe_ip)
    device_doc = ensure_device(safe_ip)
    if devices_collection is not None:
        devices_collection.update_one(
            {"ip": safe_ip},
            {"$set": {"is_isolated": True, "updated_at": datetime.utcnow().isoformat()}},
        )
    if actions_collection is not None:
        actions_collection.insert_one(
            {
                "action": "isolate",
                "ip": safe_ip,
                "reason": action.reason,
                "status": (
                    "done" if (not enforcement["attempted"] or enforcement["applied"]) else "failed"
                ),
                "device_id": device_doc["_id"] if device_doc else None,
                "alert_id": None,
                "created_at": datetime.utcnow().isoformat(),
                "enforcement": enforcement,
            },
        )
    publish_event(
        {
            "kind": "action",
            "action": "isolate",
            "ip": safe_ip,
            "reason": action.reason,
            "enforcement_applied": enforcement.get("applied", False),
        },
    )
    return {"ip": safe_ip, "isolated": True, "reason": action.reason, "enforcement": enforcement}


@app.post(
    "/actions/unisolate-ip",
    tags=["Actions"],
    summary="Remove IP isolation",
    description="Clears in-memory isolation and sets `devices.is_isolated=false`.",
)
def unisolate_ip(action: BlockIpRequest):
    safe_ip = _validate_ip_or_raise(action.ip)
    ISOLATED_IPS.discard(safe_ip)
    logger.info("unisolate_ip ip=%s reason=%s", safe_ip, action.reason)
    record_action(safe_ip, "unisolate", action.reason)
    enforcement = run_enforcement_command("unisolate", safe_ip)
    device_doc = ensure_device(safe_ip)
    if devices_collection is not None:
        devices_collection.update_one(
            {"ip": safe_ip},
            {"$set": {"is_isolated": False, "updated_at": datetime.utcnow().isoformat()}},
        )
    if actions_collection is not None:
        actions_collection.insert_one(
            {
                "action": "unisolate",
                "ip": safe_ip,
                "reason": action.reason,
                "status": (
                    "done" if (not enforcement["attempted"] or enforcement["applied"]) else "failed"
                ),
                "device_id": device_doc["_id"] if device_doc else None,
                "alert_id": None,
                "created_at": datetime.utcnow().isoformat(),
                "enforcement": enforcement,
            },
        )
    publish_event(
        {
            "kind": "action",
            "action": "unisolate",
            "ip": safe_ip,
            "reason": action.reason,
            "enforcement_applied": enforcement.get("applied", False),
        },
    )
    return {"ip": safe_ip, "isolated": False, "reason": action.reason, "enforcement": enforcement}


@app.get(
    "/actions/isolated-ips",
    tags=["Actions"],
    summary="List isolated IPs (memory)",
    description="IPs currently marked isolated in the in-memory set `ISOLATED_IPS`.",
)
def list_isolated_ips():
    return {"isolated_ips": sorted(ISOLATED_IPS)}


@app.get(
    "/",
    tags=["Core"],
    summary="API root",
    description=(
        "On **localhost** (browser), redirects to **`/docs`** so Swagger opens immediately. "
        "Set `ROOT_REDIRECT_TO_DOCS=0` to always return JSON. On Vercel, returns JSON with doc links."
    ),
)
def root(request: Request):
    host = (request.headers.get("host") or "").split(":")[0].lower()
    redirect_on = os.getenv("ROOT_REDIRECT_TO_DOCS", "1").strip().lower() not in {"0", "false", "no"}
    if (
        redirect_on
        and not os.getenv("VERCEL")
        and host in ("localhost", "127.0.0.1", "::1")
    ):
        return RedirectResponse(url="/docs", status_code=302)
    base = str(request.base_url).rstrip("/")
    return {
        "message": "DDoS and Brute-force Detection API Running",
        "docs": f"{base}/docs",
        "redoc": f"{base}/redoc",
        "openapi_json": f"{base}/openapi.json",
        "health_db": f"{base}/health/db",
        "health": f"{base}/health",
        "health_accuracy": f"{base}/health/accuracy",
        "health_models": f"{base}/health/models",
    }


@app.get(
    "/health/accuracy",
    tags=["Core"],
    summary="Combined model accuracy",
    description=(
        "Returns **`{ \"accuracy\": <number|null> }`** only. Value is the **mean** of test-set "
        "accuracies from `model_metrics.json` for DDoS and brute-force (whichever are present). "
        "`null` if no metrics yet — run `train_model.py` / `train_bruteforce_model.py`."
    ),
)
def health_accuracy():
    return _accuracy_only_response()


@app.get(
    "/health/models",
    tags=["Core"],
    summary="Combined model accuracy (alias)",
    description="Same response as **`GET /health/accuracy`**: `{ \"accuracy\": ... }`.",
)
def models_health():
    return _accuracy_only_response()


@app.get(
    "/health",
    tags=["Core"],
    summary="Combined health (Mongo + accuracy)",
    description="MongoDB from `/health/db` plus single **`accuracy`** (mean of all model metrics).",
)
def health_combined():
    return {
        "mongo": db_health(),
        "accuracy": _combined_model_accuracy(),
    }


@app.get(
    "/health/db",
    tags=["Core"],
    summary="MongoDB health",
    description=(
        "Returns whether MongoDB ping succeeded at startup and which connection string/database are configured."
    ),
)
def db_health():
    """MongoDB connection status message."""
    if mongo_client is None:
        using_default = MONGO_URL == _DEFAULT_MONGO or not (os.getenv("MONGO_URL") or "").strip()
        if _on_vercel and using_default:
            hint = (
                "Vercel does not use your laptop `.env`. Add MONGO_URL (Atlas mongodb+srv://...) "
                "and MONGO_DB in Vercel → Project → Settings → Environment Variables, then Redeploy."
            )
        elif _on_vercel and not using_default:
            hint = (
                "MONGO_URL is set but connection failed. In Atlas: Network Access allow 0.0.0.0/0, "
                "check user/password, and MONGO_DB name."
            )
        elif using_default:
            hint = (
                "No MONGO_URL in environment. Put Atlas URI in `.env` next to main.py, restart "
                "uvicorn, or run: docker compose up -d for local mongodb://localhost:27017"
            )
        else:
            hint = (
                "MONGO_URL is set but connection failed. Check Atlas IP allowlist, credentials, "
                "and that the host in the URI is correct."
            )
        out: dict = {
            "mongo_connected": False,
            "message": hint,
            "mongo_url_configured": not using_default,
            "mongo_host_hint": MONGO_URL.split("@")[-1] if "@" in MONGO_URL else MONGO_URL,
            "runtime": "vercel" if _on_vercel else "local_or_other",
            "env_file_found": _DOTENV_PATH.is_file(),
        }
        if MONGO_LAST_ERROR:
            out["last_error"] = MONGO_LAST_ERROR
        return out
    return {
        "mongo_connected": True,
        "message": f"MongoDB connected (db: {MONGO_DB})",
        "mongo_host_hint": MONGO_URL.split("@")[-1] if "@" in MONGO_URL else MONGO_URL,
    }


def _safe_wifi_log_path(user_path: Optional[str]) -> Optional[Path]:
    """Only allow files under WIFI_LOG_DIR to avoid path traversal."""
    if not user_path:
        return None
    base = WIFI_LOG_DIR.resolve()
    candidate = (base / Path(user_path).name).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        return None
    return candidate


@app.get(
    "/logs/wifi",
    tags=["WiFi logs"],
    summary="Read WiFi log file (tail)",
    description=(
        "Returns the last `lines` lines from the WiFi log file (default `WIFI_LOG_PATH`, e.g. `./logs/wifi.log`). "
        "The API does not capture WiFi by itself—something must write to that file (router syslog, `log stream`, "
        "or `POST /logs/wifi/append`). Optional query `file` is a **basename** under `WIFI_LOG_DIR`."
    ),
)
def get_wifi_logs(
    lines: int = Query(500, ge=1, le=10000, description="Max lines to return from end of file"),
    file: Optional[str] = Query(
        None,
        description="Basename only, file must live under WIFI_LOG_DIR",
    ),
):
    """
    Return WiFi-related log lines from a file on disk.

    Configure automatic collection by:
    - Setting env WIFI_LOG_PATH to your router/syslog export file, or
    - Writing WiFi logs into WIFI_LOG_DIR (default: ./logs) and optionally pass ?file=wifi.log

    Typical setup: rsyslog or router cron appends to logs/wifi.log.
    """
    path = _safe_wifi_log_path(file) if file else WIFI_LOG_PATH.resolve()
    if file and path is None:
        return {"error": "invalid file", "lines": [], "path": None}

    if not path.is_file():
        return {
            "source": str(path),
            "exists": False,
            "lines": [],
            "message": "No WiFi log file yet. Set WIFI_LOG_PATH or export router logs to this path.",
        }

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"error": str(exc), "source": str(path), "lines": []}

    all_lines = text.splitlines()
    tail = all_lines[-lines:] if len(all_lines) > lines else all_lines
    return {
        "source": str(path),
        "exists": True,
        "total_lines": len(all_lines),
        "returned_lines": len(tail),
        "lines": tail,
    }


@app.get(
    "/logs/wifi/list",
    tags=["WiFi logs"],
    summary="List WiFi log files",
    description=(
        "Lists filenames under `WIFI_LOG_DIR` that look like WiFi logs (`wifi` in name or `.log`/`.txt`). "
        "Includes `default` path hint."
    ),
)
def list_wifi_log_files():
    """List candidate WiFi log files under WIFI_LOG_DIR (for frontend pickers)."""
    base = WIFI_LOG_DIR.resolve()
    if not base.is_dir():
        return {"dir": str(base), "files": []}
    names = sorted(
        p.name
        for p in base.iterdir()
        if p.is_file() and ("wifi" in p.name.lower() or p.suffix.lower() in {".log", ".txt"})
    )
    return {"dir": str(base), "files": names, "default": str(WIFI_LOG_PATH)}


def _check_wifi_ingest_auth(request: Request, x_wifi_log_key: Optional[str]) -> None:
    if WIFI_LOG_INGEST_KEY:
        if x_wifi_log_key != WIFI_LOG_INGEST_KEY:
            raise HTTPException(status_code=401, detail="Invalid or missing X-WiFi-Log-Key")
        return
    host = request.client.host if request.client else ""
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise HTTPException(
            status_code=403,
            detail="Set WIFI_LOG_INGEST_KEY for remote ingest, or POST only from localhost",
        )


@app.post(
    "/logs/wifi/append",
    tags=["WiFi logs"],
    summary="Append WiFi log lines",
    description=(
        "Appends one or more lines to `WIFI_LOG_PATH` with a UTC timestamp prefix. "
        "If `WIFI_LOG_INGEST_KEY` is set, send header **X-WiFi-Log-Key**. If not set, only **localhost** may POST. "
        "Body: `{\"line\": \"...\"}` or `{\"lines\": [\"...\", \"...\"]}`."
    ),
)
def append_wifi_logs(
    payload: WiFiLogAppend,
    request: Request,
    x_wifi_log_key: Optional[str] = Header(None, alias="X-WiFi-Log-Key"),
):
    """
    Append live lines to WIFI_LOG_PATH so GET /logs/wifi shows real-time data.

    Use a small script on the same machine (or router syslog → file) to push lines here.
    If WIFI_LOG_INGEST_KEY is set, send header: X-WiFi-Log-Key: <key>
    """
    _check_wifi_ingest_auth(request, x_wifi_log_key)
    to_write: list[str] = []
    if payload.lines:
        to_write.extend([ln for ln in payload.lines if ln is not None])
    if payload.line:
        to_write.append(payload.line)
    if not to_write:
        raise HTTPException(status_code=422, detail="Provide line or lines")

    path = WIFI_LOG_PATH.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.utcnow().isoformat()
    block = "".join(f"{stamp} {ln}\n" for ln in to_write)
    try:
        with path.open("a", encoding="utf-8") as f:
            f.write(block)
    except OSError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {"appended": len(to_write), "path": str(path)}


def load_packet_bytes_from_wifi_auto() -> bytes:
    """
    For GET /detect/packet-auto: load PCAP/raw bytes written by WiFi automation.

    1) Read file at WIFI_AUTO_PACKET_PATH (default logs/wifi_last.pcap) if it exists and non-empty.
    2) Else scan last lines of WIFI_LOG_PATH for a line starting with B64: or PCAP64: (base64 PCAP/frame).
    """
    pcap_path = WIFI_AUTO_PACKET_PATH.resolve()
    if pcap_path.is_file() and pcap_path.stat().st_size > 0:
        return pcap_path.read_bytes()

    log_path = WIFI_LOG_PATH.resolve()
    if log_path.is_file():
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for line in reversed(text.splitlines()[-800:]):
            s = line.strip()
            if s.startswith("B64:"):
                try:
                    return base64.b64decode(s[4:].strip())
                except Exception:
                    continue
            if s.startswith("PCAP64:"):
                try:
                    return base64.b64decode(s[7:].strip())
                except Exception:
                    continue

    raise HTTPException(
        status_code=400,
        detail=(
            "No packet bytes for GET /detect/packet-auto. Use POST /detect/packet-auto/upload with a .pcap, "
            f"or write a PCAP to {WIFI_AUTO_PACKET_PATH}, or append to {WIFI_LOG_PATH} a line: "
            "B64:<base64 of small pcap bytes>."
        ),
    )


def _preamble_detect_client(request: Request) -> Tuple[str, Optional[dict]]:
    """Client IP, request counts, and device doc — same bookkeeping as POST /detect."""
    client_ip = request.client.host if request.client else "unknown"
    CLIENT_IPS.add(client_ip)
    CLIENT_IP_COUNTS[client_ip] = CLIENT_IP_COUNTS.get(client_ip, 0) + 1
    device_doc = ensure_device(client_ip)
    return client_ip, device_doc


def detect_ddos_from_packet(
    packet: Packet,
    client_ip: str,
    device_doc: Optional[dict],
) -> dict:
    """
    DDoS model + Mongo/Redis/actions — same behavior as POST /detect with a JSON Packet body.
    Used by GET /detect/packet-auto and POST /detect/packet-auto/upload.
    """
    if model is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "DDoS model is not available. Add model.pkl to deployment artifact or "
                "download it at runtime before calling detection endpoints."
            ),
        )

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
        packet.TCPChecksum,
    ]])

    try:
        prediction = model.predict(features)[0]
    except Exception as exc:
        logger.exception("DDoS model.predict failed")
        raise HTTPException(
            status_code=503,
            detail=f"Model inference failed: {exc!s}"[:500],
        ) from exc
    if device_doc is not None and alerts_collection is not None:
        record_alert_tp_fp(
            device_doc["_id"],
            attack_kind="ddos",
            prediction=int(prediction),
        )
    if device_doc is not None and devices_collection is not None:
        devices_collection.update_one(
            {"_id": device_doc["_id"]},
            {
                "$inc": {"total_requests": 1},
                "$set": {
                    "last_seen_at": datetime.utcnow().isoformat(),
                    "last_detection_type": "DDoS",
                },
            },
        )

    if prediction == 1:
        alert_doc = None
        if device_doc is not None and devices_collection is not None and alerts_collection is not None:
            devices_collection.update_one(
                {"_id": device_doc["_id"]},
                {
                    "$inc": {"attack_counts.ddos": 1},
                    "$set": {"updated_at": datetime.utcnow().isoformat()},
                },
            )
            alert_doc = upsert_attack_alert(device_doc["_id"], "ddos")
            create_action_record(
                action="auto_detect_ddos",
                ip=client_ip,
                reason="DDoS attack detected",
                status="triggered",
                device_id=device_doc["_id"],
                alert_id=alert_doc["_id"] if alert_doc else None,
            )
        # Dashboard: DDoS → caller IP isolated in Mongo + in-memory set (aligned with isolate-ip)
        persist_device_is_isolated(client_ip, True)
        try:
            ISOLATED_IPS.add(_validate_ip_or_raise(client_ip))
        except HTTPException:
            pass
        logger.info(
            "ddos_detect client_ip=%s src_port=%s dst_port=%s result=DDoS",
            client_ip,
            packet.SourcePort,
            packet.DestPort,
        )
        publish_event(
            {
                "kind": "ddos",
                "client_ip": client_ip,
                "src_port": packet.SourcePort,
                "dst_port": packet.DestPort,
                "attack_detected": True,
                "attack_type": "DDoS",
                "device_id": str(device_doc["_id"]) if device_doc else None,
                "alert_id": str(alert_doc["_id"]) if alert_doc else None,
            },
        )
        return {
            "attack_detected": True,
            "attack_type": "DDoS",
            "client_ip": client_ip,
            "device_id": str(device_doc["_id"]) if device_doc else None,
            "alert_id": str(alert_doc["_id"]) if alert_doc else None,
        }

    logger.info(
        "ddos_detect client_ip=%s src_port=%s dst_port=%s result=Benign",
        client_ip,
        packet.SourcePort,
        packet.DestPort,
    )
    publish_event(
        {
            "kind": "ddos",
            "client_ip": client_ip,
            "src_port": packet.SourcePort,
            "dst_port": packet.DestPort,
            "attack_detected": False,
            "attack_type": "Benign",
        },
    )
    return {
        "attack_detected": False,
        "attack_type": "Benign",
        "client_ip": client_ip,
    }


def detect_bruteforce_from_payload(
    payload: BruteForceRequest,
    client_ip: str,
    device_doc: Optional[dict],
) -> dict:
    """Brute-force model path (same outputs as POST /detect for BF JSON)."""
    if model_bruteforce is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Brute-force model is not available. Add model_bruteforce.pkl and encoder "
                "files to deployment artifact or download them at runtime."
            ),
        )

    try:
        u = username_encoder.transform([payload.username])[0]
    except (ValueError, TypeError):
        u = 0

    try:
        ip_enc = ip_encoder.transform([payload.foreign_ip])[0]
    except (ValueError, TypeError):
        ip_enc = 0

    features = np.array([[
        u,
        payload.hour,
        payload.day_of_week,
        payload.password_count,
        ip_enc,
    ]])

    try:
        prediction = model_bruteforce.predict(features)[0]
    except Exception as exc:
        logger.exception("Brute-force model.predict failed")
        raise HTTPException(
            status_code=503,
            detail=f"Model inference failed: {exc!s}"[:500],
        ) from exc
    if device_doc is not None and alerts_collection is not None:
        record_alert_tp_fp(
            device_doc["_id"],
            attack_kind="brute_force",
            prediction=int(prediction),
            password_count=payload.password_count,
        )
    if device_doc is not None and devices_collection is not None:
        devices_collection.update_one(
            {"_id": device_doc["_id"]},
            {
                "$inc": {"total_requests": 1},
                "$set": {
                    "last_seen_at": datetime.utcnow().isoformat(),
                    "last_detection_type": "BruteForce",
                },
            },
        )

    if prediction == 1:
        alert_doc = None
        if device_doc is not None and devices_collection is not None and alerts_collection is not None:
            devices_collection.update_one(
                {"_id": device_doc["_id"]},
                {
                    "$inc": {"attack_counts.brute_force": 1},
                    "$set": {"updated_at": datetime.utcnow().isoformat()},
                },
            )
            alert_doc = upsert_attack_alert(device_doc["_id"], "brute_force")
            create_action_record(
                action="auto_detect_bruteforce",
                ip=client_ip,
                reason="Brute-force attack detected",
                status="triggered",
                device_id=device_doc["_id"],
                alert_id=alert_doc["_id"] if alert_doc else None,
            )
        # Brute-force: block attacker IP in Mongo + memory when threshold met (aligned with block-ip)
        if payload.password_count >= BF_AUTO_BLOCK_THRESHOLD:
            persist_device_is_blocked(payload.foreign_ip, True)
            try:
                BLOCKED_IPS.add(_validate_ip_or_raise(payload.foreign_ip))
            except HTTPException:
                pass
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
                "device_id": str(device_doc["_id"]) if device_doc else None,
                "alert_id": str(alert_doc["_id"]) if alert_doc else None,
            },
        )
        return {
            "attack_detected": True,
            "attack_type": "BruteForce",
            "client_ip": client_ip,
            "device_id": str(device_doc["_id"]) if device_doc else None,
            "alert_id": str(alert_doc["_id"]) if alert_doc else None,
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
        "client_ip": client_ip,
    }


def apply_ddos_automated_response(client_ip: str, out: dict, enabled: bool) -> dict:
    if not enabled:
        return out
    if out.get("attack_detected") and out.get("attack_type") == "DDoS":
        isolate_ip(
            BlockIpRequest(
                ip=client_ip,
                reason="Automated policy: DDoS detected — isolate source",
            ),
        )
        return {
            **out,
            "automated_action": {"type": "isolate", "ip": client_ip},
        }
    return {**out, "automated_action": None}


def apply_bruteforce_automated_response(
    payload: BruteForceRequest,
    out: dict,
    enabled: bool,
) -> dict:
    if not enabled:
        return out
    if not (out.get("attack_detected") and out.get("attack_type") == "BruteForce"):
        return {**out, "automated_action": None}
    if payload.password_count < BF_AUTO_BLOCK_THRESHOLD:
        return {
            **out,
            "automated_action": None,
            "policy_note": (
                f"Brute-force attack detected but password_count ({payload.password_count}) "
                f"< threshold ({BF_AUTO_BLOCK_THRESHOLD}); no block"
            ),
        }
    block_ip(
        BlockIpRequest(
            ip=payload.foreign_ip,
            reason=(
                f"Automated policy: brute-force attack, "
                f"password_count>={BF_AUTO_BLOCK_THRESHOLD}"
            ),
        ),
    )
    return {
        **out,
        "automated_action": {"type": "block", "ip": payload.foreign_ip},
    }


def run_detection(
    request: Request,
    payload: Union[Packet, BruteForceRequest],
    apply_response_policy: bool,
) -> dict:
    """
    Shared detection: classification only, or + automated response
    (DDoS → isolate caller IP; brute-force attack → block foreign_ip when password_count >= threshold).
    """
    client_ip, device_doc = _preamble_detect_client(request)
    if isinstance(payload, Packet):
        out = detect_ddos_from_packet(payload, client_ip, device_doc)
        return apply_ddos_automated_response(client_ip, out, apply_response_policy)
    out = detect_bruteforce_from_payload(payload, client_ip, device_doc)
    return apply_bruteforce_automated_response(payload, out, apply_response_policy)


def _detection_failed_http_exception(exc: BaseException) -> HTTPException:
    """
    Map unexpected detection errors to HTTP 500.
    By default the real exception is returned in `detail` (helps Vercel debugging).
    Set SOC_DEBUG_ERRORS=0 to hide details in production.
    """
    if os.getenv("SOC_DEBUG_ERRORS", "").strip().lower() in {"0", "false", "no"}:
        return HTTPException(
            status_code=500,
            detail="Internal error during detection (detail hidden: set SOC_DEBUG_ERRORS unset or 1).",
        )
    exc_type = type(exc).__name__
    msg = str(exc).strip()[:900]
    return HTTPException(status_code=500, detail=f"{exc_type}: {msg}")


_DETECT_JSON_EXAMPLES = {
    "ddos_packet_features": {
        "summary": "DDoS — 18 packet fields",
        "description": (
            "JSON object with all packet feature fields. Same as training CSV columns for DDoS. "
            "Use **Try it out** → pick this example from the dropdown."
        ),
        "value": {
            "IPLength": 40,
            "IPHeaderLength": 20,
            "TTL": 62,
            "Protocol": 6,
            "SourcePort": 11024,
            "DestPort": 8000,
            "SequenceNumber": 160752180,
            "AckNumber": 260351565,
            "WindowSize": 512,
            "TCPHeaderLength": 20,
            "TCPLength": 0,
            "TCPStream": 32891,
            "TCPUrgentPointer": 0,
            "IPFlags": 0,
            "IPID": 27547,
            "IPchecksum": 30689,
            "TCPflags": 16,
            "TCPChecksum": 46656,
        },
    },
    "brute_force_login": {
        "summary": "Brute-force — login features",
        "description": (
            "Different JSON shape (not mixed with DDoS fields). Trained on mixed_dataset-style rows."
        ),
        "value": {
            "username": "root",
            "hour": 22,
            "day_of_week": 0,
            "password_count": 6,
            "foreign_ip": "42.7.27.166",
        },
    },
}


@app.get(
    "/detect/packet-auto",
    tags=["Detection"],
    summary="DDoS detect — WiFi auto PCAP / log (GET, no body)",
    description=(
        "**No request body.** Same **DDoS** response and side effects as **`POST /detect`** with packet JSON — "
        "features come from PCAP, not the request body. Reads bytes from:\n\n"
        "1. **`WIFI_AUTO_PACKET_PATH`** (default `logs/wifi_last.pcap`).\n"
        "2. Else newest line in **`WIFI_LOG_PATH`** with **`B64:`** or **`PCAP64:`** + base64 PCAP.\n\n"
        "Requires **scapy**. To upload a file from Swagger, use **`POST /detect/packet-auto/upload`**."
    ),
)
def detect_packet_auto(request: Request):
    """Run DDoS model on the last PCAP from WiFi auto file or B64 line in wifi log."""
    raw = load_packet_bytes_from_wifi_auto()
    packet = parse_raw_bytes_to_packet(raw)
    return run_detection(request, packet, apply_response_policy=True)


@app.post(
    "/detect/packet-auto/upload",
    tags=["Detection"],
    summary="DDoS detect — upload PCAP (Swagger-friendly)",
    description=(
        "Same logic as **`GET /detect/packet-auto`** but accepts **multipart file upload** (Swagger-friendly). "
        "First packet must be IPv4+TCP."
    ),
)
async def detect_packet_auto_upload(
    request: Request,
    file: UploadFile = File(
        ...,
        description="Small PCAP from tcpdump/Wireshark, or raw frame with IPv4+TCP",
    ),
):
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Empty file")
    packet = parse_raw_bytes_to_packet(raw)
    return run_detection(request, packet, apply_response_policy=True)


@app.post(
    "/detect",
    tags=["Detection"],
    summary="Detect DDoS (JSON) or brute-force (JSON) — classification only",
    description=(
        "**Classification only** (no auto block/isolate). For policy responses use **`POST /automated-actions/detect`**.\n\n"
        "Open **Request body** and choose an example:\n\n"
        "- **DDoS**: 18 packet fields.\n"
        "- **Brute-force**: `username`, `hour`, `day_of_week`, `password_count`, `foreign_ip`.\n\n"
        "Returns `attack_detected`, `attack_type`, `client_ip`, and when Mongo is connected may include "
        "`device_id` and `alert_id`. When Mongo is connected: **DDoS** sets **`devices.is_isolated=true`** "
        "for the caller IP; **brute-force attack** sets **`devices.is_blocked=true`** for **`foreign_ip`** "
        f"when `password_count` ≥ **`{BF_AUTO_BLOCK_THRESHOLD}`** (same as auto-block policy)."
    ),
)
def detect(
    request: Request,
    payload: Annotated[
        Union[Packet, BruteForceRequest],
        Body(openapi_examples=_DETECT_JSON_EXAMPLES),
    ],
):
    """
    Classification only (no automated block/isolate). For policy responses use
    **`POST /automated-actions/detect`**.
    """
    try:
        return run_detection(request, payload, apply_response_policy=False)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("POST /detect failed")
        raise _detection_failed_http_exception(exc) from exc


@app.post(
    "/automated-actions/detect",
    tags=["Actions"],
    summary="Detect + automated response (block / isolate)",
    description=(
        "Same JSON body as **`POST /detect`** (DDoS packet fields or brute-force login features). "
        "Runs classification **and** applies policy:\n\n"
        "- **DDoS** (attack): **`POST /actions/isolate-ip`** on the **caller** `client_ip` (HTTP peer).\n"
        "- **Brute-force** (attack): **`POST /actions/block-ip`** on **`foreign_ip`** when "
        f"`password_count` ≥ **`{BF_AUTO_BLOCK_THRESHOLD}`** (override with env `BF_AUTO_BLOCK_THRESHOLD`).\n\n"
        "Response includes `automated_action` (`isolate` / `block` / `null`) when policy ran."
    ),
)
def automated_actions_detect(
    request: Request,
    payload: Annotated[
        Union[Packet, BruteForceRequest],
        Body(openapi_examples=_DETECT_JSON_EXAMPLES),
    ],
):
    """Detection with automated containment: DDoS → isolate; brute-force → block at threshold."""
    try:
        return run_detection(request, payload, apply_response_policy=True)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("POST /automated-actions/detect failed")
        raise _detection_failed_http_exception(exc) from exc


@app.get(
    "/stats/client-ips",
    tags=["Stats"],
    summary="Unique client IPs",
    description="All distinct IPs that have called `POST /detect` since process start (in-memory).",
)
def list_client_ips():
    """Return all unique client IPs that have called /detect."""
    return {"ips": sorted(CLIENT_IPS)}


@app.get(
    "/stats/client-ips/detail",
    tags=["Stats"],
    summary="Client IPs with counts and last action",
    description=(
        "Per IP: number of `/detect` calls and last block/unblock action from in-memory `IP_ACTIONS`."
    ),
)
def list_client_ips_detail():
    """Return client IPs with call counts and last action (if any)."""
    return {
        "clients": [
            {
                "ip": ip,
                "count": CLIENT_IP_COUNTS.get(ip, 0),
                "last_action": IP_ACTIONS.get(ip, [])[-1]["action"]
                if IP_ACTIONS.get(ip)
                else None,
            }
            for ip in sorted(CLIENT_IPS)
        ],
    }


@app.get(
    "/stats/ip-actions",
    tags=["Stats"],
    summary="Full action history per IP",
    description="Complete block/unblock history from in-memory `IP_ACTIONS` (not Mongo).",
)
def list_ip_actions():
    """Return full action history (block/unblock) for each IP."""
    return {
        "ips": [
            {
                "ip": ip,
                "actions": IP_ACTIONS.get(ip, []),
            }
            for ip in sorted(IP_ACTIONS.keys())
        ],
    }


@app.get(
    "/events/recent",
    tags=["Realtime"],
    summary="Recent realtime events",
    description=(
        "Returns recent events from detections/actions. Use for initial dashboard load, "
        "then subscribe to `WS /ws/events` for live updates."
    ),
)
def get_recent_events(
    limit: int = Query(100, ge=1, le=2000, description="Number of most recent events"),
):
    with EVENT_LOCK:
        events = EVENT_HISTORY[-limit:]
        latest_seq = EVENT_SEQUENCE
    return {
        "events": events,
        "count": len(events),
        "latest_seq": latest_seq,
    }


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    """
    Realtime event stream for dashboards.
    Query params:
    - replay: send last N events on connect (default 50)
    - since: send events with seq > since, then continue live
    """
    await websocket.accept()
    params = websocket.query_params
    replay_raw = params.get("replay", "50")
    since_raw = params.get("since")
    try:
        replay = min(max(int(replay_raw), 0), EVENT_HISTORY_MAXLEN)
    except ValueError:
        replay = 50
    since: Optional[int] = None
    if since_raw is not None:
        try:
            since = int(since_raw)
        except ValueError:
            since = None

    last_seq_sent = 0
    with EVENT_LOCK:
        if since is not None:
            initial_events = [evt for evt in EVENT_HISTORY if evt.get("seq", 0) > since]
            last_seq_sent = since
        else:
            initial_events = EVENT_HISTORY[-replay:] if replay > 0 else []
            if initial_events:
                last_seq_sent = int(initial_events[-1].get("seq", 0))
            else:
                last_seq_sent = EVENT_SEQUENCE

    try:
        await websocket.send_json(
            {
                "kind": "system",
                "type": "connected",
                "latest_seq": EVENT_SEQUENCE,
                "replayed": len(initial_events),
            },
        )
        for evt in initial_events:
            await websocket.send_json(evt)
            last_seq_sent = int(evt.get("seq", last_seq_sent))

        while True:
            with EVENT_LOCK:
                pending = [evt for evt in EVENT_HISTORY if int(evt.get("seq", 0)) > last_seq_sent]
            for evt in pending:
                await websocket.send_json(evt)
                last_seq_sent = int(evt.get("seq", last_seq_sent))

            try:
                message = await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
                if message.strip().lower() == "ping":
                    await websocket.send_json(
                        {
                            "kind": "system",
                            "type": "pong",
                            "timestamp": datetime.utcnow().isoformat(),
                        },
                    )
            except asyncio.TimeoutError:
                continue
    except WebSocketDisconnect:
        return