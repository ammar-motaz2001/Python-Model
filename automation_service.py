import ipaddress
import json
import logging
import os
import shlex
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

import redis


@dataclass
class Config:
    redis_url: str
    stream: str
    group: str
    consumer: str
    block_ms: int
    count: int
    brute_force_block_threshold: int
    enforce_block_cmd: str
    enforce_isolate_cmd: str
    enforce_enabled: bool
    enforce_timeout_seconds: int


def load_config() -> Config:
    return Config(
        redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        stream=os.getenv("ALERT_QUEUE_STREAM", "security-alerts"),
        group=os.getenv("ACTION_SERVICE_GROUP", "action-service"),
        consumer=os.getenv("ACTION_SERVICE_CONSUMER", "consumer-1"),
        block_ms=max(100, int(os.getenv("ACTION_SERVICE_BLOCK_MS", "5000"))),
        count=max(1, int(os.getenv("ACTION_SERVICE_COUNT", "50"))),
        brute_force_block_threshold=max(
            1,
            int(os.getenv("BF_AUTO_BLOCK_THRESHOLD", "6")),
        ),
        enforce_block_cmd=os.getenv("ENFORCE_BLOCK_CMD", "").strip(),
        enforce_isolate_cmd=os.getenv("ENFORCE_ISOLATE_CMD", "").strip(),
        enforce_enabled=os.getenv("ENFORCEMENT_ENABLED", "0").strip() in {"1", "true", "yes"},
        enforce_timeout_seconds=max(1, int(os.getenv("ENFORCE_TIMEOUT_SECONDS", "8"))),
    )


logger = logging.getLogger("automation_service")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

RUNNING = True


def handle_signal(_sig: int, _frame) -> None:
    global RUNNING
    RUNNING = False


def validate_ip(ip: str) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


def run_action_command(action: str, ip: str, cfg: Config) -> dict:
    if not cfg.enforce_enabled:
        return {
            "attempted": False,
            "applied": False,
            "message": "ENFORCEMENT_ENABLED is off",
        }
    command_template = cfg.enforce_block_cmd if action == "block" else cfg.enforce_isolate_cmd
    if not command_template:
        return {
            "attempted": False,
            "applied": False,
            "message": f"Command for action '{action}' is not configured",
        }
    safe_ip = validate_ip(ip)
    if safe_ip is None:
        return {
            "attempted": False,
            "applied": False,
            "message": f"Invalid IP: {ip}",
        }
    command = command_template.format(ip=safe_ip)
    try:
        result = subprocess.run(
            shlex.split(command),
            check=False,
            capture_output=True,
            text=True,
            timeout=cfg.enforce_timeout_seconds,
        )
    except Exception as exc:
        return {
            "attempted": True,
            "applied": False,
            "command": command,
            "error": str(exc),
        }
    return {
        "attempted": True,
        "applied": result.returncode == 0,
        "command": command,
        "return_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def choose_action(event: dict, cfg: Config) -> Optional[tuple[str, str, str]]:
    """
    Return action tuple: (action, ip, reason)
    - ddos attack_detected=True => isolate client_ip
    - bruteforce attack_detected=True and password_count>=threshold => block foreign_ip
    """
    if not event.get("attack_detected"):
        return None

    kind = str(event.get("kind", "")).lower()
    attack_type = str(event.get("attack_type", "")).lower()

    is_ddos = kind == "ddos" or attack_type == "ddos"
    if is_ddos:
        ip = str(event.get("client_ip") or "").strip()
        if not ip:
            return None
        return ("isolate", ip, "Automation Service: DDoS detected")

    is_bruteforce = kind == "bruteforce" or attack_type == "bruteforce"
    if is_bruteforce:
        try:
            password_count = int(event.get("password_count", 0))
        except Exception:
            password_count = 0
        if password_count < cfg.brute_force_block_threshold:
            return None
        ip = str(event.get("foreign_ip") or "").strip()
        if not ip:
            return None
        return (
            "block",
            ip,
            (
                "Automation Service: Brute-force detected "
                f"(password_count={password_count}, threshold={cfg.brute_force_block_threshold})"
            ),
        )
    return None


def ensure_group(r: redis.Redis, cfg: Config) -> None:
    try:
        r.xgroup_create(cfg.stream, cfg.group, id="0", mkstream=True)
        logger.info("Created stream/group: %s / %s", cfg.stream, cfg.group)
    except redis.exceptions.ResponseError as exc:
        if "BUSYGROUP" in str(exc):
            return
        raise


def process_message(r: redis.Redis, cfg: Config, msg_id: str, fields: dict) -> None:
    raw = fields.get("event_json")
    if not raw:
        logger.warning("Skip message %s: missing event_json", msg_id)
        r.xack(cfg.stream, cfg.group, msg_id)
        return
    try:
        event = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Skip message %s: invalid JSON", msg_id)
        r.xack(cfg.stream, cfg.group, msg_id)
        return

    decision = choose_action(event, cfg)
    if decision is None:
        r.xack(cfg.stream, cfg.group, msg_id)
        return

    action, ip, reason = decision
    result = run_action_command(action, ip, cfg)
    logger.info(
        "event_id=%s kind=%s action=%s ip=%s applied=%s",
        msg_id,
        event.get("kind"),
        action,
        ip,
        result.get("applied"),
    )

    # Keep audit trail in Redis (optional, best-effort).
    try:
        r.xadd(
            "security-actions",
            {
                "event_id": msg_id,
                "action": action,
                "ip": ip,
                "reason": reason,
                "applied": json.dumps(bool(result.get("applied"))),
                "result_json": json.dumps(result),
            },
            maxlen=20000,
            approximate=True,
        )
    except Exception:
        logger.exception("Failed to write security-actions audit stream")

    r.xack(cfg.stream, cfg.group, msg_id)


def run() -> int:
    cfg = load_config()
    logger.info(
        "Starting Automation Service redis=%s stream=%s group=%s consumer=%s",
        cfg.redis_url,
        cfg.stream,
        cfg.group,
        cfg.consumer,
    )
    r = redis.from_url(cfg.redis_url, decode_responses=True)
    ensure_group(r, cfg)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    while RUNNING:
        entries = r.xreadgroup(
            groupname=cfg.group,
            consumername=cfg.consumer,
            streams={cfg.stream: ">"},
            count=cfg.count,
            block=cfg.block_ms,
        )
        if not entries:
            continue
        for _stream_name, messages in entries:
            for msg_id, fields in messages:
                try:
                    process_message(r, cfg, msg_id, fields)
                except Exception:
                    logger.exception("Failed to process message %s", msg_id)
    logger.info("Automation Service stopped")
    return 0


if __name__ == "__main__":
    sys.exit(run())
