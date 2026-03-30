#!/usr/bin/env bash
set -euo pipefail

# Example: real commands must exist on your machine and support "{ip}" placeholder.
# export ENFORCEMENT_ENABLED=1
# export ENFORCE_BLOCK_CMD='sudo /usr/local/bin/soc-block-ip {ip}'
# export ENFORCE_ISOLATE_CMD='sudo /usr/local/bin/soc-isolate-ip {ip}'

export REDIS_URL="${REDIS_URL:-redis://localhost:6379/0}"
export ALERT_QUEUE_STREAM="${ALERT_QUEUE_STREAM:-security-alerts}"
export ACTION_SERVICE_GROUP="${ACTION_SERVICE_GROUP:-action-service}"
export ACTION_SERVICE_CONSUMER="${ACTION_SERVICE_CONSUMER:-consumer-1}"
export BF_AUTO_BLOCK_THRESHOLD="${BF_AUTO_BLOCK_THRESHOLD:-6}"

python3 automation_service.py
