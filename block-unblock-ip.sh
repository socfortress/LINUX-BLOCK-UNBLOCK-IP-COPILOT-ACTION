#!/bin/bash
TARGET_IP=""
ACTION="block"
LOG_PATH="/tmp/LinuxFirewall-script.log"
AR_LOG="/var/ossec/active-response/active-responses.log"
HOSTNAME=$(hostname)
RUN_START=$(date +%s)

# Map Velociraptor arguments
[ -n "$ARG1" ] && [ -z "$TARGET_IP" ] && TARGET_IP="$ARG1"
[ -n "$ARG2" ] && [ "$ACTION" = "block" ] && ACTION="$ARG2"

# Validate IP
if [[ -z "$TARGET_IP" ]]; then
  echo "ERROR: TARGET_IP is required (no interactive input allowed)" >&2
  exit 1
fi
if ! [[ "$TARGET_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "ERROR: Invalid IPv4 address format: $TARGET_IP" >&2
  exit 1
fi

write_log() {
  local level="$1"
  local message="$2"
  local ts
  ts=$(date +"%Y-%m-%d %H:%M:%S.%3N")
  echo "[$ts][$level] $message" | tee -a "$LOG_PATH"
}

rotate_log() {
  local max_kb=100
  local keep=5
  if [[ -f "$LOG_PATH" ]]; then
    local size_kb=$(( $(stat -c%s "$LOG_PATH") / 1024 ))
    if (( size_kb > max_kb )); then
      for ((i=keep-1; i>=0; i--)); do
        [[ -f "$LOG_PATH.$i" ]] && mv -f "$LOG_PATH.$i" "$LOG_PATH.$((i+1))"
      done
      mv -f "$LOG_PATH" "$LOG_PATH.1"
    fi
  fi
}

rotate_log
write_log "INFO" "=== SCRIPT START : Firewall $ACTION for IP $TARGET_IP ==="

STATUS="unknown"
if [[ "$ACTION" == "block" ]]; then
  if iptables -C INPUT -s "$TARGET_IP" -j DROP 2>/dev/null; then
    write_log "WARN" "IP $TARGET_IP already blocked"
    STATUS="already_blocked"
  else
    iptables -I INPUT -s "$TARGET_IP" -j DROP && STATUS="blocked" || STATUS="error"
    write_log "INFO" "Blocking IP $TARGET_IP: $STATUS"
  fi
else
  if iptables -C INPUT -s "$TARGET_IP" -j DROP 2>/dev/null; then
    iptables -D INPUT -s "$TARGET_IP" -j DROP && STATUS="unblocked" || STATUS="error"
    write_log "INFO" "Unblocking IP $TARGET_IP: $STATUS"
  else
    write_log "WARN" "No block rule for IP $TARGET_IP"
    STATUS="not_found"
  fi
fi

TS=$(date -Iseconds)
JSON=$(jq -n \
  --arg timestamp "$TS" \
  --arg host "$HOSTNAME" \
  --arg action "firewall_$ACTION" \
  --arg target_ip "$TARGET_IP" \
  --arg status "$STATUS" \
  --arg copilot_action "true" \
  '{timestamp:$timestamp,host:$host,action:$action,target_ip:$target_ip,status:$status, copilot_action:$copilot_action}')

echo "$JSON" >> "$AR_LOG"
write_log "INFO" "JSON appended to $AR_LOG"

RUN_END=$(date +%s)
DURATION=$((RUN_END - RUN_START))
write_log "INFO" "=== SCRIPT END : duration ${DURATION}s ==="
exit 0

