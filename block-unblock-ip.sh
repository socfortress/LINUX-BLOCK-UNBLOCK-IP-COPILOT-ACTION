#!/bin/bash
set -eu

ScriptName="LinuxFirewall-iptables"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
RunStart="$(date +%s)"
TARGET_IP="${ARG1:-${1:-}}"
ACTION_LOWER="$(printf '%s' "${ARG2:-${2:-block}}" | tr '[:upper:]' '[:lower:]')"
case "$ACTION_LOWER" in block|unblock) ACTION="$ACTION_LOWER";; *) ACTION="block";; esac

WriteLog() {
  local msg="$1" lvl="${2:-INFO}"
  local ts; ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  local line="[$ts][$lvl] $msg"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >> "$LogPath" 2>/dev/null || true
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  local size_kb; size_kb=$(awk -v s="$(wc -c <"$LogPath")" 'BEGIN{printf "%.0f", s/1024}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  local i=$((LogKeep-1))
  while [ $i -ge 1 ]; do
    local src="$LogPath.$i" dst="$LogPath.$((i+1))"
    [ -f "$src" ] && mv -f "$src" "$dst" || true
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

iso_now(){ date -u +"%Y-%m-%dT%H:%M:%SZ"; }
escape_json(){ printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
am_root(){ [ "$(id -u)" -eq 0 ]; }
maybe_sudo(){ if am_root; then "$@"; elif command -v sudo >/dev/null 2>&1; then sudo "$@"; else "$@"; fi; }

BeginNDJSON(){ TMP_AR="$(mktemp)"; }

AddRecord(){
  local ts ip status reason details
  ts="$(iso_now)"
  ip="$(escape_json "${1:-}")"
  status="$(escape_json "${2:-}")"
  reason="$(escape_json "${3:-}")"
  details="$(escape_json "${4:-}")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"ip":"%s","status":"%s","reason":"%s","details":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$ip" "$status" "$reason" "$details" >> "$TMP_AR"
}

CommitNDJSON(){
  local ar_dir; ar_dir="$(dirname "$ARLog")"
  [ -d "$ar_dir" ] || WriteLog "Directory missing: $ar_dir (will attempt write anyway)" WARN
  if mv -f "$TMP_AR" "$ARLog" 2>/dev/null; then
    :
  else
    WriteLog "Primary write FAILED to $ARLog" WARN
    if mv -f "$TMP_AR" "$ARLog.new" 2>/dev/null; then
      WriteLog "Wrote NDJSON to $ARLog.new (fallback)" WARN
    else
      local keep="/tmp/active-responses.$$.ndjson"
      cp -f "$TMP_AR" "$keep" 2>/dev/null || true
      WriteLog "Failed to write both $ARLog and $ARLog.new; saved $keep" ERROR
      rm -f "$TMP_AR" 2>/dev/null || true
      exit 1
    fi
  fi
  for p in "$ARLog" "$ARLog.new"; do
    if [ -f "$p" ]; then
      local sz ino head1
      sz=$(wc -c < "$p" 2>/dev/null || echo 0)
      ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
      head1=$(head -n1 "$p" 2>/dev/null || true)
      WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO
    fi
  done
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="

if [ -z "${TARGET_IP:-}" ]; then
  BeginNDJSON; AddRecord "" "error" "No IP provided (ARG1 or \$1)" ""; CommitNDJSON; exit 1
fi
if ! printf '%s' "$TARGET_IP" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
  BeginNDJSON; AddRecord "$TARGET_IP" "error" "Invalid IPv4 address format" ""; CommitNDJSON; exit 1
fi
if ! command -v iptables >/dev/null 2>&1; then
  BeginNDJSON; AddRecord "$TARGET_IP" "failed" "iptables not installed" ""; CommitNDJSON; exit 1
fi

STATUS="unknown"; REASON=""; DETAILS=""

if [ "$ACTION" = "block" ]; then
  if maybe_sudo iptables -C INPUT -s "$TARGET_IP" -j DROP 2>/dev/null; then
    STATUS="already_blocked"; REASON="Rule exists"; DETAILS="iptables -C INPUT -s $TARGET_IP -j DROP"
  else
    if maybe_sudo iptables -I INPUT -s "$TARGET_IP" -j DROP 2>/dev/null; then
      STATUS="blocked"; REASON="Rule inserted"; DETAILS="iptables -I INPUT -s $TARGET_IP -j DROP"
    else
      STATUS="failed"; REASON="iptables insert failed"; DETAILS="iptables -I INPUT -s $TARGET_IP -j DROP"
    fi
  fi
else 
  REMOVED=0
  while maybe_sudo iptables -C INPUT -s "$TARGET_IP" -j DROP 2>/dev/null; do
    if maybe_sudo iptables -D INPUT -s "$TARGET_IP" -j DROP 2>/dev/null; then
      REMOVED=$((REMOVED+1))
    else
      break
    fi
  done
  if [ "$REMOVED" -gt 0 ]; then
    STATUS="unblocked"; REASON="Removed DROP rules"; DETAILS="count=${REMOVED}"
  else
    STATUS="not_blocked"; REASON="No matching rule"; DETAILS="iptables -C INPUT -s $TARGET_IP -j DROP (not found)"
  fi
fi

BeginNDJSON
AddRecord "$TARGET_IP" "$STATUS" "$REASON" "$DETAILS"
CommitNDJSON

Duration=$(( $(date +%s) - RunStart ))
WriteLog "=== SCRIPT END : duration ${Duration}s ==="
