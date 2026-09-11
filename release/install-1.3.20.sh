#!/usr/bin/env bash
# Meshia Node installer — one line and idempotent. The node itself is entirely
# current-user scoped; first-time installation of the small OS filesystem
# runtime may request one administrator approval.
#
#   bash -c 'script=$(curl -fsSL "https://connect.meshia.io/?prompt=1") && bash <<< "$script"'
#
# The authenticated Meshia workspace shows the one-time code separately; this
# installer reads it without echo from the terminal and never puts it in a URL
# or shell history.
#
# Private Meshia state/runtime land under ~/.meshia (0700), the CLI under
# ~/.local/bin, and the private recovery working set under ~/.meshia. Only small
# OS prerequisites (the optional filesystem runtime and, on musl Linux, a
# dynamically linked system Python) may be system-installed; meshia-node itself
# never runs as root.
set -euo pipefail

# A direct/manual install may receive PAIR_CODE or PAIR_GRANT as an exported
# variable. Copy it into a shell-only variable and erase both exported names
# before even a platform probe or downloader child can inherit the grant.
set +a
PAIR_GRANT_VALUE="${PAIR_CODE:-${PAIR_GRANT:-}}"
if [ "${MESHIA_ROOT_PAIR_STDIN:-0}" = "1" ]; then
  # A Linux root bootstrap passes the one-use grant on stdin while invoking
  # the real installer as the dedicated unprivileged user.  The grant never
  # enters argv, a temporary file, or the delegated environment.
  IFS= read -r PAIR_GRANT_VALUE || PAIR_GRANT_VALUE=""
fi
unset MESHIA_ROOT_PAIR_STDIN
unset PAIR_CODE PAIR_GRANT
PAIR_GRANT="$PAIR_GRANT_VALUE"
unset PAIR_GRANT_VALUE
export -n PAIR_GRANT
PROMPT_PAIR="${PROMPT_PAIR:-0}"
REPAIR_EXISTING="${REPAIR_EXISTING:-0}"

UV_VERSION="${MESHIA_UV_VERSION:-0.12.11}"
PYTHON_VERSION="${MESHIA_PYTHON_VERSION:-3.12.14}"
DEFAULT_MESHIA_HOME="$HOME/.meshia"
MESHIA_HOME="${MESHIA_HOME:-$DEFAULT_MESHIA_HOME}"
case "$MESHIA_HOME" in
  /*) ;;
  *) MESHIA_HOME="$(pwd -P)/$MESHIA_HOME" ;;
esac
CUSTOM_MESHIA_HOME=1
[ "$MESHIA_HOME" = "$DEFAULT_MESHIA_HOME" ] && CUSTOM_MESHIA_HOME=0
RUNTIME_LINK="$MESHIA_HOME/runtime"
PREVIOUS_RUNTIME_LINK="$MESHIA_HOME/previous-runtime"
RUNTIMES_DIR="$MESHIA_HOME/runtimes"
TOOL_DIR="$MESHIA_HOME/bin"
CACHE_DIR="$MESHIA_HOME/cache"
BIN_DIR="${MESHIA_BIN_DIR:-$HOME/.local/bin}"
case "$BIN_DIR" in
  /*) ;;
  *) BIN_DIR="$(pwd -P)/$BIN_DIR" ;;
esac
UV_CACHE_DIR="${UV_CACHE_DIR:-$CACHE_DIR/uv}"
UV_PYTHON_INSTALL_DIR="${UV_PYTHON_INSTALL_DIR:-$CACHE_DIR/python}"
case "$UV_CACHE_DIR" in
  /*) ;;
  *) UV_CACHE_DIR="$(pwd -P)/$UV_CACHE_DIR" ;;
esac
case "$UV_PYTHON_INSTALL_DIR" in
  /*) ;;
  *) UV_PYTHON_INSTALL_DIR="$(pwd -P)/$UV_PYTHON_INSTALL_DIR" ;;
esac
PACKAGE_URL="${MESHIA_NODE_PACKAGE_URL:-}"
NODE_APP_URL="${MESHIA_NODE_MACOS_APP_URL:-}"
NODE_APP_SHA="${MESHIA_NODE_MACOS_APP_SHA256:-}"
# Optional signed macOS host app carrying File Provider and, when supplied, FSKit (release.json
# macos_app / macos_app_sha256, a local zip via MESHIA_NATIVE_APP_ZIP (legacy:
# MESHIA_FSKIT_APP_ZIP), or the
# checkout's build/Meshia.app in --from-dir mode). Installed under
# ~/Applications; the node's `mount --backend auto` uses it once enabled.
NATIVE_APP_ZIP_NAME=""
NATIVE_APP_ZIP_SHA=""
NATIVE_APP_MODE="${MESHIA_NATIVE_APP:-${MESHIA_FSKIT_APP:-auto}}"
NATIVE_APP_BUNDLE_ID="io.meshia.Meshia"
FSKIT_EXTENSION_BUNDLE_ID="io.meshia.Meshia.MeshiaFSExtension"
FILE_PROVIDER_EXTENSION_BUNDLE_ID="io.meshia.Meshia.MeshiaFileProvider"
PACKAGE_SHA256="${MESHIA_NODE_PACKAGE_SHA256:-}"
FROM_DIR=""
INSECURE_DEV=0
API_URL="${API_URL:-}"
TIER_EXPLICIT=0
[ -n "${TIER:-}" ] && TIER_EXPLICIT=1
TIER="${TIER:-compute}"
ACCESS_EXPLICIT=0
[ -n "${ACCESS:-}" ] && ACCESS_EXPLICIT=1
ACCESS="${ACCESS:-}"
[ "$ACCESS_EXPLICIT" = "1" ] && TIER="compute" && TIER_EXPLICIT=1
WORKSPACE_EXPLICIT=0
[ -n "${WORKSPACE:-}" ] && WORKSPACE_EXPLICIT=1
WORKSPACE="${WORKSPACE:-}"
ADOPT_EXISTING_WORKSPACE=0
CONNECT_MODE="${CONNECT_MODE:-service}"
WORK_DIR=""
LOCK_DIR="$MESHIA_HOME/locks"
INSTALL_LOCK_DIR="$LOCK_DIR/installer.lock"
INSTALL_LOCK_HELD=0
CANDIDATE_RUNTIME=""
CANDIDATE_CLI=""
CANDIDATE_CREATED=0
CANDIDATE_COMMITTED=0
TRANSACTION_ACTIVE=0
POINTER_FLIPPED=0
PRIOR_SERVICE_UNINSTALLED=0
CANDIDATE_SERVICE_INSTALLED=0
ACCOUNT_CUTOVER_PREPARED=0
PRIOR_RUNTIME=""
PRIOR_VERSION=""
PRIOR_SERVICE_SUPPORTED=0
HAD_ENROLLMENT=0
PARKED_ENROLLMENT=0
HAD_MESHIA_ALIAS=0
MIGRATION_MARKER="$MESHIA_HOME/.runtime-migration"
BASE_PYTHON=""
LINUX_MUSL=0
MOUNT_RUNTIME_MODE="${MESHIA_MOUNT_RUNTIME:-auto}"
NATIVE_MOUNT_READY=0
REFRESH_FINDER_AFTER_MOUNT=0
ROOT_BOOTSTRAP_REQUIRED=0
FUSE_T_VERSION="1.2.7"
FUSE_T_SHA256="6a29c747e61a86a405a189efc3de42812d73147135f93a1bb0624c1e7b90e654"
FUSE_T_INSTALLER_ID="Developer ID Installer: alex fishman (6DY7Z4SVDZ)"
FUSE_T_TEAM_ID="6DY7Z4SVDZ"
FUSE_T_LIBRARY_IDENTIFIER="libfuse-t-1"
FUSE_T_HELPER_IDENTIFIER="go-nfsv4-1"
FUSE_T_CODESIGN_BIN="/usr/bin/codesign"
FUSE_T_PKGUTIL_BIN="/usr/sbin/pkgutil"
FUSE_T_READLINK_BIN="/usr/bin/readlink"
FUSE_T_STAT_BIN="/usr/bin/stat"

UI_INTERACTIVE=0
UI_UNICODE=0
UI_COLOR=0
UI_ANIMATE=0
UI_COMPLETED=0
UI_LOADER_PID=""
if [ -t 2 ] && [ "${TERM:-dumb}" != "dumb" ] \
    && [ "${MESHIA_PLAIN:-0}" != "1" ]; then
  UI_INTERACTIVE=1
fi
case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
  *UTF-8*|*utf8*)
    if [ "$UI_INTERACTIVE" = "1" ]; then UI_UNICODE=1; fi
    ;;
esac
if [ "$UI_INTERACTIVE" = "1" ] && [ -z "${NO_COLOR:-}" ]; then UI_COLOR=1; fi
if [ "$UI_INTERACTIVE" = "1" ] && [ -z "${CI:-}" ] \
    && [ "${MESHIA_REDUCE_MOTION:-0}" != "1" ]; then
  UI_ANIMATE=1
fi

ui_tint() { # ui_tint <ansi code> <text>
  if [ "$UI_COLOR" = "1" ]; then printf '\033[%sm%s\033[0m' "$1" "$2" >&2
  else printf '%s' "$2" >&2
  fi
}

ui_pixel_strip() { # ui_pixel_strip <active index 1..5> <active|progress|success|fail>
  local active="$1" mode="$2" index=1 distance=0 color=236
  while [ "$index" -le 5 ]; do
    case "$mode" in
      success) color=42 ;;
      fail)
        if [ "$index" -le 2 ]; then color=196; else color=236; fi
        ;;
      progress)
        if [ "$index" -lt "$active" ]; then color=97
        elif [ "$index" -eq "$active" ]; then color=213
        else color=236
        fi
        ;;
      *)
        distance=$((index - active))
        [ "$distance" -ge 0 ] || distance=$((-distance))
        case "$distance" in
          0) color=219 ;;
          1) color=177 ;;
          2) color=97 ;;
          *) color=236 ;;
        esac
        ;;
    esac
    [ "$index" -eq 1 ] || printf ' ' >&2
    # Two background-colored character cells are approximately square in a
    # normal terminal. The animation is pixels, not a sequence of text glyphs.
    printf '\033[48;5;%sm  \033[0m' "$color" >&2
    index=$((index + 1))
  done
}

ui_begin() {
  printf '\n' >&2
  if [ "$UI_UNICODE" = "1" ]; then
    printf '  ' >&2; ui_tint '38;5;141' '■ ◻ ■'; printf '   ' >&2
    ui_tint '1;38;5;213' 'M E S H I A'; printf '\n  ' >&2
    ui_tint '38;5;141' '◻ ■ ■'; printf '   ' >&2
    ui_tint '38;5;110' 'NODE INSTALLER'; printf '\n\n' >&2
  else
    printf '  # . #   M E S H I A\n  . # #   NODE INSTALLER\n\n' >&2
  fi
}

ui_phase_bar_capture() { # ui_phase_bar_capture <filled> <total> <active glyph>
  local filled="$1" total="$2" active="$3" index=1
  while [ "$index" -le "$total" ]; do
    [ "$index" -eq 1 ] || printf ' '
    if [ "$index" -lt "$filled" ]; then printf '■'
    elif [ "$index" -eq "$filled" ]; then printf '%s' "$active"
    else printf '□'
    fi
    index=$((index + 1))
  done
}

ui_phase() { # ui_phase <current> <total> <label>
  local current="$1" total="$2" label="$3" bar=""
  if [ "$UI_INTERACTIVE" != "1" ]; then
    printf '\n[%s/%s] %s\n' "$current" "$total" "$label" >&2
    return
  fi
  if [ "$UI_COLOR" = "1" ]; then
    printf '  ' >&2; ui_pixel_strip "$current" progress
    printf '  %s/%s  %s\n' "$current" "$total" "$label" >&2
  elif [ "$UI_UNICODE" = "1" ]; then
    bar="$(ui_phase_bar_capture "$current" "$total" '■')"
    printf '  ' >&2; ui_tint '38;5;141' "$bar"
    printf '  %s/%s  %s\n' "$current" "$total" "$label" >&2
  else
    printf '  [%s/%s] %s\n' "$current" "$total" "$label" >&2
  fi
}

ui_loader_loop() { # ui_loader_loop <label>
  local label="$1" frame=""
  trap 'exit 0' HUP INT TERM
  while :; do
    if [ "$UI_COLOR" = "1" ]; then
      for frame in 1 2 3 4 5 4 3 2; do
        printf '\r  ' >&2; ui_pixel_strip "$frame" active
        printf '  %s' "$label" >&2
        sleep 0.065
      done
    else
      for frame in \
        '■ □ □ □ □' '□ ■ □ □ □' '□ □ ■ □ □' '□ □ □ ■ □' \
        '□ □ □ □ ■' '□ □ □ ■ □' '□ □ ■ □ □' '□ ■ □ □ □'; do
        printf '\r  %s  %s' "$frame" "$label" >&2
        sleep 0.085
      done
    fi
  done
}

ui_loader_start() { # ui_loader_start <label>
  local label="$1"
  UI_LOADER_PID=""
  [ "$UI_INTERACTIVE" = "1" ] || return 0
  if [ "$UI_ANIMATE" = "1" ] && { [ "$UI_COLOR" = "1" ] || [ "$UI_UNICODE" = "1" ]; }; then
    ui_loader_loop "$label" &
    UI_LOADER_PID=$!
  elif [ "$UI_COLOR" = "1" ]; then
    printf '  ' >&2; ui_pixel_strip 3 active
    printf '  %s' "$label" >&2
  elif [ "$UI_UNICODE" = "1" ]; then
    printf '  ' >&2; ui_tint '38;5;141' '□ □ ■ □ □'
    printf '  %s' "$label" >&2
  else
    printf '  [...] %s' "$label" >&2
  fi
}

ui_loader_stop() { # ui_loader_stop <ok|fail> <label>
  local result="$1" label="$2"
  if [ -n "$UI_LOADER_PID" ]; then
    kill "$UI_LOADER_PID" 2>/dev/null || true
    wait "$UI_LOADER_PID" 2>/dev/null || true
    UI_LOADER_PID=""
  fi
  [ "$UI_INTERACTIVE" = "1" ] || return 0
  printf '\r\033[2K  ' >&2
  if [ "$UI_COLOR" = "1" ]; then
    if [ "$result" = "ok" ]; then ui_pixel_strip 0 success
    else ui_pixel_strip 0 fail
    fi
  elif [ "$UI_UNICODE" = "1" ]; then
    if [ "$result" = "ok" ]; then printf '■ ■ ■ ■ ■' >&2
    else printf '■ ■ □ □ □' >&2
    fi
  elif [ "$result" = "ok" ]; then printf '[done]' >&2
  else printf '[fail]' >&2
  fi
  printf '  %s\n' "$label" >&2
}

ui_loader_cancel() {
  if [ -n "$UI_LOADER_PID" ]; then
    kill "$UI_LOADER_PID" 2>/dev/null || true
    wait "$UI_LOADER_PID" 2>/dev/null || true
    UI_LOADER_PID=""
    [ "$UI_INTERACTIVE" != "1" ] || printf '\r\033[2K' >&2
  fi
}

ui_run_quiet() { # ui_run_quiet <label> <command> [args...]
  local label="$1" status=0
  shift
  ui_loader_start "$label"
  if "$@" >/dev/null 2>&1; then
    ui_loader_stop ok "$label"
    return 0
  else
    status=$?
    ui_loader_stop fail "$label"
    return "$status"
  fi
}

ui_complete() { # ui_complete <version>
  [ "$UI_COMPLETED" = "0" ] || return 0
  UI_COMPLETED=1
  printf '\n' >&2
  if [ "$UI_COLOR" = "1" ]; then
    printf '  ' >&2; ui_pixel_strip 0 success; printf '  ' >&2
    ui_tint '38;5;110' 'complete'; printf '\n\n  ' >&2
    ui_tint '38;5;141' '■ ◻ ■'; printf '   ' >&2
    ui_tint '1;38;5;213' 'M E S H I A'; printf '\n  ' >&2
    ui_tint '38;5;141' '◻ ■ ■'; printf '   ' >&2
    ui_tint '1;38;5;120' "NODE $1 READY"; printf '\n' >&2
  elif [ "$UI_UNICODE" = "1" ]; then
    printf '  ■ ■ ■ ■ ■  ' >&2
    ui_tint '38;5;110' 'complete'; printf '\n\n  ' >&2
    ui_tint '38;5;141' '■ ◻ ■'; printf '   ' >&2
    ui_tint '1;38;5;213' 'M E S H I A'; printf '\n  ' >&2
    ui_tint '38;5;141' '◻ ■ ■'; printf '   ' >&2
    ui_tint '1;38;5;120' "NODE $1 READY"; printf '\n' >&2
  else
    printf '  [#####] complete\n\n  # . #   M E S H I A\n  . # #   NODE %s READY\n' "$1" >&2
  fi
  printf '\n  meshia login               Connect your account\n  meshia projects            Find your projects\n  meshia host install codex  Connect Codex, conversation sync and callbacks\n  meshia mcp config          Configure other desktop AI clients\n  meshia status              Check account and native files\n\n' >&2
}

log() {
  if [ "$UI_INTERACTIVE" = "1" ]; then
    printf '    ' >&2; ui_tint '38;5;244' '│'; printf ' %s\n' "$*" >&2
  else printf '  %s\n' "$*" >&2
  fi
}
step() {
  if [ "$UI_INTERACTIVE" = "1" ]; then
    printf '    ' >&2; ui_tint '38;5;213' '◆'; printf ' %s\n' "$*" >&2
  else printf '\n> %s\n' "$*" >&2
  fi
}
die() {
  printf '\n' >&2
  if [ "$UI_INTERACTIVE" = "1" ]; then
    ui_tint '1;31' '× Meshia install stopped'; printf ': %s\n' "$*" >&2
  else printf 'meshia-node install failed: %s\n' "$*" >&2
  fi
  exit 1
}

quote_shell_argument() { # quote_shell_argument <value>
  # Bash's %q produces one token that can be pasted back into Bash without
  # losing spaces, apostrophes, or other shell metacharacters.
  printf '%q' "$1"
}

installer_download_command() {
  # The printed repair command must not execute a truncated HTTP response.
  # Pass caller arguments separately so custom paths cannot become shell code.
  local runner='script=$(curl -fsSL "https://connect.meshia.io/?prompt=1") && bash -s -- "$@" <<< "$script"'
  printf 'bash -c %s sh' "$(quote_shell_argument "$runner")"
  local argument
  for argument in "$@"; do
    printf ' %s' "$(quote_shell_argument "$argument")"
  done
}

connect_with_pair_stdin() {
  local connect_status=0
  # The writer is a shell builtin in a pipeline subshell: the grant is neither
  # exported nor placed in either child's argv. pipefail makes a closed reader
  # or a failed connect visible without bypassing the mandatory secret clear.
  if printf '%s\n' "$PAIR_GRANT" | "$@"; then
    connect_status=0
  else
    connect_status=$?
  fi
  PAIR_GRANT=""
  unset PAIR_GRANT
  return "$connect_status"
}

prompt_for_pair_grant() {
  [ -r /dev/tty ] && [ -w /dev/tty ] \
    || die "a terminal is required to enter the one-time pairing code securely"
  printf 'Paste the one-time Meshia pairing code: ' >/dev/tty
  if ! IFS= read -r -s PAIR_GRANT </dev/tty; then
    printf '\n' >/dev/tty
    die "could not read the one-time pairing code"
  fi
  printf '\n' >/dev/tty
  if [[ ! "$PAIR_GRANT" =~ ^mesh_[A-Za-z0-9_-]{32}$ ]]; then
    PAIR_GRANT=""
    unset PAIR_GRANT
    die "the one-time pairing code is invalid or expired"
  fi
}

atomic_symlink() { # atomic_symlink <target> <link>
  local target="$1" link="$2" temporary="${2}.new.$$"
  [ -x "$BASE_PYTHON" ] || return 1
  rm -f "$temporary"
  ln -s "$target" "$temporary"
  if ! "$BASE_PYTHON" - "$temporary" "$link" <<'PY'
import os
import sys

os.replace(sys.argv[1], sys.argv[2])
PY
  then
    rm -f "$temporary"
    return 1
  fi
}

cleanup_files() {
  ui_loader_cancel
  if [ "$CANDIDATE_CREATED" = "1" ] && [ "$CANDIDATE_COMMITTED" != "1" ] \
      && [ -n "$CANDIDATE_RUNTIME" ]; then
    case "$CANDIDATE_RUNTIME" in
      "$RUNTIMES_DIR"/*) rm -rf "$CANDIDATE_RUNTIME" ;;
    esac
  fi
  [ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR" || true
  rm -f "$RUNTIME_LINK.new.$$" "$PREVIOUS_RUNTIME_LINK.new.$$" \
    "$BIN_DIR/meshia-node.new.$$" "$BIN_DIR/meshia.new.$$" "$MIGRATION_MARKER.new.$$"
  if [ "$INSTALL_LOCK_HELD" = "1" ]; then
    rm -f "$INSTALL_LOCK_DIR/pid"
    rmdir "$INSTALL_LOCK_DIR" 2>/dev/null || true
    INSTALL_LOCK_HELD=0
  fi
}

rollback_service_state() { # read-only; never a substitute for restart --wait
  local output="$WORK_DIR/rollback-service-status.json"
  if ! run_bounded 5 "$output" "$1" --home "$MESHIA_HOME" --json service status; then
    printf 'unknown\n'
    return 0
  fi
  "$BASE_PYTHON" - "$output" "$PRIOR_RUNTIME" "$PRIOR_VERSION" <<'PY' 2>/dev/null || printf 'unknown\n'
import json
import os
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        service = json.load(source)["service"]
    runtime = service.get("runtime") or {}
    owned = (
        service.get("installed_for_home") is True
        and service.get("manager_registered") is True
    )
    expected = {
        os.path.realpath(os.path.join(sys.argv[2], suffix))
        for suffix in (
            "bin/meshia-node", "bin/Meshia",
            "native/Meshia Node.app/Contents/MacOS/MeshiaNode",
        )
    }
    if (
        owned
        and service.get("manager_active") is True
        and service.get("runner_active") is True
        and runtime.get("live") is True
        and runtime.get("package_version") == sys.argv[3]
        and os.path.realpath(str(runtime.get("executable") or "")) in expected
    ):
        state = "running"
    elif (
        owned
        and service.get("manager_active") is False
        and service.get("runner_active") is False
        and runtime.get("live") is False
    ):
        state = "stopped"
    else:
        state = "unknown"
except (OSError, KeyError, TypeError, ValueError, AttributeError):
    state = "unknown"
print(state)
PY
}

rollback_transaction() {
  local rollback_ok=1 prior_ready=1 prior_cli="" parked_now=0 cutover_phase="" service_state="unknown"
  [ "$TRANSACTION_ACTIVE" = "1" ] || return 0
  TRANSACTION_ACTIVE=0
  if [ "$ACCOUNT_CUTOVER_PREPARED" = "1" ] && [ -n "$CANDIDATE_CLI" ]; then
    if ! cutover_phase="$("$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover inspect 2>/dev/null \
      | "$BASE_PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["phase"])')"; then
      # Destructive rollback is unsafe when its durable phase cannot be read:
      # the replacement may already be committed and serving the only mount.
      # Preserve its immutable runtime for the next installer recovery pass.
      CANDIDATE_COMMITTED=1
      return 1
    fi
    if [ "$cutover_phase" = "committed" ]; then
      "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover finalize \
        >/dev/null 2>&1 || true
      ACCOUNT_CUTOVER_PREPARED=0
      CANDIDATE_COMMITTED=1
      PRIOR_SERVICE_UNINSTALLED=0
      return 0
    fi
  fi
  log "upgrade did not become ready; restoring the previous runtime"

  if [ "$CANDIDATE_SERVICE_INSTALLED" = "1" ] && [ -n "$CANDIDATE_CLI" ]; then
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" service stop >/dev/null 2>&1 || rollback_ok=0
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" service uninstall >/dev/null 2>&1 || rollback_ok=0
    CANDIDATE_SERVICE_INSTALLED=0
  elif [ "$PRIOR_SERVICE_UNINSTALLED" = "1" ] && [ -n "$CANDIDATE_CLI" ]; then
    # A failed install may have created the fixed-label definition before
    # returning non-zero. Remove it if present; the prior install below is the
    # authoritative read-back of whether the definition is available again.
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" service uninstall >/dev/null 2>&1 || true
  fi
  if [ "$ACCOUNT_CUTOVER_PREPARED" = "1" ] && [ -n "$CANDIDATE_CLI" ]; then
    if "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover rollback \
        >/dev/null 2>&1; then
      ACCOUNT_CUTOVER_PREPARED=0
    else
      rollback_ok=0
    fi
  fi
  if [ -f "$MIGRATION_MARKER" ]; then
    local recovery_runtime=""
    IFS= read -r recovery_runtime <"$MIGRATION_MARKER" || true
    if [ -d "$recovery_runtime" ]; then
      PRIOR_RUNTIME="$recovery_runtime"
    elif [ -d "$RUNTIME_LINK" ] && [ ! -L "$RUNTIME_LINK" ]; then
      rm -f "$MIGRATION_MARKER"
    fi
  fi
  if [ -n "$PRIOR_RUNTIME" ] && [ -d "$PRIOR_RUNTIME" ]; then
    if { [ "$POINTER_FLIPPED" != "1" ] && { [ -e "$RUNTIME_LINK" ] || [ -L "$RUNTIME_LINK" ]; }; } \
        || atomic_symlink "$PRIOR_RUNTIME" "$RUNTIME_LINK"; then
      POINTER_FLIPPED=0
      rm -f "$MIGRATION_MARKER"
      prior_cli="$PRIOR_RUNTIME/bin/meshia-node"
      atomic_symlink "$RUNTIME_LINK/bin/meshia-node" "$BIN_DIR/meshia-node" || rollback_ok=0
      if [ "$HAD_MESHIA_ALIAS" = "1" ]; then
        atomic_symlink "$RUNTIME_LINK/bin/meshia-node" "$BIN_DIR/meshia" || rollback_ok=0
      elif [ -L "$BIN_DIR/meshia" ]; then
        rm -f "$BIN_DIR/meshia" || rollback_ok=0
      elif [ -e "$BIN_DIR/meshia" ]; then
        rollback_ok=0
      fi
      if [ "$PRIOR_SERVICE_SUPPORTED" = "1" ]; then
        if "$BASE_PYTHON" - "$MESHIA_HOME/config.json" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        config = json.load(source)
except (OSError, ValueError):
    raise SystemExit(1)
raise SystemExit(0 if config.get("lifecycle") == "disconnected" else 1)
PY
        then
          parked_now=1
        fi
        "$prior_cli" --home "$MESHIA_HOME" service install >/dev/null 2>&1 || rollback_ok=0
        if [ "$parked_now" = "1" ]; then
          "$prior_cli" --home "$MESHIA_HOME" service start >/dev/null 2>&1 \
            || rollback_ok=0
        else
          "$prior_cli" --home "$MESHIA_HOME" service restart --wait \
            --timeout-seconds 45 --expected-version "$PRIOR_VERSION" >/dev/null 2>&1 \
            || prior_ready=0
        fi
      fi
      PRIOR_SERVICE_UNINSTALLED=0
    else
      rollback_ok=0
    fi
  else
    rollback_ok=0
  fi

  if [ "$rollback_ok" = "1" ] && [ "$prior_ready" = "1" ]; then
    log "restored meshia-node $PRIOR_VERSION"
    return 0
  fi
  if [ -n "$prior_cli" ] && [ "$PRIOR_SERVICE_SUPPORTED" = "1" ]; then
    service_state="$(rollback_service_state "$prior_cli")"
  fi
  if [ "$rollback_ok" = "1" ] && [ "$service_state" = "running" ]; then
    log "restored meshia-node $PRIOR_VERSION; the service is running, but readiness was not verified"
    log "the upgrade failed; the previous service remains active and may still be reconnecting"
  elif [ "$service_state" = "running" ]; then
    log "CRITICAL: automatic rollback was incomplete; the previous service is running, but restoration did not complete"
  elif [ "$service_state" = "stopped" ]; then
    log "CRITICAL: automatic rollback was incomplete; the previous service is not running"
  else
    log "CRITICAL: automatic rollback was incomplete; the previous service state could not be verified"
  fi
  log "check the current state with: $(quote_shell_argument "$BIN_DIR/meshia-node") --home $(quote_shell_argument "$MESHIA_HOME") service status"
  return 1
}

on_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [ "$TRANSACTION_ACTIVE" = "1" ]; then
    rollback_transaction || status=1
    [ "$status" -eq 0 ] && status=1
  fi
  cleanup_files
  exit "$status"
}
trap on_exit EXIT
trap 'exit 130' HUP INT TERM

usage() {
  cat >&2 <<'USAGE'
Usage: install.sh [options] [-- <connect options>]

Install options:
  --package-url URL       sdist/wheel to install (or $MESHIA_NODE_PACKAGE_URL)
  --package-sha256 HEX    required checksum for --package-url (or $MESHIA_NODE_PACKAGE_SHA256)
  --from-dir DIR          install from a local checkout instead (dev/test mode)
  --insecure-dev          allow loopback HTTP and an unverified package (development only)
  --python X.Y.Z          interpreter version to provision (default 3.12.14)
  --bin-dir DIR           symlink location (default ~/.local/bin)
  --mount-runtime         install the native filesystem runtime (FUSE-T/libfuse2)
  --no-mount-runtime      disable the native mount and its runtime installation
  --no-native-app         macOS: skip installing Meshia.app and its File Provider
  --no-fskit-app          legacy alias for --no-native-app
  -h, --help              show this message

Connect options (after `--`):
  --pair CODE             one-time mesh_… pairing code; runs `meshia-node connect`
  --prompt-pair           ask for the one-time code without echo or shell history
  --re-pair               intentionally replace an existing enrollment; requires
                          --prompt-pair or --pair
  --api-url URL           control-plane origin
  --tier personal|compute node tier (default compute)
  --access files|limited|full  files mounts workspaces; limited runs workspace-only
                              native compute; full grants full computer access
  --workspace PATH        private write-back directory (default ~/.meshia/workspace)
  --adopt-existing-workspace
                          explicitly claim a non-empty unowned workspace root
  --foreground            run in this terminal instead of installing the
                          current-user background service
  --background            install the current-user service (default)
  --no-connect            install only, even if --pair was supplied
USAGE
}

# ---------------------------------------------------------------- argument parsing
while [ $# -gt 0 ]; do
  case "$1" in
    --package-url)    PACKAGE_URL="${2:-}"; shift 2 ;;
    --package-sha256) PACKAGE_SHA256="${2:-}"; shift 2 ;;
    --from-dir)       FROM_DIR="${2:-}"; shift 2 ;;
    --insecure-dev)   INSECURE_DEV=1; shift ;;
    --python)         PYTHON_VERSION="${2:-}"; shift 2 ;;
    --bin-dir)        BIN_DIR="${2:-}"; shift 2 ;;
    --mount-runtime)  MOUNT_RUNTIME_MODE="install"; shift ;;
    --no-mount-runtime) MOUNT_RUNTIME_MODE="off"; shift ;;
    --no-native-app|--no-fskit-app) NATIVE_APP_MODE="off"; shift ;;
    -h|--help)        usage; exit 0 ;;
    --)               shift; break ;;
    *)                die "unknown option $1 (try --help)" ;;
  esac
done
while [ $# -gt 0 ]; do
  case "$1" in
    --pair)       PAIR_GRANT="${2:-}"; shift 2 ;;
    --prompt-pair) PROMPT_PAIR=1; shift ;;
    --re-pair)    REPAIR_EXISTING=1; shift ;;
    --api-url)    API_URL="${2:-}"; shift 2 ;;
    --tier)       TIER="${2:-}"; TIER_EXPLICIT=1; shift 2 ;;
    --access)     ACCESS="${2:-}"; ACCESS_EXPLICIT=1; TIER="compute"; TIER_EXPLICIT=1; shift 2 ;;
    --workspace)  WORKSPACE="${2:-}"; WORKSPACE_EXPLICIT=1; shift 2 ;;
    --adopt-existing-workspace) ADOPT_EXISTING_WORKSPACE=1; shift ;;
    --foreground) CONNECT_MODE="foreground"; shift ;;
    --background) CONNECT_MODE="service"; shift ;;
    --no-connect) CONNECT_MODE="none"; shift ;;
    -h|--help)    usage; exit 0 ;;
    *)            die "unknown connect option $1 (try --help)" ;;
  esac
done

case "$CONNECT_MODE" in
  background) CONNECT_MODE="service" ;;
  service|foreground|none) ;;
  *) die "invalid CONNECT_MODE '$CONNECT_MODE' (expected service, foreground, or none)" ;;
esac
case "$PROMPT_PAIR" in
  0|1) ;;
  *) die "invalid PROMPT_PAIR '$PROMPT_PAIR' (expected 0 or 1)" ;;
esac
case "$REPAIR_EXISTING" in
  0|1) ;;
  *) die "invalid REPAIR_EXISTING '$REPAIR_EXISTING' (expected 0 or 1)" ;;
esac
[ "$REPAIR_EXISTING" = "0" ] || [ "$PROMPT_PAIR" = "1" ] || [ -n "$PAIR_GRANT" ] \
  || die "--re-pair requires --prompt-pair or --pair"
case "$ACCESS" in
  ""|files|limited|full) ;;
  *) die "invalid access mode '$ACCESS' (expected files, limited or full)" ;;
esac
case "$MOUNT_RUNTIME_MODE" in
  auto|install|off) ;;
  *) die "invalid MESHIA_MOUNT_RUNTIME '$MOUNT_RUNTIME_MODE' (expected auto, install, or off)" ;;
esac
case "$BIN_DIR" in
  /*) ;;
  *) BIN_DIR="$(pwd -P)/$BIN_DIR" ;;
esac

# Meshia itself never runs as root.  On Linux, however, cloud hosts commonly
# begin at a root shell.  Mark that case for a narrowly scoped OS bootstrap
# which creates a dedicated locked-down user and re-runs this verified
# installer there.  macOS and an explicitly re-entered root bootstrap remain
# fail-closed.
CURRENT_UID="${EUID:-}"
[ -n "$CURRENT_UID" ] || CURRENT_UID="$(id -u)"
if [ "$CURRENT_UID" -eq 0 ]; then
  if [ "$(uname -s)" = "Linux" ] \
      && [ "${MESHIA_ROOT_BOOTSTRAPPED:-0}" != "1" ]; then
    ROOT_BOOTSTRAP_REQUIRED=1
  else
    die "refusing to install or connect meshia-node as root; rerun without sudo"
  fi
fi

# ------------------------------------------------------------------ platform gate
OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux|Darwin) ;;
  MINGW*|MSYS*|CYGWIN*)
    die "this is Windows: use the PowerShell installer instead (install.ps1, minted by the workspace's Windows connect command)" ;;
  *) die "unsupported operating system: $OS" ;;
esac

linux_user_service_persists() {
  [ "$OS" = "Linux" ] || return 0
  command -v loginctl >/dev/null 2>&1 || return 1
  [ "$(loginctl show-user --property=Linger --value "$CURRENT_UID" 2>/dev/null || true)" = "yes" ]
}

ensure_linux_user_service_persists() {
  [ "$OS" = "Linux" ] || return 0
  linux_user_service_persists && return 0
  if ! command -v loginctl >/dev/null 2>&1; then
    log "WARNING: automatic restart after logout or reboot is not enabled because systemd-logind is unavailable"
    return 1
  fi

  step "Enabling automatic Meshia restart after logout and reboot"
  if loginctl enable-linger "$CURRENT_UID" >/dev/null 2>&1 \
      || linux_admin loginctl enable-linger "$CURRENT_UID" >/dev/null 2>&1; then
    if linux_user_service_persists; then
      log "verified systemd linger for uid $CURRENT_UID"
      return 0
    fi
  fi
  log "WARNING: automatic restart after logout or reboot is not enabled for this user"
  return 1
}

prepare_linux_user_service() {
  [ "$OS" = "Linux" ] && [ "$CONNECT_MODE" = "service" ] || return 0
  [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1 \
    || die "persistent Linux attachment requires systemd; use --foreground explicitly on other init systems"
  ensure_linux_user_service_persists \
    || die "Meshia could not enable this user's persistent service before connecting"
  local runtime_dir="/run/user/$CURRENT_UID"
  if [ ! -S "$runtime_dir/bus" ]; then
    # SSH and sudo sessions can lack the user's bus even though systemd is
    # available. Start its existing user manager, never a root Meshia daemon.
    linux_admin systemctl start "user@$CURRENT_UID.service" \
      || die "could not start the current user's systemd manager"
    if [ ! -S "$runtime_dir/bus" ]; then
      if command -v apt-get >/dev/null 2>&1; then
        linux_admin env DEBIAN_FRONTEND=noninteractive apt-get install -y dbus-user-session \
          || die "could not install the systemd user session bus"
      elif command -v dnf >/dev/null 2>&1; then
        linux_admin dnf install -y dbus-daemon || die "could not install the systemd user session bus"
      fi
    fi
  fi
  [ ! -L "$runtime_dir" ] && [ -d "$runtime_dir" ] \
    && [ "$(directory_owner_uid "$runtime_dir")" = "$CURRENT_UID" ] \
    || die "the current user's systemd runtime directory is unavailable or has unsafe ownership"
  export XDG_RUNTIME_DIR="$runtime_dir"
  export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
  if [ ! -S "$runtime_dir/bus" ]; then
    systemctl --user start dbus.socket >/dev/null 2>&1 \
      || die "could not start the current user's session bus"
  fi
  [ -S "$runtime_dir/bus" ] && systemctl --user show-environment >/dev/null 2>&1 \
    || die "the current user's session bus is unavailable; attachment was not started"
}

report_mount_ready() {
  local attempt=1 mount_report="" mount_status=0
  NATIVE_MOUNT_READY=0
  if [ "$MOUNT_RUNTIME_MODE" = "off" ]; then
    log "Meshia native file mount was intentionally disabled; sync remains active"
    return 0
  fi
  # FUSE-T's SMB bridge owns a bounded 40-second startup window so its local
  # transport can become ready. Sample beyond that boundary before the
  # installer makes a final decision.
  while [ "$attempt" -le 50 ]; do
    if mount_report="$(
      "$CANDIDATE_CLI" --home "$MESHIA_HOME" --json status 2>/dev/null \
        | "$BASE_PYTHON" -c '
import json
import sys

try:
    document = json.load(sys.stdin)
    file_provider = document.get("file_provider")
    if not isinstance(file_provider, dict):
        file_provider = {}
    mount = document.get("mount")
    if not isinstance(mount, dict):
        raise ValueError("missing mount state")
except (ValueError, TypeError, json.JSONDecodeError):
    print("WARNING: native file mount needs attention: mount state could not be read back")
    raise SystemExit(12)

if document.get("native_mount_enabled") is False:
    print("Meshia native file mount is intentionally disabled; workspace sync remains active. Rerun this installer with --mount-runtime to enable it.")
    raise SystemExit(13)
if file_provider.get("active") is True:
    print("Meshia native files are ready via File Provider at {}".format(
        file_provider.get("user_visible_url") or "Meshia Files"
    ))
    raise SystemExit(0)
if mount.get("mounted") is True and mount.get("state") == "mounted":
    backend = mount.get("transport_backend")
    suffix = " via {}".format(backend.upper()) if backend else ""
    print("Meshia native file mount is ready at {}{}".format(mount.get("mount_point") or "Meshia", suffix))
    raise SystemExit(0)
if mount.get("state") == "runtime_missing":
    print("WARNING: native file mount needs attention: the OS mount runtime was not detected")
    raise SystemExit(10)
print("WARNING: native file mount needs attention: state is {}".format(mount.get("state") or "unknown"))
raise SystemExit(11)
'
    )"; then
      NATIVE_MOUNT_READY=1
      log "$mount_report"
      return 0
    else
      mount_status=$?
    fi
    if [ "$mount_status" -eq 13 ]; then
      log "$mount_report"
      return 0
    fi
    [ "$mount_status" -eq 11 ] || break
    attempt=$((attempt + 1))
    case "$attempt" in
      10|20|30|40)
        log "Still starting the Meshia native file mount (${attempt}s elapsed)..."
        ;;
    esac
    [ "$attempt" -le 50 ] && sleep 1
  done
  [ -n "$mount_report" ] \
    && log "$mount_report" \
    || log "ERROR: native file mount did not become ready: status readback failed"
  log "The Meshia service is connected, but installation is incomplete until the native mount is ready."
  log "Run: $BIN_DIR/meshia-node doctor"
  return 1
}

refresh_macos_finder_after_mount_replacement() {
  [ "$OS" = "Darwin" ] \
    && [ "$REFRESH_FINDER_AFTER_MOUNT" = "1" ] \
    && [ "$NATIVE_MOUNT_READY" = "1" ] \
    || return 0
  REFRESH_FINDER_AFTER_MOUNT=0

  # FUSE-T exposes an SMB-backed network volume. macOS can retain the retired
  # row in Finder's Computer view after a clean unmount even though the mount
  # registry and helper process are already gone. Relaunch Finder only after a
  # controlled Meshia mount replacement is confirmed ready. First installs and
  # exact healthy reinstalls never enter this path.
  if [ -n "${MESHIA_TEST_FINDER_REFRESH_MARKER:-}" ]; then
    printf '%s\n' "finder mount replacement refreshed" \
      >"$MESHIA_TEST_FINDER_REFRESH_MARKER"
    return 0
  fi
  # Installer lifecycle tests run with synthetic services and must never touch
  # the developer's real Finder process.
  [ -z "${MESHIA_TEST_EVENTS:-}" ] || return 0

  local finder_pid="" attempt=1
  finder_pid="$(/usr/bin/pgrep -x -u "$CURRENT_UID" Finder 2>/dev/null | head -n 1 || true)"
  [ -n "$finder_pid" ] || return 0
  case "$finder_pid" in
    *[!0-9]*)
      log "WARNING: Finder volume cache could not be refreshed safely"
      return 0
      ;;
  esac
  if kill -TERM "$finder_pid" 2>/dev/null; then
    while [ "$attempt" -le 20 ] && kill -0 "$finder_pid" 2>/dev/null; do
      sleep 0.1
      attempt=$((attempt + 1))
    done
    /usr/bin/open -gj -a Finder >/dev/null 2>&1 || true
    log "refreshed Finder after replacing the Meshia mount"
  else
    log "WARNING: Finder retained a stale Meshia row; relaunch Finder to clear it"
  fi
}

report_native_workspace_access() {
  [ "$STAGE_NODE_APP" = 1 ] && [ "$NATIVE_MOUNT_READY" = 1 ] || return 0
  local attempt=1 access_report=""
  # The LaunchAgent's native host starts its own mounted-read request. macOS
  # owns any first-use consent dialog; no second app or installer process is
  # launched to borrow the terminal's privacy authorization.
  while [ "$attempt" -le 30 ]; do
    if access_report="$(
      "$CANDIDATE_CLI" --home "$MESHIA_HOME" --json status 2>/dev/null \
        | "$BASE_PYTHON" -c '
import json
import sys

try:
    document = json.load(sys.stdin)
    service = document["service"]
    runtime = service["runtime"]
    evidence = runtime.get("workspace_execution") or {}
    ready = (
        service.get("native_host_owned") is True
        and service.get("manager_active") is True
        and runtime.get("live") is True
        and runtime.get("runtime_ready") is True
        and evidence.get("ready") is True
    )
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
if ready:
    print("The persistent Meshia service can access its mounted workspace.")
raise SystemExit(0 if ready else 1)
'
    )"; then
      log "$access_report"
      return 0
    fi
    if [ "$attempt" = 1 ]; then
      log "Waiting for the Meshia service to verify workspace access. If macOS asks for Network Volumes access, choose Allow."
    fi
    attempt=$((attempt + 1))
    [ "$attempt" -le 30 ] && sleep 2
  done
  log "Meshia is connected, but its background service has not verified access to the mounted workspace."
  log "Installation is incomplete while macOS workspace access is pending. A previously denied Network Volumes permission must be restored in macOS Privacy & Security."
  return 1
}

report_service_ready() {
  report_mount_ready || return 1
  refresh_macos_finder_after_mount_replacement
  if [ "$OS" = "Linux" ] && ! ensure_linux_user_service_persists; then
    log "Meshia is connected on meshia-node $RELEASE_VERSION for this login session"
  else
    log "Meshia is connected on meshia-node $RELEASE_VERSION and will restart automatically for this user"
  fi
  if [ "$NATIVE_MOUNT_READY" = "1" ]; then
    log "Open your mounted files anytime with: $BIN_DIR/meshia open"
  fi
  report_fskit_approval_if_pending
  report_native_workspace_access || return 1
  ui_phase 5 5 "Verify the connection"
  ui_complete "$RELEASE_VERSION"
}

wait_for_account_cutover_ready() {
  local attempt=1
  # A normal restart wait proves the runner and heartbeat. Account replacement
  # additionally waits for the replacement catalog to own the mounted roots and
  # for every workspace coordinator to report convergence before discarding the
  # old config snapshot.
  while [ "$attempt" -le 50 ]; do
    if "$CANDIDATE_CLI" --home "$MESHIA_HOME" --json status --deep 2>/dev/null \
        | "$BASE_PYTHON" -c '
import json
import sys

try:
    document = json.load(sys.stdin)
    service = document["service"]
    runtime = service["runtime"]
    fabric = document["fabric"]
    mount = document["mount"]
    file_provider = document.get("file_provider")
    if not isinstance(file_provider, dict):
        file_provider = {}
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)
ready = (
    document.get("enrolled") is True
    and isinstance(document.get("account_id"), str)
    and isinstance(document.get("account_email"), str)
    and document.get("lifecycle") == "connected"
    and service.get("runner_active") is True
    and (sys.argv[1] != "1" or service.get("native_host_owned") is True)
    and runtime.get("live") is True
    and runtime.get("runtime_ready") is True
    and fabric.get("command_safe") is True
    and fabric.get("sync_converged") is True
    and (
        document.get("native_mount_enabled") is False
        or file_provider.get("active") is True
        or (mount.get("mounted") is True and mount.get("state") == "mounted")
    )
)
raise SystemExit(0 if ready else 1)
' "$STAGE_NODE_APP"; then
      log "verified replacement account, catalog, mount, and sync convergence"
      return 0
    fi
    attempt=$((attempt + 1))
    [ "$attempt" -le 50 ] && sleep 1
  done
  return 1
}

exact_running_release_ready() {
  # An exact reinstall is a health check, not a reason to tear down a live
  # Finder/Explorer mount.  Bind the no-op to the immutable runtime, current
  # service definition, live runner receipt, fresh heartbeat, and workspace
  # ownership marker.  Any explicit preference change or stale/missing proof
  # falls through to the normal transactional restart below.
  local expected_service_executable="$CANDIDATE_CLI"
  if [ "$OS" = "Darwin" ] \
      && [ -f "$CANDIDATE_RUNTIME/bin/Meshia" ] \
      && [ ! -L "$CANDIDATE_RUNTIME/bin/Meshia" ] \
      && [ -x "$CANDIDATE_RUNTIME/bin/Meshia" ]; then
    # The packaged macOS service deliberately registers the product-named
    # launcher so Background Items says "Meshia". The interactive CLI remains
    # ``meshia-node``; both belong to the same immutable runtime, but they are
    # distinct console-script files and therefore have distinct realpaths.
    expected_service_executable="$CANDIDATE_RUNTIME/bin/Meshia"
  fi
  if [ "$STAGE_NODE_APP" = 1 ]; then
    expected_service_executable="$CANDIDATE_RUNTIME/native/Meshia Node.app/Contents/MacOS/MeshiaNode"
  fi

  [ "$CONNECT_MODE" = "service" ] \
    && [ "$PARKED_ENROLLMENT" = "0" ] \
    && [ "$ADOPT_EXISTING_WORKSPACE" = "0" ] \
    && [ "$MOUNT_RUNTIME_MODE" = "auto" ] \
    && [ "$TIER_EXPLICIT" = "0" ] \
    && [ "$ACCESS_EXPLICIT" = "0" ] \
    && [ "$WORKSPACE_EXPLICIT" = "0" ] \
    && [ -z "$API_URL" ] \
    && [ "$PRIOR_SERVICE_SUPPORTED" = "1" ] \
    && same_runtime "$PRIOR_RUNTIME" "$CANDIDATE_RUNTIME" \
    || return 1

  "$CANDIDATE_CLI" --home "$MESHIA_HOME" --json status 2>/dev/null \
    | "$BASE_PYTHON" -c '
from datetime import datetime, timezone
import json
import os
import sys

expected_executable = os.path.realpath(sys.argv[1])
expected_version = sys.argv[2]
try:
    document = json.load(sys.stdin)
    service = document["service"]
    runtime = service["runtime"]
    mount = document["mount"]
    file_provider = document.get("file_provider")
    if not isinstance(file_provider, dict):
        file_provider = {}
    claim = document["workspace_claim"]
    heartbeat = datetime.fromisoformat(
        str(document["last_heartbeat_at"]).replace("Z", "+00:00")
    )
except (KeyError, TypeError, ValueError, json.JSONDecodeError):
    raise SystemExit(1)

fresh_seconds = (datetime.now(timezone.utc) - heartbeat.astimezone(timezone.utc)).total_seconds()
ready = (
    document.get("enrolled") is True
    and document.get("lifecycle") == "connected"
    and claim.get("valid") is True
    and service.get("installed_for_home") is True
    and service.get("manager_registered") is True
    and (sys.argv[3] != "1" or service.get("native_host_owned") is True)
    and service.get("runner_active") is True
    and runtime.get("live") is True
    and runtime.get("runtime_ready") is True
    and runtime.get("package_version") == expected_version
    and os.path.realpath(str(runtime.get("executable") or "")) == expected_executable
    and -30.0 <= fresh_seconds <= 120.0
    and (
        document.get("native_mount_enabled") is False
        or file_provider.get("active") is True
        or mount.get("mounted") is True
    )
)
raise SystemExit(0 if ready else 1)
' "$expected_service_executable" "$RELEASE_VERSION" "$STAGE_NODE_APP"
}

report_service_parked() {
  log "Meshia updated to meshia-node $RELEASE_VERSION"
  log "The existing remote connection remains safely parked; no mount or background retry loop was started"
  log "Reconnect it explicitly from a workspace with available Files when you are ready"
  report_fskit_approval_if_pending
}

FSKIT_SETTINGS_URL="x-apple.systempreferences:com.apple.ExtensionsPreferences?extensionPointIdentifier=com.apple.fskit.fsmodule"

print_fskit_approval_steps() {
  # Printed, never executed: the installer stays terminal-only and the user
  # flips the per-user toggle themselves.
  printf '%s\n' \
    "One-time step to switch Meshia to native FSKit volumes (no kernel NFS client, nothing that can wedge):" \
    "  1. open \"$FSKIT_SETTINGS_URL\"" \
    "     (System Settings > General > Login Items & Extensions > File System Extensions)" \
    "  2. turn on \"Meshia\"" \
    "  3. run: $BIN_DIR/meshia-node service restart" \
    "Until then Meshia keeps serving files through the FUSE-T mount." >&2
}

report_fskit_approval_if_pending() {
  # Detect "Meshia.app's file system extension is installed but the user has
  # not approved it in System Settings" and say exactly what to do, instead
  # of silently staying on FUSE-T. Bounded: the probe behind it can touch
  # mount(8), which blocks on a wedged mount.
  [ "$OS" = "Darwin" ] || return 0
  # An explicit app-free install is complete on FUSE-T. Do not contradict that
  # choice with System Settings instructions for an unrelated older app.
  [ "$NATIVE_APP_MODE" != "off" ] || return 0
  [ -n "$CANDIDATE_CLI" ] || return 0
  local probe_output="$WORK_DIR/fskit-state.json"
  run_bounded 15 "$probe_output" "$CANDIDATE_CLI" --home "$MESHIA_HOME" --json mount \
    || return 0
  "$BASE_PYTHON" - "$probe_output" <<'PY' || return 0
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        document = json.load(source)
except (OSError, ValueError):
    raise SystemExit(1)
pending = document.get("extension_state") == "disabled" and document.get("backend") != "fskit"
raise SystemExit(0 if pending else 1)
PY
  log "WARNING: Meshia's file system extension is installed but not yet approved in System Settings"
  print_fskit_approval_steps
}

case "$ARCH" in
  x86_64|amd64)  UV_ARCH="x86_64" ;;
  aarch64|arm64) UV_ARCH="aarch64" ;;
  *) die "unsupported architecture: $ARCH" ;;
esac

if [ "$OS" = "Darwin" ]; then
  UV_TARGET="${UV_ARCH}-apple-darwin"
elif [ -n "$(ldd --version 2>&1 | grep -i musl || true)" ]; then
  UV_TARGET="${UV_ARCH}-unknown-linux-musl"
  LINUX_MUSL=1
else
  UV_TARGET="${UV_ARCH}-unknown-linux-gnu"
fi

command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 \
  || die "either curl or wget is required"
command -v tar >/dev/null 2>&1 || die "tar is required"

fetch() { # fetch <url> <destination>
  enforce_url_transport "$1" "download URL" 0
  if command -v curl >/dev/null 2>&1; then
    if [ "$PARSED_URL_SCHEME" = "https" ]; then
      curl -fsSL --proto '=https' --proto-redir '=https' --retry 3 --connect-timeout 15 -o "$2" "$1"
    else
      # Explicit loopback development downloads must not redirect off loopback.
      curl -fsSL --proto '=http' --max-redirs 0 --retry 3 --connect-timeout 15 -o "$2" "$1"
    fi
  else
    # wget's --https-only applies to recursive links, not HTTP redirects.
    wget -q --max-redirect=0 -T 15 -t 3 -O "$2" "$1" || {
      printf '%s\n' 'Download failed; install curl if this download requires HTTPS redirects.' >&2
      return 1
    }
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1;  then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$1" | awk '{print $NF}'
  else die "no sha256 tool found (need sha256sum, shasum, or openssl)"
  fi
}

verify_sha256() { # verify_sha256 <file> <expected> <label>
  local actual; actual="$(sha256_of "$1")"
  [ "$actual" = "$(printf '%s' "$2" | tr 'A-Z' 'a-z')" ] \
    || die "$3 checksum mismatch (expected $2, got $actual)"
  log "verified $3 sha256 $actual"
}

fuse_t_path_is_safe() { # fuse_t_path_is_safe <path> <stat-kind>
  local path="$1" expected_kind="$2" metadata="" kind="" owner="" mode=""
  metadata="$("$FUSE_T_STAT_BIN" -f '%HT:%u:%Lp' "$path" 2>/dev/null)" \
    || return 1
  IFS=: read -r kind owner mode <<EOF
$metadata
EOF
  [ "$kind" = "$expected_kind" ] || return 1
  [ "$owner" = "0" ] || return 1
  case "$mode" in
    ''|*[!0-7]*) return 1 ;;
  esac
  # Refuse a runtime that another local account can replace in place. The
  # pinned package installs each checked directory, link, and binary root-owned
  # without group/other write permission.
  [ $((8#$mode & 8#22)) -eq 0 ]
}

fuse_t_signed_by_pinned_team() { # fuse_t_signed_by_pinned_team <path> <identifier>
  local path="$1" expected_identifier="$2" details=""
  "$FUSE_T_CODESIGN_BIN" --verify --strict --verbose=2 "$path" \
    >/dev/null 2>&1 || return 1
  details="$("$FUSE_T_CODESIGN_BIN" -dv --verbose=4 "$path" 2>&1)" \
    || return 1
  printf '%s\n' "$details" \
    | grep -Fx "Identifier=$expected_identifier" >/dev/null \
    || return 1
  printf '%s\n' "$details" \
    | grep -Fx "TeamIdentifier=$FUSE_T_TEAM_ID" >/dev/null
}

fuse_t_receipt_is_pinned() {
  local receipt_id="org.fuse-t.core.$FUSE_T_VERSION" details=""
  details="$("$FUSE_T_PKGUTIL_BIN" --pkg-info "$receipt_id" 2>/dev/null)" \
    || return 1
  printf '%s\n' "$details" | grep -Fx "package-id: $receipt_id" >/dev/null \
    || return 1
  printf '%s\n' "$details" | grep -Fx "version: $FUSE_T_VERSION" >/dev/null
}

fuse_t_candidate_is_compatible() { # <library-dir> <helper-dir> [library-entry]
  local library_dir="$1" helper_dir="$2"
  local library_entry="${3:-libfuse-t.dylib}"
  local library_link="$library_dir/$library_entry"
  local library_name="libfuse-t-$FUSE_T_VERSION.dylib"
  local library_target="$library_dir/$library_name"
  local helper_link="$helper_dir/go-nfsv4"
  local helper_name="go-nfsv4-$FUSE_T_VERSION"
  local helper_target="$helper_dir/$helper_name"
  local link_target="" directory=""

  if [ "$library_entry" = "$library_name" ]; then
    # The protected vendor payload has a versioned regular file and no alias.
    [ ! -L "$library_target" ] || return 1
  elif [ "$library_entry" = "libfuse-t.dylib" ]; then
    [ -L "$library_link" ] && [ -e "$library_link" ] || return 1
    link_target="$("$FUSE_T_READLINK_BIN" "$library_link" 2>/dev/null)" \
      || return 1
    [ "$link_target" = "$library_name" ] || return 1
    fuse_t_path_is_safe "$library_link" "Symbolic Link" || return 1
  else
    return 1
  fi
  [ -L "$helper_link" ] && [ -e "$helper_link" ] || return 1
  link_target="$("$FUSE_T_READLINK_BIN" "$helper_link" 2>/dev/null)" \
    || return 1
  [ "$link_target" = "$helper_name" ] || return 1

  for directory in \
    "$(dirname "$library_dir")" "$library_dir" \
    "$(dirname "$(dirname "$helper_dir")")" \
    "$(dirname "$helper_dir")" "$helper_dir"; do
    fuse_t_path_is_safe "$directory" "Directory" || return 1
  done
  fuse_t_path_is_safe "$library_target" "Regular File" || return 1
  fuse_t_path_is_safe "$helper_link" "Symbolic Link" || return 1
  fuse_t_path_is_safe "$helper_target" "Regular File" || return 1
  [ -r "$library_target" ] || return 1
  [ -x "$helper_target" ] || return 1
  fuse_t_signed_by_pinned_team "$library_target" "$FUSE_T_LIBRARY_IDENTIFIER" \
    || return 1
  fuse_t_signed_by_pinned_team "$helper_target" "$FUSE_T_HELPER_IDENTIFIER" \
    || return 1
  fuse_t_receipt_is_pinned
}

fuse_t_available() {
  # The signed core package owns this path. Its optional /usr/local copy can
  # sit in a Homebrew-writable directory; never weaken that trust check or
  # change permissions on the customer's package-manager prefix.
  if fuse_t_candidate_is_compatible \
    "/Library/Application Support/fuse-t/lib" "/Library/Application Support/fuse-t/bin" \
    "libfuse-t-$FUSE_T_VERSION.dylib"; then
    return 0
  fi
  local library_dir=""
  for library_dir in /usr/local/lib /opt/homebrew/lib; do
    if fuse_t_candidate_is_compatible \
      "$library_dir" "/Library/Application Support/fuse-t/bin"; then
      return 0
    fi
  done
  return 1
}

write_fuse_t_choice_changes() { # write_fuse_t_choice_changes <path> <fskit 0|1>
  local destination="$1" preserve_fskit="$2"
  "$BASE_PYTHON" - "$destination" "$preserve_fskit" <<'PY'
import os
import plistlib
import sys

destination, preserve_fskit_text = sys.argv[1:]
preserve_fskit = int(preserve_fskit_text)
if preserve_fskit not in (0, 1):
    raise SystemExit("invalid FUSE-T FSKit selection")
choices = [
    {
        "choiceIdentifier": "fuse-t_core",
        "choiceAttribute": "selected",
        "attributeSetting": 1,
    },
    {
        "choiceIdentifier": "fuse-t_fskit",
        "choiceAttribute": "selected",
        "attributeSetting": preserve_fskit,
    },
]
descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "wb") as output:
    plistlib.dump(choices, output, fmt=plistlib.FMT_XML, sort_keys=True)
PY
}

verify_fuse_t_choice_changes() { # verify_fuse_t_choice_changes <readback> <fskit 0|1>
  "$BASE_PYTHON" - "$1" "$2" <<'PY'
import plistlib
import sys

source, preserve_fskit_text = sys.argv[1:]
expected = {"fuse-t_core": 1, "fuse-t_fskit": int(preserve_fskit_text)}
with open(source, "rb") as stream:
    root = plistlib.load(stream)

found = {}
choices = root if isinstance(root, list) else []
for choice in choices:
    if not isinstance(choice, dict):
        raise SystemExit("invalid FUSE-T installer choice readback")
    identifier = choice.get("choiceIdentifier")
    if identifier in expected and choice.get("choiceAttribute") == "selected":
        if identifier in found:
            raise SystemExit("duplicate FUSE-T installer choice readback")
        found[identifier] = choice.get("attributeSetting")
if found != expected:
    raise SystemExit(f"FUSE-T installer choices do not match: {found!r}")
PY
}

ensure_macos_mount_runtime() {
  [ "$OS" = "Darwin" ] || return 0
  if fuse_t_available; then
    log "kext-less Meshia mount runtime is available; no FUSE-T app or System Settings setup is required"
    return 0
  fi
  if [ "$MOUNT_RUNTIME_MODE" = "off" ]; then
    log "WARNING: Meshia volume mounting was disabled with --no-mount-runtime"
    return 0
  fi
  if [ "$MOUNT_RUNTIME_MODE" = "auto" ] && [ -n "$FROM_DIR" ]; then
    log "development install: mount runtime was not changed; use --mount-runtime to install it"
    return 0
  fi

  command -v pkgutil >/dev/null 2>&1 \
    || die "pkgutil is required to verify the macOS mount runtime"
  command -v spctl >/dev/null 2>&1 \
    || die "spctl is required to verify the macOS mount runtime"
  command -v sudo >/dev/null 2>&1 \
    || die "sudo is required for the one-time FUSE-T runtime installation"

  local package="$WORK_DIR/fuse-t-$FUSE_T_VERSION.pkg"
  local signature="$WORK_DIR/fuse-t-signature.txt"
  local choices="$WORK_DIR/fuse-t-choices.plist"
  local choices_readback="$WORK_DIR/fuse-t-choices-readback.plist"
  # Always install the signed FUSE-T core (the go-nfsv4 runtime binary) and
  # NEVER the vendor's "fuse-t FSKit Integration" component. That component is
  # the only thing that drops /Applications/fuse-t.app, whose bundled
  # FskitSrvModule.appex registers a Login Item -- the source of the macOS
  # "Background Items Added -- fuse-t" popup on every restart. We do not use
  # fuse-t's FSKit backend at all: FUSE-T mode uses go-nfsv4 (core), and our
  # native FSKit volume uses Meshia's own MeshiaFSExtension. The pkg selects
  # this component by default on macOS 26 (`supportsFSKit()`), so we must
  # explicitly deselect it. Deselecting only means "this run does not install
  # it" -- it never uninstalls a fuse-t.app a user chose to install
  # independently, so a pre-existing app is left untouched, not clobbered.
  local preserve_fskit=0
  if [ -e /Applications/fuse-t.app ] || [ -L /Applications/fuse-t.app ]; then
    log "leaving the existing FUSE-T app untouched; installing the core runtime only (its Login Item, if any, is not ours to manage)"
  fi
  step "Preparing the kext-less Meshia filesystem runtime"
  fetch \
    "https://github.com/macos-fuse-t/fuse-t/releases/download/$FUSE_T_VERSION/fuse-t-macos-installer-$FUSE_T_VERSION.pkg" \
    "$package"
  verify_sha256 "$package" "$FUSE_T_SHA256" "FUSE-T $FUSE_T_VERSION"
  pkgutil --check-signature "$package" >"$signature" \
    || die "the FUSE-T installer signature is invalid"
  grep -F "$FUSE_T_INSTALLER_ID" "$signature" >/dev/null \
    || die "the FUSE-T installer signer is not the pinned publisher"
  spctl -a -t install "$package" >/dev/null 2>&1 \
    || die "Gatekeeper rejected the FUSE-T installer"
  write_fuse_t_choice_changes "$choices" "$preserve_fskit" \
    || die "could not create private FUSE-T installer choices"
  (umask 077; /usr/sbin/installer \
    -showChoicesAfterApplyingChangesXML "$choices" \
    -pkg "$package" -target / >"$choices_readback") \
    || die "the FUSE-T component selection is unavailable"
  chmod 600 "$choices_readback"
  verify_fuse_t_choice_changes "$choices_readback" "$preserve_fskit" \
    || die "the FUSE-T component selection could not be verified"
  log "selected the signed FUSE-T core only; no control app or Login Item will be installed"

  step "Installing the kext-less filesystem runtime (one-time administrator approval)"
  sudo /usr/sbin/installer -applyChoiceChangesXML "$choices" \
    -pkg "$package" -target / >/dev/null \
    || die "the FUSE-T runtime could not be installed"
  fuse_t_available \
    || die "the FUSE-T installer completed but its library is unavailable"
  log "installed verified FUSE-T $FUSE_T_VERSION; no FUSE-T app or System Settings setup is required"
  log "Meshia itself remains a script-installed user service"
}

linux_fuse_available() {
  local candidate=""
  # libfuse2 delegates an unprivileged mount to this distro helper. The
  # library alone is insufficient on minimal Linux installations.
  command -v fusermount >/dev/null 2>&1 || return 1
  for candidate in \
    /lib/libfuse.so.2 /usr/lib/libfuse.so.2 \
    /lib64/libfuse.so.2 /usr/lib64/libfuse.so.2 \
    /lib/*-linux-gnu/libfuse.so.2 /usr/lib/*-linux-gnu/libfuse.so.2; do
    [ -f "$candidate" ] && return 0
  done
  return 1
}

linux_admin() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return
  fi
  command -v sudo >/dev/null 2>&1 || return 125
  if sudo -n true >/dev/null 2>&1; then
    sudo "$@"
    return
  fi
  [ -r /dev/tty ] && [ -w /dev/tty ] || return 125
  sudo "$@"
}

linux_apk_command() {
  local apk_path=""
  apk_path="$(command -v apk 2>/dev/null || true)"
  if [ -z "$apk_path" ]; then
    for apk_path in /sbin/apk /usr/sbin/apk; do
      [ -x "$apk_path" ] && break
      apk_path=""
    done
  fi
  [ -n "$apk_path" ] || return 1
  printf '%s\n' "$apk_path"
}

python_runtime_compatible() { # python_runtime_compatible <executable>
  [ -x "$1" ] || return 1
  "$1" - <<'PY' >/dev/null 2>&1
import sys

raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
}

prepare_musl_system_python() {
  local apk_path=""
  [ "$OS" = "Linux" ] && [ "$LINUX_MUSL" = "1" ] || return 1

  if command -v python3 >/dev/null 2>&1 \
      && python_runtime_compatible "$(command -v python3)"; then
    BASE_PYTHON="$(command -v python3)"
    return 0
  fi

  apk_path="$(linux_apk_command)" || return 124
  linux_admin "$apk_path" add --no-cache python3 >/dev/null || return $?
  command -v python3 >/dev/null 2>&1 || return 1
  BASE_PYTHON="$(command -v python3)"
  python_runtime_compatible "$BASE_PYTHON"
}

install_linux_fuse_package() {
  local apk_path="" package=""
  if command -v apt-get >/dev/null 2>&1; then
    package="libfuse2"
    if command -v apt-cache >/dev/null 2>&1; then
      if ! apt-cache show libfuse2 >/dev/null 2>&1 \
          && ! apt-cache show libfuse2t64 >/dev/null 2>&1; then
        linux_admin apt-get update || return $?
      fi
      if ! apt-cache show libfuse2 >/dev/null 2>&1 \
          && apt-cache show libfuse2t64 >/dev/null 2>&1; then
        package="libfuse2t64"
      fi
    fi
    set -- "$package"
    if ! command -v fusermount >/dev/null 2>&1; then
      if command -v apt-cache >/dev/null 2>&1 && apt-cache show fuse3 >/dev/null 2>&1; then
        set -- "$@" fuse3
      else
        set -- "$@" fuse
      fi
    fi
    linux_admin env DEBIAN_FRONTEND=noninteractive apt-get install --no-remove -y "$@"
  elif command -v dnf >/dev/null 2>&1; then
    linux_admin dnf install -y fuse-libs fuse
  elif command -v yum >/dev/null 2>&1; then
    linux_admin yum install -y fuse-libs fuse
  elif command -v pacman >/dev/null 2>&1; then
    linux_admin pacman -S --needed --noconfirm fuse2
  elif command -v zypper >/dev/null 2>&1; then
    linux_admin zypper --non-interactive install libfuse2 fuse
  elif apk_path="$(linux_apk_command)"; then
    linux_admin "$apk_path" add --no-cache fuse
  else
    return 124
  fi
}

ensure_linux_mount_runtime() {
  [ "$OS" = "Linux" ] || return 0
  if linux_fuse_available; then
    log "libfuse2 Meshia mount runtime is available"
    return 0
  fi
  if [ "$MOUNT_RUNTIME_MODE" = "off" ]; then
    log "WARNING: Meshia volume mounting was disabled with --no-mount-runtime"
    return 0
  fi
  if [ "$MOUNT_RUNTIME_MODE" = "auto" ] && [ -n "$FROM_DIR" ]; then
    log "development install: mount runtime was not changed; use --mount-runtime to install it"
    return 0
  fi

  step "Installing the native Meshia filesystem runtime (one-time administrator approval)"
  local install_status=0
  if install_linux_fuse_package; then
    install_status=0
  else
    install_status=$?
  fi
  if [ "$install_status" -ne 0 ] || ! linux_fuse_available; then
    if [ "$MOUNT_RUNTIME_MODE" = "install" ]; then
      [ "$install_status" -ne 125 ] \
        || die "an interactive sudo session is required to install libfuse2"
      [ "$install_status" -ne 124 ] \
        || die "no supported Linux package manager was found; install libfuse2 manually"
      die "libfuse2 could not be installed; install it manually and rerun Meshia"
    fi
    log "WARNING: libfuse2 is unavailable, so Meshia will sync without a native file mount"
    log "rerun with --mount-runtime from an interactive terminal to enable the mount"
    return 0
  fi
  if [ ! -e /dev/fuse ]; then
    linux_admin modprobe fuse >/dev/null 2>&1 || true
  fi
  if [ ! -e /dev/fuse ]; then
    log "WARNING: libfuse2 is installed but /dev/fuse is unavailable in this environment"
  else
    log "installed libfuse2; Meshia itself remains a current-user service"
  fi
}

ensure_linux_compute_runtime() {
  [ "$OS" = "Linux" ] || return 0
  if [ -x /usr/bin/bwrap ]; then
    log "bubblewrap native workspace compute runtime is available"
    ensure_linux_bwrap_policy || log "WARNING: the distro's bubblewrap AppArmor policy is unavailable; Workspace only will remain disabled unless its real boundary probe passes"
    return 0
  fi
  [ "$MOUNT_RUNTIME_MODE" != "off" ] || return 0
  if [ "$MOUNT_RUNTIME_MODE" = "auto" ] && [ -n "$FROM_DIR" ]; then
    log "development install: compute runtime was not changed; use --mount-runtime to install it"
    return 0
  fi
  step "Installing native workspace compute support (one-time administrator approval)"
  local install_status=0 apk_path=""
  if command -v apt-get >/dev/null 2>&1; then
    linux_admin env DEBIAN_FRONTEND=noninteractive apt-get install -y bubblewrap || install_status=$?
  elif command -v dnf >/dev/null 2>&1; then
    linux_admin dnf install -y bubblewrap || install_status=$?
  elif command -v yum >/dev/null 2>&1; then
    linux_admin yum install -y bubblewrap || install_status=$?
  elif command -v pacman >/dev/null 2>&1; then
    linux_admin pacman -S --needed --noconfirm bubblewrap || install_status=$?
  elif command -v zypper >/dev/null 2>&1; then
    linux_admin zypper --non-interactive install bubblewrap || install_status=$?
  elif apk_path="$(linux_apk_command)"; then
    linux_admin "$apk_path" add --no-cache bubblewrap || install_status=$?
  else
    install_status=124
  fi
  if [ "$install_status" -ne 0 ] || [ ! -x /usr/bin/bwrap ]; then
    if [ "$ACCESS" = "limited" ]; then
      die "native workspace compute requires distro bubblewrap; install it with your Linux package manager and rerun Meshia"
    fi
    log "WARNING: Workspace only compute needs distro bubblewrap; Files and Full access remain available"
    return 0
  fi
  ensure_linux_bwrap_policy || log "WARNING: the distro's bubblewrap AppArmor policy could not be activated; Workspace only will remain disabled unless its real boundary probe passes"
  log "installed native workspace compute support; the node will verify kernel isolation before enabling Workspace only"
}

ensure_linux_bwrap_policy() {
  # Ubuntu 24.04 keeps its restrictive bwrap profile in apparmor-profiles'
  # inactive extras. Installing bubblewrap alone does not permit its userns
  # setup. Activate the distro policy, including its restricted child domain;
  # never write an unconfined exemption or change the global sysctl.
  local restriction=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
  local policy=/etc/apparmor.d/bwrap-userns-restrict
  local extra=/usr/share/apparmor/extra-profiles/bwrap-userns-restrict
  local candidate=""
  [ -r "$restriction" ] && [ "$(cat "$restriction")" = "1" ] || return 0
  [ "$MOUNT_RUNTIME_MODE" != "off" ] || return 0
  [ "$MOUNT_RUNTIME_MODE" != "auto" ] || [ -z "$FROM_DIR" ] || return 0
  if [ -e /etc/apparmor.d/disable/bwrap-userns-restrict ] \
      || [ -L /etc/apparmor.d/disable/bwrap-userns-restrict ]; then
    log "the administrator disabled the distro bubblewrap policy; leaving that setting unchanged"
    return 1
  fi
  if [ ! -e "$policy" ] && [ ! -L "$policy" ]; then
    # Other distro versions or administrators may use another filename or
    # profile name for the same executable. Do not install a second attachment
    # that could conflict with their policy at the next boot. The real native
    # preflight below decides whether their existing policy permits compute.
    for candidate in /etc/apparmor.d/*; do
      [ -f "$candidate" ] || continue
      if grep -Fq '/usr/bin/bwrap' "$candidate"; then
        log "keeping the existing bubblewrap AppArmor policy at $candidate"
        return 0
      fi
    done
    if [ ! -f "$extra" ] && command -v apt-get >/dev/null 2>&1; then
      linux_admin env DEBIAN_FRONTEND=noninteractive apt-get install -y apparmor-profiles \
        || return 1
    fi
    [ -f "$extra" ] && [ ! -L "$extra" ] \
      && [ "$(directory_owner_uid "$extra")" = "0" ] || return 1
    linux_admin install -o root -g root -m 0644 "$extra" "$policy" || return 1
  fi
  [ -f "$policy" ] && [ ! -L "$policy" ] \
    && [ "$(directory_owner_uid "$policy")" = "0" ] || return 1
  linux_admin apparmor_parser -r "$policy" || return 1
  log "activated the distro bubblewrap AppArmor policy; global user-namespace restrictions are unchanged"
}

verify_linux_workspace_compute() {
  [ "$OS" = "Linux" ] && [ "$ACCESS" = "limited" ] && [ "$CONNECT_MODE" != "none" ] || return 0
  # This candidate is already verified, but has not consumed enrollment or
  # replaced the prior service. Probe the actual OS boundary with no grant.
  local report="$WORK_DIR/linux-workspace-compute-readiness.txt"
  if ! run_bounded 12 "$report" "$CANDIDATE_RUNTIME/bin/python" -I -c \
      'from meshia_node import native_execution as n; print(n.detail()); raise SystemExit(0 if n.available() else 1)'; then
    [ ! -f "$report" ] || cat "$report" >&2
    die "Workspace only compute is unavailable on this Linux kernel; no pairing grant was consumed. Use a supported kernel with Landlock ABI 6 and user namespaces, or explicitly choose Full access"
  fi
}

ensure_mount_runtime() {
  case "$OS" in
    Darwin)
      install_macos_native_app
      # A registered domain alone does not prove shared-account eligibility or
      # a running bridge. Use the staged node's canonical active predicate,
      # and only for an unchanged enrollment with a live native service. Fresh
      # enrollment/cutover keeps driver preparation before consuming its grant.
      local native_status="$WORK_DIR/native-driver-readiness.json"
      if [ "$HAD_ENROLLMENT" = "1" ] \
          && [ "$CONNECT_MODE" = "service" ] \
          && [ "$REPAIR_EXISTING" != "1" ] \
          && [ "$WORKSPACE_EXPLICIT" = "0" ] \
          && [ "$ADOPT_EXISTING_WORKSPACE" = "0" ] \
          && [ "$NATIVE_APP_MODE" != "off" ] \
          && [ "$MOUNT_RUNTIME_MODE" != "off" ] \
          && run_bounded 15 "$native_status" "$CANDIDATE_CLI" --home "$MESHIA_HOME" --json status \
          && "$BASE_PYTHON" - "$native_status" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        document = json.load(source)
    provider = document["file_provider"]
    service = document["service"]
    runtime = service["runtime"]
    active = (
        document.get("enrolled") is True
        and document.get("lifecycle") == "connected"
        and document.get("native_mount_enabled") is True
        and provider.get("active") is True
        and service.get("runner_active") is True
        and runtime.get("live") is True
        and runtime.get("runtime_ready") is True
    )
except (OSError, ValueError, KeyError, TypeError, AttributeError):
    active = False
raise SystemExit(0 if active else 1)
PY
      then
        log "the active on-demand Meshia File Provider needs no FUSE-T driver setup"
        return 0
      fi
      ensure_macos_mount_runtime
      ;;
    Linux)
      ensure_linux_mount_runtime
      ensure_linux_compute_runtime
      verify_linux_workspace_compute
      prepare_linux_user_service
      ;;
  esac
}

# Meshia.app always carries the sparse, on-demand File Provider for macOS 15+.
# A release may additionally carry the macOS 26 FSKit backend. The app remains
# optional, and FUSE-T remains the fallback when it is absent or not ready.
install_macos_native_app() {
  [ "$OS" = "Darwin" ] || return 0
  [ "$NATIVE_APP_MODE" != "off" ] || { log "skipping the native Meshia.app as requested"; return 0; }
  [ "$MOUNT_RUNTIME_MODE" != "off" ] || return 0
  local macos_major
  macos_major="$(sw_vers -productVersion 2>/dev/null | cut -d. -f1)"
  if [ -z "$macos_major" ] || [ "$macos_major" -lt 15 ] 2>/dev/null; then
    log "Meshia Files needs macOS 15 or newer; keeping the existing mount"
    return 0
  fi
  # The publisher currently builds and verifies an arm64 native app. The
  # platform-neutral node wheel still supports Intel through the existing
  # mount; do not replace an app or invoke an incompatible binary there.
  case "$ARCH" in
    arm64|aarch64) ;;
    *) log "Meshia Files native app currently requires Apple Silicon; keeping the existing mount"; return 0 ;;
  esac
  local source_app="" zip="" staged
  local local_app_zip="${MESHIA_NATIVE_APP_ZIP:-${MESHIA_FSKIT_APP_ZIP:-}}"
  if [ -n "$local_app_zip" ]; then
    zip="$local_app_zip"
    [ -f "$zip" ] || die "MESHIA_NATIVE_APP_ZIP does not name a file: $zip"
  elif [ -n "$FROM_DIR" ] && [ -d "$FROM_DIR/../macos/MeshiaFS/build/Meshia.app" ]; then
    # --from-dir names installer/meshia-node (the pyproject.toml directory),
    # not the product checkout root. The native app is its sibling source tree.
    source_app="$FROM_DIR/../macos/MeshiaFS/build/Meshia.app"
  elif [ -n "$NATIVE_APP_ZIP_NAME" ]; then
    zip="$WORK_DIR/$NATIVE_APP_ZIP_NAME"
    step "Downloading Meshia Files for macOS"
    fetch "$NATIVE_APP_ZIP_URL" "$zip" || die "could not download $NATIVE_APP_ZIP_URL"
    [ -n "$NATIVE_APP_ZIP_SHA" ] || die "release.json names a macOS app without macos_app_sha256"
    verify_sha256 "$zip" "$NATIVE_APP_ZIP_SHA" "Meshia.app"
  else
    log "this release carries no Meshia.app; the FUSE-T mount stays in use"
    return 0
  fi
  staged="$WORK_DIR/native-app"
  rm -rf "$staged"; mkdir -p "$staged"
  if [ -n "$zip" ]; then
    ditto -x -k "$zip" "$staged" || die "could not extract $zip"
    source_app="$staged/Meshia.app"
  fi
  [ -d "$source_app/Contents/PlugIns/MeshiaFileProvider.appex" ] \
    || die "$source_app does not embed MeshiaFileProvider.appex"
  [ "$(defaults read "$source_app/Contents/Info.plist" CFBundleIdentifier 2>/dev/null || true)" \
      = "$NATIVE_APP_BUNDLE_ID" ] \
    || die "$source_app has an unexpected application bundle identifier"
  [ "$(defaults read "$source_app/Contents/PlugIns/MeshiaFileProvider.appex/Contents/Info.plist" CFBundleIdentifier 2>/dev/null || true)" \
      = "$FILE_PROVIDER_EXTENSION_BUNDLE_ID" ] \
    || die "$source_app embeds an unexpected File Provider bundle"
  [ "$(/usr/libexec/PlistBuddy -c 'Print :NSExtension:NSExtensionPointIdentifier' \
        "$source_app/Contents/PlugIns/MeshiaFileProvider.appex/Contents/Info.plist" 2>/dev/null || true)" \
      = "com.apple.fileprovider-nonui" ] \
    || die "$source_app does not embed a replicated File Provider extension"
  local host_group provider_group document_group
  host_group="$(defaults read "$source_app/Contents/Info.plist" MeshiaAppGroupIdentifier 2>/dev/null || true)"
  provider_group="$(defaults read "$source_app/Contents/PlugIns/MeshiaFileProvider.appex/Contents/Info.plist" MeshiaAppGroupIdentifier 2>/dev/null || true)"
  document_group="$(/usr/libexec/PlistBuddy -c 'Print :NSExtension:NSExtensionFileProviderDocumentGroup' \
    "$source_app/Contents/PlugIns/MeshiaFileProvider.appex/Contents/Info.plist" 2>/dev/null || true)"
  [[ "$host_group" =~ ^[A-Z0-9]{10}\.io\.meshia$ ]] \
    || die "$source_app has an invalid Meshia app group"
  [ "$provider_group" = "$host_group" ] && [ "$document_group" = "$host_group" ] \
    || die "$source_app File Provider groups do not match the host"
  local source_fskit="$source_app/Contents/Extensions/MeshiaFSExtension.appex"
  if [ -d "$source_fskit" ]; then
    [ "$(defaults read "$source_fskit/Contents/Info.plist" CFBundleIdentifier 2>/dev/null || true)" \
        = "$FSKIT_EXTENSION_BUNDLE_ID" ] \
      || die "$source_app embeds an unexpected FSKit bundle"
    [ "$(/usr/libexec/PlistBuddy -c 'Print :EXAppExtensionAttributes:EXExtensionPointIdentifier' \
          "$source_fskit/Contents/Info.plist" 2>/dev/null || true)" \
        = "com.apple.fskit.fsmodule" ] \
      || die "$source_app embeds an invalid FSKit extension"
  fi
  codesign --verify --deep --strict "$source_app" >/dev/null 2>&1 \
    || die "the Meshia.app code signature is invalid; refusing to install it"
  step "Installing Meshia Files for macOS"
  mkdir -p "$HOME/Applications"
  local destination="$HOME/Applications/Meshia.app" incoming="$HOME/Applications/.Meshia.app.incoming.$$"
  rm -rf "$incoming"
  ditto "$source_app" "$incoming" || die "could not stage Meshia.app"
  rm -rf "$destination"
  mv "$incoming" "$destination"
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
    -f "$destination" >/dev/null 2>&1 || true
  # Register the File Provider synchronously and read back the exact domain.
  # Repeating --register is safe: addDomain updates the same identifier. The
  # FSKit election is separate; its final approval remains the per-user System
  # Settings toggle that only the user can flip.
  local register_output="" register_status=0
  if register_output="$("$destination/Contents/MacOS/Meshia" --register 2>&1)"; then
    if ! printf '%s\n' "$register_output" | "$BASE_PYTHON" -c '
import json, re, sys
document = json.load(sys.stdin)
ready = (
    document.get("schema") == "meshia.file-provider.status.v1"
    and document.get("identifier") == "io.meshia.files"
    and document.get("registered") is True
    and document.get("ready") is True
    and re.fullmatch(r"[A-Z0-9]{10}\.io\.meshia", document.get("app_group") or "")
    and isinstance(document.get("container_path"), str)
    and isinstance(document.get("user_visible_url"), str)
)
raise SystemExit(0 if ready else 1)
'; then
      register_status=1
    fi
  else
    register_status=$?
  fi
  local has_fskit=0
  if [ "$macos_major" -ge 26 ] 2>/dev/null \
      && [ -d "$destination/Contents/Extensions/MeshiaFSExtension.appex" ]; then
    has_fskit=1
    pluginkit -e use -i "$FSKIT_EXTENSION_BUNDLE_ID" >/dev/null 2>&1 || true
  fi
  log "installed $destination"
  if [ "$register_status" -ne 0 ]; then
    log "WARNING: Meshia Files could not register its on-demand File Provider domain"
    log "the existing FUSE-T mount remains in use; run '$destination/Contents/MacOS/Meshia --register' to retry"
  else
    log "registered the on-demand Meshia Files domain"
  fi
  if [ "$has_fskit" = "1" ]; then
    printf '%s\n' \
      "Optional one-time step for native per-workspace FSKit volumes:" \
      "  open \"$FSKIT_SETTINGS_URL\"" \
      "  System Settings > General > Login Items & Extensions > File System Extensions > enable \"Meshia\"" \
      "  then run: meshia-node mount --backend auto && meshia-node service restart" \
      "Until then Meshia keeps using File Provider or the existing mount." >&2
  fi
}

bootstrap_linux_root() {
  [ "$ROOT_BOOTSTRAP_REQUIRED" = "1" ] || return 0
  [ "$OS" = "Linux" ] || die "the dedicated-user bootstrap is Linux-only"
  [ "$CUSTOM_MESHIA_HOME" = "0" ] \
    || die "root bootstrap requires the default Meshia home; rerun custom installs as their owning user"
  [ "$BIN_DIR" = "$HOME/.local/bin" ] \
    || die "root bootstrap requires the default Meshia command directory; rerun custom installs as their owning user"
  [ -z "$FROM_DIR" ] && [ "$INSECURE_DEV" = "0" ] \
    || die "root bootstrap supports verified releases only; run development installs as their owning user"

  local target_user="meshia" passwd_entry="" shadow_entry="" dedicated=1
  local target_uid="" target_gid="" target_home="" password_field=""
  local group_ids="" bootstrap_dir="" delegated_installer="" target_shell=""
  local device_group="" device_gid="" group_id="" allowed_groups=""
  local bootstrap_status=0 base_origin="${API_URL:-https://meshia.io}"
  local -a child_args=() child_env=(env -i)

  command -v getent >/dev/null 2>&1 \
    || die "getent is required to prepare the dedicated Meshia Linux user"
  command -v useradd >/dev/null 2>&1 \
    || die "useradd is required to prepare the dedicated Meshia Linux user"
  command -v runuser >/dev/null 2>&1 \
    || die "runuser is required to hand Meshia to its dedicated Linux user"

  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    target_user="$SUDO_USER"
    passwd_entry="$(getent passwd "$target_user" || true)"
    IFS=: read -r _ _ target_uid _ _ _ _ <<<"$passwd_entry"
    case "${SUDO_UID:-}" in
      ""|0|*[!0-9]*) die "sudo bootstrap requires the verified original non-root account uid" ;;
    esac
    [ "$target_uid" = "$SUDO_UID" ] \
      || die "sudo account name and uid do not identify the same Linux user"
    dedicated=0
    log "Using your existing Linux account $target_user; Full access has that account's files and device permissions"
  else
    log "This root shell will attach as the unprivileged meshia account. Full access runs as meshia, never as root"
  fi

  passwd_entry="$(getent passwd "$target_user" || true)"
  if [ -z "$passwd_entry" ]; then
    [ "$dedicated" = "1" ] || die "the selected Linux account does not exist"
    step "Creating the dedicated unprivileged Meshia user"
    useradd --create-home --user-group --shell /bin/bash "$target_user" \
      || die "could not create the dedicated Meshia Linux user"
    passwd_entry="$(getent passwd "$target_user" || true)"
  else
    log "reusing Linux account $target_user"
  fi
  IFS=: read -r _ _ target_uid target_gid _ target_home target_shell <<<"$passwd_entry"
  case "$target_uid" in
    ""|0|*[!0-9]*) die "the dedicated Meshia user has an invalid uid" ;;
  esac
  case "$target_gid" in
    ""|*[!0-9]*) die "the dedicated Meshia user has an invalid gid" ;;
  esac
  if [ "$dedicated" = "1" ]; then
    [ "$target_home" = "/home/$target_user" ] \
      || die "the dedicated Meshia user must use /home/$target_user (found $target_home)"
    allowed_groups=" $target_gid "
    for device_group in render video; do
      device_gid="$(getent group "$device_group" | cut -d: -f3 || true)"
      case "$device_gid" in
        ""|*[!0-9]*) continue ;;
      esac
      allowed_groups="$allowed_groups$device_gid "
    done
    group_ids="$(id -G "$target_user" 2>/dev/null || true)"
    for group_id in $group_ids; do
      case "$allowed_groups" in
        *" $group_id "*) ;;
        *) die "the dedicated Meshia user may belong only to its primary and render/video device groups" ;;
      esac
    done
    shadow_entry="$(getent shadow "$target_user" || true)"
    IFS=: read -r _ password_field _ <<<"$shadow_entry"
    case "$password_field" in
      '!'*|'*'*) ;;
      *) die "the dedicated Meshia user must have password login disabled" ;;
    esac
    for device_group in render video; do
      if getent group "$device_group" >/dev/null 2>&1; then
        usermod -a -G "$device_group" "$target_user" \
          || die "could not enable $device_group compute-device access for the meshia account"
      fi
    done
  fi
  case "$target_home" in
    /*) ;;
    *) die "the dedicated Meshia user has a non-absolute home directory" ;;
  esac
  [ ! -L "$target_home" ] \
    || die "the dedicated Meshia user home must not be a symlink: $target_home"
  if [ ! -d "$target_home" ]; then
    install -d -m 0755 -o "$target_uid" -g "$target_gid" "$target_home" \
      || die "could not create the dedicated Meshia user home"
  fi
  [ "$(directory_owner_uid "$target_home")" -eq "$target_uid" ] \
    || die "the dedicated Meshia user does not own its home directory"

  # OS prerequisites may be installed by this short root bootstrap, but the
  # package, identity, cache, mount, service, and all remotely controlled work
  # are created only after privileges have been dropped.
  ensure_linux_mount_runtime
  ensure_linux_compute_runtime
  if [ "$LINUX_MUSL" = "1" ]; then
    prepare_musl_system_python >/dev/null \
      || die "could not prepare Python for the dedicated Meshia user on musl Linux"
  fi
  if [ "$CONNECT_MODE" = "service" ]; then
    [ -d /run/systemd/system ] && command -v loginctl >/dev/null 2>&1 \
      || die "persistent Linux attachment requires systemd; use --foreground explicitly on other init systems"
    if command -v apt-get >/dev/null 2>&1; then
      env DEBIAN_FRONTEND=noninteractive apt-get install -y dbus-user-session \
        || die "could not prepare the Linux user session bus"
    fi
    loginctl enable-linger "$target_user" >/dev/null 2>&1 \
      && systemctl start "user@$target_uid.service" \
      || die "could not start the selected Linux user's persistent service manager"
  fi

  # The root SSH terminal belongs to the invoking administrator, not to the
  # deliberately isolated `meshia` account. Read the grant exactly once here,
  # after OS prerequisites are ready but before the delegated installer can
  # consume it. The existing private stdin lane keeps it out of argv, the
  # sanitized child environment, and temporary files.
  if [ "$PROMPT_PAIR" = "1" ] && [ -z "$PAIR_GRANT" ] \
      && [ "$CONNECT_MODE" != "none" ]; then
    prompt_for_pair_grant
  fi

  bootstrap_dir="$(mktemp -d "${TMPDIR:-/tmp}/meshia-root-bootstrap.XXXXXX")"
  chmod 755 "$bootstrap_dir"
  delegated_installer="$bootstrap_dir/install.sh"
  if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    install -m 0755 "${BASH_SOURCE[0]}" "$delegated_installer" \
      || die "could not stage the delegated Meshia installer"
  else
    fetch "${base_origin%/}/meshia-node/release/install.sh" "$delegated_installer" \
      || die "could not fetch the delegated Meshia installer"
  fi
  chmod 755 "$delegated_installer"
  bash -n "$delegated_installer" \
    || die "the delegated Meshia installer failed its shell integrity check"

  [ -z "$PACKAGE_URL" ] || child_args+=(--package-url "$PACKAGE_URL")
  [ -z "$PACKAGE_SHA256" ] || child_args+=(--package-sha256 "$PACKAGE_SHA256")
  child_args+=(--python "$PYTHON_VERSION")
  case "$MOUNT_RUNTIME_MODE" in
    install) child_args+=(--mount-runtime) ;;
    off) child_args+=(--no-mount-runtime) ;;
  esac
  child_args+=(--)
  [ "$PROMPT_PAIR" = "0" ] || child_args+=(--prompt-pair)
  [ "$REPAIR_EXISTING" = "0" ] || child_args+=(--re-pair)
  [ -z "$API_URL" ] || child_args+=(--api-url "$API_URL")
  [ "$TIER_EXPLICIT" = "0" ] || child_args+=(--tier "$TIER")
  [ "$ACCESS_EXPLICIT" = "0" ] || child_args+=(--access "$ACCESS")
  [ "$WORKSPACE_EXPLICIT" = "0" ] || child_args+=(--workspace "$WORKSPACE")
  [ "$ADOPT_EXISTING_WORKSPACE" = "0" ] || child_args+=(--adopt-existing-workspace)
  case "$CONNECT_MODE" in
    foreground) child_args+=(--foreground) ;;
    none) child_args+=(--no-connect) ;;
    *) child_args+=(--background) ;;
  esac

  child_env+=(
    "HOME=$target_home"
    "USER=$target_user"
    "LOGNAME=$target_user"
    "SHELL=$target_shell"
    "PATH=/usr/local/bin:/usr/bin:/bin:$target_home/.local/bin"
    "MESHIA_ROOT_BOOTSTRAPPED=1"
    "MESHIA_ROOT_PAIR_STDIN=1"
  )
  [ -z "${TERM:-}" ] || child_env+=("TERM=$TERM")
  [ -z "${LANG:-}" ] || child_env+=("LANG=$LANG")
  [ -z "${LC_ALL:-}" ] || child_env+=("LC_ALL=$LC_ALL")
  [ -z "${NO_COLOR:-}" ] || child_env+=("NO_COLOR=$NO_COLOR")
  [ -z "${CI:-}" ] || child_env+=("CI=$CI")
  [ -z "${MESHIA_PLAIN:-}" ] || child_env+=("MESHIA_PLAIN=$MESHIA_PLAIN")
  [ -z "${MESHIA_REDUCE_MOTION:-}" ] \
    || child_env+=("MESHIA_REDUCE_MOTION=$MESHIA_REDUCE_MOTION")

  step "Continuing as Linux user $target_user (uid $target_uid)"
  set +e
  printf '%s\n' "$PAIR_GRANT" \
    | runuser -u "$target_user" -- "${child_env[@]}" \
      bash -c 'cd "$HOME" && exec "$@"' bash \
      "$delegated_installer" "${child_args[@]}"
  bootstrap_status="${PIPESTATUS[1]}"
  set -e
  PAIR_GRANT=""
  unset PAIR_GRANT
  rm -f "$delegated_installer"
  rmdir "$bootstrap_dir" 2>/dev/null \
    || log "WARNING: could not remove the empty root-bootstrap directory $bootstrap_dir"
  if [ "$bootstrap_status" -eq 0 ]; then
    install_linux_root_command_wrapper "$target_user" "$target_home" "meshia"
    install_linux_root_command_wrapper "$target_user" "$target_home" "meshia-node"
  fi
  exit "$bootstrap_status"
}

install_linux_root_command_wrapper() { # <user> <home> <command>
  local target_user="$1" target_home="$2" command_name="$3"
  local wrapper_path="/usr/local/bin/$command_name" wrapper_tmp=""
  local marker="# Managed by the Meshia Linux root bootstrap"

  if [ -e "$wrapper_path" ] || [ -L "$wrapper_path" ]; then
    if [ ! -f "$wrapper_path" ] \
        || ! grep -Fqx "$marker" "$wrapper_path" 2>/dev/null; then
      log "WARNING: leaving the existing $wrapper_path untouched"
      return 0
    fi
  fi
  wrapper_tmp="$(mktemp "${TMPDIR:-/tmp}/meshia-command.XXXXXX")"
  {
    printf '%s\n' '#!/bin/bash' "$marker"
    # A verified sudo account can have a home containing shell metacharacters
    # or spaces. Render each argument as Bash code, never interpolate it raw.
    printf 'target_user=%q\ntarget_home=%q\ncommand_path=%q\n' \
      "$target_user" "$target_home" "$target_home/.local/bin/$command_name"
    cat <<'SH'
if [ "$(id -u)" = "$(id -u "$target_user")" ]; then
  exec "$command_path" "$@"
fi
exec runuser -u "$target_user" -- env \
  "HOME=$target_home" "USER=$target_user" "LOGNAME=$target_user" \
  "PATH=/usr/local/bin:/usr/bin:/bin:$target_home/.local/bin" \
  sh -c 'cd "$HOME" && exec "$@"' sh "$command_path" "$@"
SH
  } >"$wrapper_tmp"
  install -m 0755 -o root -g root "$wrapper_tmp" "$wrapper_path" \
    || die "could not install the unprivileged $command_name command wrapper"
  rm -f "$wrapper_tmp"
}

parse_url_authority() { # parse_url_authority <url> <label> <origin-only: 0|1>
  local url="$1" label="$2" origin_only="$3" remainder="" authority=""
  local host="" port=""
  case "$url" in
    https://*) PARSED_URL_SCHEME="https"; remainder="${url#https://}" ;;
    http://*)  PARSED_URL_SCHEME="http"; remainder="${url#http://}" ;;
    *) die "$label must use https:// (http:// is development-loopback only)" ;;
  esac
  [ -n "$remainder" ] || die "$label has no host"

  if [ "$origin_only" = "1" ]; then
    case "$remainder" in
      *'?'*|*'#'*|*@*) die "$label must be an origin without credentials, path, query, or fragment" ;;
    esac
    case "$remainder" in
      */) authority="${remainder%/}" ;;
      *)  authority="$remainder" ;;
    esac
    case "$authority" in
      ""|*/*) die "$label must be an origin without credentials, path, query, or fragment" ;;
    esac
  else
    authority="${remainder%%/*}"
    authority="${authority%%\?*}"
    authority="${authority%%\#*}"
    case "$authority" in
      ""|*@*) die "$label has an invalid or credential-bearing authority" ;;
    esac
  fi

  if [[ "$authority" =~ ^\[([0-9A-Fa-f:.]+)\](:([1-9][0-9]{0,4}))?$ ]]; then
    host="[${BASH_REMATCH[1]}]"
    port="${BASH_REMATCH[3]:-}"
  elif [[ "$authority" =~ ^([A-Za-z0-9.-]+)(:([1-9][0-9]{0,4}))?$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[3]:-}"
  else
    die "$label has an invalid host or port"
  fi
  if [ -n "$port" ] && [ "$port" -gt 65535 ]; then
    die "$label has an invalid port"
  fi
  PARSED_URL_HOST="$host"
}

enforce_url_transport() { # enforce_url_transport <url> <label> <origin-only: 0|1>
  parse_url_authority "$1" "$2" "$3"
  if [ "$PARSED_URL_SCHEME" = "http" ]; then
    [ "$INSECURE_DEV" = "1" ] \
      || die "$2 uses http://; pass --insecure-dev only for a loopback development server"
    case "$PARSED_URL_HOST" in
      localhost|127.0.0.1|'[::1]') ;;
      *) die "$2 may use http:// only for localhost, 127.0.0.1, or [::1]" ;;
    esac
  fi
}

directory_owner_uid() {
  if [ "$OS" = "Darwin" ]; then stat -f '%u' "$1"
  else stat -c '%u' "$1"
  fi
}

managed_directory_is_safe() {
  local owner=""
  [ ! -L "$1" ] && [ -d "$1" ] || return 1
  owner="$(directory_owner_uid "$1")" || return 1
  [ "$owner" -eq "$CURRENT_UID" ]
}

preflight_managed_directory() {
  if [ -L "$1" ]; then
    die "managed directory must not be a symlink: $1"
  elif [ -e "$1" ] && ! managed_directory_is_safe "$1"; then
    die "managed path is not a real directory owned by uid $CURRENT_UID: $1"
  fi
}

require_managed_directory() {
  managed_directory_is_safe "$1" \
    || die "managed path is not a real directory owned by uid $CURRENT_UID: $1"
}

directory_has_entries() {
  local entry=""
  for entry in "$1"/* "$1"/.[!.]* "$1"/..?*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    return 0
  done
  return 1
}

recognizable_custom_home() {
  [ -x "$MESHIA_HOME/runtime/bin/meshia-node" ] && return 0
  if [ -f "$MESHIA_HOME/config.json" ] \
      && grep -q '"host_id"' "$MESHIA_HOME/config.json" \
      && grep -q '"api_url"' "$MESHIA_HOME/config.json"; then
    return 0
  fi
  [ -x "$MESHIA_HOME/bin/uv" ] && [ -d "$MESHIA_HOME/runtimes" ] \
    && [ -d "$MESHIA_HOME/locks" ]
}

# Reject transport ambiguity before uv, manifest, or package downloaders run.
[ -z "$API_URL" ] || enforce_url_transport "$API_URL" "Meshia API URL" 1
[ -z "$PACKAGE_URL" ] || enforce_url_transport "$PACKAGE_URL" "meshia-node package URL" 0

acquire_installer_lock() {
  local lock_owner="" pid_file="$INSTALL_LOCK_DIR/pid" pid_owner=""
  local lock_pid="" pid_bytes=""

  if ! mkdir "$INSTALL_LOCK_DIR" 2>/dev/null; then
    # Recovery is deliberately narrower than `rm -rf`: only an exact, real,
    # same-user lock directory with one trustworthy PID file is eligible.
    [ ! -L "$INSTALL_LOCK_DIR" ] && [ -d "$INSTALL_LOCK_DIR" ] \
      || die "installer lock is unsafe or malformed; refusing to replace it: $INSTALL_LOCK_DIR"
    lock_owner="$(directory_owner_uid "$INSTALL_LOCK_DIR")" \
      || die "could not verify installer lock ownership: $INSTALL_LOCK_DIR"
    [ "$lock_owner" -eq "$CURRENT_UID" ] \
      || die "installer lock is owned by uid $lock_owner, not uid $CURRENT_UID"
    [ ! -L "$pid_file" ] && [ -f "$pid_file" ] \
      || die "installer lock has no safe regular PID file; refusing to replace it: $INSTALL_LOCK_DIR"
    pid_owner="$(directory_owner_uid "$pid_file")" \
      || die "could not verify installer lock PID ownership: $pid_file"
    [ "$pid_owner" -eq "$CURRENT_UID" ] \
      || die "installer lock PID is owned by uid $pid_owner, not uid $CURRENT_UID"
    IFS= read -r lock_pid <"$pid_file" \
      || die "installer lock PID is malformed; refusing to replace it: $pid_file"
    case "$lock_pid" in
      ""|0|0*|*[!0-9]*)
        die "installer lock PID is malformed; refusing to replace it: $pid_file"
        ;;
    esac
    [ "${#lock_pid}" -le 10 ] \
      || die "installer lock PID is malformed; refusing to replace it: $pid_file"
    [ "$lock_pid" -le 2147483647 ] \
      || die "installer lock PID is malformed; refusing to replace it: $pid_file"
    pid_bytes="$(wc -c <"$pid_file" | tr -d '[:space:]')"
    [ "$pid_bytes" = "$(( ${#lock_pid} + 1 ))" ] \
      || die "installer lock PID is malformed; refusing to replace it: $pid_file"

    if kill -0 "$lock_pid" 2>/dev/null; then
      die "another meshia-node installer is active (pid $lock_pid; lock: $INSTALL_LOCK_DIR)"
    fi
    # `kill -0` can also fail for a live process the user cannot signal. ps is
    # the fail-closed discriminator; only a PID absent from both checks is stale.
    command -v ps >/dev/null 2>&1 \
      || die "cannot safely determine whether installer pid $lock_pid is stale"
    if ps -p "$lock_pid" >/dev/null 2>&1; then
      die "installer lock refers to a live process that cannot be signaled (pid $lock_pid)"
    fi
    local entry=""
    for entry in "$INSTALL_LOCK_DIR"/* "$INSTALL_LOCK_DIR"/.[!.]* "$INSTALL_LOCK_DIR"/..?*; do
      [ -e "$entry" ] || [ -L "$entry" ] || continue
      [ "$entry" = "$pid_file" ] \
        || die "stale installer lock contains unexpected entries; refusing to replace it: $INSTALL_LOCK_DIR"
    done

    rm -f "$pid_file" \
      || die "could not remove stale installer PID file: $pid_file"
    rmdir "$INSTALL_LOCK_DIR" 2>/dev/null \
      || die "stale installer lock contains unexpected entries; refusing to replace it: $INSTALL_LOCK_DIR"
    log "recovered stale installer lock from pid $lock_pid"
    mkdir "$INSTALL_LOCK_DIR" 2>/dev/null \
      || die "another meshia-node installer acquired the lock first: $INSTALL_LOCK_DIR"
  fi

  INSTALL_LOCK_HELD=1
  chmod 700 "$INSTALL_LOCK_DIR"
  (umask 077; printf '%s\n' "$$" >"$INSTALL_LOCK_DIR/pid")
}

# chmod must never repurpose an arbitrary path supplied through MESHIA_HOME.
# The default keeps compatibility with legacy ~/.meshia layouts; a custom,
# non-empty directory needs durable evidence that Meshia already owns it.
bootstrap_linux_root
if [ -L "$MESHIA_HOME" ]; then
  die "Meshia home must not be a symlink: $MESHIA_HOME"
elif [ -e "$MESHIA_HOME" ]; then
  [ -d "$MESHIA_HOME" ] || die "Meshia home is not a directory: $MESHIA_HOME"
  HOME_OWNER_UID="$(directory_owner_uid "$MESHIA_HOME")" \
    || die "could not verify ownership of Meshia home: $MESHIA_HOME"
  [ "$HOME_OWNER_UID" -eq "$CURRENT_UID" ] \
    || die "Meshia home is owned by uid $HOME_OWNER_UID, not uid $CURRENT_UID"
  if [ "$CUSTOM_MESHIA_HOME" = "1" ] \
      && directory_has_entries "$MESHIA_HOME" \
      && ! recognizable_custom_home; then
    die "custom Meshia home is non-empty and has no recognizable Meshia state: $MESHIA_HOME"
  fi
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/meshia-install.XXXXXX")"
ui_begin

# ----------------------------------------------------------------- private layout
ui_phase 1 5 "Secure local state"
step "Preparing $MESHIA_HOME"
for MANAGED_DIR in "$TOOL_DIR" "$RUNTIMES_DIR" "$CACHE_DIR" "$LOCK_DIR" \
    "$UV_CACHE_DIR" "$UV_PYTHON_INSTALL_DIR" "$BIN_DIR"; do
  preflight_managed_directory "$MANAGED_DIR"
done
mkdir -p "$MESHIA_HOME" "$TOOL_DIR" "$BIN_DIR" "$RUNTIMES_DIR" "$CACHE_DIR" \
  "$LOCK_DIR" "$UV_CACHE_DIR" "$UV_PYTHON_INSTALL_DIR"
# Re-read every leaf after creation, before chmod or installation, so mkdir
# races and pre-existing redirects fail closed rather than writing elsewhere.
require_managed_directory "$MESHIA_HOME"
for MANAGED_DIR in "$TOOL_DIR" "$RUNTIMES_DIR" "$CACHE_DIR" "$LOCK_DIR" \
    "$UV_CACHE_DIR" "$UV_PYTHON_INSTALL_DIR" "$BIN_DIR"; do
  require_managed_directory "$MANAGED_DIR"
done
chmod 700 "$MESHIA_HOME" "$TOOL_DIR" "$RUNTIMES_DIR" "$CACHE_DIR" "$LOCK_DIR"
log "state directory ready (0700, no sudo used)"

# mkdir is the one portable atomic lock primitive available on both stock
# macOS and Linux. Never let two installers stop/flip the same user service.
acquire_installer_lock

# A legacy real venv needs one rename before `runtime` becomes an atomic
# selector. If power was lost in that tiny migration window, recover the link
# before inspecting or starting either runtime.
if [ -f "$MIGRATION_MARKER" ]; then
  IFS= read -r RECOVERY_RUNTIME <"$MIGRATION_MARKER" || true
  case "$RECOVERY_RUNTIME" in
    "$RUNTIMES_DIR"/*)
      [ -d "$RECOVERY_RUNTIME" ] \
        || die "runtime migration marker points to a missing directory: $RECOVERY_RUNTIME"
      if [ ! -e "$RUNTIME_LINK" ] && [ ! -L "$RUNTIME_LINK" ]; then
        # BASE_PYTHON is not available yet, so recovery uses a direct symlink.
        # No competing installer can observe it while the installer lock is held.
        ln -s "$RECOVERY_RUNTIME" "$RUNTIME_LINK"
      elif [ ! -L "$RUNTIME_LINK" ]; then
        die "runtime migration marker conflicts with non-symlink $RUNTIME_LINK"
      fi
      rm -f "$MIGRATION_MARKER"
      ;;
    *) die "invalid runtime migration marker" ;;
  esac
fi

uv_release_sha256() {
  # Release asset digests from astral-sh/uv 0.12.11. Custom versions retain
  # the explicit checksum override or verified release-checksum path below.
  case "$UV_VERSION/$UV_TARGET" in
    0.12.11/aarch64-apple-darwin) printf '%s\n' e01b69ee15e81918d5e8fc9cf39b3db7f59c5576e5e306cd9b7aeb2c7b7321c3 ;;
    0.12.11/x86_64-apple-darwin) printf '%s\n' 96d773bf5fda4f9b08c4444847f9183d1c14bc8a28ff9c0490e261a8fc6e5309 ;;
    0.12.11/aarch64-unknown-linux-gnu) printf '%s\n' e9933d907fb9cd27d606d819bbded419f2844c0e2efc98225ecfa409288eb28d ;;
    0.12.11/x86_64-unknown-linux-gnu) printf '%s\n' 4ae93e0f148a18434cc094072547cec88912fc4a72b984183c7d0d0e9586cb5e ;;
    0.12.11/aarch64-unknown-linux-musl) printf '%s\n' de99cafdeb5ee6f61ac3acd6d9dc6a1ef166f9398fa5623c436246ee1ecea099 ;;
    0.12.11/x86_64-unknown-linux-musl) printf '%s\n' 3343303ad6b4f9537ae0abfb36f1926a90c0445ba8f23d0e0a840a66a124cffd ;;
    *) return 1 ;;
  esac
}

# ------------------------------------------------------------------------- uv
ui_phase 2 5 "Prepare the runtime"
UV_BIN=""
if [ -x "$TOOL_DIR/uv" ] && "$TOOL_DIR/uv" --version 2>/dev/null | grep -q "$UV_VERSION"; then
  UV_BIN="$TOOL_DIR/uv"
  step "uv $UV_VERSION already installed"
elif command -v uv >/dev/null 2>&1 && uv --version 2>/dev/null | grep -q "$UV_VERSION"; then
  UV_BIN="$(command -v uv)"
  step "using system uv $UV_VERSION"
else
  step "Installing uv $UV_VERSION ($UV_TARGET)"
  ASSET="uv-${UV_TARGET}.tar.gz"
  BASE="https://github.com/astral-sh/uv/releases/download/${UV_VERSION}"
  ui_run_quiet "Downloading the verified runtime tool" \
    fetch "${BASE}/${ASSET}" "$WORK_DIR/$ASSET" \
    || die "could not download $ASSET"
  if [ -n "${MESHIA_UV_SHA256:-}" ]; then
    # An out-of-band pin always wins over the release-hosted checksum.
    verify_sha256 "$WORK_DIR/$ASSET" "$MESHIA_UV_SHA256" "uv"
  elif UV_PINNED_SHA256="$(uv_release_sha256)"; then
    verify_sha256 "$WORK_DIR/$ASSET" "$UV_PINNED_SHA256" "uv"
  elif ui_run_quiet "Checking the runtime tool signature" \
      fetch "${BASE}/${ASSET}.sha256" "$WORK_DIR/$ASSET.sha256"; then
    verify_sha256 "$WORK_DIR/$ASSET" "$(awk '{print $1}' "$WORK_DIR/$ASSET.sha256")" "uv"
  else
    die "no uv checksum available; set MESHIA_UV_SHA256 to pin one"
  fi
  tar -xzf "$WORK_DIR/$ASSET" -C "$WORK_DIR"
  install -m 0755 "$WORK_DIR/uv-${UV_TARGET}/uv" "$TOOL_DIR/uv"
  [ -f "$WORK_DIR/uv-${UV_TARGET}/uvx" ] && install -m 0755 "$WORK_DIR/uv-${UV_TARGET}/uvx" "$TOOL_DIR/uvx" || true
  UV_BIN="$TOOL_DIR/uv"
  log "installed $("$UV_BIN" --version)"
fi

export UV_CACHE_DIR UV_PYTHON_INSTALL_DIR

# --------------------------------------------------------------------- interpreter
step "Preparing the managed Python toolchain"
if [ "$LINUX_MUSL" = "1" ]; then
  step "Preparing a musl-compatible Python runtime (one-time administrator approval)"
  musl_python_status=0
  if prepare_musl_system_python; then
    musl_python_status=0
  else
    musl_python_status=$?
  fi
  if [ "$musl_python_status" -eq 125 ]; then
    die "an interactive sudo session is required to install Python on musl Linux"
  elif [ "$musl_python_status" -eq 124 ]; then
    die "musl Linux requires Python 3.11+ from the system package manager"
  elif [ "$musl_python_status" -ne 0 ]; then
    die "could not install a working Python 3.11+ runtime on musl Linux"
  fi
  log "system Python $("$BASE_PYTHON" --version 2>&1 | awk '{print $2}') is ready for musl Linux"
else
  ui_loader_start "Provisioning Python $PYTHON_VERSION"
  "$UV_BIN" python install --no-bin "$PYTHON_VERSION" >/dev/null 2>&1 || true
  BASE_PYTHON="$("$UV_BIN" python find "$PYTHON_VERSION" 2>/dev/null || true)"
  if python_runtime_compatible "$BASE_PYTHON"; then
    ui_loader_stop ok "Python $PYTHON_VERSION is ready"
  else
    ui_loader_stop fail "Python $PYTHON_VERSION could not be provisioned"
    die "could not locate the provisioned Python $PYTHON_VERSION"
  fi
fi

# ------------------------------------------------------------------------ package
ui_phase 3 5 "Verify the Meshia release"
step "Resolving the meshia-node release"
RELEASE_VERSION=""
PACKAGE_DIGEST=""
if [ -n "$FROM_DIR" ]; then
  [ -f "$FROM_DIR/pyproject.toml" ] || die "--from-dir $FROM_DIR has no pyproject.toml"
  RELEASE_VERSION="$("$BASE_PYTHON" - "$FROM_DIR/pyproject.toml" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as source:
    print(tomllib.load(source)["project"]["version"])
PY
)"
  PACKAGE_DIGEST="$("$BASE_PYTHON" - "$FROM_DIR" <<'PY'
import hashlib
import os
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve()
excluded = {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".venv", "__pycache__", "dist"}
digest = hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative = path.relative_to(root)
    if any(part in excluded for part in relative.parts):
        continue
    encoded = relative.as_posix().encode("utf-8")
    if path.is_symlink():
        digest.update(b"L\0" + encoded + b"\0" + os.readlink(path).encode("utf-8") + b"\0")
    elif path.is_file():
        digest.update(b"F\0" + encoded + b"\0")
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\0")
print(digest.hexdigest())
PY
)"
  TARGET="$FROM_DIR"
  log "development install from $FROM_DIR"
else
  if [ -z "$PACKAGE_URL" ]; then
    BASE_ORIGIN="${API_URL:-https://meshia.io}"
    BASE_ORIGIN="${BASE_ORIGIN%/}"
    MANIFEST_URL="${BASE_ORIGIN}/meshia-node/release.json"
    MANIFEST_FILE="$WORK_DIR/release.json"
    log "fetching release manifest from $MANIFEST_URL"
    ui_run_quiet "Finding the current Meshia release" fetch "$MANIFEST_URL" "$MANIFEST_FILE" \
      || die "could not download release manifest from $MANIFEST_URL"

    RELEASE_VERSION="$("$BASE_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$MANIFEST_FILE")"
    PKG_NAME="$("$BASE_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["package"])' "$MANIFEST_FILE")"
    PKG_SHA="$("$BASE_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha256"])' "$MANIFEST_FILE")"
    [ -n "$RELEASE_VERSION" ] && [ -n "$PKG_NAME" ] && [ -n "$PKG_SHA" ] \
      || die "could not parse package information from $MANIFEST_URL"
    PACKAGE_URL="${BASE_ORIGIN}/meshia-node/${PKG_NAME}"
    PACKAGE_SHA256="$PKG_SHA"
    NATIVE_APP_ZIP_NAME="$("$BASE_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("macos_app") or "")' "$MANIFEST_FILE")"
    NATIVE_APP_ZIP_SHA="$("$BASE_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("macos_app_sha256") or "")' "$MANIFEST_FILE")"
    if [ -n "$NATIVE_APP_ZIP_NAME" ]; then
      NATIVE_APP_ZIP_URL="${BASE_ORIGIN}/meshia-node/${NATIVE_APP_ZIP_NAME}"
    fi
    NODE_APP_NAME="$("$BASE_PYTHON" - "$MANIFEST_FILE" <<'PY'
import json, re, sys
with open(sys.argv[1], encoding="utf-8") as source:
    release = json.load(source)
name, digest = release.get("macos_node_app"), release.get("macos_node_app_sha256")
if name is not None or digest is not None:
    if name != f"MeshiaNode-{release['version']}.app.zip" or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise SystemExit("invalid native node app release binding")
print(name or "")
PY
)" || die "release.json has an invalid native node app"
    if [ -n "$NODE_APP_NAME" ]; then
      NODE_APP_URL="${BASE_ORIGIN}/meshia-node/${NODE_APP_NAME}"
      NODE_APP_SHA="$("$BASE_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["macos_node_app_sha256"])' "$MANIFEST_FILE")"
    fi
  fi

  ARCHIVE="$WORK_DIR/$(basename "${PACKAGE_URL%%\?*}")"
  ui_run_quiet "Downloading the signed Meshia package" fetch "$PACKAGE_URL" "$ARCHIVE" \
    || die "could not download the signed Meshia package; check your connection and request a fresh install command"
  if [ -n "$PACKAGE_SHA256" ]; then
    verify_sha256 "$ARCHIVE" "$PACKAGE_SHA256" "meshia-node package"
  elif [ "$INSECURE_DEV" = "1" ]; then
    log "WARNING: installing an unverified package because --insecure-dev was set"
  else
    die "--package-sha256 (or \$MESHIA_NODE_PACKAGE_SHA256) is required; use --insecure-dev to override"
  fi
  PACKAGE_DIGEST="$(sha256_of "$ARCHIVE")"
  ARCHIVE_VERSION="$("$BASE_PYTHON" - "$ARCHIVE" <<'PY'
import email.parser
import pathlib
import sys
import tarfile
import zipfile

archive = pathlib.Path(sys.argv[1])
metadata = None
if zipfile.is_zipfile(archive):
    with zipfile.ZipFile(archive) as package:
        names = sorted(name for name in package.namelist() if name.endswith(".dist-info/METADATA"))
        if len(names) == 1:
            metadata = package.read(names[0]).decode("utf-8")
elif tarfile.is_tarfile(archive):
    with tarfile.open(archive) as package:
        members = sorted(
            (member for member in package.getmembers() if member.isfile() and member.name.endswith("/PKG-INFO")),
            key=lambda member: member.name,
        )
        if len(members) == 1:
            source = package.extractfile(members[0])
            if source is not None:
                metadata = source.read().decode("utf-8")
if metadata is None:
    raise SystemExit("package contains no unique distribution metadata")
version = email.parser.Parser().parsestr(metadata).get("Version")
if not version:
    raise SystemExit("package metadata has no Version")
print(version)
PY
)" || die "could not read the package version from $ARCHIVE"
  if [ -n "$RELEASE_VERSION" ] && [ "$ARCHIVE_VERSION" != "$RELEASE_VERSION" ]; then
    die "release manifest version $RELEASE_VERSION does not match package version $ARCHIVE_VERSION"
  fi
  RELEASE_VERSION="$ARCHIVE_VERSION"
  TARGET="$ARCHIVE"
fi

case "$RELEASE_VERSION" in
  ""|*[!A-Za-z0-9._+-]*) die "invalid package version: $RELEASE_VERSION" ;;
esac
case "$PACKAGE_DIGEST" in
  ""|*[!a-f0-9]*)
    die "invalid package digest for meshia-node $RELEASE_VERSION"
    ;;
esac
[ "${#PACKAGE_DIGEST}" -eq 64 ] || die "invalid package digest length"

# Each artifact gets an immutable venv. The package digest is part of the path,
# so `uv pip` can never mutate the runtime currently owned by a service process.
CANDIDATE_RUNTIME="$RUNTIMES_DIR/$RELEASE_VERSION-$PACKAGE_DIGEST"
CANDIDATE_CLI="$CANDIDATE_RUNTIME/bin/meshia-node"
RELEASE_MARKER="$CANDIDATE_RUNTIME/.meshia-release"
EXPECTED_MARKER="version=$RELEASE_VERSION
digest=$PACKAGE_DIGEST"
STAGE_NODE_APP=0
native_node_app_eligible() {
  [ "$OS" = "Darwin" ] || return 1
  local native_account_home
  native_account_home="$("$BASE_PYTHON" -c 'import os,pwd; print(pwd.getpwuid(os.getuid()).pw_dir)')" || return 1
  [ "$MESHIA_HOME" = "$native_account_home/.meshia" ]
}
if [ -n "$NODE_APP_URL$NODE_APP_SHA" ] && native_node_app_eligible; then
  [ -n "$NODE_APP_URL" ] && [[ "$NODE_APP_SHA" =~ ^[a-f0-9]{64}$ ]] \
    || die "native node app requires its release URL and checksum"
  STAGE_NODE_APP=1
  EXPECTED_MARKER="$EXPECTED_MARKER
macos_node_app_sha256=$NODE_APP_SHA"
fi

validate_candidate() {
  local marker="" version=""
  [ -x "$CANDIDATE_RUNTIME/bin/python" ] && [ -x "$CANDIDATE_CLI" ] \
    && [ -f "$RELEASE_MARKER" ] || return 1
  marker="$("$BASE_PYTHON" -c 'import sys; print(open(sys.argv[1], encoding="utf-8").read().rstrip("\n"))' "$RELEASE_MARKER")" \
    || return 1
  [ "$marker" = "$EXPECTED_MARKER" ] || return 1
  version="$("$CANDIDATE_CLI" --version 2>/dev/null)" || return 1
  [ "$version" = "meshia-node $RELEASE_VERSION" ] || return 1
  "$CANDIDATE_RUNTIME/bin/python" -c 'import meshia_node.service' >/dev/null 2>&1 \
    || return 1
  "$CANDIDATE_CLI" service restart --help >/dev/null 2>&1 || return 1
  "$CANDIDATE_CLI" connect --help 2>&1 | grep -q -- '--pair-stdin' || return 1
  "$CANDIDATE_CLI" connect --help 2>&1 | grep -q -- '--adopt-existing-workspace' \
    || return 1
  "$CANDIDATE_CLI" account-cutover prepare --help >/dev/null 2>&1 || return 1
  if [ "$STAGE_NODE_APP" = 1 ]; then
    "$CANDIDATE_RUNTIME/bin/python" -I -m meshia_node.native_host check \
      "$CANDIDATE_RUNTIME/native/Meshia Node.app" >/dev/null || return 1
  fi
}

preflight_macos_native_compute() {
  [ "$OS" = "Darwin" ] || return 0
  local selected_access="${ACCESS:-}"
  if [ -z "$selected_access" ] && [ -f "$MESHIA_HOME/config.json" ]; then
    selected_access="$("$BASE_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("access", "files"))' \
      "$MESHIA_HOME/config.json")" || die "the retained compute access could not be read before upgrade"
  fi
  case "$selected_access" in limited|full) ;; *) return 0 ;; esac
  native_node_app_eligible \
    || die "native macOS compute requires installation in this account's standard ~/.meshia directory"
  [ "$STAGE_NODE_APP" = 1 ] \
    || die "native macOS compute requires the release's checksum-bound Meshia Node app; no pairing token was consumed"
  # Use the candidate interpreter: readiness resolves its own immutable app
  # through sys.prefix and verifies the kernel ownership API before cutover.
  "$CANDIDATE_RUNTIME/bin/python" -I -c '
import sys
from meshia_node.macos_native import readiness
ready, detail = readiness()
if not ready:
    print(detail, file=sys.stderr)
    raise SystemExit(1)
' || die "native macOS compute requires macOS 14.2 or later and its verified Meshia Node app; no pairing token was consumed"
}

recover_interrupted_account_cutover() {
  local inspection="$WORK_DIR/account-cutover.json" phase="" prior_runtime=""
  local old_lifecycle="" current_cli="$RUNTIME_LINK/bin/meshia-node"
  local legacy_prior_runtime=0 prior_cli="" prior_version=""

  "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover inspect >"$inspection" \
    || die "the interrupted account-cutover receipt could not be inspected"
  phase="$("$BASE_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["phase"])' "$inspection")" \
    || die "the interrupted account-cutover phase is unreadable"
  [ "$phase" != "absent" ] || return 0
  if [ "$phase" = "rolled_back" ]; then
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover retry-retirement \
      >/dev/null \
      || die "the retired replacement identity could not be reconciled safely"
    log "retried cleanup of a retired replacement identity without stopping the current mount"
    return 0
  fi
  if [ "$phase" = "committed" ]; then
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover finalize >/dev/null \
      || die "the committed account cutover could not retire rollback material"
    log "finalized an already-ready replacement account without interrupting its mount"
    return 0
  fi
  if [ "$phase" = "preparing" ] || [ "$phase" = "prepared" ]; then
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover rollback >/dev/null \
      || die "the interrupted pre-activation account cutover could not be retired"
    log "retired an interrupted account preparation without stopping the current mount"
    return 0
  fi
  [ "$phase" = "activating" ] || [ "$phase" = "published" ] \
    || die "the interrupted account-cutover phase is invalid: $phase"

  # An activating receipt can precede the very first stop instruction.  Prove
  # the old runner is still healthy before demanding an immutable rollback
  # runtime that a legacy install has not migrated yet; retiring only the
  # candidate files then preserves truly uninterrupted availability.
  if [ "$phase" = "activating" ] && [ -x "$current_cli" ] \
      && "$current_cli" --home "$MESHIA_HOME" --json status 2>/dev/null \
        | "$BASE_PYTHON" -c 'import json,sys; d=json.load(sys.stdin); s=d.get("service", {}); raise SystemExit(0 if s.get("installed_for_home") is True and s.get("runner_active") is True and d.get("lifecycle") == "connected" else 1)'; then
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover rollback >/dev/null \
      || die "the interrupted activation receipt could not be retired"
    log "retired an interrupted activation while the prior mount stayed live"
    return 0
  fi

  prior_runtime="$("$BASE_PYTHON" -c 'import json,sys; print(json.load(open(sys.argv[1]))["prior_runtime"])' "$inspection")" \
    || die "the interrupted account cutover has no prior runtime"
  prior_runtime="$("$BASE_PYTHON" - "$prior_runtime" "$RUNTIMES_DIR" "$RUNTIME_LINK" "$phase" <<'PY'
import os
import pathlib
import sys

runtime = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
selector = pathlib.Path(sys.argv[3])
phase = sys.argv[4]
if runtime == selector and phase == "activating" and selector.is_symlink():
    runtime = selector.resolve(strict=True)
legacy = (
    runtime == selector
    and phase == "activating"
    and selector.exists()
    and not selector.is_symlink()
    and selector.is_dir()
)
if runtime.is_symlink() or not runtime.is_dir() or (runtime.parent != root and not legacy):
    raise SystemExit(1)
if (
    (runtime.resolve().parent != root.resolve() and not legacy)
    or not (runtime / "bin" / "meshia-node").is_file()
):
    raise SystemExit(1)
print(runtime)
PY
  )" || die "the interrupted account cutover names an unsafe prior runtime"
  if [ "$prior_runtime" = "$RUNTIME_LINK" ] && [ -d "$RUNTIME_LINK" ] \
      && [ ! -L "$RUNTIME_LINK" ]; then
    legacy_prior_runtime=1
  fi

  # Outside the live-old optimization above, require an idempotent manager
  # uninstall through a runnable home-owned CLI.  This waits for the singleton
  # runner/lease to exit; unreadable status can therefore cause downtime but
  # can never be mistaken for proof that a candidate mount is absent.
  [ -x "$current_cli" ] || current_cli="$CANDIDATE_CLI"
  "$current_cli" --home "$MESHIA_HOME" service uninstall >/dev/null \
    || die "the interrupted replacement service could not be stopped and removed safely"
  "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover rollback >/dev/null \
    || die "the prior Meshia account could not be restored after an interrupted cutover"
  if [ "$legacy_prior_runtime" != "1" ]; then
    atomic_symlink "$prior_runtime" "$RUNTIME_LINK" \
      || die "the prior Meshia runtime selector could not be restored"
  fi
  atomic_symlink "$RUNTIME_LINK/bin/meshia-node" "$BIN_DIR/meshia-node" \
    || die "the prior Meshia command could not be restored"
  atomic_symlink "$RUNTIME_LINK/bin/meshia-node" "$BIN_DIR/meshia" \
    || die "the prior Meshia command alias could not be restored"
  prior_cli="$prior_runtime/bin/meshia-node"
  prior_version="$("$prior_cli" --version 2>/dev/null)" \
    || die "the prior Meshia runtime is no longer runnable"
  prior_version="${prior_version#meshia-node }"
  old_lifecycle="$("$prior_cli" --home "$MESHIA_HOME" --json status 2>/dev/null \
    | "$BASE_PYTHON" -c 'import json,sys; print(json.load(sys.stdin)["lifecycle"])')" \
    || die "the restored Meshia lifecycle could not be read back"
  [ "$old_lifecycle" = "disconnected" ] || [ "$old_lifecycle" = "connected" ] \
    || [ "$old_lifecycle" = "enrolled" ] || [ "$old_lifecycle" = "attaching" ] \
    || [ "$old_lifecycle" = "offline" ] \
    || die "the restored Meshia lifecycle is invalid: $old_lifecycle"
  "$prior_cli" --home "$MESHIA_HOME" service install >/dev/null \
    || die "the prior Meshia service definition could not be restored"
  if [ "$old_lifecycle" = "disconnected" ]; then
    "$prior_cli" --home "$MESHIA_HOME" service start >/dev/null \
      || die "the prior parked Meshia service could not be restored"
  else
    "$prior_cli" --home "$MESHIA_HOME" service restart --wait \
      --timeout-seconds 45 --expected-version "$prior_version" >/dev/null \
      || die "the prior Meshia service did not become ready after crash recovery"
  fi
  log "recovered the prior Meshia account and mount after an interrupted cutover"
}

ui_phase 4 5 "Stage the verified node"
if [ -e "$CANDIDATE_RUNTIME" ] || [ -L "$CANDIDATE_RUNTIME" ]; then
  [ -d "$CANDIDATE_RUNTIME" ] && [ ! -L "$CANDIDATE_RUNTIME" ] \
    || die "immutable runtime path is not a directory: $CANDIDATE_RUNTIME"
  validate_candidate \
    || die "existing immutable runtime failed validation: $CANDIDATE_RUNTIME"
  step "Reusing verified meshia-node $RELEASE_VERSION runtime"
else
  step "Staging meshia-node $RELEASE_VERSION beside the active runtime"
  CANDIDATE_CREATED=1
  ui_run_quiet "Creating an isolated Meshia runtime" \
    "$UV_BIN" venv --python "$BASE_PYTHON" "$CANDIDATE_RUNTIME" \
    || die "could not create the isolated Meshia runtime"
  CANDIDATE_PYTHON="$CANDIDATE_RUNTIME/bin/python"
  [ -x "$CANDIDATE_PYTHON" ] \
    || die "candidate runtime was not created at $CANDIDATE_RUNTIME"
  ui_run_quiet "Installing the verified Meshia node" \
    "$UV_BIN" pip install --python "$CANDIDATE_PYTHON" --quiet "$TARGET" \
    || die "could not install meshia-node into the isolated runtime"
  "$CANDIDATE_PYTHON" -c 'import _cffi_backend; import cryptography' >/dev/null 2>&1 \
    || die "candidate Python runtime cannot load Meshia's signed cryptography dependencies"
  "$CANDIDATE_PYTHON" -c 'import meshia_node.service' >/dev/null \
    || die "candidate package does not contain the service controller"
  "$CANDIDATE_CLI" service restart --help >/dev/null 2>&1 \
    || die "candidate package does not implement transactional service restart"
  if [ "$STAGE_NODE_APP" = 1 ]; then
    NODE_APP_ARCHIVE="$WORK_DIR/MeshiaNode.app.zip"
    ui_run_quiet "Downloading Meshia's native connection app" fetch "$NODE_APP_URL" "$NODE_APP_ARCHIVE" \
      || die "could not download the native node app"
    verify_sha256 "$NODE_APP_ARCHIVE" "$NODE_APP_SHA" "Meshia Node.app"
    "$CANDIDATE_PYTHON" -I -m meshia_node.native_host stage "$NODE_APP_ARCHIVE" "$CANDIDATE_RUNTIME" \
      || die "native node app failed Apple distribution verification"
  fi
  printf '%s\n' "$EXPECTED_MARKER" >"$RELEASE_MARKER.new"
  chmod 600 "$RELEASE_MARKER.new"
  "$BASE_PYTHON" - "$RELEASE_MARKER.new" "$RELEASE_MARKER" <<'PY'
import os
import sys

os.replace(sys.argv[1], sys.argv[2])
PY
  validate_candidate || die "candidate runtime failed its read-back validation"
fi

preflight_macos_native_compute
recover_interrupted_account_cutover

# ---------------------------------------------------------------- existing state
if [ -L "$RUNTIME_LINK" ] || [ -d "$RUNTIME_LINK" ]; then
  PRIOR_RUNTIME="$(cd "$RUNTIME_LINK" 2>/dev/null && pwd -P)" \
    || die "current runtime selector is dangling: $RUNTIME_LINK"
  PRIOR_CLI="$PRIOR_RUNTIME/bin/meshia-node"
  [ -x "$PRIOR_CLI" ] || die "current runtime has no runnable meshia-node CLI"
  PRIOR_VERSION_OUTPUT="$("$PRIOR_CLI" --version 2>/dev/null)" \
    || die "current meshia-node runtime is not runnable"
  PRIOR_VERSION="${PRIOR_VERSION_OUTPUT#meshia-node }"
  case "$PRIOR_VERSION" in
    ""|*[!A-Za-z0-9._+-]*) die "current runtime reported an invalid version" ;;
  esac
  if "$PRIOR_CLI" service restart --help >/dev/null 2>&1; then
    PRIOR_SERVICE_SUPPORTED=1
  fi
elif [ -e "$RUNTIME_LINK" ]; then
  die "current runtime path is neither a directory nor a symlink: $RUNTIME_LINK"
fi

[ -f "$MESHIA_HOME/config.json" ] && HAD_ENROLLMENT=1
if [ "$HAD_ENROLLMENT" = "1" ] \
    && "$BASE_PYTHON" - "$MESHIA_HOME/config.json" <<'PY'
import json
import sys
import uuid

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        config = json.load(source)
except (OSError, ValueError):
    raise SystemExit(1)
account_id = config.get("account_id")
try:
    account_valid = isinstance(account_id, str) and bool(uuid.UUID(account_id))
except ValueError:
    account_valid = False
# Retired workspace storage does not revoke an account device. The candidate
# must restart and prove account-mount readiness using its existing identity.
# Explicit disconnects and device authority failures remain parked.
reason = config.get("disconnect_reason")
storage_recovery = account_valid and isinstance(reason, str) and reason in {
    "WORKSPACE_STORAGE_DELETED", "WORKSPACE_STORAGE_DISABLED", "WORKSPACE_STORAGE_SUPERSEDED",
}
raise SystemExit(0 if config.get("lifecycle") == "disconnected" and not storage_recovery else 1)
PY
then
  PARKED_ENROLLMENT=1
fi
if [ "$HAD_ENROLLMENT" = "1" ] && [ -z "$PRIOR_RUNTIME" ]; then
  die "enrolled state exists without a current runtime; repair the runtime before upgrading"
fi

if [ "$HAD_ENROLLMENT" = "1" ] && [ "$MOUNT_RUNTIME_MODE" != "off" ]; then
  legacy_mount_collision=""
  if ! legacy_mount_collision="$("$BASE_PYTHON" - \
      "$MESHIA_HOME/config.json" "$MESHIA_HOME" "$HOME" \
      "$WORKSPACE_EXPLICIT" "$WORKSPACE" "$ADOPT_EXISTING_WORKSPACE" <<'PY'
import json
import os
import sys

(
    config_path,
    meshia_home,
    user_home,
    workspace_explicit,
    requested_workspace,
    adopt_existing,
) = sys.argv[1:]
try:
    with open(config_path, encoding="utf-8") as source:
        config = json.load(source)
except (OSError, ValueError):
    raise SystemExit(2)

def normalized(value: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.expanduser(value)))

home = normalized(meshia_home)
default_home = normalized(os.path.join(user_home, ".meshia"))
public_mount = normalized(
    os.environ.get("MESHIA_MOUNT_POINT")
    or (
        os.path.join(user_home, "Meshia")
        if home == default_home
        else os.path.join(meshia_home, "mounts", "Meshia")
    )
)
configured_workspace = normalized(str(config.get("workspace", "")))
if configured_workspace != public_mount:
    raise SystemExit(0)

# Once the user has moved the preserved directory away, an explicit private
# replacement lets the same one-liner complete the migration. Lexical path
# checks avoid touching a potentially wedged mount.
if (
    workspace_explicit == "1"
    and adopt_existing == "1"
    and normalized(requested_workspace) != public_mount
):
    try:
        os.lstat(public_mount)
    except FileNotFoundError:
        raise SystemExit(0)
    except OSError:
        pass
print(public_mount)
PY
  )"; then
    die "the existing Meshia enrollment could not be checked for a legacy workspace collision"
  fi
  if [ -n "$legacy_mount_collision" ]; then
    recovery_home="$(quote_shell_argument "$MESHIA_HOME")"
    recovery_command="MESHIA_HOME=$recovery_home $(installer_download_command -- --workspace "$MESHIA_HOME/workspace" --adopt-existing-workspace)"
    die "the legacy private workspace at $legacy_mount_collision is now reserved for the remote Meshia mount; every local file was left untouched. Move that directory to a backup path first. Then run: $recovery_command"
  fi
fi

check_matching_enrollment() {
  "$BASE_PYTHON" - "$MESHIA_HOME/config.json" "$API_URL" "$TIER" "$ACCESS" "$WORKSPACE" \
    "$TIER_EXPLICIT" "$ACCESS_EXPLICIT" "$WORKSPACE_EXPLICIT" "$PARKED_ENROLLMENT" <<'PY'
import json
import os
import sys

config_path, api_url, tier, access, workspace = sys.argv[1:6]
tier_explicit, access_explicit, workspace_explicit = (value == "1" for value in sys.argv[6:9])
parked_enrollment = sys.argv[9] == "1"
try:
    with open(config_path, encoding="utf-8") as source:
        config = json.load(source)
except (OSError, ValueError) as error:
    print(f"local enrollment cannot be read: {type(error).__name__}")
    raise SystemExit(1)

mismatches = []
if api_url and config.get("api_url", "").rstrip("/") != api_url.rstrip("/"):
    mismatches.append("control-plane origin")
if tier_explicit and config.get("tier") != tier:
    mismatches.append("tier")
if access_explicit and config.get("access") != access:
    mismatches.append("access")
if workspace_explicit:
    desired_workspace = os.path.realpath(os.path.expanduser(workspace))
    current_workspace = os.path.realpath(os.path.expanduser(str(config.get("workspace", ""))))
    if current_workspace != desired_workspace:
        mismatches.append("workspace")
if config.get("lifecycle") == "disconnected" and parked_enrollment:
    mismatches.append("sticky disconnected lifecycle")
if mismatches:
    print(", ".join(mismatches))
    raise SystemExit(1)
PY
}

if [ "$HAD_ENROLLMENT" = "1" ] && [ -n "$PAIR_GRANT" ] \
    && [ "$REPAIR_EXISTING" != "1" ] && [ "$CONNECT_MODE" != "none" ]; then
  MATCH_DETAIL=""
  if ! MATCH_DETAIL="$(check_matching_enrollment)"; then
    die "existing enrollment differs in $MATCH_DETAIL; refusing to consume a new grant during upgrade (use meshia-node forget/re-pair explicitly)"
  fi
  log "existing enrollment matches; retaining its identity without replaying the one-time grant"
  PAIR_GRANT=""
fi

if [ -e "$BIN_DIR/meshia-node" ] && [ ! -L "$BIN_DIR/meshia-node" ]; then
  die "refusing to replace non-symlink CLI at $BIN_DIR/meshia-node"
fi
if [ -e "$BIN_DIR/meshia" ] || [ -L "$BIN_DIR/meshia" ]; then
  [ -L "$BIN_DIR/meshia" ] \
    || die "refusing to replace existing command at $BIN_DIR/meshia"
  if [ ! -e "$BIN_DIR/meshia-node" ] || ! "$BASE_PYTHON" - "$BIN_DIR/meshia" "$BIN_DIR/meshia-node" <<'PY'
import os
import sys

raise SystemExit(0 if os.path.realpath(sys.argv[1]) == os.path.realpath(sys.argv[2]) else 1)
PY
  then
    die "refusing to replace a meshia symlink that is not owned by this Meshia installation"
  fi
  HAD_MESHIA_ALIAS=1
fi

runtime_package_digest() { # runtime_package_digest <runtime>
  "$1/bin/python" - <<'PY'
import hashlib
import importlib.util
import pathlib

spec = importlib.util.find_spec("meshia_node")
if spec is None or not spec.submodule_search_locations:
    raise SystemExit("meshia_node package not found")
root = pathlib.Path(next(iter(spec.submodule_search_locations)))
digest = hashlib.sha256()
for path in sorted((path for path in root.rglob("*") if path.is_file()), key=lambda item: item.relative_to(root).as_posix()):
    digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
    digest.update(path.read_bytes() + b"\0")
print(digest.hexdigest())
PY
}

migrate_legacy_runtime() {
  local legacy_digest="" legacy_runtime="" marker_tmp="" legacy_marker=""
  [ -d "$RUNTIME_LINK" ] && [ ! -L "$RUNTIME_LINK" ] || return 0
  legacy_digest="$(runtime_package_digest "$RUNTIME_LINK")" \
    || die "could not fingerprint the legacy runtime before migration"
  legacy_runtime="$RUNTIMES_DIR/legacy-$PRIOR_VERSION-$legacy_digest"
  [ ! -e "$legacy_runtime" ] && [ ! -L "$legacy_runtime" ] \
    || die "legacy rollback runtime already exists: $legacy_runtime"
  legacy_marker="$RUNTIME_LINK/.meshia-release"
  printf 'version=%s\ndigest=%s\nkind=legacy\n' "$PRIOR_VERSION" "$legacy_digest" \
    >"$legacy_marker.new"
  chmod 600 "$legacy_marker.new"
  "$BASE_PYTHON" - "$legacy_marker.new" "$legacy_marker" <<'PY'
import os
import sys

os.replace(sys.argv[1], sys.argv[2])
PY
  marker_tmp="$MIGRATION_MARKER.new.$$"
  printf '%s\n' "$legacy_runtime" >"$marker_tmp"
  chmod 600 "$marker_tmp"
  "$BASE_PYTHON" - "$marker_tmp" "$MIGRATION_MARKER" <<'PY'
import os
import sys

os.replace(sys.argv[1], sys.argv[2])
PY
  mv "$RUNTIME_LINK" "$legacy_runtime"
  PRIOR_RUNTIME="$legacy_runtime"
  atomic_symlink "$PRIOR_RUNTIME" "$RUNTIME_LINK"
  POINTER_FLIPPED=1
  if [ "$ACCOUNT_CUTOVER_PREPARED" = "1" ]; then
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover set-prior-runtime \
      --runtime "$PRIOR_RUNTIME" >/dev/null \
      || die "could not describe the migrated rollback runtime for account cutover"
  fi
  rm -f "$MIGRATION_MARKER"
}

switch_to_candidate() {
  atomic_symlink "$CANDIDATE_RUNTIME" "$RUNTIME_LINK"
  POINTER_FLIPPED=1
  atomic_symlink "$RUNTIME_LINK/bin/meshia-node" "$BIN_DIR/meshia-node"
  atomic_symlink "$RUNTIME_LINK/bin/meshia-node" "$BIN_DIR/meshia"
  log "activated meshia-node $RELEASE_VERSION ($PACKAGE_DIGEST)"
}

validate_gc_runtime() { # validate_gc_runtime <direct child of runtimes/>
  "$BASE_PYTHON" - "$1" "$RUNTIMES_DIR" <<'PY'
import pathlib
import re
import sys

runtime = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
if root.is_symlink() or not root.is_dir():
    raise SystemExit(1)
if runtime.parent != root or runtime.is_symlink() or not runtime.is_dir():
    raise SystemExit(1)
if runtime.resolve().parent != root.resolve():
    raise SystemExit(1)
marker = runtime / ".meshia-release"
if marker.is_symlink() or not marker.is_file():
    raise SystemExit(1)
fields = {}
for line in marker.read_text(encoding="utf-8").splitlines():
    if "=" not in line:
        raise SystemExit(1)
    key, value = line.split("=", 1)
    if key in fields:
        raise SystemExit(1)
    fields[key] = value
if set(fields) - {"version", "digest", "kind", "macos_node_app_sha256"}:
    raise SystemExit(1)
if "macos_node_app_sha256" in fields and not re.fullmatch(r"[a-f0-9]{64}", fields["macos_node_app_sha256"]):
    raise SystemExit(1)
version = fields.get("version", "")
digest = fields.get("digest", "")
kind = fields.get("kind", "candidate")
if not re.fullmatch(r"[A-Za-z0-9._+\-]+", version):
    raise SystemExit(1)
if not re.fullmatch(r"[a-f0-9]{64}", digest):
    raise SystemExit(1)
expected = f"{version}-{digest}" if kind == "candidate" else f"legacy-{version}-{digest}"
if kind not in {"candidate", "legacy"} or runtime.name != expected:
    raise SystemExit(1)
PY
}

same_runtime() {
  local left="" right=""
  left="$(cd "$1" 2>/dev/null && pwd -P)" || return 1
  right="$(cd "$2" 2>/dev/null && pwd -P)" || return 1
  [ "$left" = "$right" ]
}

record_previous_runtime() {
  local previous_runtime="" candidate_runtime=""
  if same_runtime "$PRIOR_RUNTIME" "$CANDIDATE_RUNTIME"; then
    if [ -L "$PREVIOUS_RUNTIME_LINK" ]; then
      previous_runtime="$(cd "$PREVIOUS_RUNTIME_LINK" 2>/dev/null && pwd -P)" \
        || die "existing rollback runtime selector is dangling: $PREVIOUS_RUNTIME_LINK"
      validate_gc_runtime "$previous_runtime" \
        || die "existing rollback runtime is not a validated direct runtime child: $previous_runtime"
      candidate_runtime="$(cd "$CANDIDATE_RUNTIME" 2>/dev/null && pwd -P)" \
        || die "candidate runtime disappeared before rollback retention"
      [ "$previous_runtime" != "$candidate_runtime" ] \
        || die "existing rollback selector points to the current runtime instead of N-1"
      log "preserved rollback runtime $previous_runtime for identical release reinstall"
    elif [ -e "$PREVIOUS_RUNTIME_LINK" ]; then
      die "rollback runtime selector is not a symlink: $PREVIOUS_RUNTIME_LINK"
    fi
    return 0
  fi
  atomic_symlink "$PRIOR_RUNTIME" "$PREVIOUS_RUNTIME_LINK"
}

garbage_collect_runtimes() {
  local current_runtime="" previous_runtime="" runtime="" runtime_physical=""
  if ! managed_directory_is_safe "$RUNTIMES_DIR"; then
    log "WARNING: refusing runtime cleanup because the runtimes root is redirected or not current-user-owned: $RUNTIMES_DIR"
    return 1
  fi
  current_runtime="$(cd "$RUNTIME_LINK" 2>/dev/null && pwd -P)" || return 1
  validate_gc_runtime "$current_runtime" || return 1

  if [ -L "$PREVIOUS_RUNTIME_LINK" ]; then
    previous_runtime="$(cd "$PREVIOUS_RUNTIME_LINK" 2>/dev/null && pwd -P)" || return 1
    validate_gc_runtime "$previous_runtime" || return 1
  elif [ -e "$PREVIOUS_RUNTIME_LINK" ]; then
    log "WARNING: refusing runtime cleanup because $PREVIOUS_RUNTIME_LINK is not a symlink"
    return 1
  fi

  for runtime in "$RUNTIMES_DIR"/*; do
    [ -e "$runtime" ] || [ -L "$runtime" ] || continue
    if ! validate_gc_runtime "$runtime"; then
      log "WARNING: preserving unrecognized runtime entry $runtime"
      continue
    fi
    runtime_physical="$(cd "$runtime" 2>/dev/null && pwd -P)" || return 1
    [ "$runtime_physical" != "$current_runtime" ] || continue
    [ -z "$previous_runtime" ] || [ "$runtime_physical" != "$previous_runtime" ] || continue
    [ -z "$PRIOR_RUNTIME" ] || [ "$runtime_physical" != "$PRIOR_RUNTIME" ] || continue
    if rm -rf "$runtime"; then
      log "removed superseded runtime $runtime"
    else
      log "WARNING: could not remove superseded runtime $runtime"
      return 1
    fi
  done
}

# ------------------------------------------------------------- unmount first
# `service stop` ends in launchd/systemd SIGKILL after its grace period. A
# runner killed while the kernel still has its NFS/SMB mount attached leaves
# that mount wedged until the machine reboots. So before any stop, the verified
# candidate CLI asks the running node to detach through the node's own bounded
# teardown, waits for the OS mount registry to agree, and refuses otherwise.
# Every probe below is bounded and abandoned on expiry: a probe that hangs is
# "not released", never "released".
# The idle detach bound. Past it the node keeps waiting only while its runner
# is still draining a consumed stop request (up to the CLI's 90 s drain bound:
# a busy engine reaches its stop check after 29-35 s, then the mount worker's
# 20 s unmount budget and 25 s supervisor grace). The command bound must
# exceed timeout + drain, or the release JSON goes absent and the installer
# cannot tell whether the runner was asked to stop.
MOUNT_RELEASE_TIMEOUT_SECONDS=20
MOUNT_RELEASE_COMMAND_BOUND_SECONDS=130
MOUNT_PROBE_TIMEOUT_SECONDS=5
RELEASED_MOUNT_POINT=""
# Optional function name run before a refusal exits, so a caller that armed
# durable state (an account cutover) can disarm it without a service restart.
ON_MOUNT_RELEASE_REFUSED=""

refuse_mount_release() { # refuse_mount_release <message>
  [ -z "$ON_MOUNT_RELEASE_REFUSED" ] || "$ON_MOUNT_RELEASE_REFUSED"
  die "$@"
}

run_bounded() { # run_bounded <seconds> <stdout-file> <command> [args...]
  # Never `wait` on a child that may be sitting in an uninterruptible kernel
  # wait on a dead mount: poll, kill on expiry, and abandon it (status 124).
  local seconds="$1" output="$2" pid="" ticks=0 limit=0
  shift 2
  limit=$((seconds * 10))
  "$@" >"$output" 2>"$output.err" &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$ticks" -ge "$limit" ]; then
      kill -9 "$pid" 2>/dev/null || true
      return 124
    fi
    sleep 0.1
    ticks=$((ticks + 1))
  done
  wait "$pid"
}

install_retry_command() {
  if [ "$REPAIR_EXISTING" = "1" ]; then
    installer_download_command -- --re-pair --prompt-pair
  else
    installer_download_command
  fi
}

default_mount_point() {
  if [ "$MESHIA_HOME" = "$HOME/.meshia" ]; then
    printf '%s' "$HOME/Meshia"
  else
    printf '%s' "$MESHIA_HOME/mounts/Meshia"
  fi
}

mount_probe_says_released() {
  # Independent bounded read-back of the receipt + OS mount registry. Exit 0
  # only on a proven release; a hung, failed, or "attached/unknown" probe is 1.
  local probe_output="$WORK_DIR/mount-probe.json"
  run_bounded "$MOUNT_PROBE_TIMEOUT_SECONDS" "$probe_output" \
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" --json mount --probe || return 1
  "$BASE_PYTHON" - "$probe_output" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        mount = json.load(source)["mount"]
    mounted = mount["mounted"]
    state = mount["state"]
except (OSError, KeyError, TypeError, ValueError):
    raise SystemExit(1)
released = mounted is False and state in (
    "stopped", "idle", "disabled", "detached", "runtime_missing", "platform_not_enabled"
)
raise SystemExit(0 if released else 1)
PY
}

RELEASE_NODE_VERDICT="the current Meshia node was left running"

restore_prior_service_after_refused_release() { # <release-json> <phase>
  # A refused release must leave the previously running node running. Once
  # `mount --release` has asked the runner to stop, that request is consumed
  # within 100 ms and the runner exits after its current poll and mount
  # teardown (29-35 s on a busy engine, past the 20 s release bound). Refusing
  # at that point and exiting with "the node was left running" stranded the
  # owner's node on 2026-09-03: service stopped, ~/Meshia empty, nothing to
  # restart it. The CLI restores the service itself when it can; this is the
  # installer's own verification and fallback with the PRIOR runtime's CLI.
  local release_output="$1" phase="$2" verdict=""
  verdict="$("$BASE_PYTHON" - "$release_output" "$phase" <<'PY' 2>/dev/null || echo "unknown"
import json
import sys

phase = sys.argv[2]
try:
    with open(sys.argv[1], encoding="utf-8") as source:
        document = json.load(source)
except (OSError, ValueError):
    print("unknown")
    raise SystemExit(0)
requested = bool(document.get("requested"))
if phase == "probe":
    # A reported release means the runner was asked to stop.
    requested = requested or bool(document.get("released"))
if not requested:
    print("running")
elif document.get("restored") is True:
    print("restored")
else:
    print("stopped")
PY
)"
  case "$verdict" in
    running)
      RELEASE_NODE_VERDICT="the current Meshia node was left running"
      return 0 ;;
    restored)
      RELEASE_NODE_VERDICT="the current Meshia node was asked to stop and has been restarted"
      return 0 ;;
  esac
  step "Restarting the current Meshia node after the refused mount release"
  if [ -n "$PRIOR_CLI" ] && "$PRIOR_CLI" --home "$MESHIA_HOME" service restart --wait \
      --timeout-seconds 45 --expected-version "$PRIOR_VERSION" >/dev/null 2>&1; then
    RELEASE_NODE_VERDICT="the current Meshia node was asked to stop and has been restarted"
    return 0
  fi
  log "CRITICAL: the current Meshia node was asked to stop and could not be restarted; run: meshia-node service restart"
  RELEASE_NODE_VERDICT="the current Meshia node was asked to stop and could NOT be restarted (run: meshia-node service restart)"
  return 0
}

release_native_mount_before_stop() {
  local release_output="$WORK_DIR/mount-release.json" retry_command="" status=0
  local mount_point=""
  retry_command="$(install_retry_command)"
  step "Releasing the native Meshia mount before touching the current service"
  if run_bounded "$MOUNT_RELEASE_COMMAND_BOUND_SECONDS" "$release_output" \
      "$CANDIDATE_CLI" --home "$MESHIA_HOME" --json mount --release \
      --timeout-seconds "$MOUNT_RELEASE_TIMEOUT_SECONDS" \
      --retry-command "$retry_command"; then
    status=0
  else
    status=$?
  fi
  RELEASED_MOUNT_POINT="$("$BASE_PYTHON" - "$release_output" <<'PY' 2>/dev/null || true
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as source:
        print(json.load(source).get("mount_point") or "")
except (OSError, ValueError, AttributeError):
    pass
PY
)"
  mount_point="${RELEASED_MOUNT_POINT:-$(default_mount_point)}"
  if [ "$status" = "124" ]; then
    # The release command was abandoned mid-flight: it may already have asked
    # the runner to stop. Restore first, then say exactly what happened.
    restore_prior_service_after_refused_release "$release_output" "unknown"
    refuse_mount_release "the native Meshia mount at $mount_point did not release within ${MOUNT_RELEASE_COMMAND_BOUND_SECONDS}s; $RELEASE_NODE_VERDICT and no files were replaced. Close what holds it open, then retry with: $retry_command"
  fi
  if [ "$status" != "0" ]; then
    # Surface the CLI's exact refusal: mount point, likely holders, retry command.
    "$BASE_PYTHON" - "$release_output" "$release_output.err" <<'PY' >&2 2>/dev/null || true
import json
import sys

for path in sys.argv[1:]:
    try:
        with open(path, encoding="utf-8") as source:
            raw = source.read()
        message = json.loads(raw)["error"]
    except (OSError, KeyError, TypeError, ValueError):
        continue
    print(message)
    raise SystemExit(0)
try:
    with open(sys.argv[2], encoding="utf-8") as source:
        print(source.read(), end="")
except OSError:
    pass
PY
    restore_prior_service_after_refused_release "$release_output" "held"
    refuse_mount_release "the native Meshia mount at $mount_point was not released; $RELEASE_NODE_VERDICT and no files were replaced. Close what holds it open, then retry with: $retry_command"
  fi
  if ! mount_probe_says_released; then
    # The node reported a release (so its runner was asked to stop) but the
    # independent probe disagrees: the runner is exiting either way.
    restore_prior_service_after_refused_release "$release_output" "probe"
    refuse_mount_release "could not confirm that the native Meshia mount at $mount_point is released (the bounded ${MOUNT_PROBE_TIMEOUT_SECONDS}s probe did not answer or still reports it attached); $RELEASE_NODE_VERDICT and no files were replaced. Close what holds it open, then retry with: $retry_command"
  fi
  log "native mount released; the current service can stop without stranding a kernel mount"
}

upgrade_background_service() {
  [ -n "$PRIOR_RUNTIME" ] || die "upgrade has no prior runtime to restore"

  if [ "$OS" = "Darwin" ]; then
    REFRESH_FINDER_AFTER_MOUNT=1
  fi

  if [ "$PRIOR_SERVICE_SUPPORTED" != "1" ]; then
    local legacy_definition=""
    case "$OS" in
      Darwin) legacy_definition="$HOME/Library/LaunchAgents/io.meshia.node.plist" ;;
      Linux) legacy_definition="$HOME/.config/systemd/user/meshia-node.service" ;;
    esac
    [ ! -e "$legacy_definition" ] && [ ! -L "$legacy_definition" ] \
      || die "the legacy Meshia service definition cannot be managed by the installed runtime; stop and remove it explicitly before retrying"

    TRANSACTION_ACTIVE=1
    step "Activating the verified Meshia runtime from a service-free legacy install"
    adopt_existing_workspace_if_requested
    migrate_legacy_runtime
    switch_to_candidate
    configure_native_mount_if_explicit

    # The prior runtime has no service controller and the exact current-user
    # definition is absent. Mark this before install so rollback removes a
    # partially written candidate definition while restoring only the prior
    # runtime pointer (there is no old service to invent or restart).
    PRIOR_SERVICE_UNINSTALLED=1
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" service install >/dev/null
    CANDIDATE_SERVICE_INSTALLED=1
    if [ "$PARKED_ENROLLMENT" = "1" ]; then
      "$CANDIDATE_CLI" --home "$MESHIA_HOME" service start >/dev/null
    else
      "$CANDIDATE_CLI" --home "$MESHIA_HOME" service restart --wait \
        --timeout-seconds 45 --expected-version "$RELEASE_VERSION" >/dev/null
    fi

    record_previous_runtime
    CANDIDATE_COMMITTED=1
    PRIOR_SERVICE_UNINSTALLED=0
    TRANSACTION_ACTIVE=0
    garbage_collect_runtimes || log "WARNING: runtime cleanup was skipped; current and rollback runtimes were retained"
    if [ "$PARKED_ENROLLMENT" = "1" ]; then
      report_service_parked
    else
      report_service_ready
    fi
    return 0
  fi

  release_native_mount_before_stop
  TRANSACTION_ACTIVE=1
  step "Stopping the current Meshia service before activation"
  if ! "$PRIOR_CLI" --home "$MESHIA_HOME" service stop >/dev/null; then
    TRANSACTION_ACTIVE=0
    die "the current service could not be stopped; runtime pointer was not changed"
  fi
  step "Removing the prior service definition before activation"
  "$PRIOR_CLI" --home "$MESHIA_HOME" service uninstall >/dev/null \
    || die "the current service definition could not be removed; restoring the prior service"
  PRIOR_SERVICE_UNINSTALLED=1
  adopt_existing_workspace_if_requested
  migrate_legacy_runtime
  switch_to_candidate
  configure_native_mount_if_explicit

  step "Installing and verifying the meshia-node $RELEASE_VERSION service"
  "$CANDIDATE_CLI" --home "$MESHIA_HOME" service install >/dev/null
  CANDIDATE_SERVICE_INSTALLED=1
  if [ "$PARKED_ENROLLMENT" = "1" ]; then
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" service start >/dev/null
  else
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" service restart --wait \
      --timeout-seconds 45 --expected-version "$RELEASE_VERSION" >/dev/null
  fi

  record_previous_runtime
  CANDIDATE_COMMITTED=1
  TRANSACTION_ACTIVE=0
  garbage_collect_runtimes || log "WARNING: runtime cleanup was skipped; current and rollback runtimes were retained"
  if [ "$PARKED_ENROLLMENT" = "1" ]; then
    report_service_parked
  else
    report_service_ready
  fi
}

adopt_existing_workspace_if_requested() {
  [ "$ADOPT_EXISTING_WORKSPACE" = "1" ] || return 0
  step "Claiming the explicitly adopted existing workspace"
  set -- "$CANDIDATE_CLI" --home "$MESHIA_HOME" connect --enroll-only \
    --adopt-existing-workspace
  [ -n "$WORKSPACE" ] && set -- "$@" --workspace "$WORKSPACE"
  "$@" >/dev/null || die "the existing workspace could not be claimed safely"
}

configure_native_mount_if_explicit() {
  local mount_flag=""
  case "$MOUNT_RUNTIME_MODE" in
    off) mount_flag="--no-native-mount" ;;
    install) mount_flag="--native-mount" ;;
    *) return 0 ;;
  esac
  "$CANDIDATE_CLI" --home "$MESHIA_HOME" connect --enroll-only "$mount_flag" >/dev/null \
    || die "the native mount preference could not be persisted safely"
}

disarm_prepared_account_cutover() {
  "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover rollback >/dev/null 2>&1 || true
  ACCOUNT_CUTOVER_PREPARED=0
}

reenroll_existing_service() {
  [ -n "$PRIOR_RUNTIME" ] || die "re-pair has no prior runtime to restore"
  [ "$PRIOR_SERVICE_SUPPORTED" = "1" ] \
    || die "the existing Meshia service cannot be replaced transactionally; run meshia-node service uninstall and retry"
  [ "$CONNECT_MODE" = "service" ] \
    || die "account replacement requires the background service so mount readiness can be verified before commit"

  if [ "$OS" = "Darwin" ]; then
    REFRESH_FINDER_AFTER_MOUNT=1
  fi

  step "Preparing the selected Meshia account while the current mount stays available"
  local access_value="${ACCESS:-files}" tier_value="${TIER:-compute}"
  [ -n "$ACCESS" ] && tier_value="compute"
  set -- "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover prepare \
    --pair-stdin --api-url "${API_URL:-https://meshia.io}" --tier "$tier_value" \
    --access "$access_value"
  [ "$MOUNT_RUNTIME_MODE" = "off" ] && set -- "$@" --no-native-mount
  [ "$MOUNT_RUNTIME_MODE" != "off" ] && set -- "$@" --native-mount
  [ -n "$WORKSPACE" ] && set -- "$@" --workspace "$WORKSPACE"
  [ "$ADOPT_EXISTING_WORKSPACE" = "1" ] && set -- "$@" --adopt-existing-workspace
  if ! connect_with_pair_stdin "$@" >/dev/null; then
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover abort >/dev/null 2>&1 || true
    die "replacement account preparation failed; the current Meshia service and mount were left unchanged"
  fi
  set --
  ACCOUNT_CUTOVER_PREPARED=1

  if ! "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover activate >/dev/null; then
    "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover rollback >/dev/null 2>&1 || true
    ACCOUNT_CUTOVER_PREPARED=0
    die "replacement account activation could not be armed; the current service and mount were left unchanged"
  fi
  # A refused release must disarm the prepared cutover itself: the rollback
  # trap would otherwise restart the prior service, which is the exact stop
  # under an attached mount this gate exists to prevent.
  ON_MOUNT_RELEASE_REFUSED=disarm_prepared_account_cutover
  release_native_mount_before_stop
  ON_MOUNT_RELEASE_REFUSED=""
  TRANSACTION_ACTIVE=1
  step "Stopping the current Meshia service after the replacement account is ready"
  if ! "$PRIOR_CLI" --home "$MESHIA_HOME" service stop >/dev/null; then
    die "the current service could not be stopped; restoring the prepared account cutover"
  fi
  step "Removing the prior service definition before re-pairing"
  "$PRIOR_CLI" --home "$MESHIA_HOME" service uninstall >/dev/null \
    || die "the current service definition could not be removed; restoring the prior service"
  PRIOR_SERVICE_UNINSTALLED=1

  migrate_legacy_runtime
  switch_to_candidate

  step "Publishing the prepared account to the stopped Meshia service"
  "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover publish >/dev/null \
    || die "the prepared account could not be published safely"
  PARKED_ENROLLMENT=0

  step "Installing and verifying the re-paired Meshia service"
  "$CANDIDATE_CLI" --home "$MESHIA_HOME" service install >/dev/null
  CANDIDATE_SERVICE_INSTALLED=1
  "$CANDIDATE_CLI" --home "$MESHIA_HOME" service restart --wait \
    --timeout-seconds 45 --expected-version "$RELEASE_VERSION" >/dev/null
  wait_for_account_cutover_ready \
    || die "the replacement Meshia account did not mount and converge in time"

  record_previous_runtime
  "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover commit >/dev/null \
    || die "the ready replacement account could not be committed"
  # Once the durable receipt says committed, disarm rollback before clearing
  # its local discovery flag. A trapped signal on any following line must keep
  # the ready candidate service/mount rather than uninstalling it.
  CANDIDATE_COMMITTED=1
  TRANSACTION_ACTIVE=0
  ACCOUNT_CUTOVER_PREPARED=0
  PRIOR_SERVICE_UNINSTALLED=0
  "$CANDIDATE_CLI" --home "$MESHIA_HOME" account-cutover finalize >/dev/null \
    || die "the committed replacement account could not retire rollback material"
  garbage_collect_runtimes \
    || log "WARNING: runtime cleanup was skipped; current and rollback runtimes were retained"
  report_service_ready
}

# ---------------------------------------------------------------- activation
if [ "$MOUNT_RUNTIME_MODE" = "install" ] \
    || { [ "$CONNECT_MODE" != "none" ] \
         && { [ "$HAD_ENROLLMENT" = "1" ] || [ -n "$PAIR_GRANT" ] || [ "$PROMPT_PAIR" = "1" ]; }; }; then
  ensure_mount_runtime
fi

if [ "$HAD_ENROLLMENT" = "1" ]; then
  if [ "$PROMPT_PAIR" = "1" ] && [ "$REPAIR_EXISTING" != "1" ] \
      && [ -z "$PAIR_GRANT" ] && [ "$CONNECT_MODE" != "none" ]; then
    # The public one-liner is deliberately rerunnable. A prompt request enrolls
    # a fresh machine, but it must never turn a routine update into an account
    # replacement. Account cutover remains explicit through --re-pair.
    log "existing Meshia enrollment found; retaining its identity without asking for another pairing code"
    PROMPT_PAIR=0
  fi
  if [ "$REPAIR_EXISTING" = "1" ] && [ "$PROMPT_PAIR" = "1" ] \
      && [ -z "$PAIR_GRANT" ] \
      && [ "$CONNECT_MODE" != "none" ]; then
    # A workspace-generated attach command explicitly selects a workspace.
    # Prompt only after the OS mount runtime is ready, immediately before the
    # bounded re-enrollment transaction consumes the single-use grant.
    prompt_for_pair_grant
  fi
  if [ "$REPAIR_EXISTING" = "1" ] && [ -n "$PAIR_GRANT" ] \
      && [ "$CONNECT_MODE" != "none" ]; then
    reenroll_existing_service
    exit 0
  fi

  # The grant is deliberately gone before any stop/install/restart child. An
  # ordinary update uses only the identity already persisted under this home.
  PAIR_GRANT=""
  unset PAIR_GRANT

  if [ "$CONNECT_MODE" = "none" ]; then
    log "verified meshia-node $RELEASE_VERSION at $CANDIDATE_RUNTIME"
    log "--no-connect left the enrolled service and current runtime unchanged"
    exit 0
  fi

  if [ "$CONNECT_MODE" = "service" ]; then
    if exact_running_release_ready; then
      CANDIDATE_COMMITTED=1
      log "meshia-node $RELEASE_VERSION is already verified and running; the service and native mount were left uninterrupted"
      report_service_ready
      exit 0
    fi
    upgrade_background_service
    exit 0
  fi

  # Explicit foreground mode replaces the user service with this terminal. The
  # verified candidate is committed before exec; service teardown is still
  # rolled back if it fails before the foreground process takes ownership.
  [ "$PRIOR_SERVICE_SUPPORTED" = "1" ] \
    || die "current runtime cannot be stopped transactionally; stop it explicitly before retrying"
  release_native_mount_before_stop
  TRANSACTION_ACTIVE=1
  step "Stopping the current Meshia service before foreground activation"
  if ! "$PRIOR_CLI" --home "$MESHIA_HOME" service stop >/dev/null; then
    TRANSACTION_ACTIVE=0
    die "the current service could not be stopped; runtime pointer was not changed"
  fi
  step "Removing the prior service definition before foreground activation"
  "$PRIOR_CLI" --home "$MESHIA_HOME" service uninstall >/dev/null \
    || die "the current service definition could not be removed; restoring the prior service"
  PRIOR_SERVICE_UNINSTALLED=1
  adopt_existing_workspace_if_requested
  migrate_legacy_runtime
  switch_to_candidate
  configure_native_mount_if_explicit
  record_previous_runtime
  CANDIDATE_COMMITTED=1
  TRANSACTION_ACTIVE=0
  garbage_collect_runtimes || log "WARNING: runtime cleanup was skipped; current and rollback runtimes were retained"
  cleanup_files
  trap - EXIT HUP INT TERM
  exec "$CANDIDATE_CLI" --home "$MESHIA_HOME" connect --foreground
fi

# With no enrollment there is no resident service to stop. There may still be
# a prior install-only runtime, including the legacy real `runtime` directory.
# Preserve that exact runtime as N-1 and collect only validated older children.
# Mark the candidate retained before the first pointer operation so a later
# link failure can never make cleanup delete the selected runtime.
CANDIDATE_COMMITTED=1
if [ -n "$PRIOR_RUNTIME" ]; then
  if ! same_runtime "$PRIOR_RUNTIME" "$CANDIDATE_RUNTIME"; then
    migrate_legacy_runtime
    switch_to_candidate
  else
    # Reinstalling the identical immutable release must not replace the true
    # N-1 pointer with another link to the current runtime.
    switch_to_candidate
  fi
  record_previous_runtime
  garbage_collect_runtimes \
    || log "WARNING: runtime cleanup was skipped; current and rollback runtimes were retained"
else
  switch_to_candidate
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    step "Add $BIN_DIR to your PATH"
    log "echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.profile && export PATH=\"$BIN_DIR:\$PATH\""
    ;;
esac

step "Installed Meshia Node $RELEASE_VERSION"
if { [ -z "$PAIR_GRANT" ] && [ "$PROMPT_PAIR" != "1" ]; } \
    || [ "$CONNECT_MODE" = "none" ]; then
  ui_phase 5 5 "Finish the installation"
  ui_complete "$RELEASE_VERSION"
fi

# ------------------------------------------------------------------------ connect
if [ "$PROMPT_PAIR" = "1" ] && [ -z "$PAIR_GRANT" ] && [ "$CONNECT_MODE" != "none" ]; then
  prompt_for_pair_grant
fi

if [ -n "$PAIR_GRANT" ] && [ "$CONNECT_MODE" != "none" ]; then
  [ -n "$API_URL" ] || API_URL="https://meshia.io"
  ACCESS_VAL="${ACCESS:-files}"
  TIER_VAL="${TIER:-compute}"
  [ -n "$ACCESS" ] && TIER_VAL="compute"
  CLI="$CANDIDATE_CLI"

  if [ "$CONNECT_MODE" = "foreground" ]; then
    step "Connecting this machine to $API_URL in the foreground"
    set -- "$CLI" --home "$MESHIA_HOME" connect --pair-stdin --api-url "$API_URL" \
      --tier "$TIER_VAL" --access "$ACCESS_VAL" --foreground
    [ "$MOUNT_RUNTIME_MODE" = "off" ] && set -- "$@" --no-native-mount
    [ "$MOUNT_RUNTIME_MODE" = "install" ] && set -- "$@" --native-mount
    [ -n "$WORKSPACE" ] && set -- "$@" --workspace "$WORKSPACE"
    [ "$ADOPT_EXISTING_WORKSPACE" = "1" ] && set -- "$@" --adopt-existing-workspace
    ui_phase 5 5 "Launch the connection"
    ui_complete "$RELEASE_VERSION"
    cleanup_files
    trap - EXIT HUP INT TERM
    if connect_with_pair_stdin "$@"; then
      exit 0
    else
      CONNECT_STATUS=$?
      exit "$CONNECT_STATUS"
    fi
  fi

  # The one-time grant exists only in this enrollment process.  Service
  # definitions are rendered later from the persisted identity and contain
  # only an absolute executable, an absolute --home, and `service run`.
  step "Enrolling this machine with $API_URL"
  set -- "$CLI" --home "$MESHIA_HOME" connect --pair-stdin --api-url "$API_URL" \
    --tier "$TIER_VAL" --access "$ACCESS_VAL" --enroll-only
  [ "$MOUNT_RUNTIME_MODE" = "off" ] && set -- "$@" --no-native-mount
  [ "$MOUNT_RUNTIME_MODE" = "install" ] && set -- "$@" --native-mount
  [ -n "$WORKSPACE" ] && set -- "$@" --workspace "$WORKSPACE"
  [ "$ADOPT_EXISTING_WORKSPACE" = "1" ] && set -- "$@" --adopt-existing-workspace
  if ! connect_with_pair_stdin "$@" >/dev/null; then
    die "pairing enrollment failed"
  fi

  # The helper cleared the single-use grant before any service lifecycle
  # child, including when PAIR_CODE arrived as an exported variable.
  set --

  step "Installing and verifying the Meshia background service"
  if "$CLI" --home "$MESHIA_HOME" service install >/dev/null \
      && "$CLI" --home "$MESHIA_HOME" service restart --wait \
        --timeout-seconds 45 --expected-version "$RELEASE_VERSION" >/dev/null; then
    if [ -n "$PRIOR_RUNTIME" ]; then
      record_previous_runtime
    elif [ -L "$PREVIOUS_RUNTIME_LINK" ]; then
      rm -f "$PREVIOUS_RUNTIME_LINK"
    fi
    garbage_collect_runtimes || log "WARNING: runtime cleanup was skipped; the ready runtime was retained"
    report_service_ready
    exit 0
  fi

  # A user service manager can be unavailable in containers, SSH-only Linux
  # sessions, or a restricted desktop.  Enrollment is already durable, so the
  # safe fallback reattaches without ever replaying the pairing code.
  if [ "$STAGE_NODE_APP" = 1 ]; then
    die "the native Meshia background service did not become ready; enrollment was retained. Run the installer in this account's macOS desktop session to retry."
  fi
  if [ "$OS" = "Linux" ]; then
    "$CLI" --home "$MESHIA_HOME" service uninstall >/dev/null \
      || die "Linux service startup failed and its registration could not be removed"
    die "the Linux background service could not start; enrollment is retained. Rerun the installer to repair the service, or choose --foreground explicitly"
  fi
  log "WARNING: the per-user service could not start; continuing in this terminal"
  "$CLI" --home "$MESHIA_HOME" service uninstall >/dev/null \
    || die "service startup failed and its persistent registration could not be removed"
  cleanup_files
  trap - EXIT HUP INT TERM
  exec "$CLI" --home "$MESHIA_HOME" connect --foreground
fi

cat >&2 <<EOF

Next steps:
  $BIN_DIR/meshia login
  $BIN_DIR/meshia projects
  $BIN_DIR/meshia mcp config
  $BIN_DIR/meshia host install codex
  $BIN_DIR/meshia doctor
  $BIN_DIR/meshia help
  $BIN_DIR/meshia mount <workspace-id>
EOF
