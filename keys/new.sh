#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"
MINTOR="${SCRIPT_DIR}/../.github/scripts/kuzzle-key.sh"

if [[ ! -x "${MINTOR}" ]]; then
  echo "error: cannot find executable mintor at ${MINTOR}" >&2
  exit 1
fi

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <index> <collection> <label> [expiresIn]" >&2
  exit 1
fi

IDX="$1"; COL="$2"; LABEL="$3"; EXPIRES_IN="${4:-}"

load_key() {
  if [[ -n "${KUZZLE_ADMIN_KEY:-}" ]]; then
    return
  fi
  if [[ -f "${SCRIPT_DIR}/../keys/.env" ]]; then
    # expand variables from a protected file, never print secrets to terminal
    set -a
    source "${SCRIPT_DIR}/../keys/.env" >/dev/null 2>&1
    set +a
  fi
  if [[ -z "${KUZZLE_ADMIN_KEY:-}" ]]; then
    read -s -r -p "Kuzzle admin key: " KUZZLE_ADMIN_KEY
    echo
  fi
}

load_key
export KUZZLE_ADMIN_KEY KUZZLE_HOST KUZZLE_PORT KUZZLE_SCHEME IDX COL LABEL EXPIRES_IN

OUTDIR="$(cd "${SCRIPT_DIR}/.." && pwd)/keys"
mkdir -p "${OUTDIR}"

RESULT="$("${MINTOR}" )" || exit $?

printf '%s\n' "$RESULT" > "${OUTDIR}/last.json"

printf 'export KUZZLE_ADMIN_KEY="%s"\n' \
  "$KUZZLE_ADMIN_KEY" > "${OUTDIR}/last.env"
printf 'export OUTPUT_INDEX="%s"\n' "$IDX" >> "${OUTDIR}/last.env"
printf 'export OUTPUT_COLLECTION="%s"\n' "$COL" >> "${OUTDIR}/last.env"
printf 'export OUTPUT_LABEL="%s"\n' "$LABEL" >> "${OUTDIR}/last.env"
printf 'export OUTPUT_TOKEN="%s"\n' \
  "$(printf '%s' "$RESULT" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')" \
  >> "${OUTDIR}/last.env"

K=$(printf '%s' "$RESULT" | sed -n 's/.*"keyId":"\([^"]*\)".*/\1/p')
echo ""
echo "new key: $LABEL"
echo "  key id : $K"
echo "  expires: ${EXPIRES_IN:-never}"
echo "  index  : $IDX / $COL"
echo "  saved  : ${OUTDIR}/last.json"
echo ""
echo "security note: last.env contains the token. protect it like a password."
