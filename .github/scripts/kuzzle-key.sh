#!/usr/bin/env bash
# kuzzle-key.sh -- CI-safe Kuzzle API key minting for GitHub Actions.
#
# Non-interactive. No prompts. Fails closed rather than minting a key that
# would be silently unscoped.
#
# WHY THIS EXISTS
#   Kuzzle 2.55.0 has no per-key index restriction. The ApiKey model
#   (lib/model/storage/apiKey.js) carries only `token` and `userId` -- there is
#   no `restrictedTo` field. Sending one returns HTTP 200 and is then silently
#   discarded; the key keeps full access to every index.
#
#   `restrictedTo` exists, but only on profiles/policies. A key is scoped by
#   scoping its owner:
#     1. role     granting document.* with NO index restriction
#     2. profile  whose POLICY carries restrictedTo for the target index
#     3. user     holding only that profile
#     4. creds    via POST /credentials/local/<kuid>/_create  (NOT _update)
#     5. key      minted FOR that user: POST /users/<kuid>/api-keys/_create
#
# THREE TRAPS, all hit and verified on this stack
#
#   A) Putting "indexes"/"collections" on the ROLE does nothing. The profile
#      optimizer builds optimizedPolicies from each policy's `restrictedTo`
#      only (lib/core/security/profileRepository.ts). With nothing set,
#      Role.checkRestrictions() hits
#        if (!restrictedTo || restrictedTo.size === 0) return true;
#      and allows everything -- no error.
#
#   B) DO NOT gate on `optimizedPolicies`. On 2.55.0 a correctly restricted
#      profile still shows `{"restrictedTo":{}}` there, yet it genuinely denies
#      access to other indexes. That field is a cosmetic artifact of the
#      optimizer. Enforcement reads the profile's `policies`, which retains the
#      full restrictedTo. Gate on `policies`.
#
#   B2) The role's own `indexes`/`collections` are IGNORED for scoping. A role
#      of just {"document":{"actions":{"*":true}}} plus a policy restrictedTo
#      scopes correctly (verified). Conversely a role WITH indexes but a policy
#      WITHOUT restrictedTo grants full access (verified). The policy is the
#      only thing that matters.
#
#   C) Minting via a login as the scoped user fails with 403 auth:createApiKey,
#      because createApiKey is not index-scoped. Granting it to that account
#      just to unblock would let it mint UNRESTRICTED keys -- escalation.
#      => Mint as the admin, FOR the user.
#
# USAGE (env driven):
#   KUZZLE_ADMIN_KEY  (required) admin API key
#   KUZZLE_HOST       (default 127.0.0.1)
#   KUZZLE_PORT       (default 443)
#   KUZZLE_SCHEME     (default https on 443, else http)
#   IDX COL LABEL     (required) index, collection, short name
#   EXPIRES_IN        (optional) e.g. 12h, 30d. Omit for non-expiring.
#
# Emits one JSON object on stdout. Diagnostics to stderr.

set -euo pipefail

: "${KUZZLE_ADMIN_KEY:?KUZZLE_ADMIN_KEY is required}"
: "${IDX:?IDX is required}"
: "${COL:?COL is required}"
: "${LABEL:?LABEL is required}"

HOST="${KUZZLE_HOST:-127.0.0.1}"
PORT="${KUZZLE_PORT:-443}"
if [ -z "${KUZZLE_SCHEME:-}" ]; then
  if [ "$PORT" = "443" ]; then KUZZLE_SCHEME="https"; else KUZZLE_SCHEME="http"; fi
fi
BASE="${KUZZLE_SCHEME}://${HOST}:${PORT}"

esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

api() { # $1 method, $2 path, $3 body
  # Body goes through a temp file and --data-binary @file. Passing JSON as a
  # shell argument proved unreliable here: an identical body succeeded when
  # typed directly but failed with network.http.body_parse_failed when passed
  # through the function. A file removes all quoting/escaping ambiguity and is
  # the safer pattern for CI anyway.
  local tmp
  tmp="$(mktemp)"
  printf '%s' "$3" > "$tmp"
  curl -sS -X "$1" "${BASE}$2" \
    -H "Authorization: Bearer ${KUZZLE_ADMIN_KEY}" \
    -H 'Content-Type: application/json' \
    --data-binary "@${tmp}" 2>/dev/null || true
  rm -f "$tmp"
}

get() { # $1 path  (no body)
  curl -sS -X GET "${BASE}$1" -H "Authorization: Bearer ${KUZZLE_ADMIN_KEY}" 2>/dev/null || true
}

# Unique suffix so we never collide with an existing (possibly corrupted)
# profile. Trap B means we must never reuse a profile name.
SFX="$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
ROLE="scoped_${LABEL}"
PROFILE="scoped_${LABEL}_${SFX}"

echo "::group::configure (suffix ${SFX})" >&2

# --- role: actions only, no index restriction (trap A) -----------------------
ROLE_BODY='{"controllers":{"document":{"actions":{"*":true}}}}'
api POST "/roles/${ROLE}/_create" "$ROLE_BODY" >/dev/null
echo "role ${ROLE}" >&2

# --- profile: restriction lives on the POLICY ---------------------------------
BODY_PROFILE=""
printf -v BODY_PROFILE \
  '{"policies":[{"roleId":"%s","restrictedTo":[{"index":"%s","collections":["%s"]}]}]}' \
  "$(esc "$ROLE")" "$(esc "$IDX")" "$(esc "$COL")"

R2="$(api POST "/profiles/${PROFILE}/_create" "$BODY_PROFILE")"

# Fail closed on ANY creation error.
case "$R2" in
  *'"error":null'*) : ;;
  *) echo "error: profile creation failed: $R2" >&2; exit 1 ;;
esac

# --- verify the restriction was actually STORED ---------------------------
# Check the profile's `policies`, NOT `optimizedPolicies`.
#
# On 2.55.0 optimizedPolicies stores "restrictedTo":{} even for a correctly
# restricted profile. Verified: such a profile still DENIES reads of other
# indices. It is a cosmetic artifact of the optimizer, so gating on it causes
# false alarms and blocks working configs.
#
# `policies` is what the rights check actually reads.
VERIFY="$(get "/profiles/${PROFILE}")"
STORED="$(printf '%s' "$VERIFY" | sed -n 's/.*"policies":\[\([^]]*\)\].*/\1/p')"

if printf '%s' "$STORED" | grep -q '"restrictedTo"' \
   && printf '%s' "$STORED" | grep -q "\"index\":\"${IDX}\""; then
  echo "restriction verified in policies: ${IDX}/${COL}" >&2
else
  echo "error: profile policies lost the restriction." >&2
  echo "       expected index=${IDX} in policies; got: ${STORED:-<empty>}" >&2
  echo "       Refusing to mint an unscoped key." >&2
  exit 1
fi
echo "profile ${PROFILE}" >&2

# --- service user -----------------------------------------------------------
# Password: hex only, no shell/JSON metacharacters.
SVC_PASS="Svc$(od -An -N18 -tx1 /dev/urandom | tr -d ' \n')!"
BODY_USER=""
printf -v BODY_USER '{"content":{"password":"%s","profileIds":["%s"]}}' "$(esc "$SVC_PASS")" "$(esc "$PROFILE")"
R3="$(api POST "/users/_create" "$BODY_USER")"

KUID="$(printf '%s' "$R3" | sed -n 's/.*"result":{"_id":"\([^"]*\)".*/\1/p')"
[ -n "$KUID" ] || { echo "error: user creation failed: $R3" >&2; exit 1; }
echo "user ${KUID}" >&2

# --- credentials: POST /credentials/local/:_id/_create ---------------------
# POST, not PUT: lib/api/httpRoutes.js:843 declares
#   { verb: "post", path: "/credentials/:strategy/:_id/_create", ... }
# and there is no PUT variant. PUT returns 404 network.http.url_not_found.
#
# MUST be _create for a brand-new user. The _update route hits a real bug in
# kuzzle-plugin-auth-passport-local's _validateUpdate, which calls
# getCredentialsFromUserId() without a null check and throws
# "Cannot read properties of null (reading 'validateCredentials')".
BODY_CRED=""
printf -v BODY_CRED '{"username":"%s","password":"%s"}' \
  "$(esc "$KUID")" "$(esc "$SVC_PASS")"

R4="$(api POST "/credentials/local/${KUID}/_create" "$BODY_CRED")"
case "$R4" in
  *'"error":null'*) : ;;
  *) echo "error: credentials failed: $R4" >&2; exit 1 ;;
esac
echo "::endgroup::" >&2

# --- mint the key FOR that user -------------------------------------------
URL="/users/${KUID}/api-keys/_create"
[ -n "${EXPIRES_IN:-}" ] && URL="${URL}?expiresIn=${EXPIRES_IN}"

BODY_KEY=""
printf -v BODY_KEY '{"description":"%s"}' "$(esc "${LABEL}-scoped-key")"

KEYRESP="$(api POST "$URL" "$BODY_KEY")"

TOKEN="$(printf '%s' "$KEYRESP" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
KEYID="$(printf '%s' "$KEYRESP" | sed -n 's/.*"result":{"_id":"\([^"]*\)".*/\1/p')"
[ -n "$TOKEN" ] || { echo "error: key not created: $KEYRESP" >&2; exit 1; }

printf '{"token":"%s","keyId":"%s","index":"%s","collection":"%s","role":"%s","profile":"%s","kuid":"%s","password":"%s","base":"%s"}\n' \
  "$(esc "$TOKEN")" "$KEYID" "$IDX" "$COL" "$ROLE" "$PROFILE" "$KUID" "$SVC_PASS" "$BASE"