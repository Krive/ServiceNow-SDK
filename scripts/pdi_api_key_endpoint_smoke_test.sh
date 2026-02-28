#!/usr/bin/env bash
set -Eeuo pipefail

# ServiceNow SDK Endpoint Smoke Test (API Key)
#
# This script exercises the major endpoint families implemented by this SDK
# against a real ServiceNow instance (recommended: PDI).
#
# Required env vars:
#   SN_INSTANCE_URL   e.g. https://dev12345.service-now.com
#   SN_API_KEY        API key value (sent as x-sn-apikey)
#
# Strongly recommended env vars:
#   SN_TEST_TABLE             default: incident
#   SN_TEST_RECORD_JSON       default incident payload
#   SN_IMPORT_SET_TABLE       enables Import Set tests
#   SN_CATALOG_ITEM_SYS_ID    enables cart mutation tests
#   SN_CMDB_CI_SYS_ID         enables CMDB instance get test
#   SN_CMDB_CI_CLASS          required with SN_CMDB_CI_SYS_ID for class-qualified get
#   SN_ATTACHMENT_TABLE       default: SN_TEST_TABLE
#   SN_ATTACHMENT_RECORD_SYS_ID if set, attachment tests use this record instead of created test record
#   SN_ATTACHMENT_MIME_TYPE   default: text/plain
#   SN_ATTACHMENT_FILE_EXT    default: txt
#
# Optional behavior toggles:
#   SN_RUN_MUTATION=1|0       default: 0 (create/update/delete tests)
#   SN_VERBOSE=1|0            default: 0 (dump response body per request)
#   SN_TEST_LEVEL=basic|full  default: full
#   SN_ENFORCE_PDI_ONLY=1|0   default: 1 (block non-devNNNNNN.service-now.com unless overridden)
#   SN_ALLOW_NON_PDI=1|0      default: 0 (required override for non-PDI hostnames)
#   SN_ALLOW_PROD_MUTATION=1|0 default: 0 (required override for mutating tests on prod-like hosts)
#   SN_CONFIRM_INSTANCE_HOST   optional exact hostname guard (fails if mismatch)
#   SN_SETUP_IF_MISSING=1|0   default: 1 (interactive prompt when required vars are missing)
#   SN_SETUP_SAVE_ENV=ask|1|0 default: ask (save prompted values to SN_ENV_FILE)
#   SN_ENV_FILE               default: .sn_smoke_env
#
# Full mode optional env vars (enables deeper endpoint coverage):
#   SN_CATALOG_REQUEST_NUMBER          request number for tracker lookups (optional)
#   SN_CMDB_REL_PARENT_SYS_ID          parent CI sys_id for relationship create/delete
#   SN_CMDB_REL_CHILD_SYS_ID           child CI sys_id for relationship create/delete
#   SN_CMDB_REL_TYPE_SYS_ID            relationship type sys_id (optional; auto-detected if omitted)
#   SN_CMDB_CREATE_CLASS               class/table for CI create test (default: cmdb_ci_computer)
#   SN_CMDB_CREATE_PAYLOAD_JSON        JSON body for CMDB create mutation (optional; required for strict classes)
#   SN_IDENTITY_ASSIGN_USER_SYS_ID     user to use for role/group assignment tests (optional)
#   SN_IDENTITY_DEEP_MUTATION=1|0      default: 1 in full mode, 0 in basic mode
#
# Usage:
#   SN_INSTANCE_URL="https://devXXXXX.service-now.com" \
#   SN_API_KEY="..." \
#   bash scripts/pdi_api_key_endpoint_smoke_test.sh

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
RESET="\033[0m"

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL_COUNT=0

SN_INSTANCE_URL="${SN_INSTANCE_URL:-}"
SN_API_KEY="${SN_API_KEY:-}"
SN_TEST_TABLE="${SN_TEST_TABLE:-incident}"
SN_RUN_MUTATION="${SN_RUN_MUTATION:-0}"
SN_VERBOSE="${SN_VERBOSE:-0}"
SN_TEST_LEVEL="${SN_TEST_LEVEL:-full}"
SN_ENFORCE_PDI_ONLY="${SN_ENFORCE_PDI_ONLY:-1}"
SN_ALLOW_NON_PDI="${SN_ALLOW_NON_PDI:-0}"
SN_ALLOW_PROD_MUTATION="${SN_ALLOW_PROD_MUTATION:-0}"
SN_CONFIRM_INSTANCE_HOST="${SN_CONFIRM_INSTANCE_HOST:-}"
SN_SETUP_IF_MISSING="${SN_SETUP_IF_MISSING:-1}"
SN_SETUP_SAVE_ENV="${SN_SETUP_SAVE_ENV:-ask}"
SN_ENV_FILE="${SN_ENV_FILE:-.sn_smoke_env}"
SN_TEST_RECORD_JSON="${SN_TEST_RECORD_JSON:-{\"short_description\":\"sdk-smoke\",\"urgency\":\"3\",\"impact\":\"3\"}}"
SN_ATTACHMENT_MIME_TYPE="${SN_ATTACHMENT_MIME_TYPE:-text/plain}"
SN_ATTACHMENT_FILE_EXT="${SN_ATTACHMENT_FILE_EXT:-txt}"
SN_CMDB_CREATE_CLASS="${SN_CMDB_CREATE_CLASS:-cmdb_ci_computer}"
SN_CMDB_CREATE_PAYLOAD_JSON="${SN_CMDB_CREATE_PAYLOAD_JSON:-}"
if [[ "$SN_TEST_LEVEL" == "full" ]]; then
  SN_IDENTITY_DEEP_MUTATION="${SN_IDENTITY_DEEP_MUTATION:-1}"
else
  SN_IDENTITY_DEEP_MUTATION="${SN_IDENTITY_DEEP_MUTATION:-0}"
fi

# Runtime state
LAST_STATUS=""
LAST_BODY_FILE=""
LAST_URL=""
TEST_TAG="sdk-smoke-$(date +%s)"
CATALOG_LAST_CART_ID=""
CATALOG_LAST_CART_ITEM_ID=""
IDENTITY_TEST_USER_ID=""
CMDB_TEST_CI_ID=""

CREATED_TABLE_RECORDS=() # entries: table:sys_id
CREATED_ATTACHMENTS=()   # sys_id
TEMP_FILES=()

log() { printf "%b\n" "$*"; }
info() { log "${BLUE}[INFO]${RESET} $*"; }
ok() { log "${GREEN}[PASS]${RESET} $*"; }
warn() { log "${YELLOW}[SKIP]${RESET} $*"; }
err() { log "${RED}[FAIL]${RESET} $*"; }
section() { log "\n${BLUE}=== $* ===${RESET}"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    err "missing required command: $1"
    exit 1
  }
}

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    err "required env var is missing: $name"
    exit 1
  fi
}

is_interactive_tty() {
  [[ -t 0 && -t 1 ]]
}

prompt_value() {
  local var_name="$1"
  local prompt_text="$2"
  local default_value="${3:-}"
  local secret="${4:-0}"
  local current="${!var_name:-}"
  local input=""

  if [[ -n "$current" ]]; then
    return 0
  fi

  if ! is_interactive_tty; then
    err "missing required env var: ${var_name} (non-interactive shell cannot prompt)"
    return 1
  fi

  while true; do
    if [[ "$secret" == "1" ]]; then
      read -r -s -p "${prompt_text} " input
      printf "\n"
    else
      if [[ -n "$default_value" ]]; then
        read -r -p "${prompt_text} [${default_value}] " input
      else
        read -r -p "${prompt_text} " input
      fi
    fi

    if [[ -z "$input" ]]; then
      input="$default_value"
    fi
    if [[ -n "$input" ]]; then
      printf -v "$var_name" "%s" "$input"
      export "$var_name"
      return 0
    fi
    warn "${var_name} cannot be empty."
  done
}

save_env_file() {
  local env_file="$SN_ENV_FILE"
  umask 077
  {
    printf "# shellcheck shell=bash\n"
    printf "# generated by scripts/pdi_api_key_endpoint_smoke_test.sh on %s\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    printf "export SN_INSTANCE_URL=%q\n" "$SN_INSTANCE_URL"
    printf "export SN_API_KEY=%q\n" "$SN_API_KEY"
    printf "export SN_CONFIRM_INSTANCE_HOST=%q\n" "${SN_CONFIRM_INSTANCE_HOST:-}"
    printf "export SN_TEST_LEVEL=%q\n" "$SN_TEST_LEVEL"
    printf "export SN_RUN_MUTATION=%q\n" "$SN_RUN_MUTATION"
    printf "export SN_ENFORCE_PDI_ONLY=%q\n" "$SN_ENFORCE_PDI_ONLY"
    printf "export SN_ALLOW_NON_PDI=%q\n" "$SN_ALLOW_NON_PDI"
    printf "export SN_ALLOW_PROD_MUTATION=%q\n" "$SN_ALLOW_PROD_MUTATION"
    printf "export SN_VERBOSE=%q\n" "$SN_VERBOSE"
  } >"$env_file"
  chmod 600 "$env_file"
  info "Saved environment values to ${env_file} (mode 600 via umask)."
}

setup_missing_env() {
  [[ "$SN_SETUP_IF_MISSING" == "1" ]] || return 0

  local missing=()
  [[ -z "$SN_INSTANCE_URL" ]] && missing+=("SN_INSTANCE_URL")
  [[ -z "$SN_API_KEY" ]] && missing+=("SN_API_KEY")

  if [[ "${#missing[@]}" -eq 0 ]]; then
    return 0
  fi

  if ! is_interactive_tty; then
    err "Required env vars missing (${missing[*]}). Set them or run in interactive shell."
    return 1
  fi

  section "Interactive Setup"
  info "Missing required env vars: ${missing[*]}"

  prompt_value "SN_INSTANCE_URL" "Enter ServiceNow instance URL (e.g. https://dev123456.service-now.com):" "" "0" || return 1
  SN_INSTANCE_URL="${SN_INSTANCE_URL%/}"
  export SN_INSTANCE_URL

  prompt_value "SN_API_KEY" "Enter ServiceNow API key:" "" "1" || return 1

  if [[ -z "${SN_CONFIRM_INSTANCE_HOST:-}" ]]; then
    local host_guess
    host_guess="$(extract_host "$SN_INSTANCE_URL")"
    prompt_value "SN_CONFIRM_INSTANCE_HOST" "Confirm expected instance host for safety gate:" "$host_guess" "0" || return 1
  fi

  if [[ "$SN_SETUP_SAVE_ENV" == "1" ]]; then
    save_env_file
  elif [[ "$SN_SETUP_SAVE_ENV" == "ask" ]]; then
    local save_choice
    read -r -p "Save these values to ${SN_ENV_FILE} for reuse? [y/N] " save_choice
    if [[ "$save_choice" =~ ^[Yy]$ ]]; then
      save_env_file
      info "Reuse later with: source ${SN_ENV_FILE}"
    fi
  fi
}

base64_no_wrap() {
  printf "%s" "$1" | base64 | tr -d '\n'
}

uri_encode() {
  jq -rn --arg v "$1" '$v|@uri'
}

extract_host() {
  local url="$1"
  url="${url#http://}"
  url="${url#https://}"
  url="${url%%/*}"
  url="${url%%:*}"
  printf "%s" "$url"
}

is_pdi_host() {
  local host="${1,,}"
  [[ "$host" =~ ^dev[0-9]+\.service-now\.com$ ]]
}

is_likely_non_prod_host() {
  local host="${1,,}"
  if is_pdi_host "$host"; then
    return 0
  fi
  [[ "$host" =~ (dev|test|qa|uat|stg|stage|sandbox|nonprod|np|pdi) ]]
}

safety_gate() {
  local host lower_host
  host="$(extract_host "$SN_INSTANCE_URL")"
  lower_host="${host,,}"

  [[ -n "$host" ]] || {
    err "Could not parse hostname from SN_INSTANCE_URL"
    exit 1
  }

  if [[ -n "$SN_CONFIRM_INSTANCE_HOST" && "$host" != "$SN_CONFIRM_INSTANCE_HOST" ]]; then
    err "Safety gate: SN_CONFIRM_INSTANCE_HOST mismatch. expected=${SN_CONFIRM_INSTANCE_HOST} actual=${host}"
    exit 1
  fi

  if [[ "$SN_ENFORCE_PDI_ONLY" == "1" && "$SN_ALLOW_NON_PDI" != "1" ]]; then
    if ! is_pdi_host "$lower_host"; then
      err "Safety gate: host '${host}' is not a PDI-style host (devNNNNNN.service-now.com). Refusing to run."
      err "Override only if intentional: set SN_ALLOW_NON_PDI=1"
      exit 1
    fi
  fi

  if [[ "$SN_RUN_MUTATION" == "1" && "$SN_ALLOW_PROD_MUTATION" != "1" ]]; then
    if ! is_likely_non_prod_host "$lower_host"; then
      err "Safety gate: mutating tests requested for host '${host}', which does not look non-production. Refusing to run."
      err "Override only if intentional: set SN_ALLOW_PROD_MUTATION=1 (and SN_ALLOW_NON_PDI=1 if non-PDI)."
      exit 1
    fi
  fi
}

cleanup() {
  set +e

  # Delete created attachments first.
  for aid in "${CREATED_ATTACHMENTS[@]:-}"; do
    [[ -z "$aid" ]] && continue
    curl -sS -X DELETE "${SN_INSTANCE_URL}/api/now/attachment/${aid}" \
      -H "Accept: application/json" \
      -H "x-sn-apikey: ${SN_API_KEY}" >/dev/null 2>&1 || true
  done

  # Delete created table records.
  for pair in "${CREATED_TABLE_RECORDS[@]:-}"; do
    [[ -z "$pair" ]] && continue
    local table="${pair%%:*}"
    local sys_id="${pair#*:}"
    [[ -z "$table" || -z "$sys_id" ]] && continue
    curl -sS -X DELETE "${SN_INSTANCE_URL}/api/now/table/${table}/${sys_id}" \
      -H "Accept: application/json" \
      -H "x-sn-apikey: ${SN_API_KEY}" >/dev/null 2>&1 || true
  done

  for f in "${TEMP_FILES[@]:-}"; do
    [[ -f "$f" ]] && rm -f "$f" || true
  done
}
trap cleanup EXIT

_api_request() {
  local method="$1"
  local path="$2"
  local body="${3:-}"

  local url="${SN_INSTANCE_URL}${path}"
  local body_file
  body_file="$(mktemp)"
  TEMP_FILES+=("$body_file")

  local -a curl_cmd=(
    curl -sS -X "$method" "$url"
    -H "Accept: application/json"
    -H "x-sn-apikey: ${SN_API_KEY}"
    -o "$body_file"
    -w "%{http_code}"
  )

  if [[ -n "$body" ]]; then
    curl_cmd+=(
      -H "Content-Type: application/json"
      --data "$body"
    )
  fi

  LAST_STATUS="$("${curl_cmd[@]}")"
  LAST_BODY_FILE="$body_file"
  LAST_URL="$url"

  if [[ "$SN_VERBOSE" == "1" ]]; then
    info "$method $path -> HTTP $LAST_STATUS"
    if jq -e . "$LAST_BODY_FILE" >/dev/null 2>&1; then
      jq . "$LAST_BODY_FILE"
    else
      cat "$LAST_BODY_FILE"
    fi
  fi
}

_api_request_with_optional_version() {
  local method="$1"
  local path="$2"
  local body="${3:-}"

  _api_request "$method" "$path" "$body"

  if [[ "$LAST_STATUS" == "404" || "$LAST_STATUS" == "405" ]]; then
    if [[ "$path" == /api/sn_sc/servicecatalog* ]]; then
      local versioned_path="${path/\/api\/sn_sc\/servicecatalog/\/api\/sn_sc\/v1\/servicecatalog}"
      info "Retrying with versioned Service Catalog path: ${versioned_path}"
      _api_request "$method" "$versioned_path" "$body"
      return
    fi

    if [[ "$path" == /api/now/import* && "$path" != /api/now/v1/import* ]]; then
      local versioned_path="${path/\/api\/now\/import/\/api\/now\/v1\/import}"
      info "Retrying with versioned Import Set path: ${versioned_path}"
      _api_request "$method" "$versioned_path" "$body"
      return
    fi
  fi
}

_api_upload_file() {
  local path="$1"
  local table_name="$2"
  local table_sys_id="$3"
  local file_path="$4"
  local mime_type="${5:-text/plain}"
  local upload_name="${6:-upload.txt}"

  local url="${SN_INSTANCE_URL}${path}"
  local body_file
  body_file="$(mktemp)"
  TEMP_FILES+=("$body_file")

  LAST_STATUS="$(curl -sS -X POST "$url" \
    -H "Accept: application/json" \
    -H "x-sn-apikey: ${SN_API_KEY}" \
    -F "table_name=${table_name}" \
    -F "table_sys_id=${table_sys_id}" \
    -F "file=@${file_path};type=${mime_type};filename=${upload_name}" \
    -o "$body_file" \
    -w "%{http_code}")"

  LAST_BODY_FILE="$body_file"
  LAST_URL="$url"

  if [[ "$SN_VERBOSE" == "1" ]]; then
    info "POST $path (multipart) -> HTTP $LAST_STATUS"
    if jq -e . "$LAST_BODY_FILE" >/dev/null 2>&1; then
      jq . "$LAST_BODY_FILE"
    else
      cat "$LAST_BODY_FILE"
    fi
  fi
}

expect_status() {
  local allowed="$1"
  if [[ " ${allowed} " != *" ${LAST_STATUS} "* ]]; then
    err "HTTP ${LAST_STATUS} from ${LAST_URL}; expected one of: ${allowed}"
    if [[ -f "$LAST_BODY_FILE" ]]; then
      if jq -e . "$LAST_BODY_FILE" >/dev/null 2>&1; then
        jq . "$LAST_BODY_FILE"
      else
        cat "$LAST_BODY_FILE"
      fi
    fi
    return 1
  fi
  return 0
}

json_get() {
  local jq_filter="$1"
  jq -r "$jq_filter // empty" "$LAST_BODY_FILE"
}

track_record() {
  local table="$1"
  local sys_id="$2"
  CREATED_TABLE_RECORDS+=("${table}:${sys_id}")
}

track_attachment() {
  local sys_id="$1"
  CREATED_ATTACHMENTS+=("${sys_id}")
}

run_test() {
  local name="$1"
  shift
  TOTAL_COUNT=$((TOTAL_COUNT + 1))

  info "Running: ${name}"
  if "$@"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    ok "$name"
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    err "$name"
  fi
}

skip_test() {
  local name="$1"
  TOTAL_COUNT=$((TOTAL_COUNT + 1))
  SKIP_COUNT=$((SKIP_COUNT + 1))
  warn "$name"
}

run_test_full() {
  local name="$1"
  shift
  if [[ "$SN_TEST_LEVEL" != "full" ]]; then
    skip_test "$name (requires SN_TEST_LEVEL=full)"
    return 0
  fi
  run_test "$name" "$@"
}

get_first_sys_id_from_table() {
  local table="$1"
  local query="${2:-}"
  local path="/api/now/table/${table}?sysparm_fields=sys_id&sysparm_limit=1"
  if [[ -n "$query" ]]; then
    path="${path}&sysparm_query=$(uri_encode "$query")"
  fi
  _api_request "GET" "$path"
  if ! expect_status "200"; then
    return 1
  fi
  json_get '.result[0].sys_id'
}

# -----------------------------
# Test implementations
# -----------------------------

test_connectivity_and_auth() {
  _api_request "GET" "/api/now/table/sys_user?sysparm_limit=1"
  expect_status "200"
}

TEST_RECORD_SYS_ID=""

# Covers table CRUD + query + count/keys behavior that SDK now uses.
test_table_crud_and_query() {
  local table="$SN_TEST_TABLE"
  local create_payload
  create_payload="$(jq -nc --argjson base "$SN_TEST_RECORD_JSON" --arg tag "$TEST_TAG" '$base + {short_description: ((.short_description // "sdk-smoke") + "-" + $tag)}')"

  _api_request "POST" "/api/now/table/${table}" "$create_payload"
  expect_status "200 201"

  local sys_id
  sys_id="$(json_get '.result.sys_id')"
  [[ -n "$sys_id" ]] || {
    err "create response missing result.sys_id"
    return 1
  }
  TEST_RECORD_SYS_ID="$sys_id"
  track_record "$table" "$sys_id"

  _api_request "GET" "/api/now/table/${table}/${sys_id}"
  expect_status "200"

  local patch_payload
  patch_payload="$(jq -nc --arg d "updated-${TEST_TAG}" '{description:$d}')"
  _api_request "PATCH" "/api/now/table/${table}/${sys_id}" "$patch_payload"
  expect_status "200"

  if [[ "$SN_RUN_MUTATION" == "1" ]]; then
    local put_payload
    put_payload="$(jq -nc --arg sd "put-${TEST_TAG}" '{short_description:$sd, urgency:"3", impact:"3"}')"
    _api_request "PUT" "/api/now/table/${table}/${sys_id}" "$put_payload"
    expect_status "200"
  fi

  local query
  query="$(uri_encode "sys_id=${sys_id}^ORDERBYDESCsys_updated_on")"
  _api_request "GET" "/api/now/table/${table}?sysparm_query=${query}&sysparm_limit=1"
  expect_status "200"

  # SDK CountWithContext now uses stats endpoint.
  local q_enc
  q_enc="$(uri_encode "sys_id=${sys_id}")"
  _api_request "GET" "/api/now/stats/${table}?sysparm_count=true&sysparm_query=${q_enc}"
  expect_status "200"

  # SDK GetKeys now uses paged table read with sys_id field.
  _api_request "GET" "/api/now/table/${table}?sysparm_fields=sys_id&sysparm_limit=5&sysparm_offset=0&sysparm_query=${q_enc}"
  expect_status "200"
}

test_aggregate_stats_endpoint() {
  local table="$SN_TEST_TABLE"
  local query
  query="$(uri_encode "ORDERBYactive")"
  _api_request "GET" "/api/now/stats/${table}?sysparm_count=true&sysparm_group_by=active&sysparm_order_by=active&sysparm_limit=5&sysparm_query=${query}"
  expect_status "200"
}

test_batch_endpoint() {
  local payload
  payload="$(jq -nc --arg req_id "batch-${TEST_TAG}" '
    {
      batch_request_id: $req_id,
      enforce_order: false,
      rest_requests: [
        {
          id: "users",
          url: "/api/now/table/sys_user?sysparm_limit=1",
          method: "GET",
          headers: [{name:"Accept", value:"application/json"}],
          exclude_response_headers: true
        },
        {
          id: "groups",
          url: "/api/now/table/sys_user_group?sysparm_limit=1",
          method: "GET",
          headers: [{name:"Accept", value:"application/json"}],
          exclude_response_headers: true
        }
      ]
    }
  ')"

  _api_request "POST" "/api/now/v1/batch" "$payload"
  expect_status "200"

  local serviced_count
  serviced_count="$(json_get '.serviced_requests | length')"
  [[ -n "$serviced_count" ]] || serviced_count="0"
  if [[ "$serviced_count" == "0" ]]; then
    err "batch returned zero serviced requests"
    return 1
  fi
}

test_catalog_table_endpoints() {
  _api_request "GET" "/api/now/table/sc_catalog?sysparm_query=active=true&sysparm_limit=3"
  expect_status "200"

  _api_request "GET" "/api/now/table/sc_cat_item_category?sysparm_query=active=true&sysparm_limit=3"
  expect_status "200"

  _api_request "GET" "/api/now/table/sc_cat_item?sysparm_query=active=true&sysparm_limit=3"
  expect_status "200"
}

test_catalog_table_detail_endpoints() {
  _api_request "GET" "/api/now/table/sc_catalog?sysparm_fields=sys_id&sysparm_query=active=true&sysparm_limit=1"
  expect_status "200"
  local catalog_id
  catalog_id="$(json_get '.result[0].sys_id')"
  if [[ -n "$catalog_id" ]]; then
    _api_request "GET" "/api/now/table/sc_catalog/${catalog_id}"
    expect_status "200"
  else
    warn "No active catalog found; skipped sc_catalog/{sys_id} detail check"
  fi

  _api_request "GET" "/api/now/table/sc_cat_item_category?sysparm_fields=sys_id&sysparm_query=active=true&sysparm_limit=1"
  expect_status "200"
  local category_id
  category_id="$(json_get '.result[0].sys_id')"
  if [[ -n "$category_id" ]]; then
    _api_request "GET" "/api/now/table/sc_cat_item_category/${category_id}"
    expect_status "200"
  else
    warn "No active catalog category found; skipped sc_cat_item_category/{sys_id} detail check"
  fi

  _api_request "GET" "/api/now/table/sc_cat_item?sysparm_fields=sys_id&sysparm_query=active=true&sysparm_limit=1"
  expect_status "200"
  local item_id
  item_id="$(json_get '.result[0].sys_id')"
  if [[ -n "$item_id" ]]; then
    _api_request "GET" "/api/now/table/sc_cat_item/${item_id}"
    expect_status "200"
  else
    warn "No active catalog item found; skipped sc_cat_item/{sys_id} detail check"
  fi
}

test_catalog_variable_endpoints() {
  local item_id
  item_id="${SN_CATALOG_ITEM_SYS_ID:-}"
  if [[ -z "$item_id" ]]; then
    _api_request "GET" "/api/now/table/sc_cat_item?sysparm_fields=sys_id&sysparm_query=active=true&sysparm_limit=1"
    if ! expect_status "200"; then
      return 1
    fi
    item_id="$(json_get '.result[0].sys_id')"
  fi

  [[ -n "$item_id" ]] || {
    warn "No catalog item id available; skipping variable table checks"
    return 0
  }

  local q_vars
  q_vars="$(uri_encode "cat_item=${item_id}")"
  _api_request "GET" "/api/now/table/item_option_new?sysparm_query=${q_vars}&sysparm_limit=3"
  expect_status "200"

  local question_id
  question_id="$(json_get '.result[0].sys_id')"
  if [[ -n "$question_id" ]]; then
    local q_choices
    q_choices="$(uri_encode "question=${question_id}")"
    _api_request "GET" "/api/now/table/question_choice?sysparm_query=${q_choices}&sysparm_limit=3"
    expect_status "200"
  else
    warn "No item variables found for item ${item_id}; skipped question_choice checks"
  fi
}

test_catalog_cart_endpoints() {
  local item_sys_id="${SN_CATALOG_ITEM_SYS_ID:-}"
  [[ -n "$item_sys_id" ]] || {
    warn "SN_CATALOG_ITEM_SYS_ID not set; skipping cart mutation checks"
    return 0
  }

  local add_payload='{"sysparm_quantity":1}'
  _api_request_with_optional_version "POST" "/api/sn_sc/servicecatalog/items/${item_sys_id}/add_to_cart" "$add_payload"
  expect_status "200"

  local cart_item_id
  cart_item_id="$(json_get '.result.item_id')"

  _api_request_with_optional_version "GET" "/api/sn_sc/servicecatalog/cart"
  expect_status "200"

  if [[ -n "$cart_item_id" ]]; then
    local update_payload='{"sysparm_quantity":2}'
    _api_request_with_optional_version "PUT" "/api/sn_sc/servicecatalog/cart/${cart_item_id}" "$update_payload"
    expect_status "200"

    _api_request_with_optional_version "DELETE" "/api/sn_sc/servicecatalog/cart/${cart_item_id}"
    expect_status "200 204"
  else
    warn "Cart add response did not include result.item_id; skipped item update/delete"
  fi
}

test_attachment_flow() {
  local table_name="${SN_ATTACHMENT_TABLE:-$SN_TEST_TABLE}"
  local table_sys_id="${SN_ATTACHMENT_RECORD_SYS_ID:-$TEST_RECORD_SYS_ID}"

  [[ -n "$table_sys_id" ]] || {
    err "attachment test needs a record sys_id (set SN_ATTACHMENT_RECORD_SYS_ID or allow table CRUD test)"
    return 1
  }

  local upload_file
  upload_file="$(mktemp)"
  local ext="${SN_ATTACHMENT_FILE_EXT#.}"
  local renamed_upload_file="${upload_file}.${ext}"
  mv "$upload_file" "$renamed_upload_file"
  upload_file="$renamed_upload_file"
  TEMP_FILES+=("$upload_file")
  printf "attachment-smoke-%s\n" "$TEST_TAG" > "$upload_file"

  local upload_name="sdk-smoke-${TEST_TAG}.${ext}"
  _api_upload_file \
    "/api/now/attachment/upload" \
    "$table_name" \
    "$table_sys_id" \
    "$upload_file" \
    "$SN_ATTACHMENT_MIME_TYPE" \
    "$upload_name"
  expect_status "200 201"

  local attachment_id
  attachment_id="$(json_get '.result.sys_id')"
  [[ -n "$attachment_id" ]] || {
    err "upload response missing attachment sys_id"
    return 1
  }
  track_attachment "$attachment_id"

  local q
  q="$(uri_encode "table_name=${table_name}^table_sys_id=${table_sys_id}")"
  _api_request "GET" "/api/now/attachment?sysparm_query=${q}&sysparm_limit=5"
  if [[ "$LAST_STATUS" != "200" ]]; then
    # Legacy fallback for older behavior.
    local q_legacy
    q_legacy="table_name=$(uri_encode "$table_name")&table_sys_id=$(uri_encode "$table_sys_id")&sysparm_limit=5"
    _api_request "GET" "/api/now/attachment?${q_legacy}"
  fi
  expect_status "200"

  local download_file
  download_file="$(mktemp)"
  TEMP_FILES+=("$download_file")
  local dl_status
  dl_status="$(curl -sS -X GET "${SN_INSTANCE_URL}/api/now/attachment/${attachment_id}/file" \
    -H "Accept: application/json" \
    -H "x-sn-apikey: ${SN_API_KEY}" \
    -o "$download_file" \
    -w "%{http_code}")"

  if [[ "$dl_status" != "200" ]]; then
    err "attachment download failed with HTTP ${dl_status}"
    return 1
  fi

  if ! cmp -s "$upload_file" "$download_file"; then
    err "downloaded attachment content did not match uploaded file"
    return 1
  fi

  _api_request "DELETE" "/api/now/attachment/${attachment_id}"
  expect_status "200 204"

  # Removed successfully; avoid duplicate delete in cleanup.
  CREATED_ATTACHMENTS=()
}

test_import_set_endpoints() {
  local import_table="${SN_IMPORT_SET_TABLE:-}"
  [[ -n "$import_table" ]] || {
    warn "SN_IMPORT_SET_TABLE not set; skipping import set checks"
    return 0
  }

  local payload
  payload="$(jq -nc --arg tag "$TEST_TAG" '{u_name:("sdk-import-"+$tag), u_source:"sdk-smoke"}')"

  _api_request_with_optional_version "POST" "/api/now/import/${import_table}" "$payload"
  expect_status "200 201"

  local import_set_id
  local import_row_id
  import_set_id="$(json_get '.result.import_set // .result.sys_import_set // .result[0].import_set // .result[0].sys_import_set // empty')"
  import_row_id="$(json_get '.result.sys_id // .result[0].sys_id // empty')"
  if [[ -n "$import_set_id" ]]; then
    _api_request "GET" "/api/now/table/sys_import_set/${import_set_id}"
    if [[ "$LAST_STATUS" != "200" && -n "$import_row_id" ]]; then
      _api_request_with_optional_version "GET" "/api/now/import/${import_table}/${import_row_id}"
    fi
    expect_status "200"

    local q
    q="$(uri_encode "import_set=${import_set_id}")"
    _api_request "GET" "/api/now/table/sys_transform_entry?sysparm_query=${q}&sysparm_limit=5"
    expect_status "200"
  elif [[ -n "$import_row_id" ]]; then
    _api_request_with_optional_version "GET" "/api/now/import/${import_table}/${import_row_id}"
    expect_status "200"
  else
    warn "Import response did not expose import_set or row sys_id; skipped import_set lookup/transform checks"
  fi
}

test_cmdb_endpoints() {
  _api_request "GET" "/api/now/table/cmdb_ci?sysparm_fields=sys_id,sys_class_name,name&sysparm_limit=1"
  expect_status "200"

  local ci_id ci_class
  ci_id="$(json_get '.result[0].sys_id')"
  ci_class="$(json_get '.result[0].sys_class_name')"

  if [[ -n "${SN_CMDB_CI_SYS_ID:-}" && -n "${SN_CMDB_CI_CLASS:-}" ]]; then
    ci_id="$SN_CMDB_CI_SYS_ID"
    ci_class="$SN_CMDB_CI_CLASS"
  fi

  if [[ -n "$ci_id" && -n "$ci_class" ]]; then
    _api_request "GET" "/api/now/table/cmdb_ci/${ci_id}?sysparm_fields=sys_id,sys_class_name"
    expect_status "200"

    _api_request "GET" "/api/now/cmdb/instance/${ci_class}/${ci_id}"
    expect_status "200"

    # GetCIByClass path used in SDK.
    _api_request "GET" "/api/now/table/${ci_class}/${ci_id}"
    expect_status "200"
  else
    warn "No CI/class available for class-qualified CMDB instance check; skipped that subtest"
  fi

  # Relationship tables used by relationship client.
  _api_request "GET" "/api/now/table/cmdb_rel_ci?sysparm_limit=3"
  expect_status "200"

  _api_request "GET" "/api/now/table/cmdb_rel_type?sysparm_limit=3"
  expect_status "200"
}

test_identity_endpoints() {
  # Core identity tables.
  _api_request "GET" "/api/now/table/sys_user?sysparm_query=active=true^ORDERBYuser_name&sysparm_limit=3"
  expect_status "200"

  _api_request "GET" "/api/now/table/sys_user_role?sysparm_query=active=true^ORDERBYname&sysparm_limit=3"
  expect_status "200"

  _api_request "GET" "/api/now/table/sys_user_group?sysparm_query=active=true^ORDERBYname&sysparm_limit=3"
  expect_status "200"

  # Role and group membership tables used by SDK role/group assignment methods.
  _api_request "GET" "/api/now/table/sys_user_has_role?sysparm_limit=3"
  expect_status "200"

  _api_request "GET" "/api/now/table/sys_user_grmember?sysparm_limit=3"
  expect_status "200"

  # Role hierarchy table used by SDK.
  _api_request "GET" "/api/now/table/sys_user_role_contains?sysparm_limit=3"
  expect_status "200"

  # Session and preference tables used by access client.
  _api_request "GET" "/api/now/table/sys_user_session?sysparm_limit=1"
  expect_status "200"

  local sample_user
  sample_user="$(json_get '.result[0].sys_id')"
  if [[ -n "$sample_user" ]]; then
    local q
    q="$(uri_encode "user=${sample_user}")"
    _api_request "GET" "/api/now/table/sys_user_preference?sysparm_query=${q}&sysparm_limit=3"
    expect_status "200"
  else
    warn "Could not resolve sample user for preference lookup; skipped preference query"
  fi
}

test_identity_detail_endpoints() {
  local user_id role_id group_id

  _api_request "GET" "/api/now/table/sys_user?sysparm_fields=sys_id&sysparm_query=active=true&sysparm_limit=1"
  expect_status "200"
  user_id="$(json_get '.result[0].sys_id')"
  if [[ -n "$user_id" ]]; then
    _api_request "GET" "/api/now/table/sys_user/${user_id}"
    expect_status "200"
  else
    warn "No active user found; skipped sys_user/{sys_id} detail check"
  fi

  _api_request "GET" "/api/now/table/sys_user_role?sysparm_fields=sys_id&sysparm_query=active=true&sysparm_limit=1"
  expect_status "200"
  role_id="$(json_get '.result[0].sys_id')"
  if [[ -n "$role_id" ]]; then
    _api_request "GET" "/api/now/table/sys_user_role/${role_id}"
    expect_status "200"
  else
    warn "No active role found; skipped sys_user_role/{sys_id} detail check"
  fi

  _api_request "GET" "/api/now/table/sys_user_group?sysparm_fields=sys_id&sysparm_query=active=true&sysparm_limit=1"
  expect_status "200"
  group_id="$(json_get '.result[0].sys_id')"
  if [[ -n "$group_id" ]]; then
    _api_request "GET" "/api/now/table/sys_user_group/${group_id}"
    expect_status "200"
  else
    warn "No active group found; skipped sys_user_group/{sys_id} detail check"
  fi
}

test_identity_mutation_endpoints() {
  if [[ "$SN_RUN_MUTATION" != "1" ]]; then
    warn "SN_RUN_MUTATION=0; skipping identity mutation tests"
    return 0
  fi

  local uname="sdk_user_${TEST_TAG}"
  local create_user_payload
  create_user_payload="$(jq -nc --arg uname "$uname" --arg mail "${uname}@example.com" '{user_name:$uname, first_name:"SDK", last_name:"Smoke", email:$mail, active:true}')"

  _api_request "POST" "/api/now/table/sys_user" "$create_user_payload"
  expect_status "200 201"

  local user_id
  user_id="$(json_get '.result.sys_id')"
  [[ -n "$user_id" ]] || {
    err "identity create user missing sys_id"
    return 1
  }
  track_record "sys_user" "$user_id"
  IDENTITY_TEST_USER_ID="$user_id"

  local update_user_payload='{"title":"SDK Smoke Updated"}'
  _api_request "PUT" "/api/now/table/sys_user/${user_id}" "$update_user_payload"
  expect_status "200"

  # SDK delete for user is deactivate (active=false), not hard delete.
  _api_request "PUT" "/api/now/table/sys_user/${user_id}" '{"active":"false"}'
  expect_status "200"
}

test_catalog_servicecatalog_extended_endpoints() {
  local item_sys_id="${SN_CATALOG_ITEM_SYS_ID:-}"
  [[ -n "$item_sys_id" ]] || {
    warn "SN_CATALOG_ITEM_SYS_ID not set; skipping extended Service Catalog tests"
    return 0
  }

  _api_request_with_optional_version "POST" "/api/sn_sc/servicecatalog/items/${item_sys_id}/add_to_cart" '{"sysparm_quantity":1}'
  expect_status "200"
  CATALOG_LAST_CART_ITEM_ID="$(json_get '.result.item_id')"
  CATALOG_LAST_CART_ID="$(json_get '.result.cart_id // .result.sys_id')"

  _api_request_with_optional_version "GET" "/api/sn_sc/servicecatalog/cart"
  expect_status "200"
  if [[ -z "$CATALOG_LAST_CART_ID" ]]; then
    CATALOG_LAST_CART_ID="$(json_get '.result.cart_id // .result.sys_id')"
  fi
  if [[ -z "$CATALOG_LAST_CART_ITEM_ID" ]]; then
    CATALOG_LAST_CART_ITEM_ID="$(json_get '.result.items[0].sys_id')"
  fi

  _api_request_with_optional_version "POST" "/api/sn_sc/servicecatalog/items/${item_sys_id}/order_now" '{"sysparm_quantity":1}'
  expect_status "200"

  _api_request_with_optional_version "POST" "/api/sn_sc/servicecatalog/cart/submit_order"
  expect_status "200"

  if [[ -n "$CATALOG_LAST_CART_ID" ]]; then
    _api_request_with_optional_version "DELETE" "/api/sn_sc/servicecatalog/cart/${CATALOG_LAST_CART_ID}/empty"
    expect_status "200 204"
  else
    warn "Cart id not available; skipped /cart/{id}/empty endpoint check"
  fi
}

test_catalog_request_tracking_endpoints() {
  _api_request "GET" "/api/now/table/sc_request?sysparm_query=ORDERBYDESCsys_created_on&sysparm_limit=1"
  expect_status "200"

  local req_number
  req_number="${SN_CATALOG_REQUEST_NUMBER:-$(json_get '.result[0].number')}"
  if [[ -z "$req_number" ]]; then
    warn "No request number available; skipping request-tracking detail checks"
    return 0
  fi

  local q_req
  q_req="$(uri_encode "number=${req_number}")"
  _api_request "GET" "/api/now/table/sc_request?sysparm_query=${q_req}&sysparm_limit=1"
  expect_status "200"

  local q_items
  q_items="$(uri_encode "request.number=${req_number}")"
  _api_request "GET" "/api/now/table/sc_req_item?sysparm_query=${q_items}&sysparm_limit=3"
  expect_status "200"

  local req_item_number
  req_item_number="$(json_get '.result[0].number')"
  if [[ -n "$req_item_number" ]]; then
    local q_tasks
    q_tasks="$(uri_encode "request_item.number=${req_item_number}")"
    _api_request "GET" "/api/now/table/sc_task?sysparm_query=${q_tasks}&sysparm_limit=3"
    expect_status "200"
  else
    warn "No sc_req_item found for ${req_number}; skipped sc_task linked check"
  fi
}

test_import_set_multi_record_endpoint() {
  local import_table="${SN_IMPORT_SET_TABLE:-}"
  [[ -n "$import_table" ]] || {
    warn "SN_IMPORT_SET_TABLE not set; skipping multi-record import test"
    return 0
  }

  local payload1 payload2
  payload1="$(jq -nc --arg tag "$TEST_TAG" '{u_name:("sdk-import-a-"+$tag), u_source:"sdk-smoke"}')"
  payload2="$(jq -nc --arg tag "$TEST_TAG" '{u_name:("sdk-import-b-"+$tag), u_source:"sdk-smoke"}')"

  _api_request "POST" "/api/now/import/${import_table}" "$payload1"
  expect_status "200 201"
  _api_request "POST" "/api/now/import/${import_table}" "$payload2"
  expect_status "200 201"
}

test_cmdb_class_metadata_endpoints() {
  _api_request "GET" "/api/now/table/sys_db_object?sysparm_query=$(uri_encode "super_class.name=cmdb_ci^ORname=cmdb_ci")&sysparm_limit=3"
  expect_status "200"

  _api_request "GET" "/api/now/table/sys_dictionary?sysparm_query=$(uri_encode "name=${SN_CMDB_CREATE_CLASS}")&sysparm_limit=3"
  expect_status "200"
}

test_cmdb_relationship_mutation_endpoints() {
  if [[ "$SN_RUN_MUTATION" != "1" ]]; then
    warn "SN_RUN_MUTATION=0; skipping CMDB relationship mutation tests"
    return 0
  fi

  local parent child rel_type
  parent="${SN_CMDB_REL_PARENT_SYS_ID:-}"
  child="${SN_CMDB_REL_CHILD_SYS_ID:-}"
  rel_type="${SN_CMDB_REL_TYPE_SYS_ID:-}"

  if [[ -z "$parent" || -z "$child" ]]; then
    _api_request "GET" "/api/now/table/cmdb_ci?sysparm_fields=sys_id&sysparm_limit=2"
    if ! expect_status "200"; then
      return 1
    fi
    parent="${parent:-$(json_get '.result[0].sys_id')}"
    child="${child:-$(json_get '.result[1].sys_id')}"
  fi

  [[ -n "$parent" && -n "$child" ]] || {
    warn "Need two CI sys_ids for relationship mutation; set SN_CMDB_REL_PARENT_SYS_ID and SN_CMDB_REL_CHILD_SYS_ID"
    return 0
  }

  if [[ -z "$rel_type" ]]; then
    _api_request "GET" "/api/now/table/cmdb_rel_type?sysparm_fields=sys_id&sysparm_limit=1"
    if ! expect_status "200"; then
      return 1
    fi
    rel_type="$(json_get '.result[0].sys_id')"
  fi
  [[ -n "$rel_type" ]] || {
    warn "No relationship type sys_id available; set SN_CMDB_REL_TYPE_SYS_ID"
    return 0
  }

  local payload
  payload="$(jq -nc --arg p "$parent" --arg c "$child" --arg t "$rel_type" '{parent:$p, child:$c, type:$t}')"
  _api_request "POST" "/api/now/table/cmdb_rel_ci" "$payload"
  expect_status "200 201"

  local rel_id
  rel_id="$(json_get '.result.sys_id')"
  [[ -n "$rel_id" ]] || {
    err "relationship create response missing sys_id"
    return 1
  }

  _api_request "DELETE" "/api/now/table/cmdb_rel_ci/${rel_id}"
  expect_status "200 204"
}

test_cmdb_ci_mutation_endpoints() {
  if [[ "$SN_RUN_MUTATION" != "1" ]]; then
    warn "SN_RUN_MUTATION=0; skipping CMDB CI mutation tests"
    return 0
  fi

  local class_name="$SN_CMDB_CREATE_CLASS"
  local payload="$SN_CMDB_CREATE_PAYLOAD_JSON"
  if [[ -z "$payload" ]]; then
    payload="$(jq -nc --arg n "sdk-cmdb-${TEST_TAG}" '{name:$n}')"
  fi

  _api_request "POST" "/api/now/table/${class_name}" "$payload"
  if [[ "$LAST_STATUS" == "400" && -z "$SN_CMDB_CREATE_PAYLOAD_JSON" ]]; then
    warn "CMDB class ${class_name} needs required fields; set SN_CMDB_CREATE_PAYLOAD_JSON to enable this mutation test"
    return 0
  fi
  expect_status "200 201"

  local ci_id
  ci_id="$(json_get '.result.sys_id')"
  [[ -n "$ci_id" ]] || {
    err "cmdb create response missing sys_id"
    return 1
  }
  CMDB_TEST_CI_ID="$ci_id"
  track_record "$class_name" "$ci_id"

  _api_request "PUT" "/api/now/table/${class_name}/${ci_id}" "$(jq -nc --arg d "updated-${TEST_TAG}" '{short_description:$d}')"
  expect_status "200"

  _api_request "DELETE" "/api/now/table/${class_name}/${ci_id}"
  expect_status "200 204"
}

test_batch_mutation_endpoint() {
  if [[ "$SN_RUN_MUTATION" != "1" ]]; then
    warn "SN_RUN_MUTATION=0; skipping batch mutation test"
    return 0
  fi
  [[ -n "$TEST_RECORD_SYS_ID" ]] || {
    warn "No test record sys_id from table CRUD; skipping batch mutation test"
    return 0
  }

  local patch_body verify_query
  patch_body="$(base64_no_wrap "$(jq -nc --arg d "batch-updated-${TEST_TAG}" '{description:$d}')")"
  verify_query="/api/now/table/${SN_TEST_TABLE}/${TEST_RECORD_SYS_ID}?sysparm_fields=sys_id,description"

  local payload
  payload="$(jq -nc \
    --arg req_id "batch-mut-${TEST_TAG}" \
    --arg patch_url "/api/now/table/${SN_TEST_TABLE}/${TEST_RECORD_SYS_ID}" \
    --arg patch_body "$patch_body" \
    --arg get_url "$verify_query" \
    '{
      batch_request_id:$req_id,
      enforce_order:true,
      rest_requests:[
        {id:"patch1", url:$patch_url, method:"PATCH", headers:[{name:"Content-Type",value:"application/json"},{name:"Accept",value:"application/json"}], body:$patch_body, exclude_response_headers:true},
        {id:"get1", url:$get_url, method:"GET", headers:[{name:"Accept",value:"application/json"}], exclude_response_headers:true}
      ]
    }')"

  _api_request "POST" "/api/now/v1/batch" "$payload"
  expect_status "200"

  local unserviced
  unserviced="$(json_get '.unserviced_requests | length')"
  [[ -n "$unserviced" ]] || unserviced="0"
  if [[ "$unserviced" != "0" ]]; then
    err "batch mutation returned unserviced requests: $unserviced"
    return 1
  fi
}

test_identity_deep_mutation_endpoints() {
  if [[ "$SN_RUN_MUTATION" != "1" || "$SN_IDENTITY_DEEP_MUTATION" != "1" ]]; then
    warn "identity deep mutation disabled (set SN_RUN_MUTATION=1 and SN_IDENTITY_DEEP_MUTATION=1)"
    return 0
  fi

  local target_user role_id group_id
  target_user="${SN_IDENTITY_ASSIGN_USER_SYS_ID:-$IDENTITY_TEST_USER_ID}"
  if [[ -z "$target_user" ]]; then
    target_user="$(get_first_sys_id_from_table "sys_user" "active=true" || true)"
  fi
  [[ -n "$target_user" ]] || {
    warn "No target user available for identity deep mutation tests"
    return 0
  }

  local role_name
  role_name="x_sdk_role_${TEST_TAG}"
  _api_request "POST" "/api/now/table/sys_user_role" "$(jq -nc --arg n "$role_name" '{name:$n, description:"SDK smoke role", active:true}')"
  expect_status "200 201"
  role_id="$(json_get '.result.sys_id')"
  [[ -n "$role_id" ]] || {
    err "role create missing sys_id"
    return 1
  }
  track_record "sys_user_role" "$role_id"

  _api_request "PUT" "/api/now/table/sys_user_role/${role_id}" '{"description":"SDK smoke role updated"}'
  expect_status "200"

  local group_name
  group_name="x_sdk_group_${TEST_TAG}"
  _api_request "POST" "/api/now/table/sys_user_group" "$(jq -nc --arg n "$group_name" '{name:$n, description:"SDK smoke group", active:true}')"
  expect_status "200 201"
  group_id="$(json_get '.result.sys_id')"
  [[ -n "$group_id" ]] || {
    err "group create missing sys_id"
    return 1
  }
  track_record "sys_user_group" "$group_id"

  _api_request "PUT" "/api/now/table/sys_user_group/${group_id}" '{"description":"SDK smoke group updated"}'
  expect_status "200"

  _api_request "POST" "/api/now/table/sys_user_has_role" "$(jq -nc --arg u "$target_user" --arg r "$role_id" '{user:$u, role:$r}')"
  expect_status "200 201"
  local assignment_id
  assignment_id="$(json_get '.result.sys_id')"
  if [[ -n "$assignment_id" ]]; then
    _api_request "DELETE" "/api/now/table/sys_user_has_role/${assignment_id}"
    expect_status "200 204"
  fi

  _api_request "POST" "/api/now/table/sys_user_grmember" "$(jq -nc --arg u "$target_user" --arg g "$group_id" '{user:$u, group:$g}')"
  expect_status "200 201"
  local membership_id
  membership_id="$(json_get '.result.sys_id')"
  if [[ -n "$membership_id" ]]; then
    _api_request "DELETE" "/api/now/table/sys_user_grmember/${membership_id}"
    expect_status "200 204"
  fi

  local pref_name="x_sdk_pref_${TEST_TAG}"
  _api_request "POST" "/api/now/table/sys_user_preference" "$(jq -nc --arg u "$target_user" --arg n "$pref_name" '{user:$u, name:$n, value:"a", personal:"true"}')"
  expect_status "200 201"
  local pref_id
  pref_id="$(json_get '.result.sys_id')"
  if [[ -n "$pref_id" ]]; then
    _api_request "PUT" "/api/now/table/sys_user_preference/${pref_id}" '{"value":"b"}'
    expect_status "200"
    _api_request "DELETE" "/api/now/table/sys_user_preference/${pref_id}"
    expect_status "200 204"
  fi

  # SDK delete semantics for role/group are deactivation.
  _api_request "PUT" "/api/now/table/sys_user_role/${role_id}" '{"active":"false"}'
  expect_status "200"
  _api_request "PUT" "/api/now/table/sys_user_group/${group_id}" '{"active":"false"}'
  expect_status "200"
}

# -----------------------------
# Main
# -----------------------------

require_cmd curl
require_cmd jq
setup_missing_env
require_env SN_INSTANCE_URL
require_env SN_API_KEY

SN_INSTANCE_URL="${SN_INSTANCE_URL%/}"
safety_gate

section "Configuration"
info "Target host: $(extract_host "$SN_INSTANCE_URL")"
info "Instance: ${SN_INSTANCE_URL}"
info "Table for CRUD tests: ${SN_TEST_TABLE}"
info "Mutation tests: ${SN_RUN_MUTATION}"
info "Test level: ${SN_TEST_LEVEL}"
info "Verbose mode: ${SN_VERBOSE}"
info "Safety enforce PDI only: ${SN_ENFORCE_PDI_ONLY}"
info "Safety allow non-PDI override: ${SN_ALLOW_NON_PDI}"
info "Safety allow prod mutation override: ${SN_ALLOW_PROD_MUTATION}"
info "Safety confirm host guard: ${SN_CONFIRM_INSTANCE_HOST:-<not set>}"
info "Import Set table: ${SN_IMPORT_SET_TABLE:-<not set>}"
info "Catalog item id: ${SN_CATALOG_ITEM_SYS_ID:-<not set>}"
info "CMDB CI override: ${SN_CMDB_CI_CLASS:-<not set>}/${SN_CMDB_CI_SYS_ID:-<not set>}"
info "CMDB create class: ${SN_CMDB_CREATE_CLASS}"
info "Identity deep mutation: ${SN_IDENTITY_DEEP_MUTATION}"

section "Running Endpoint Smoke Suite"
run_test "Connectivity/Auth (API key)" test_connectivity_and_auth
run_test "Table API (CRUD + query + count + keys pattern)" test_table_crud_and_query
run_test "Aggregate/Stats API" test_aggregate_stats_endpoint
run_test "Batch API (/api/now/v1/batch)" test_batch_endpoint
run_test "Catalog table-backed endpoints" test_catalog_table_endpoints
run_test_full "Catalog table detail endpoints" test_catalog_table_detail_endpoints
run_test_full "Catalog variable endpoints" test_catalog_variable_endpoints
run_test "Catalog cart endpoints (/api/sn_sc/servicecatalog)" test_catalog_cart_endpoints
run_test_full "Catalog servicecatalog extended endpoints" test_catalog_servicecatalog_extended_endpoints
run_test_full "Catalog request tracking endpoints" test_catalog_request_tracking_endpoints
run_test "Attachment API (upload/list/download/delete)" test_attachment_flow
run_test "Import Set API" test_import_set_endpoints
run_test_full "Import Set API (multi-record)" test_import_set_multi_record_endpoint
run_test "CMDB endpoints" test_cmdb_endpoints
run_test_full "CMDB class metadata endpoints" test_cmdb_class_metadata_endpoints
run_test_full "CMDB relationship mutation endpoints" test_cmdb_relationship_mutation_endpoints
run_test_full "CMDB CI mutation endpoints" test_cmdb_ci_mutation_endpoints
run_test "Identity read endpoints" test_identity_endpoints
run_test_full "Identity detail endpoints" test_identity_detail_endpoints
run_test "Identity mutation endpoints" test_identity_mutation_endpoints
run_test_full "Identity deep mutation endpoints" test_identity_deep_mutation_endpoints
run_test_full "Batch mutation endpoint" test_batch_mutation_endpoint

section "Summary"
log "Total: ${TOTAL_COUNT}"
log "Pass : ${PASS_COUNT}"
log "Fail : ${FAIL_COUNT}"
log "Skip : ${SKIP_COUNT}"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  err "One or more tests failed."
  exit 1
fi

ok "All executed tests passed."
