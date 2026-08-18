#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Start the whole selective-disclosure demonstration:
#
#   1. an upstream scitt-ccf-ledger transparency service in Docker,
#   2. the mock MSRC issuance and storage service on port 8081,
#   3. the role based web control plane on port 8080.
#
# The ledger is the real upstream implementation at a pinned commit. The
# permissive development policy that upstream installs is replaced with one
# that only accepts the exact did:x509 issuer of this deployment's MSRC root,
# before anything is able to submit a statement.
#
# Nothing here performs cryptography. Certificates and statements are produced
# by the C++ tool, and receipts are verified by the official pyscitt package
# inside the submodule's own virtual environment.

set -euo pipefail

# --- constants ---------------------------------------------------------------

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SUBMODULE_DIR="${REPO_ROOT}/third_party/scitt-ccf-ledger"
SUBMODULE_SHA="5d471384ef7808cb0208ac3d141b4910b83cb48f"

CCF_VERSION="7.0.10"
CCF_HOST="${CCF_HOST:-127.0.0.1}"
CCF_PORT="${CCF_PORT:-8000}"
CCF_URL="https://${CCF_HOST}:${CCF_PORT}"

WEB_PORT="${WEB_PORT:-8080}"
MOCK_PORT="${MOCK_PORT:-8081}"

# One run must never disturb another, so every mutable name carries the run id.
RUN_ID="${RUN_ID:-$(date -u +%Y%m%d%H%M%S)-$$}"
STATE_DIR="${REPO_ROOT}/.demo/${RUN_ID}"
LEDGER_WORKSPACE="${STATE_DIR}/ledger-workspace"
LOG_DIR="${STATE_DIR}/logs"
TRUST_DIR="${STATE_DIR}/trust"
CA_DIR="${STATE_DIR}/ca"
DATA_DIR="${STATE_DIR}/data"
SHIM_DIR="${STATE_DIR}/shim"

DOCKER_TAG="${DOCKER_TAG:-scitt-ccf-ledger:${SUBMODULE_SHA:0:12}}"
CONTAINER_NAME="scitt-sd-demo-${RUN_ID}"
VOLUME_NAME="${CONTAINER_NAME}-vol"
IMAGE_TAG="${IMAGE_TAG:-scitt-selective-disclosure:demo}"

SUBMODULE_VENV="${SUBMODULE_DIR}/venv"
SUBMODULE_PYTHON="${SUBMODULE_VENV}/bin/python"
SUBMODULE_SCITT="${SUBMODULE_VENV}/bin/scitt"

APP_VENV="${REPO_ROOT}/.venv"
CLI_BIN="${SDC_CLI:-${REPO_ROOT}/build/scitt-sd}"

HEALTH_ATTEMPTS="${HEALTH_ATTEMPTS:-120}"
SMOKE_ONLY=0
KEEP_STATE=0

LEDGER_PID=""
MOCK_PID=""
WEB_PID=""

# --- output ------------------------------------------------------------------

log() { printf '[demo] %s\n' "$*" >&2; }
die() { printf '[demo] error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: demo/run.sh [--smoke] [--keep] [--help]

  --smoke   Run the end-to-end check once, print the result and exit.
  --keep    Leave the run's state directory in place after shutting down.
  --help    Show this message.

Environment:
  SDC_CLI          Path to the C++ scitt-sd tool. Built if absent.
  SDC_ISSUER_DID   Override the did:x509 the ledger policy pins.
  CCF_HOST         Ledger host, default 127.0.0.1.
  CCF_PORT         Ledger port, default 8000.
  WEB_PORT         Web control plane port, default 8080.
  MOCK_PORT        Mock MSRC port, default 8081.
EOF
}

# --- cleanup -----------------------------------------------------------------

stop_pid() {
    local name=$1 pid=$2
    [ -n "${pid}" ] || return 0
    kill -0 "${pid}" 2>/dev/null || return 0
    log "stopping ${name} (pid ${pid})"
    kill "${pid}" 2>/dev/null || true
    for _ in $(seq 1 50); do
        kill -0 "${pid}" 2>/dev/null || return 0
        sleep 0.2
    done
    kill -9 "${pid}" 2>/dev/null || true
}

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    stop_pid "web" "${WEB_PID}"
    stop_pid "mock MSRC" "${MOCK_PID}"
    # The ledger container is stopped by exact name so that a killed helper
    # process can never leave it behind.
    if command -v docker >/dev/null 2>&1; then
        if docker ps -a --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
            log "removing container ${CONTAINER_NAME}"
            docker stop --time 10 "${CONTAINER_NAME}" >/dev/null 2>&1 || true
            docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
        fi
        docker volume rm -f "${VOLUME_NAME}" >/dev/null 2>&1 || true
    fi
    stop_pid "ledger supervisor" "${LEDGER_PID}"
    if [ "${KEEP_STATE}" -eq 0 ] && [ -d "${STATE_DIR}" ]; then
        rm -rf "${STATE_DIR}"
    else
        log "state kept in ${STATE_DIR}"
    fi
    exit "${status}"
}

# --- preflight ---------------------------------------------------------------

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "$1 is required but was not found on PATH. $2"
}

check_prerequisites() {
    require_command docker "Install Docker and make sure the daemon is running."
    docker info >/dev/null 2>&1 ||
        die "the Docker daemon is not reachable. Start Docker and try again."
    require_command curl "Install curl."
    require_command git "Install git."
    HOST_PYTHON=""
    for candidate in python3.12 python3 python; do
        if command -v "${candidate}" >/dev/null 2>&1; then
            HOST_PYTHON=$(command -v "${candidate}")
            break
        fi
    done
    [ -n "${HOST_PYTHON}" ] || die "Python 3.12 or newer is required but was not found."
    "${HOST_PYTHON}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' ||
        die "Python 3.12 or newer is required. Found $("${HOST_PYTHON}" --version)."
    log "using python ${HOST_PYTHON} ($("${HOST_PYTHON}" --version 2>&1))"
}

check_submodule() {
    [ -f "${SUBMODULE_DIR}/docker/run-dev.sh" ] ||
        die "the scitt-ccf-ledger submodule is missing. Run: git submodule update --init --recursive"
    local actual
    actual=$(git -C "${SUBMODULE_DIR}" rev-parse HEAD)
    if [ "${actual}" != "${SUBMODULE_SHA}" ]; then
        log "submodule is at ${actual}, checking out the pinned ${SUBMODULE_SHA}"
        git -C "${SUBMODULE_DIR}" fetch --depth 1 origin "${SUBMODULE_SHA}" 2>/dev/null || true
        git -C "${SUBMODULE_DIR}" checkout --quiet "${SUBMODULE_SHA}" ||
            die "could not check out the pinned commit ${SUBMODULE_SHA}."
    fi
    log "scitt-ccf-ledger pinned at ${SUBMODULE_SHA}"
}

# The upstream scripts call `python`, which many distributions do not provide.
make_python_shim() {
    mkdir -p "${SHIM_DIR}"
    printf '#!/bin/sh\nexec "%s" "$@"\n' "${HOST_PYTHON}" >"${SHIM_DIR}/python"
    chmod 0755 "${SHIM_DIR}/python"
}

# --- the C++ tool ------------------------------------------------------------

build_cli() {
    if [ -x "${CLI_BIN}" ]; then
        log "using the C++ tool at ${CLI_BIN}"
        return 0
    fi
    if command -v cmake >/dev/null 2>&1 && [ -d /opt/ccf_virtual ]; then
        log "building the C++ tool with cmake"
        cmake -S "${REPO_ROOT}" -B "${REPO_ROOT}/build" \
            -DCMAKE_BUILD_TYPE=RelWithDebInfo >"${LOG_DIR}/cmake.log" 2>&1 ||
            die "cmake configuration failed. See ${LOG_DIR}/cmake.log."
        cmake --build "${REPO_ROOT}/build" --target scitt_sd_tool \
            >>"${LOG_DIR}/cmake.log" 2>&1 ||
            die "building scitt-sd failed. See ${LOG_DIR}/cmake.log."
    else
        log "building the C++ tool in Docker (CCF ${CCF_VERSION})"
        docker build --tag "${IMAGE_TAG}" \
            --build-arg "CCF_VERSION=${CCF_VERSION}" \
            "${REPO_ROOT}" >"${LOG_DIR}/image-build.log" 2>&1 ||
            {
                tail -n 80 "${LOG_DIR}/image-build.log" >&2 || true
                die "building ${IMAGE_TAG} failed. See ${LOG_DIR}/image-build.log."
            }
        log "creating a host wrapper for the containerised C++ tool"
        mkdir -p "${REPO_ROOT}/build"
        cat >"${REPO_ROOT}/build/scitt-sd" <<EOF
#!/usr/bin/env bash
# Generated by demo/run.sh. Runs the tool in ${IMAGE_TAG}, avoiding host ABI
# assumptions while exposing only paths the demo uses.
set -euo pipefail
exec docker run --rm \
    --user "\$(id -u):\$(id -g)" \
    --volume "${REPO_ROOT}:${REPO_ROOT}" \
    --volume /tmp:/tmp \
    --workdir "${REPO_ROOT}" \
    --entrypoint /opt/scitt-sd/bin/scitt-sd \
    "${IMAGE_TAG}" "\$@"
EOF
        chmod 0755 "${REPO_ROOT}/build/scitt-sd"
        CLI_BIN="${REPO_ROOT}/build/scitt-sd"
    fi
    [ -x "${CLI_BIN}" ] || die "the C++ tool was not produced at ${CLI_BIN}."
    "${CLI_BIN}" --version >/dev/null 2>&1 || die \
        "the C++ tool at ${CLI_BIN} could not be executed on this host. Build it
       natively against CCF ${CCF_VERSION}, or run the demo entirely in
       containers with: docker compose up --build"
    log "C++ tool ready: $("${CLI_BIN}" --version 2>&1 | head -n 1)"
}

# --- the application virtual environment -------------------------------------

setup_app_venv() {
    if [ ! -x "${APP_VENV}/bin/python" ]; then
        log "creating the application virtual environment"
        "${HOST_PYTHON}" -m venv "${APP_VENV}"
    fi
    if ! "${APP_VENV}/bin/python" -c 'import scitt_selective_disclosure' 2>/dev/null; then
        log "installing the application into ${APP_VENV}"
        "${APP_VENV}/bin/python" -m pip install --disable-pip-version-check --quiet \
            --upgrade pip
        "${APP_VENV}/bin/python" -m pip install --disable-pip-version-check --quiet \
            -e "${REPO_ROOT}"
    fi
    # The application must never gain a COSE, CBOR or cryptography dependency.
    if "${APP_VENV}/bin/python" -c 'import pycose' 2>/dev/null ||
        "${APP_VENV}/bin/python" -c 'import cbor2' 2>/dev/null; then
        die "the application virtual environment contains pycose or cbor2.
       Receipt verification belongs to the submodule's own environment, not to
       this one. Recreate ${APP_VENV} from pyproject.toml."
    fi
}

# --- the ledger --------------------------------------------------------------

build_ledger_image() {
    if docker image inspect "${DOCKER_TAG}" >/dev/null 2>&1; then
        log "reusing the ledger image ${DOCKER_TAG}"
        return 0
    fi
    log "building the ledger image ${DOCKER_TAG} (this takes a while)"
    docker build --progress=plain --tag "${DOCKER_TAG}" \
        --build-arg "CCF_VERSION=${CCF_VERSION}" \
        --file "${SUBMODULE_DIR}/docker/Dockerfile" \
        "${SUBMODULE_DIR}" >"${LOG_DIR}/ledger-build.log" 2>&1 ||
        {
            cat "${LOG_DIR}/ledger-build.log" >&2 || true
            die "building ${DOCKER_TAG} failed. See ${LOG_DIR}/ledger-build.log."
        }
}

start_ledger() {
    log "starting the ledger as ${CONTAINER_NAME}"
    (
        cd "${SUBMODULE_DIR}"
        PATH="${SHIM_DIR}:${PATH}" \
        CCF_HOST="${CCF_HOST}" \
        CCF_PORT="${CCF_PORT}" \
        DOCKER_TAG="${DOCKER_TAG}" \
        CONTAINER_NAME="${CONTAINER_NAME}" \
        WORKSPACE="${LEDGER_WORKSPACE}" \
        NODE_COUNT=1 \
            ./docker/run-dev.sh
    ) >"${LOG_DIR}/ledger.log" 2>&1 &
    LEDGER_PID=$!
}

wait_for_ledger() {
    log "waiting for the ledger at ${CCF_URL}"
    local attempt
    for attempt in $(seq 1 "${HEALTH_ATTEMPTS}"); do
        if ! kill -0 "${LEDGER_PID}" 2>/dev/null; then
            tail -n 40 "${LOG_DIR}/ledger.log" >&2 || true
            die "the ledger supervisor exited. See ${LOG_DIR}/ledger.log."
        fi
        if curl --silent --fail --insecure --max-time 5 \
            "${CCF_URL}/.well-known/scitt-keys" >/dev/null 2>&1; then
            log "ledger is serving service keys after ${attempt}s"
            return 0
        fi
        sleep 1
    done
    tail -n 40 "${LOG_DIR}/ledger.log" >&2 || true
    die "the ledger did not become ready. See ${LOG_DIR}/ledger.log."
}

wait_for_submodule_venv() {
    local attempt
    for attempt in $(seq 1 "${HEALTH_ATTEMPTS}"); do
        if [ -x "${SUBMODULE_SCITT}" ] &&
            "${SUBMODULE_PYTHON}" -c 'import pyscitt.verify' 2>/dev/null; then
            log "the submodule virtual environment is ready"
            return 0
        fi
        sleep 1
    done
    die "the submodule virtual environment was not created. See ${LOG_DIR}/ledger.log."
}

# --- MSRC issuance material --------------------------------------------------

init_msrc_root() {
    log "creating the MSRC root of trust with the C++ tool"
    mkdir -p "${CA_DIR}"
    "${CLI_BIN}" root init \
        --private-key "${CA_DIR}/root.key" \
        --certificate "${CA_DIR}/root.pem" \
        --issuer-json "${CA_DIR}/issuer.json" ||
        die "could not create the MSRC root identity."
    chmod 0600 "${CA_DIR}/root.key"
    ISSUER_DID=$(
        "${HOST_PYTHON}" -c \
            'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["issuer_did"])' \
            "${CA_DIR}/issuer.json"
    )
    ISSUER_DID="${SDC_ISSUER_DID:-${ISSUER_DID}}"
    ISSUER_DID=$(printf '%s' "${ISSUER_DID}" | tr -d '[:space:]')
    [ -n "${ISSUER_DID}" ] || die "the C++ tool did not report an issuer did:x509."
    case "${ISSUER_DID}" in
        did:x509:0:*) ;;
        *) die "the reported issuer is not a did:x509 identifier: ${ISSUER_DID}" ;;
    esac
    log "MSRC issuer: ${ISSUER_DID}"
}

# --- ledger policy -----------------------------------------------------------

# Upstream's run-dev.sh installs a policy that accepts everything. It is
# replaced here, before the web control plane starts, so that no submission is
# ever accepted under the permissive policy. A failure is fatal: the demo never
# falls back to the permissive policy.
restrict_ledger_policy() {
    log "replacing the permissive development policy"
    local configuration="${STATE_DIR}/ledger-configuration.json"
    "${HOST_PYTHON}" "${REPO_ROOT}/demo/make_policy.py" \
        --issuer "${ISSUER_DID}" \
        --output "${configuration}" ||
        die "could not build the ledger configuration."

    # propose_configuration votes with must_pass semantics, so a rejected or
    # unaccepted proposal exits non-zero rather than leaving the old policy.
    "${SUBMODULE_SCITT}" governance propose_configuration \
        --url "${CCF_URL}" \
        --member-key "${LEDGER_WORKSPACE}/member0_privk.pem" \
        --member-cert "${LEDGER_WORKSPACE}/member0_cert.pem" \
        --development \
        --configuration "${configuration}" \
        >"${LOG_DIR}/policy.log" 2>&1 ||
        {
            tail -n 30 "${LOG_DIR}/policy.log" >&2 || true
            die "the restricted policy was not accepted. The permissive policy is
       still in force, so the demo is stopping instead of accepting
       submissions. See ${LOG_DIR}/policy.log."
        }
    log "the ledger now accepts only ${ISSUER_DID}"
}

# --- trust store -------------------------------------------------------------

# Fetched independently of any submission, exactly as a verifier would.
fetch_trust_store() {
    log "fetching ${CCF_URL}/.well-known/scitt-keys"
    mkdir -p "${TRUST_DIR}"
    curl --silent --show-error --fail --insecure --max-time 30 \
        --output "${TRUST_DIR}/scitt-keys.cbor" \
        "${CCF_URL}/.well-known/scitt-keys" ||
        die "could not fetch the transparency service keys."
    [ -s "${TRUST_DIR}/scitt-keys.cbor" ] ||
        die "the transparency service returned an empty key set."
    curl --silent --show-error --fail --insecure --max-time 30 \
        --output "${TRUST_DIR}/service-cert.pem" \
        "${CCF_URL}/node/network" >/dev/null 2>&1 || true
    log "trust store written to ${TRUST_DIR}"
}

# --- application services ----------------------------------------------------

export_settings() {
    export SDC_CLI="${CLI_BIN}"
    export SDC_DATA_DIR="${DATA_DIR}"
    export SDC_SCITT_URL="${CCF_URL}"
    export SDC_SCITT_INSECURE=1
    export SDC_MSRC_URL="http://127.0.0.1:${MOCK_PORT}"
    export SDC_MSRC_ROOT_KEY="${CA_DIR}/root.key"
    export SDC_MSRC_ROOT_CERT="${CA_DIR}/root.pem"
    export SDC_SCITT_VERIFIER_PYTHON="${SUBMODULE_PYTHON}"
    export SDC_SCITT_VERIFIER_WRAPPER="${REPO_ROOT}/demo/official_verify.py"
    export PYTHONDONTWRITEBYTECODE=1
}

start_services() {
    mkdir -p "${DATA_DIR}"
    log "starting the mock MSRC on port ${MOCK_PORT}"
    "${APP_VENV}/bin/python" -m uvicorn \
        --factory scitt_selective_disclosure.mock_msrc.app:create_app \
        --host 127.0.0.1 --port "${MOCK_PORT}" \
        >"${LOG_DIR}/mock.log" 2>&1 &
    MOCK_PID=$!
    wait_for_http "http://127.0.0.1:${MOCK_PORT}/healthz" "mock MSRC" "${LOG_DIR}/mock.log"

    log "starting the web control plane on port ${WEB_PORT}"
    "${APP_VENV}/bin/python" -m uvicorn \
        --factory scitt_selective_disclosure.web.app:create_app \
        --host 127.0.0.1 --port "${WEB_PORT}" \
        >"${LOG_DIR}/web.log" 2>&1 &
    WEB_PID=$!
    wait_for_http "http://127.0.0.1:${WEB_PORT}/healthz" "web" "${LOG_DIR}/web.log"
}

wait_for_http() {
    local url=$1 name=$2 logfile=$3 attempt
    for attempt in $(seq 1 60); do
        if curl --silent --fail --max-time 5 "${url}" >/dev/null 2>&1; then
            log "${name} is ready"
            return 0
        fi
        sleep 0.5
    done
    tail -n 30 "${logfile}" >&2 || true
    die "${name} did not become ready. See ${logfile}."
}

# --- end to end check --------------------------------------------------------

run_smoke() {
    log "running the end-to-end check"
    "${APP_VENV}/bin/python" "${REPO_ROOT}/demo/smoke.py" \
        --web "http://127.0.0.1:${WEB_PORT}" \
        --mock "http://127.0.0.1:${MOCK_PORT}" \
        --trust-store "${TRUST_DIR}/scitt-keys.cbor"
}

# --- main --------------------------------------------------------------------

main() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --smoke) SMOKE_ONLY=1 ;;
            --keep) KEEP_STATE=1 ;;
            --help | -h) usage; return 0 ;;
            *) usage >&2; die "unknown argument: $1" ;;
        esac
        shift
    done

    check_prerequisites
    check_submodule

    mkdir -p "${LOG_DIR}"
    chmod 0700 "${STATE_DIR}"
    trap cleanup EXIT INT TERM

    make_python_shim
    setup_app_venv
    build_cli
    build_ledger_image
    start_ledger
    wait_for_ledger
    wait_for_submodule_venv
    init_msrc_root
    restrict_ledger_policy
    fetch_trust_store
    export_settings
    start_services

    if [ "${SMOKE_ONLY}" -eq 1 ]; then
        run_smoke
        log "smoke check passed"
        return 0
    fi

    cat >&2 <<EOF

  Web control plane   http://127.0.0.1:${WEB_PORT}
  Mock MSRC           http://127.0.0.1:${MOCK_PORT}
  Transparency ledger ${CCF_URL}
  Trust store         ${TRUST_DIR}/scitt-keys.cbor
  MSRC root           ${CA_DIR}/root.pem
  Logs                ${LOG_DIR}

  Press Ctrl-C to stop everything.

EOF
    while kill -0 "${WEB_PID}" 2>/dev/null && kill -0 "${MOCK_PID}" 2>/dev/null; do
        sleep 1
    done
    die "a service exited unexpectedly. See ${LOG_DIR}."
}

main "$@"
