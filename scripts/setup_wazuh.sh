#!/usr/bin/env bash
# setup_wazuh.sh — Deploy Wazuh 4.9.x single-node via Docker Compose
# Usage: ./setup_wazuh.sh [--stop] [--status]
set -euo pipefail

WAZUH_DIR="/tmp/wazuh-docker"
COMPOSE_FILE="${WAZUH_DIR}/docker-compose.yml"
CERTS_DIR="${WAZUH_DIR}/certs"
WAZUH_VERSION="4.9.2"
API_USER="wazuh-wui"
API_PASS='MyS3cr3tP4ssw0rd*'
INDEXER_PASS="admin"  # default indexer admin password

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Helper: detect docker compose command (v2 plugin vs standalone)
# ---------------------------------------------------------------------------
get_compose_cmd() {
    if docker compose version &>/dev/null; then
        echo "docker compose"
    elif command -v docker-compose &>/dev/null; then
        echo "docker-compose"
    else
        echo ""
    fi
}

# ---------------------------------------------------------------------------
# --status: show current state and exit
# ---------------------------------------------------------------------------
do_status() {
    local compose_cmd
    compose_cmd=$(get_compose_cmd)
    if [[ -z "$compose_cmd" ]]; then
        err "docker compose not found"
        exit 1
    fi
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        echo "Wazuh is not deployed (no compose file at ${COMPOSE_FILE})"
        exit 0
    fi
    echo "=== Wazuh Docker status ==="
    $compose_cmd -f "$COMPOSE_FILE" ps
    exit 0
}

# ---------------------------------------------------------------------------
# --stop: bring everything down and exit
# ---------------------------------------------------------------------------
do_stop() {
    local compose_cmd
    compose_cmd=$(get_compose_cmd)
    if [[ -z "$compose_cmd" ]]; then
        err "docker compose not found"
        exit 1
    fi
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        warn "Nothing to stop (no compose file at ${COMPOSE_FILE})"
        exit 0
    fi
    log "Stopping Wazuh containers..."
    $compose_cmd -f "$COMPOSE_FILE" down --remove-orphans
    log "Wazuh stopped."
    exit 0
}

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --stop)   do_stop ;;
        --status) do_status ;;
        --help|-h)
            echo "Usage: $0 [--stop] [--status] [--help]"
            echo "  (no flags)  Deploy Wazuh 4.9.x single-node via Docker"
            echo "  --stop      Bring down the Wazuh stack"
            echo "  --status    Show container status"
            exit 0
            ;;
        *)
            err "Unknown flag: $arg"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------
log "Checking prerequisites..."

if ! command -v docker &>/dev/null; then
    err "docker is not installed. Install Docker Engine first."
    exit 1
fi

COMPOSE_CMD=$(get_compose_cmd)
if [[ -z "$COMPOSE_CMD" ]]; then
    err "docker compose (v2 plugin or docker-compose standalone) is not installed."
    exit 1
fi

log "Using compose command: ${COMPOSE_CMD}"

# ---------------------------------------------------------------------------
# Idempotency: skip if already running
# ---------------------------------------------------------------------------
if [[ -f "$COMPOSE_FILE" ]]; then
    running=$($COMPOSE_CMD -f "$COMPOSE_FILE" ps --format '{{.State}}' 2>/dev/null | grep -c "running" || true)
    if [[ "$running" -ge 3 ]]; then
        warn "Wazuh stack is already running (${running} containers up). Skipping deploy."
        warn "Use --stop first if you want to redeploy."
        $COMPOSE_CMD -f "$COMPOSE_FILE" ps
        exit 0
    fi
fi

# ---------------------------------------------------------------------------
# Create working directory
# ---------------------------------------------------------------------------
log "Creating ${WAZUH_DIR}..."
mkdir -p "$WAZUH_DIR"
mkdir -p "$CERTS_DIR"

# ---------------------------------------------------------------------------
# Generate self-signed TLS certificates
# ---------------------------------------------------------------------------
if [[ -f "${CERTS_DIR}/root-ca.pem" ]]; then
    log "TLS certificates already exist, skipping generation."
else
    log "Generating self-signed TLS certificates..."

    # Root CA
    openssl genrsa -out "${CERTS_DIR}/root-ca-key.pem" 2048 2>/dev/null
    openssl req -new -x509 -sha256 -key "${CERTS_DIR}/root-ca-key.pem" \
        -out "${CERTS_DIR}/root-ca.pem" -days 730 \
        -subj "/C=US/ST=CA/L=SanFrancisco/O=Wazuh/CN=wazuh-root-ca" 2>/dev/null

    # Indexer cert
    openssl genrsa -out "${CERTS_DIR}/indexer-key.pem" 2048 2>/dev/null
    openssl req -new -key "${CERTS_DIR}/indexer-key.pem" \
        -out "${CERTS_DIR}/indexer.csr" \
        -subj "/C=US/ST=CA/L=SanFrancisco/O=Wazuh/CN=wazuh-indexer" 2>/dev/null

    cat > "${CERTS_DIR}/indexer-ext.cnf" <<EXTEOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = wazuh-indexer
DNS.2 = localhost
IP.1 = 127.0.0.1
EXTEOF

    openssl x509 -req -in "${CERTS_DIR}/indexer.csr" \
        -CA "${CERTS_DIR}/root-ca.pem" -CAkey "${CERTS_DIR}/root-ca-key.pem" \
        -CAcreateserial -out "${CERTS_DIR}/indexer.pem" -days 730 \
        -sha256 -extensions v3_req -extfile "${CERTS_DIR}/indexer-ext.cnf" 2>/dev/null

    # Manager cert
    openssl genrsa -out "${CERTS_DIR}/manager-key.pem" 2048 2>/dev/null
    openssl req -new -key "${CERTS_DIR}/manager-key.pem" \
        -out "${CERTS_DIR}/manager.csr" \
        -subj "/C=US/ST=CA/L=SanFrancisco/O=Wazuh/CN=wazuh-manager" 2>/dev/null

    cat > "${CERTS_DIR}/manager-ext.cnf" <<EXTEOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = wazuh-manager
DNS.2 = localhost
IP.1 = 127.0.0.1
EXTEOF

    openssl x509 -req -in "${CERTS_DIR}/manager.csr" \
        -CA "${CERTS_DIR}/root-ca.pem" -CAkey "${CERTS_DIR}/root-ca-key.pem" \
        -CAcreateserial -out "${CERTS_DIR}/manager.pem" -days 730 \
        -sha256 -extensions v3_req -extfile "${CERTS_DIR}/manager-ext.cnf" 2>/dev/null

    # Dashboard cert
    openssl genrsa -out "${CERTS_DIR}/dashboard-key.pem" 2048 2>/dev/null
    openssl req -new -key "${CERTS_DIR}/dashboard-key.pem" \
        -out "${CERTS_DIR}/dashboard.csr" \
        -subj "/C=US/ST=CA/L=SanFrancisco/O=Wazuh/CN=wazuh-dashboard" 2>/dev/null

    cat > "${CERTS_DIR}/dashboard-ext.cnf" <<EXTEOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = wazuh-dashboard
DNS.2 = localhost
IP.1 = 127.0.0.1
EXTEOF

    openssl x509 -req -in "${CERTS_DIR}/dashboard.csr" \
        -CA "${CERTS_DIR}/root-ca.pem" -CAkey "${CERTS_DIR}/root-ca-key.pem" \
        -CAcreateserial -out "${CERTS_DIR}/dashboard.pem" -days 730 \
        -sha256 -extensions v3_req -extfile "${CERTS_DIR}/dashboard-ext.cnf" 2>/dev/null

    # Fix permissions — Wazuh containers run as non-root and need to read these
    chmod 644 "${CERTS_DIR}"/*.pem
    chmod 600 "${CERTS_DIR}"/*-key.pem

    log "Certificates generated in ${CERTS_DIR}"
fi

# ---------------------------------------------------------------------------
# Write docker-compose.yml
# ---------------------------------------------------------------------------
log "Writing ${COMPOSE_FILE}..."

cat > "$COMPOSE_FILE" <<COMPOSEEOF
# Wazuh ${WAZUH_VERSION} single-node Docker Compose
# Generated by setup_wazuh.sh

services:
  wazuh-indexer:
    image: wazuh/wazuh-indexer:${WAZUH_VERSION}
    container_name: wazuh-indexer
    hostname: wazuh-indexer
    restart: unless-stopped
    ports:
      - "9200:9200"
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
      - "bootstrap.memory_lock=true"
      - "discovery.type=single-node"
      - "plugins.security.ssl.http.enabled=true"
      - "plugins.security.ssl.http.pemcert_filepath=/usr/share/wazuh-indexer/certs/indexer.pem"
      - "plugins.security.ssl.http.pemkey_filepath=/usr/share/wazuh-indexer/certs/indexer-key.pem"
      - "plugins.security.ssl.http.pemtrustedcas_filepath=/usr/share/wazuh-indexer/certs/root-ca.pem"
      - "plugins.security.ssl.transport.enforce_hostname_verification=false"
      - "plugins.security.ssl.transport.pemcert_filepath=/usr/share/wazuh-indexer/certs/indexer.pem"
      - "plugins.security.ssl.transport.pemkey_filepath=/usr/share/wazuh-indexer/certs/indexer-key.pem"
      - "plugins.security.ssl.transport.pemtrustedcas_filepath=/usr/share/wazuh-indexer/certs/root-ca.pem"
      - "compatibility.override_main_response_version=true"
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - wazuh-indexer-data:/var/lib/wazuh-indexer
      - ${CERTS_DIR}/root-ca.pem:/usr/share/wazuh-indexer/certs/root-ca.pem:ro
      - ${CERTS_DIR}/indexer.pem:/usr/share/wazuh-indexer/certs/indexer.pem:ro
      - ${CERTS_DIR}/indexer-key.pem:/usr/share/wazuh-indexer/certs/indexer-key.pem:ro
    healthcheck:
      test: ["CMD-SHELL", "curl -sku admin:admin https://localhost:9200/_cluster/health | grep -qE '\"status\":\"(green|yellow)\"'"]
      interval: 15s
      timeout: 10s
      retries: 20

  wazuh-manager:
    image: wazuh/wazuh-manager:${WAZUH_VERSION}
    container_name: wazuh-manager
    hostname: wazuh-manager
    restart: unless-stopped
    ports:
      - "1514:1514"
      - "1515:1515"
      - "55000:55000"
    environment:
      - "INDEXER_URL=https://wazuh-indexer:9200"
      - "INDEXER_USERNAME=admin"
      - "INDEXER_PASSWORD=${INDEXER_PASS}"
      - "FILEBEAT_SSL_VERIFICATION_MODE=none"
      - "SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/root-ca.pem"
      - "SSL_CERTIFICATE=/etc/ssl/filebeat.pem"
      - "SSL_KEY=/etc/ssl/filebeat-key.pem"
      - "API_USERNAME=${API_USER}"
      - "API_PASSWORD=${API_PASS}"
    volumes:
      - wazuh-manager-data:/var/ossec/data
      - wazuh-manager-etc:/var/ossec/etc
      - wazuh-manager-logs:/var/ossec/logs
      - wazuh-manager-queue:/var/ossec/queue
      - wazuh-manager-api:/var/ossec/api/configuration
      - ${CERTS_DIR}/root-ca.pem:/etc/ssl/root-ca.pem:ro
      - ${CERTS_DIR}/manager.pem:/etc/ssl/filebeat.pem:ro
      - ${CERTS_DIR}/manager-key.pem:/etc/ssl/filebeat-key.pem:ro
    depends_on:
      wazuh-indexer:
        condition: service_healthy

  wazuh-dashboard:
    image: wazuh/wazuh-dashboard:${WAZUH_VERSION}
    container_name: wazuh-dashboard
    hostname: wazuh-dashboard
    restart: unless-stopped
    ports:
      - "5601:5601"
    environment:
      - "INDEXER_USERNAME=admin"
      - "INDEXER_PASSWORD=${INDEXER_PASS}"
      - "WAZUH_API_URL=https://wazuh-manager"
      - "DASHBOARD_USERNAME=${API_USER}"
      - "DASHBOARD_PASSWORD=${API_PASS}"
      - "API_USERNAME=${API_USER}"
      - "API_PASSWORD=${API_PASS}"
      - "SERVER_SSL_ENABLED=true"
      - "SERVER_SSL_CERTIFICATE=/usr/share/wazuh-dashboard/certs/dashboard.pem"
      - "SERVER_SSL_KEY=/usr/share/wazuh-dashboard/certs/dashboard-key.pem"
      - "OPENSEARCH_SSL_CERTIFICATEAUTHORITIES=/usr/share/wazuh-dashboard/certs/root-ca.pem"
    volumes:
      - ${CERTS_DIR}/root-ca.pem:/usr/share/wazuh-dashboard/certs/root-ca.pem:ro
      - ${CERTS_DIR}/dashboard.pem:/usr/share/wazuh-dashboard/certs/dashboard.pem:ro
      - ${CERTS_DIR}/dashboard-key.pem:/usr/share/wazuh-dashboard/certs/dashboard-key.pem:ro
    depends_on:
      wazuh-indexer:
        condition: service_healthy

volumes:
  wazuh-indexer-data:
  wazuh-manager-data:
  wazuh-manager-etc:
  wazuh-manager-logs:
  wazuh-manager-queue:
  wazuh-manager-api:
COMPOSEEOF

log "Compose file written."

# ---------------------------------------------------------------------------
# Pull images and start
# ---------------------------------------------------------------------------
log "Starting Wazuh stack (this may take a few minutes on first run)..."
$COMPOSE_CMD -f "$COMPOSE_FILE" up -d

# ---------------------------------------------------------------------------
# Wait for Wazuh API to become healthy
# ---------------------------------------------------------------------------
log "Waiting for Wazuh API to become healthy..."

MAX_RETRIES=40
RETRY_INTERVAL=10
for i in $(seq 1 $MAX_RETRIES); do
    if curl -sk -u "${API_USER}:${API_PASS}" \
        "https://localhost:55000/?pretty" 2>/dev/null | grep -q '"title"'; then
        log "Wazuh API is healthy!"
        break
    fi
    if [[ "$i" -eq "$MAX_RETRIES" ]]; then
        warn "API did not become healthy after $((MAX_RETRIES * RETRY_INTERVAL))s."
        warn "Check logs: $COMPOSE_CMD -f $COMPOSE_FILE logs wazuh-manager"
        exit 1
    fi
    echo -ne "  Attempt ${i}/${MAX_RETRIES} — retrying in ${RETRY_INTERVAL}s...\r"
    sleep "$RETRY_INTERVAL"
done

# ---------------------------------------------------------------------------
# Gather info
# ---------------------------------------------------------------------------
MANAGER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' wazuh-manager 2>/dev/null || echo "unknown")
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

# Fetch the agent enrollment key from the API
ENROLLMENT_KEY=""
AGENTS_RESP=$(curl -sk -u "${API_USER}:${API_PASS}" \
    "https://localhost:55000/agents?pretty&limit=1&select=key" 2>/dev/null || true)

# Try to get the registration password from authd config
ENROLLMENT_KEY=$(docker exec wazuh-manager cat /var/ossec/etc/authd.pass 2>/dev/null || echo "")
if [[ -z "$ENROLLMENT_KEY" ]]; then
    ENROLLMENT_KEY="(use the Wazuh API or agent enrollment workflow)"
fi

# ---------------------------------------------------------------------------
# Print summary
# ---------------------------------------------------------------------------
echo ""
echo "==========================================================="
echo "  Wazuh ${WAZUH_VERSION} — Single-Node Docker Deployment"
echo "==========================================================="
echo ""
echo "  Manager container IP : ${MANAGER_IP}"
echo "  Manager host ports   : 1514 (registration), 1515 (comms), 55000 (API)"
echo "  Indexer              : https://localhost:9200"
echo "  Dashboard            : https://localhost:5601"
echo ""
echo "  API URL              : https://${HOST_IP}:55000"
echo "  API credentials      : ${API_USER} / ${API_PASS}"
echo "  Dashboard login      : ${API_USER} / ${API_PASS}"
echo "  Indexer admin        : admin / ${INDEXER_PASS}"
echo ""
echo "  Enrollment key       : ${ENROLLMENT_KEY}"
echo ""
echo "  Agent registration (from the VM guest):"
echo "    WAZUH_MANAGER=\"${HOST_IP}\" apt install wazuh-agent"
echo "    # or for Windows:"
echo "    Invoke-WebRequest -Uri https://${HOST_IP}:55000 ..."
echo ""
echo "==========================================================="
echo "  spec.yaml EDR config snippet:"
echo "==========================================================="
echo ""
echo "  edrs:"
echo "    - wazuh"
echo "  # Wazuh manager reachable from guest at ${HOST_IP}:1514"
echo ""
echo "==========================================================="
echo ""
echo "Management:"
echo "  Status : $0 --status"
echo "  Stop   : $0 --stop"
echo "  Logs   : $COMPOSE_CMD -f $COMPOSE_FILE logs -f"
echo ""
