#!/usr/bin/env bash
# setup_elastic.sh — Deploy Elastic Security 8.15.x via Docker Compose
# Usage: ./setup_elastic.sh [--stop] [--status] [--help]
#
# Deploys: Elasticsearch + Kibana + Fleet Server
# Then:    creates Fleet Server policy + Elastic Defend integration policy,
#          installs prebuilt detection rules,
#          generates agent enrollment token,
#          prints agent install command for the Windows VM.
set -euo pipefail

ELASTIC_DIR="/tmp/elastic-docker"
COMPOSE_FILE="${ELASTIC_DIR}/docker-compose.yml"
CERTS_DIR="${ELASTIC_DIR}/certs"
TOKEN_FILE="${ELASTIC_DIR}/enrollment_token"
ELASTIC_VERSION="8.15.3"
ELASTIC_PASSWORD="changeme"
KIBANA_SYSTEM_PASSWORD="changeme"

ES_URL="https://localhost:9200"
KIBANA_URL="http://localhost:5601"
FLEET_URL="https://localhost:8220"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*" >&2; }

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
# --status
# ---------------------------------------------------------------------------
do_status() {
    local compose_cmd
    compose_cmd=$(get_compose_cmd)
    if [[ -z "$compose_cmd" ]]; then err "docker compose not found"; exit 1; fi
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        echo "Elastic stack is not deployed (no compose file at ${COMPOSE_FILE})"
        exit 0
    fi
    echo "=== Elastic Docker status ==="
    $compose_cmd -f "$COMPOSE_FILE" ps
    if [[ -f "$TOKEN_FILE" ]]; then
        echo ""
        echo "Enrollment token: $(cat "$TOKEN_FILE")"
    fi
    exit 0
}

# ---------------------------------------------------------------------------
# --stop
# ---------------------------------------------------------------------------
do_stop() {
    local compose_cmd
    compose_cmd=$(get_compose_cmd)
    if [[ -z "$compose_cmd" ]]; then err "docker compose not found"; exit 1; fi
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        warn "Nothing to stop (no compose file at ${COMPOSE_FILE})"
        exit 0
    fi
    log "Stopping Elastic stack..."
    $compose_cmd -f "$COMPOSE_FILE" down --remove-orphans
    log "Elastic stack stopped."
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
            echo "  (no flags)  Deploy Elastic Security ${ELASTIC_VERSION} via Docker"
            echo "  --stop      Bring down the Elastic stack"
            echo "  --status    Show container status + enrollment token"
            exit 0
            ;;
        *)
            err "Unknown flag: $arg"
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
log "Checking prerequisites..."

if ! command -v docker &>/dev/null; then
    err "docker is not installed."
    exit 1
fi

COMPOSE_CMD=$(get_compose_cmd)
if [[ -z "$COMPOSE_CMD" ]]; then
    err "docker compose (v2 plugin or docker-compose) not found."
    exit 1
fi
log "Using compose command: ${COMPOSE_CMD}"

# Check port 9200 conflict (Wazuh)
if ss -tlnp 2>/dev/null | grep -q ':9200 '; then
    err "Port 9200 already in use (Wazuh?). Stop it first: scripts/setup_wazuh.sh --stop"
    exit 1
fi

# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------
if [[ -f "$COMPOSE_FILE" ]]; then
    running=$($COMPOSE_CMD -f "$COMPOSE_FILE" ps --format '{{.State}}' 2>/dev/null | grep -c "running" || true)
    if [[ "$running" -ge 3 ]]; then
        warn "Elastic stack already running (${running} containers). Use --stop to redeploy."
        $COMPOSE_CMD -f "$COMPOSE_FILE" ps
        if [[ -f "$TOKEN_FILE" ]]; then
            echo ""
            echo "Enrollment token: $(cat "$TOKEN_FILE")"
        fi
        exit 0
    fi
fi

# ---------------------------------------------------------------------------
# Create dirs
# ---------------------------------------------------------------------------
log "Creating ${ELASTIC_DIR}..."
mkdir -p "$ELASTIC_DIR" "$CERTS_DIR"

# ---------------------------------------------------------------------------
# TLS certificates
# ---------------------------------------------------------------------------
if [[ -f "${CERTS_DIR}/ca.pem" ]]; then
    log "TLS certificates exist, skipping."
else
    log "Generating self-signed TLS certificates..."

    # CA
    openssl genrsa -out "${CERTS_DIR}/ca-key.pem" 2048 2>/dev/null
    openssl req -new -x509 -sha256 -key "${CERTS_DIR}/ca-key.pem" \
        -out "${CERTS_DIR}/ca.pem" -days 730 \
        -subj "/C=US/ST=CA/O=MalgenLab/CN=elastic-ca" 2>/dev/null

    # Elasticsearch cert
    openssl genrsa -out "${CERTS_DIR}/es-key.pem" 2048 2>/dev/null
    openssl req -new -key "${CERTS_DIR}/es-key.pem" \
        -out "${CERTS_DIR}/es.csr" \
        -subj "/C=US/ST=CA/O=MalgenLab/CN=elasticsearch" 2>/dev/null

    cat > "${CERTS_DIR}/es-ext.cnf" <<EXTEOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = elasticsearch
DNS.2 = localhost
IP.1 = 127.0.0.1
EXTEOF

    openssl x509 -req -in "${CERTS_DIR}/es.csr" \
        -CA "${CERTS_DIR}/ca.pem" -CAkey "${CERTS_DIR}/ca-key.pem" \
        -CAcreateserial -out "${CERTS_DIR}/es.pem" -days 730 \
        -sha256 -extensions v3_req -extfile "${CERTS_DIR}/es-ext.cnf" 2>/dev/null

    # Kibana cert (kept for potential future TLS re-enable)
    openssl genrsa -out "${CERTS_DIR}/kibana-key.pem" 2048 2>/dev/null
    openssl req -new -key "${CERTS_DIR}/kibana-key.pem" \
        -out "${CERTS_DIR}/kibana.csr" \
        -subj "/C=US/ST=CA/O=MalgenLab/CN=kibana" 2>/dev/null

    cat > "${CERTS_DIR}/kibana-ext.cnf" <<EXTEOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = kibana
DNS.2 = localhost
IP.1 = 127.0.0.1
EXTEOF

    openssl x509 -req -in "${CERTS_DIR}/kibana.csr" \
        -CA "${CERTS_DIR}/ca.pem" -CAkey "${CERTS_DIR}/ca-key.pem" \
        -CAcreateserial -out "${CERTS_DIR}/kibana.pem" -days 730 \
        -sha256 -extensions v3_req -extfile "${CERTS_DIR}/kibana-ext.cnf" 2>/dev/null

    # Fleet Server cert (SAN includes 10.0.2.2 for QEMU guest access)
    openssl genrsa -out "${CERTS_DIR}/fleet-key.pem" 2048 2>/dev/null
    openssl req -new -key "${CERTS_DIR}/fleet-key.pem" \
        -out "${CERTS_DIR}/fleet.csr" \
        -subj "/C=US/ST=CA/O=MalgenLab/CN=fleet-server" 2>/dev/null

    cat > "${CERTS_DIR}/fleet-ext.cnf" <<EXTEOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = fleet-server
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = 10.0.2.2
EXTEOF

    openssl x509 -req -in "${CERTS_DIR}/fleet.csr" \
        -CA "${CERTS_DIR}/ca.pem" -CAkey "${CERTS_DIR}/ca-key.pem" \
        -CAcreateserial -out "${CERTS_DIR}/fleet.pem" -days 730 \
        -sha256 -extensions v3_req -extfile "${CERTS_DIR}/fleet-ext.cnf" 2>/dev/null

    # All certs world-readable (ES container runs as UID 1000, not host user)
    chmod 644 "${CERTS_DIR}"/*.pem

    log "Certificates generated."
fi

# ---------------------------------------------------------------------------
# Docker Compose
# ---------------------------------------------------------------------------
log "Writing ${COMPOSE_FILE}..."

cat > "$COMPOSE_FILE" <<COMPOSEEOF
# Elastic Security ${ELASTIC_VERSION} — single-node Docker Compose
# Generated by setup_elastic.sh

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:${ELASTIC_VERSION}
    container_name: elasticsearch
    hostname: elasticsearch
    restart: unless-stopped
    ports:
      - "9200:9200"
    environment:
      - node.name=elasticsearch
      - cluster.name=malgen-elastic
      - discovery.type=single-node
      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}
      - xpack.security.enabled=true
      - xpack.security.http.ssl.enabled=true
      - xpack.security.http.ssl.key=/usr/share/elasticsearch/config/certs/es-key.pem
      - xpack.security.http.ssl.certificate=/usr/share/elasticsearch/config/certs/es.pem
      - xpack.security.http.ssl.certificate_authorities=/usr/share/elasticsearch/config/certs/ca.pem
      - xpack.security.transport.ssl.enabled=true
      - xpack.security.transport.ssl.key=/usr/share/elasticsearch/config/certs/es-key.pem
      - xpack.security.transport.ssl.certificate=/usr/share/elasticsearch/config/certs/es.pem
      - xpack.security.transport.ssl.certificate_authorities=/usr/share/elasticsearch/config/certs/ca.pem
      - xpack.security.transport.ssl.verification_mode=certificate
      - "ES_JAVA_OPTS=-Xms2g -Xmx2g"
      - bootstrap.memory_lock=true
    ulimits:
      memlock:
        soft: -1
        hard: -1
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - es-data:/usr/share/elasticsearch/data
      - ${CERTS_DIR}/ca.pem:/usr/share/elasticsearch/config/certs/ca.pem:ro
      - ${CERTS_DIR}/es.pem:/usr/share/elasticsearch/config/certs/es.pem:ro
      - ${CERTS_DIR}/es-key.pem:/usr/share/elasticsearch/config/certs/es-key.pem:ro
    healthcheck:
      test: ["CMD-SHELL", "curl -sk -u elastic:${ELASTIC_PASSWORD} https://localhost:9200/_cluster/health | grep -qE '\"status\":\"(green|yellow)\"'"]
      interval: 15s
      timeout: 10s
      retries: 30

  kibana:
    image: docker.elastic.co/kibana/kibana:${ELASTIC_VERSION}
    container_name: kibana
    hostname: kibana
    restart: unless-stopped
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=https://elasticsearch:9200
      - ELASTICSEARCH_USERNAME=kibana_system
      - ELASTICSEARCH_PASSWORD=${ELASTIC_PASSWORD}
      - ELASTICSEARCH_SSL_CERTIFICATEAUTHORITIES=/usr/share/kibana/config/certs/ca.pem
      - SERVER_SSL_ENABLED=false
      - 'XPACK_FLEET_AGENTS_FLEET_SERVER_HOSTS=["https://10.0.2.2:8220"]'
      - 'XPACK_FLEET_OUTPUTS=[{"id":"default-output","name":"default","type":"elasticsearch","hosts":["https://elasticsearch:9200"],"is_default":true,"is_default_monitoring":true}]'
      - XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=a7G2kp9Jq3mR8vW5sX1cF4eB6hN0tY3uIz
    volumes:
      - ${CERTS_DIR}/ca.pem:/usr/share/kibana/config/certs/ca.pem:ro
    depends_on:
      elasticsearch:
        condition: service_healthy

  fleet-server:
    image: docker.elastic.co/beats/elastic-agent:${ELASTIC_VERSION}
    container_name: fleet-server
    hostname: fleet-server
    restart: unless-stopped
    user: root
    ports:
      - "8220:8220"
    environment:
      - FLEET_SERVER_ENABLE=1
      - FLEET_SERVER_POLICY_ID=fleet-server-policy
      - FLEET_SERVER_ELASTICSEARCH_HOST=https://elasticsearch:9200
      - FLEET_SERVER_ELASTICSEARCH_USERNAME=elastic
      - FLEET_SERVER_ELASTICSEARCH_PASSWORD=${ELASTIC_PASSWORD}
      - FLEET_SERVER_ELASTICSEARCH_CA=/usr/share/elastic-agent/ca.pem
      - FLEET_SERVER_HOST=0.0.0.0
      - FLEET_SERVER_PORT=8220
      - FLEET_SERVER_CERT=/usr/share/elastic-agent/fleet.pem
      - FLEET_SERVER_CERT_KEY=/usr/share/elastic-agent/fleet-key.pem
      - FLEET_URL=https://fleet-server:8220
      - FLEET_INSECURE=1
      - KIBANA_HOST=http://kibana:5601
      - KIBANA_USERNAME=elastic
      - KIBANA_PASSWORD=${ELASTIC_PASSWORD}
      - KIBANA_FLEET_SETUP=1
    volumes:
      - ${CERTS_DIR}/ca.pem:/usr/share/elastic-agent/ca.pem:ro
      - ${CERTS_DIR}/fleet.pem:/usr/share/elastic-agent/fleet.pem:ro
      - ${CERTS_DIR}/fleet-key.pem:/usr/share/elastic-agent/fleet-key.pem:ro
    depends_on:
      elasticsearch:
        condition: service_healthy
      kibana:
        condition: service_started

volumes:
  es-data:
COMPOSEEOF

log "Compose file written."

# ---------------------------------------------------------------------------
# Set kibana_system password (ES 8.x requires it for Kibana→ES auth)
# ---------------------------------------------------------------------------
set_kibana_password() {
    log "Setting kibana_system password..."
    for i in $(seq 1 10); do
        resp=$(curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
            -X POST "${ES_URL}/_security/user/kibana_system/_password" \
            -H "Content-Type: application/json" \
            -d "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}" 2>/dev/null || true)
        if echo "$resp" | grep -q '{}' 2>/dev/null || echo "$resp" | grep -q '"acknowledged"' 2>/dev/null; then
            log "kibana_system password set."
            return 0
        fi
        sleep 3
    done
    warn "Failed to set kibana_system password (Kibana may still connect with service token)."
    return 1
}

# ---------------------------------------------------------------------------
# Pull and start
# ---------------------------------------------------------------------------
log "Starting Elastic stack (first run pulls ~3GB of images)..."
$COMPOSE_CMD -f "$COMPOSE_FILE" up -d

# ---------------------------------------------------------------------------
# Wait for Elasticsearch
# ---------------------------------------------------------------------------
log "Waiting for Elasticsearch..."
for i in $(seq 1 60); do
    if curl -sk -u "elastic:${ELASTIC_PASSWORD}" "${ES_URL}/_cluster/health" 2>/dev/null | grep -qE '"status":"(green|yellow)"'; then
        log "Elasticsearch is healthy!"
        break
    fi
    if [[ "$i" -eq 60 ]]; then
        err "Elasticsearch did not become healthy after 300s."
        err "Check: $COMPOSE_CMD -f $COMPOSE_FILE logs elasticsearch"
        exit 1
    fi
    echo -ne "  Attempt ${i}/60 — retrying in 5s...\r"
    sleep 5
done

set_kibana_password

# ---------------------------------------------------------------------------
# Wait for Kibana
# ---------------------------------------------------------------------------
log "Waiting for Kibana..."
for i in $(seq 1 60); do
    status=$(curl -sk -u "elastic:${ELASTIC_PASSWORD}" "${KIBANA_URL}/api/status" 2>/dev/null | grep -o '"overall":{"level":"[^"]*"' | grep -o '"[^"]*"$' | tr -d '"' || true)
    if [[ "$status" == "available" ]]; then
        log "Kibana is ready!"
        break
    fi
    if [[ "$i" -eq 60 ]]; then
        err "Kibana did not become ready after 300s."
        err "Check: $COMPOSE_CMD -f $COMPOSE_FILE logs kibana"
        exit 1
    fi
    echo -ne "  Attempt ${i}/60 (status: ${status:-pending}) — retrying in 5s...\r"
    sleep 5
done

# ---------------------------------------------------------------------------
# Trigger Fleet setup and create fleet-server-policy
# ---------------------------------------------------------------------------
log "Triggering Fleet setup..."
curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
    -X POST "${KIBANA_URL}/api/fleet/setup" \
    -H "kbn-xsrf: true" >/dev/null 2>&1 || true

log "Creating Fleet Server policy..."
FS_POLICY_RESP=$(curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
    -X POST "${KIBANA_URL}/api/fleet/agent_policies" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d '{
        "id": "fleet-server-policy",
        "name": "Fleet Server Policy",
        "namespace": "default",
        "is_default_fleet_server": true,
        "has_fleet_server": true,
        "monitoring_enabled": ["logs", "metrics"]
    }' 2>/dev/null || echo '{}')

FS_POLICY_ID=$(echo "$FS_POLICY_RESP" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
if [[ -n "$FS_POLICY_ID" ]]; then
    log "Fleet Server policy created: ${FS_POLICY_ID}"

    log "Adding Fleet Server integration to policy..."
    curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
        -X POST "${KIBANA_URL}/api/fleet/package_policies" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "Fleet Server",
            "namespace": "default",
            "policy_id": "fleet-server-policy",
            "package": {
                "name": "fleet_server",
                "title": "Fleet Server",
                "version": ""
            },
            "inputs": [{
                "type": "fleet-server",
                "enabled": true,
                "streams": [],
                "vars": {}
            }]
        }' >/dev/null 2>&1 || warn "Fleet Server integration may already exist"
else
    warn "Fleet Server policy may already exist (expected on re-runs)"
fi

# ---------------------------------------------------------------------------
# Wait for Fleet Server (check /api/status on port 8220)
# ---------------------------------------------------------------------------
log "Waiting for Fleet Server to become healthy..."
for i in $(seq 1 60); do
    fs_status=$(curl -sk "https://localhost:8220/api/status" 2>/dev/null | grep -o '"status":"[^"]*"' | cut -d'"' -f4 || true)
    if [[ "$fs_status" == "HEALTHY" ]]; then
        log "Fleet Server is HEALTHY!"
        break
    fi
    if [[ "$i" -eq 60 ]]; then
        warn "Fleet Server not confirmed HEALTHY after 300s (status: ${fs_status:-unknown})."
        warn "Check: $COMPOSE_CMD -f $COMPOSE_FILE logs fleet-server"
    fi
    echo -ne "  Attempt ${i}/60 (status: ${fs_status:-pending}) — retrying in 5s...\r"
    sleep 5
done

# ---------------------------------------------------------------------------
# Configure Fleet: set host URLs so VM agents know where to connect
# ---------------------------------------------------------------------------
log "Configuring Fleet Server hosts for VM access..."
curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
    -X PUT "${KIBANA_URL}/api/fleet/settings" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d '{"fleet_server_hosts":["https://10.0.2.2:8220"]}' \
    >/dev/null 2>&1 || warn "Fleet host config may have failed"

# Set ES output to use our CA
curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
    -X PUT "${KIBANA_URL}/api/fleet/outputs/fleet-default-output" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d "{\"hosts\":[\"${ES_URL}\"],\"config_yaml\":\"ssl.certificate_authorities:\\n  - /usr/share/elastic-agent/ca.pem\"}" \
    >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Create Elastic Defend integration policy
# ---------------------------------------------------------------------------
log "Creating Elastic Defend agent policy..."

POLICY_RESP=$(curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
    -X POST "${KIBANA_URL}/api/fleet/agent_policies" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Endpoint Security Policy",
        "namespace": "default",
        "monitoring_enabled": ["logs", "metrics"],
        "description": "Policy with Elastic Defend for malware testing"
    }' 2>/dev/null || echo '{}')

POLICY_ID=$(echo "$POLICY_RESP" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [[ -z "$POLICY_ID" ]]; then
    POLICY_ID=$(curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
        "${KIBANA_URL}/api/fleet/agent_policies" \
        -H "kbn-xsrf: true" 2>/dev/null | \
        grep -o '"id":"[^"]*","name":"Endpoint Security Policy"' | head -1 | cut -d'"' -f4)
fi

if [[ -n "$POLICY_ID" ]]; then
    log "Agent policy created: ${POLICY_ID}"

    log "Adding Elastic Defend integration..."
    INTEG_RESP=$(curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
        -X POST "${KIBANA_URL}/api/fleet/package_policies" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"Elastic Defend\",
            \"namespace\": \"default\",
            \"policy_id\": \"${POLICY_ID}\",
            \"package\": {
                \"name\": \"endpoint\",
                \"title\": \"Elastic Defend\",
                \"version\": \"\"
            },
            \"inputs\": [{
                \"type\": \"endpoint\",
                \"enabled\": true,
                \"streams\": [],
                \"config\": {
                    \"policy\": {
                        \"value\": {
                            \"windows\": {
                                \"malware\": {\"mode\": \"detect\"},
                                \"events\": {
                                    \"process\": true,
                                    \"file\": true,
                                    \"network\": true,
                                    \"registry\": true,
                                    \"dns\": true,
                                    \"security\": true
                                }
                            }
                        }
                    }
                }
            }]
        }" 2>/dev/null || echo '{}')

    if echo "$INTEG_RESP" | grep -q '"id"'; then
        log "Elastic Defend integration added to policy."
    else
        warn "Elastic Defend integration may need manual setup in Kibana."
        warn "Go to ${KIBANA_URL} > Fleet > Agent policies > Add integration > Elastic Defend"
    fi
else
    warn "Could not create agent policy. Create manually in Kibana Fleet UI."
    POLICY_ID="(check Kibana)"
fi

# ---------------------------------------------------------------------------
# Install prebuilt detection rules
# ---------------------------------------------------------------------------
log "Installing prebuilt detection rules..."
RULES_RESP=$(curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
    -X PUT "${KIBANA_URL}/api/detection_engine/rules/prepackaged" \
    -H "kbn-xsrf: true" 2>/dev/null || echo '{}')

RULES_INSTALLED=$(echo "$RULES_RESP" | grep -o '"rules_installed":[0-9]*' | cut -d: -f2 || echo "?")
RULES_UPDATED=$(echo "$RULES_RESP" | grep -o '"rules_updated":[0-9]*' | cut -d: -f2 || echo "?")
log "Detection rules: ${RULES_INSTALLED} installed, ${RULES_UPDATED} updated."

log "Enabling Windows detection rules..."
curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
    -X POST "${KIBANA_URL}/api/detection_engine/rules/_bulk_action" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d '{
        "action": "enable",
        "query": "alert.attributes.tags:\"OS: Windows\""
    }' >/dev/null 2>&1 || warn "Bulk enable may have partially failed — check Kibana rules UI."

# ---------------------------------------------------------------------------
# Generate enrollment token
# ---------------------------------------------------------------------------
log "Generating enrollment token..."

if [[ -n "$POLICY_ID" && "$POLICY_ID" != "(check Kibana)" ]]; then
    TOKEN_RESP=$(curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
        -X POST "${KIBANA_URL}/api/fleet/enrollment_api_keys" \
        -H "kbn-xsrf: true" \
        -H "Content-Type: application/json" \
        -d "{\"policy_id\": \"${POLICY_ID}\"}" 2>/dev/null || echo '{}')

    ENROLLMENT_TOKEN=$(echo "$TOKEN_RESP" | grep -o '"api_key":"[^"]*"' | head -1 | cut -d'"' -f4)
else
    TOKEN_RESP=$(curl -sk -u "elastic:${ELASTIC_PASSWORD}" \
        "${KIBANA_URL}/api/fleet/enrollment_api_keys" \
        -H "kbn-xsrf: true" 2>/dev/null || echo '{}')
    ENROLLMENT_TOKEN=$(echo "$TOKEN_RESP" | grep -o '"api_key":"[^"]*"' | head -1 | cut -d'"' -f4)
fi

if [[ -n "${ENROLLMENT_TOKEN:-}" ]]; then
    echo "$ENROLLMENT_TOKEN" > "$TOKEN_FILE"
    log "Enrollment token saved to ${TOKEN_FILE}"
else
    warn "Could not generate enrollment token. Generate manually in Kibana Fleet UI."
    ENROLLMENT_TOKEN="(generate in Kibana Fleet UI)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

echo ""
echo "==========================================================="
echo "  Elastic Security ${ELASTIC_VERSION} — Docker Deployment"
echo "==========================================================="
echo ""
echo "  Elasticsearch    : ${ES_URL}"
echo "  Kibana           : ${KIBANA_URL}"
echo "  Fleet Server     : ${FLEET_URL}"
echo ""
echo "  Credentials      : elastic / ${ELASTIC_PASSWORD}"
echo "  Agent Policy ID  : ${POLICY_ID}"
echo ""
echo "  Enrollment token : ${ENROLLMENT_TOKEN}"
echo ""
echo "  Agent install command (from Windows VM):"
echo "    elastic-agent.exe install \\"
echo "      --url=https://10.0.2.2:8220 \\"
echo "      --enrollment-token=${ENROLLMENT_TOKEN} \\"
echo "      --insecure"
echo ""
echo "  Or use the helper script:"
echo "    bash scripts/install_elastic_agent.sh ${ENROLLMENT_TOKEN}"
echo ""
echo "  Prebuilt rules   : ${RULES_INSTALLED} installed, ${RULES_UPDATED} updated"
echo ""
echo "  Detection query  :"
echo "    curl -sk -u elastic:${ELASTIC_PASSWORD} \\"
echo "      '${ES_URL}/.alerts-security*/_search?q=host.name:MalwareVM&size=10'"
echo ""
echo "==========================================================="
echo ""
echo "Management:"
echo "  Status : $0 --status"
echo "  Stop   : $0 --stop"
echo "  Logs   : $COMPOSE_CMD -f $COMPOSE_FILE logs -f"
echo ""
