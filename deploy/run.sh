#!/usr/bin/env bash
set -euo pipefail

# Production container deployment for EVIDIQ Envelope MCP (port 3020).
# Stateful service: the artifact store (hashes, findings, pinned DNS — never raw
# messages) lives on the mounted volume at /data (ENVELOPE_DB_PATH=/data/envelope.db).
CONTAINER_NAME="evidiq-envelope"
IMAGE_NAME="evidiq-envelope:latest"
ENV_FILE="/root/evidiq-envelope.env"
HOST_PORT="3020"
DATA_DIR="/root/evidiq-envelope-data"

echo "Deploying ${CONTAINER_NAME} on host port ${HOST_PORT}..."

if [ ! -f "${ENV_FILE}" ]; then
  echo "Error: Environment file ${ENV_FILE} not found!"
  exit 1
fi

if [ ! -d "${DATA_DIR}" ]; then
  mkdir -p "${DATA_DIR}"
  chmod 700 "${DATA_DIR}"
  echo "Created data volume ${DATA_DIR}"
fi

docker stop "${CONTAINER_NAME}" 2>/dev/null || true
docker rm "${CONTAINER_NAME}" 2>/dev/null || true

docker run -d \
  --name "${CONTAINER_NAME}" \
  --restart unless-stopped \
  --network coolify \
  --env-file "${ENV_FILE}" \
  -p "127.0.0.1:${HOST_PORT}:3020" \
  -v "${DATA_DIR}:/data" \
  --label "traefik.enable=true" \
  --label "traefik.http.routers.envelope.rule=Host(\`mcp.evidiq.dev\`) && PathPrefix(\`/envelope\`)" \
  --label "traefik.http.routers.envelope.tls=true" \
  --label "traefik.http.routers.envelope.tls.certresolver=letsencrypt" \
  --label "traefik.http.routers.envelope.middlewares=envelope-strip" \
  --label "traefik.http.middlewares.envelope-strip.stripprefix.prefixes=/envelope" \
  --label "traefik.http.services.envelope.loadbalancer.server.port=3020" \
  "${IMAGE_NAME}"

echo "Started ${CONTAINER_NAME}."
echo "Data volume: ${DATA_DIR} -> /data (ENVELOPE_DB_PATH=/data/envelope.db)"
