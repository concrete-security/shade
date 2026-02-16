#!/bin/sh
set -e

echo "Rendering nginx configuration..."
echo "Domain: ${DOMAIN}"
echo "Dev Mode: ${DEV_MODE}"
echo "Upstream: ${UPSTREAM_HOST:-<not set>}:${UPSTREAM_PORT:-<not set>}"

# Render nginx configs from templates using env vars
uv run /app/render_nginx_conf.py

# Derive EKM HMAC key from TEE so the operator never sees it.
# In dev mode with EKM_SHARED_SECRET already set, skip (no dstack socket).
if [ "${DEV_MODE}" = "true" ] && [ -n "${EKM_SHARED_SECRET}" ]; then
  echo "Dev mode: using EKM_SHARED_SECRET from environment."
else
  echo "Deriving EKM HMAC key from TEE (dstack)..."
  EKM_SHARED_SECRET=$(uv run python3 -c "
from dstack_sdk import DstackClient
c = DstackClient()
print(c.get_key('ekm/hmac-key/v1').decode_key().hex())
")
  export EKM_SHARED_SECRET
  echo "EKM HMAC key derived from TEE successfully."
fi

echo "Starting Nginx and Certificate Manager..."

# Start supervisor to manage both nginx and cert manager
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
