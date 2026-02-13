#!/bin/sh
set -e

echo "Rendering nginx configuration..."
echo "Domain: ${DOMAIN}"
echo "Dev Mode: ${DEV_MODE}"
echo "Upstream: ${UPSTREAM_HOST:-<not set>}:${UPSTREAM_PORT:-<not set>}"

# Render nginx configs from templates using env vars
uv run /app/render_nginx_conf.py

echo "Starting Nginx and Certificate Manager..."

# Start supervisor to manage both nginx and cert manager
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
