# Combined Nginx and Certificate Manager Dockerfile

FROM nginx:1.30.7-alpine3.24@sha256:bef154735288bc38d99fac41ae63730684bcc661503673a04a0f9bc526ba8598 AS nginx-base
FROM nginx-base AS builder

# Install build dependencies
RUN apk add --no-cache \
    gcc~=15.2 \
    musl-dev~=1.2 \
    make~=4.4 \
    openssl-dev~=3.5 \
    pcre2-dev~=10.49

# Compile against the source release for the nginx version in the shared base.
RUN archive="nginx-${NGINX_VERSION}.tar.gz" \
    && curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
       --output "${archive}" "https://nginx.org/download/${archive}" \
    && printf '%s  %s\n' '2565b5c837050e958f70fb0f73c48e2bca4542ad349fd356f46fb0c72610bc6e' "${archive}" | sha256sum -c - \
    && tar -xzf "${archive}"

# Copy module source
COPY ngx_http_ekm_module /nginx-${NGINX_VERSION}/ngx_http_ekm_module

WORKDIR /nginx-${NGINX_VERSION}

# Build module
RUN ./configure --with-compat \
    --add-dynamic-module=./ngx_http_ekm_module && \
    make modules


FROM nginx-base

# Copy compiled Nginx EKM module from builder
COPY --from=builder /nginx-${NGINX_VERSION}/objs/ngx_http_ekm_module.so /usr/lib/nginx/modules/

# Load Nginx EKM module in main nginx.conf (must be at top level)
# Make EKM_SHARED_SECRET env variable available to nginx
RUN sed -i '1i load_module /usr/lib/nginx/modules/ngx_http_ekm_module.so;' /etc/nginx/nginx.conf && \
    sed -i '2i env EKM_SHARED_SECRET;' /etc/nginx/nginx.conf

# Test: verify that the module file exists and nginx config is valid
RUN test -f /usr/lib/nginx/modules/ngx_http_ekm_module.so && \
    nginx -t 2>&1 && \
    nginx -T 2>&1 | grep -q "ngx_http_ekm_module" || \
    { echo "ERROR: EKM module verification failed"; nginx -T 2>&1; exit 1; }

# ghcr.io/astral-sh/uv:0.9.5
COPY --from=ghcr.io/astral-sh/uv@sha256:f459f6f73a8c4ef5d69f4e6fbbdb8af751d6fa40ec34b39a1ab469acd6e289b7 /uv /uvx /bin/

EXPOSE 80 443

# Install supervisor
RUN apk add --no-cache supervisor=4.3.0-r1

# Create app directory
WORKDIR /app

# Install Python dependencies (uv sync needs src/ and build tools for native deps)
COPY pyproject.toml /app/
COPY src/ /app/src/
COPY uv.lock /app/
RUN apk add --no-cache --virtual .build-deps gcc musl-dev cargo rust && \
    uv sync --locked --no-cache && \
    apk del .build-deps

# Copy app files
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh
COPY nginx_conf /app/nginx_conf
COPY render_nginx_conf.py /app/
COPY proc_logger.py /app/

# Minimal fallback config for Docker healthcheck during build
# The actual config is rendered at runtime by render_nginx_conf.py
RUN echo 'server { listen 80; location /health { return 200 "healthy\n"; add_header Content-Type text/plain; } }' > /etc/nginx/conf.d/default.conf

# Create supervisor configuration
RUN mkdir -p /etc/supervisor/conf.d
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Create directories for certificates and ACME challenges
RUN mkdir -p /certs /acme-challenge /var/log/supervisor

# Ensure both nginx and cert manager processes are healthy
HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 \
    CMD (curl -f -k https://localhost/health || exit 1) && \
        (ls /etc/nginx/ssl/cert.pem /etc/nginx/ssl/key.pem || exit 1)

# Use supervisor to manage both nginx and cert manager processes
ENTRYPOINT ["/app/entrypoint.sh"]
