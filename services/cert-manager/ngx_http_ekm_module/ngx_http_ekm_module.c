/*
 * Nginx HTTP EKM Module
 *
 * Exports TLS Exported Keying Material (EKM) as an nginx variable
 * for use in proxying to backend services with session binding.
 *
 * RFC 9266: Channel Bindings for TLS 1.3
 * RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3 (Section 7.5)
 * RFC 5705: Keying Material Exporters for TLS (TLS 1.2)
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_openssl.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>

#define MODULE_ENV_VAR "ekm_channel_binding"
#define EKM_LENGTH 32
#define EKM_LABEL "EXPORTER-Channel-Binding"
#define EKM_LABEL_LEN 24
#define EKM_HEX_LENGTH (EKM_LENGTH * 2)

static const unsigned char cert_hmac_context[] = "shade-tls-certificate-v2";

static ngx_int_t ngx_http_ekm_add_variable(ngx_conf_t *cf);
static ngx_int_t ngx_http_ekm_get_variable(ngx_http_request_t *r,
                                           ngx_http_variable_value_t *v, uintptr_t data);

static ngx_http_module_t ngx_http_ekm_module_ctx = {
    ngx_http_ekm_add_variable, /* preconfiguration */
    NULL,                      /* postconfiguration */
    NULL,                      /* create main configuration */
    NULL,                      /* init main configuration */
    NULL,                      /* create server configuration */
    NULL,                      /* merge server configuration */
    NULL,                      /* create location configuration */
    NULL                       /* merge location configuration */
};

ngx_module_t ngx_http_ekm_module = {
    NGX_MODULE_V1,
    &ngx_http_ekm_module_ctx, /* module context */
    NULL,                     /* module directives */
    NGX_HTTP_MODULE,          /* module type */
    NULL,                     /* init master */
    NULL,                     /* init module */
    NULL,                     /* init process */
    NULL,                     /* init thread */
    NULL,                     /* exit thread */
    NULL,                     /* exit process */
    NULL,                     /* exit master */
    NGX_MODULE_V1_PADDING};

static ngx_http_variable_t ngx_http_ekm_variable = {
    ngx_string(MODULE_ENV_VAR), /* name */
    NULL,                       /* set_handler */
    ngx_http_ekm_get_variable,  /* get_handler */
    0,                          /* data */
    NGX_HTTP_VAR_NOCACHEABLE,   /* flags */
    0                           /* index */
};

static ngx_int_t
ngx_http_ekm_add_variable(ngx_conf_t *cf)
{
    ngx_http_variable_t *var;

    var = ngx_http_add_variable(cf, &ngx_http_ekm_variable.name, ngx_http_ekm_variable.flags);
    if (var == NULL)
    {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_ekm_variable.get_handler;
    var->data = ngx_http_ekm_variable.data;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ekm_get_variable(ngx_http_request_t *r,
                          ngx_http_variable_value_t *v,
                          uintptr_t data)
{
    ngx_ssl_connection_t *ssl_conn;
    SSL *ssl;
    unsigned char ekm_raw[EKM_LENGTH];
    unsigned char cert_sha256[EKM_LENGTH];
    unsigned char cert_signed_data[sizeof(cert_hmac_context) + 2 * EKM_LENGTH];
    unsigned char hmac_raw[EKM_LENGTH];
    unsigned int hmac_len;
    unsigned char *output;
    unsigned char *cursor;
    const unsigned char *signed_data = ekm_raw;
    size_t signed_data_len = sizeof(ekm_raw);
    size_t output_len = 2 * EKM_HEX_LENGTH + 1;
    const char *ekm_secret;
    size_t secret_len;
    const char *binding;
    ngx_flag_t report_data_v2;

    /* Initialize as not found */
    v->not_found = 1;
    v->valid = 0;

    /* Check if this is an HTTPS connection */
    if (r->connection == NULL || r->connection->ssl == NULL)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "ekm: no SSL connection");
        return NGX_OK;
    }

    ssl_conn = r->connection->ssl;
    ssl = ssl_conn->connection;

    if (ssl == NULL)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "ekm: SSL not initialized");
        return NGX_OK;
    }

    /* Enforce TLS 1.3 (RFC 9266 requirement) */
    if (SSL_version(ssl) < TLS1_3_VERSION)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ekm: TLS 1.3 required, got %s", SSL_get_version(ssl));
        return NGX_OK;
    }

    binding = getenv("SHADE_CERTIFICATE_BINDING");
    report_data_v2 = binding != NULL && strcmp(binding, "report-data-v2") == 0;
    if (binding != NULL && !report_data_v2 && strcmp(binding, "rtmr3-event") != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ekm: invalid certificate binding mode");
        return NGX_OK;
    }

    /* Get shared secret */
    ekm_secret = getenv("EKM_SHARED_SECRET");
    if (ekm_secret == NULL || (secret_len = strlen(ekm_secret)) == 0)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "ekm: EKM_SHARED_SECRET not set");
        return NGX_OK;
    }

    /* Extract EKM using RFC 9266 label */
    if (SSL_export_keying_material(
            ssl,
            ekm_raw,
            EKM_LENGTH,
            EKM_LABEL,
            EKM_LABEL_LEN,
            NULL, /* context - zero-length as per RFC 9266 */
            0,    /* contextlen */
            0     /* use_context - 0 means context should be omitted */
            ) != 1)
    {
        /* EKM extraction failed - log error but don't fail request */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ekm: SSL_export_keying_material failed");
        return NGX_OK;
    }

    if (report_data_v2)
    {
        X509 *leaf = SSL_get_certificate(ssl);
        unsigned int digest_len;

        /* A resumed handshake may not send a certificate at all. */
        if (SSL_session_reused(ssl) || leaf == NULL ||
            X509_digest(leaf, EVP_sha256(), cert_sha256, &digest_len) != 1 ||
            digest_len != sizeof(cert_sha256))
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ekm: no usable certificate from a full TLS handshake");
            return NGX_OK;
        }

        /* Include the domain separator's trailing NUL in the MAC. */
        ngx_memcpy(cert_signed_data, cert_hmac_context, sizeof(cert_hmac_context));
        ngx_memcpy(cert_signed_data + sizeof(cert_hmac_context), ekm_raw, sizeof(ekm_raw));
        ngx_memcpy(cert_signed_data + sizeof(cert_hmac_context) + sizeof(ekm_raw),
                   cert_sha256, sizeof(cert_sha256));
        signed_data = cert_signed_data;
        signed_data_len = sizeof(cert_signed_data);
        output_len += 2 + EKM_HEX_LENGTH + 1; /* '2:' and cert_hex + ':' */
    }

    if (HMAC(EVP_sha256(), ekm_secret, secret_len,
             signed_data, signed_data_len, hmac_raw, &hmac_len) == NULL ||
        hmac_len != sizeof(hmac_raw))
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ekm: HMAC calculation failed");
        return NGX_OK;
    }

    output = ngx_pnalloc(r->pool, output_len);
    if (output == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ekm: failed to allocate memory for hex output");
        return NGX_ERROR;
    }

    cursor = output;
    if (report_data_v2)
    {
        *cursor++ = '2';
        *cursor++ = ':';
    }
    cursor = ngx_hex_dump(cursor, ekm_raw, sizeof(ekm_raw));
    *cursor++ = ':';
    if (report_data_v2)
    {
        cursor = ngx_hex_dump(cursor, cert_sha256, sizeof(cert_sha256));
        *cursor++ = ':';
    }
    ngx_hex_dump(cursor, hmac_raw, sizeof(hmac_raw));

    /* Set variable value */
    v->len = output_len;
    v->data = output;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ekm: extracted and signed EKM");

    return NGX_OK;
}
