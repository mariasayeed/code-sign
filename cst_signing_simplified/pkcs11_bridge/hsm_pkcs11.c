/*
 * hsm_pkcs11.c — PKCS#11 bridge shared library for NXP CST + internal HSM REST API
 * ══════════════════════════════════════════════════════════════════════════════════
 *
 * Purpose
 * ───────
 * NXP CST 3.4.0 has a built-in PKCS#11 backend activated with:
 *
 *     cst -b pkcs11 --module /path/to/libhsm_pkcs11.so \
 *         --input csf.txt --output csf.bin
 *
 * This shared library implements the PKCS#11 v2.40 interface such that:
 *   • C_Sign() routes the signing operation to your internal HSM REST API
 *     instead of a hardware token or SoftHSM.
 *   • C_GetAttributeValue() returns certificate DER data (needed by CST to
 *     embed certs in the CSF blob).
 *   • C_FindObjects() exposes a virtual token with exactly the objects that
 *     CST queries for: the SRK cert, the CSF private key, and the IMG private key.
 *
 * Configuration
 * ─────────────
 * Set the following environment variables before running CST:
 *
 *   HSM_PKCS11_CONFIG   Path to config JSON file (see hsm_pkcs11_config.json.example)
 *
 * Or set individual variables:
 *   HSM_BASE              REST base URL  (e.g. https://192.168.1.159:7008/crypto/api/v1)
 *   HSM_AUTH_TOKEN        Bearer token
 *   HSM_TLS_VERIFY        "true" / "false" (default: false)
 *   HSM_CSF_KEY_ID        publicKeyId for the CSF signing key
 *   HSM_IMG_KEY_ID        publicKeyId for the IMG signing key
 *   HSM_CSF_CERT_PATH     Path to CSF certificate PEM
 *   HSM_IMG_CERT_PATH     Path to IMG certificate PEM
 *   HSM_SRK_CERT_PATH     Path to SRK certificate PEM (the active SRK)
 *   HSM_TOKEN_LABEL       Token label shown in PKCS#11 (default: "HSM-CST")
 *   HSM_TOKEN_PIN         PIN used when CST calls C_Login (any value; ignored)
 *
 * Build
 * ─────
 *   mkdir build && cd build
 *   cmake ..
 *   make
 *   # → libhsm_pkcs11.so (Linux) or hsm_pkcs11.dll (Windows)
 *
 * Dependencies
 * ────────────
 *   libcurl  (for HTTP calls to HSM REST API)
 *   openssl  (for base64 decode of signature response)
 *   cJSON    (bundled — single-file header; see cJSON.h)
 *
 * Object model exposed to CST
 * ───────────────────────────
 *   Handle 1  CKO_CERTIFICATE  (SRK cert)   label = "SRK"
 *   Handle 2  CKO_PRIVATE_KEY  (CSF key)    label = "CSF"
 *   Handle 3  CKO_CERTIFICATE  (CSF cert)   label = "CSF"
 *   Handle 4  CKO_PRIVATE_KEY  (IMG key)    label = "IMG"
 *   Handle 5  CKO_CERTIFICATE  (IMG cert)   label = "IMG"
 *
 * PKCS#11 URI format (use in CSF text files)
 * ───────────────────────────────────────────
 *   pkcs11:token=HSM-CST;object=CSF;type=private;pin-value=changeme
 *   pkcs11:token=HSM-CST;object=CSF;type=cert;pin-value=changeme
 *
 * Signing flow (C_Sign)
 * ─────────────────────
 *   1.  POST  /context                              → contextId
 *   2.  POST  /context/{id}/data   (raw bytes)      → (acknowledged)
 *   3.  POST  /context/{id}/ds/creator              → (triggers signing)
 *   4.  GET   /context/{id}/ds/creator/data/base64  → base64(raw RSA sig)
 *   5.  base64-decode → write to PKCS#11 output buffer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/rsa.h>

#include "pkcs11_types.h"

/* ─────────────────────────────────────────────────────────────────────────── */
/* Compile-time limits                                                         */
/* ─────────────────────────────────────────────────────────────────────────── */
#define HSM_MAX_URL          1024
#define HSM_MAX_TOKEN        1024
#define HSM_MAX_LABEL         128
#define HSM_MAX_CERT_BYTES  65536   /* 64 KiB per cert */
#define HSM_MAX_RSA_BYTES    1024   /* RSA 8192-bit = 1024 byte modulus */
#define HSM_MAX_SIG_BYTES    1024   /* RSA 8192-bit max */
#define HSM_MAX_RESP        65536

/* ─────────────────────────────────────────────────────────────────────────── */
/* Global configuration                                                        */
/* ─────────────────────────────────────────────────────────────────────────── */
static struct {
    char base_url[HSM_MAX_URL];
    char auth_token[HSM_MAX_TOKEN];
    int  tls_verify;             /* 0 = skip verify; 1 = verify */
    char csf_key_id[HSM_MAX_LABEL];
    char img_key_id[HSM_MAX_LABEL];
    char token_label[HSM_MAX_LABEL];
    char token_pin[HSM_MAX_LABEL];
    /* DER-encoded certificate bytes for each key object */
    unsigned char srk_cert_der[HSM_MAX_CERT_BYTES];
    size_t        srk_cert_len;
    unsigned char csf_cert_der[HSM_MAX_CERT_BYTES];
    size_t        csf_cert_len;
    unsigned char img_cert_der[HSM_MAX_CERT_BYTES];
    size_t        img_cert_len;
    /* RSA public key components (for private key objects) */
    unsigned char csf_modulus[HSM_MAX_RSA_BYTES];
    size_t        csf_modulus_len;
    unsigned char csf_exponent[8];
    size_t        csf_exponent_len;
    unsigned char img_modulus[HSM_MAX_RSA_BYTES];
    size_t        img_modulus_len;
    unsigned char img_exponent[8];
    size_t        img_exponent_len;
    int  initialized;
} g_cfg;

/* Current signing state */
static struct {
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE  key_handle;
    CK_MECHANISM_TYPE mechanism;
} g_sign_state;

/* Find-objects state */
static struct {
    CK_OBJECT_HANDLE matches[16];
    CK_ULONG         count;
    CK_ULONG         pos;
} g_find_state;

/* ─────────────────────────────────────────────────────────────────────────── */
/* libcurl write callback                                                      */
/* ─────────────────────────────────────────────────────────────────────────── */
typedef struct {
    char   *buf;
    size_t  len;
    size_t  cap;
} curl_buf_t;

static size_t _curl_write(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    curl_buf_t *cb = (curl_buf_t *)userdata;
    size_t total = size * nmemb;
    if (cb->len + total + 1 > cb->cap) {
        size_t new_cap = cb->cap * 2 + total + 1;
        char *p = realloc(cb->buf, new_cap);
        if (!p) return 0;
        cb->buf = p;
        cb->cap = new_cap;
    }
    memcpy(cb->buf + cb->len, ptr, total);
    cb->len += total;
    cb->buf[cb->len] = '\0';
    return total;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* HTTP helpers                                                                */
/* ─────────────────────────────────────────────────────────────────────────── */

/* Perform a POST with JSON body; response into *out (caller must free) */
static int _post_json(const char *path, const char *json_body, char **out)
{
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[HSM_MAX_URL * 2];
    snprintf(url, sizeof(url), "%s%s", g_cfg.base_url, path);

    char auth_hdr[HSM_MAX_TOKEN + 32];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", g_cfg.auth_token);

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, auth_hdr);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

    curl_buf_t resp = { calloc(1, HSM_MAX_RESP), 0, HSM_MAX_RESP };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body ? json_body : "{}");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (long)g_cfg.tls_verify);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, (long)(g_cfg.tls_verify ? 2 : 0));

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK || http_code < 200 || http_code >= 300) {
        fprintf(stderr, "[HSM-PKCS11] POST %s failed: curl=%d http=%ld\n",
                url, rc, http_code);
        free(resp.buf);
        return -1;
    }

    *out = resp.buf;  /* caller frees */
    return 0;
}

/* Perform a POST with raw binary body */
static int _post_raw(const char *path, const unsigned char *data, size_t len)
{
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[HSM_MAX_URL * 2];
    snprintf(url, sizeof(url), "%s%s", g_cfg.base_url, path);

    char auth_hdr[HSM_MAX_TOKEN + 32];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", g_cfg.auth_token);

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, auth_hdr);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/octet-stream");

    curl_buf_t resp = { calloc(1, 64), 0, 64 };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)len);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (long)g_cfg.tls_verify);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, (long)(g_cfg.tls_verify ? 2 : 0));

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    free(resp.buf);

    if (rc != CURLE_OK || http_code < 200 || http_code >= 300) {
        fprintf(stderr, "[HSM-PKCS11] POST-raw %s failed: curl=%d http=%ld\n",
                url, rc, http_code);
        return -1;
    }
    return 0;
}

/* Perform a GET; response into *out (caller must free) */
static int _get(const char *path, char **out)
{
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[HSM_MAX_URL * 2];
    snprintf(url, sizeof(url), "%s%s", g_cfg.base_url, path);

    char auth_hdr[HSM_MAX_TOKEN + 32];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", g_cfg.auth_token);

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, auth_hdr);

    curl_buf_t resp = { calloc(1, HSM_MAX_RESP), 0, HSM_MAX_RESP };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _curl_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (long)g_cfg.tls_verify);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, (long)(g_cfg.tls_verify ? 2 : 0));

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK || http_code < 200 || http_code >= 300) {
        fprintf(stderr, "[HSM-PKCS11] GET %s failed: curl=%d http=%ld\n",
                url, rc, http_code);
        free(resp.buf);
        return -1;
    }

    *out = resp.buf;
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* JSON helpers (minimal — avoids full JSON lib dependency)                   */
/* ─────────────────────────────────────────────────────────────────────────── */

/* Extract a JSON string value for a given key.  Fills out (caller ensures
 * out_size is large enough).  Returns 0 on success, -1 if not found. */
static int _json_get_str(const char *json, const char *key,
                          char *out, size_t out_size)
{
    /* Look for "key":"value" pattern */
    char pat[256];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p == ' ' || *p == ':' || *p == ' ') p++;
    if (*p != '"') return -1;
    p++;  /* skip opening quote */
    size_t i = 0;
    while (*p && *p != '"' && i < out_size - 1)
        out[i++] = *p++;
    out[i] = '\0';
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* Base64 decoding (OpenSSL)                                                  */
/* ─────────────────────────────────────────────────────────────────────────── */

static size_t _b64_decode(const char *b64, unsigned char *out, size_t out_max)
{
    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO *mem_bio = BIO_new_mem_buf(b64, (int)strlen(b64));
    BIO_push(b64_bio, mem_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    int n = BIO_read(b64_bio, out, (int)out_max);
    BIO_free_all(b64_bio);
    return n > 0 ? (size_t)n : 0;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* PEM → DER conversion                                                       */
/* ─────────────────────────────────────────────────────────────────────────── */

static size_t _pem_to_der(const char *pem_path,
                            unsigned char *der_out, size_t der_max)
{
    /* Strip header/footer and base64-decode the body */
    FILE *f = fopen(pem_path, "r");
    if (!f) {
        fprintf(stderr, "[HSM-PKCS11] Cannot open PEM: %s\n", pem_path);
        return 0;
    }
    char line[256];
    char b64[HSM_MAX_CERT_BYTES];
    size_t b64_len = 0;
    int in_cert = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "-----BEGIN"))     { in_cert = 1; continue; }
        if (strstr(line, "-----END"))       { break; }
        if (in_cert) {
            size_t l = strlen(line);
            while (l > 0 && (line[l-1] == '\n' || line[l-1] == '\r')) l--;
            memcpy(b64 + b64_len, line, l);
            b64_len += l;
        }
    }
    fclose(f);
    b64[b64_len] = '\0';
    return _b64_decode(b64, der_out, der_max);
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* RSA public key extraction from DER certificate                             */
/* ─────────────────────────────────────────────────────────────────────────── */

static int _extract_rsa_pub(const unsigned char *der, size_t der_len,
                              unsigned char *mod, size_t *mod_len,
                              unsigned char *exp, size_t *exp_len)
{
    const unsigned char *p = der;
    X509 *cert = d2i_X509(NULL, &p, (long)der_len);
    if (!cert) {
        fprintf(stderr, "[HSM-PKCS11] d2i_X509 failed\n");
        return -1;
    }
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    X509_free(cert);
    if (!pkey) {
        fprintf(stderr, "[HSM-PKCS11] X509_get_pubkey failed\n");
        return -1;
    }
    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    if (!rsa) {
        fprintf(stderr, "[HSM-PKCS11] Not an RSA key\n");
        return -1;
    }
    const BIGNUM *bn_n = NULL, *bn_e = NULL;
    RSA_get0_key(rsa, &bn_n, &bn_e, NULL);
    *mod_len = (size_t)BN_num_bytes(bn_n);
    BN_bn2bin(bn_n, mod);
    *exp_len = (size_t)BN_num_bytes(bn_e);
    BN_bn2bin(bn_e, exp);
    RSA_free(rsa);
    fprintf(stderr, "[HSM-PKCS11] RSA extracted: mod=%zu bytes exp=%zu bytes\n",
            *mod_len, *exp_len);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* HSM REST sign operation                                                    */
/* ─────────────────────────────────────────────────────────────────────────── */

static int _hsm_sign(const char *key_id,
                      const unsigned char *data, CK_ULONG data_len,
                      unsigned char *sig_out, CK_ULONG *sig_len_out)
{
    char *resp = NULL;
    char ctx_id[256] = {0};
    char path[512];

    /* Step 1: create context */
    if (_post_json("/context", NULL, &resp) != 0) return -1;
    if (_json_get_str(resp, "contextId", ctx_id, sizeof(ctx_id)) != 0)
        _json_get_str(resp, "id", ctx_id, sizeof(ctx_id));
    free(resp); resp = NULL;

    if (ctx_id[0] == '\0') {
        fprintf(stderr, "[HSM-PKCS11] /context: no contextId in response\n");
        return -1;
    }

    /* Step 2: upload data */
    snprintf(path, sizeof(path), "/context/%s/data", ctx_id);
    if (_post_raw(path, data, data_len) != 0) return -1;

    /* Step 3: configure signing */
    char body[HSM_MAX_LABEL + 128];
    snprintf(body, sizeof(body),
             "{\"publicKeyId\":\"%s\","
             "\"signatureParameters\":\"SHA256WITHRSA\","
             "\"signatureFormat\":\"RAW\"}", key_id);
    snprintf(path, sizeof(path), "/context/%s/ds/creator", ctx_id);
    if (_post_json(path, body, &resp) != 0) return -1;
    free(resp); resp = NULL;

    /* Step 4: retrieve signature */
    snprintf(path, sizeof(path), "/context/%s/ds/creator/data/base64", ctx_id);
    if (_get(path, &resp) != 0) return -1;

    /* Strip whitespace from base64 response */
    char b64[HSM_MAX_SIG_BYTES * 2];
    size_t b64_out = 0;
    for (size_t i = 0; resp[i]; i++)
        if (resp[i] != ' ' && resp[i] != '\n' && resp[i] != '\r' && resp[i] != '\t')
            b64[b64_out++] = resp[i];
    b64[b64_out] = '\0';
    free(resp);

    size_t n = _b64_decode(b64, sig_out, *sig_len_out);
    if (n == 0) {
        fprintf(stderr, "[HSM-PKCS11] Failed to decode signature\n");
        return -1;
    }
    *sig_len_out = (CK_ULONG)n;
    fprintf(stderr, "[HSM-PKCS11] Signed %lu bytes → %lu-byte RSA sig (key=%s)\n",
            data_len, (unsigned long)n, key_id);
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* Configuration loading                                                       */
/* ─────────────────────────────────────────────────────────────────────────── */

static const char *_env(const char *name, const char *def)
{
    const char *v = getenv(name);
    return (v && v[0]) ? v : def;
}

static int _load_config(void)
{
    strncpy(g_cfg.base_url,     _env("HSM_BASE",        "https://localhost:7008/crypto/api/v1"), HSM_MAX_URL-1);
    strncpy(g_cfg.auth_token,   _env("HSM_AUTH_TOKEN",  "changeme"),                            HSM_MAX_TOKEN-1);
    strncpy(g_cfg.csf_key_id,   _env("HSM_CSF_KEY_ID",  ""),                                    HSM_MAX_LABEL-1);
    strncpy(g_cfg.img_key_id,   _env("HSM_IMG_KEY_ID",  ""),                                    HSM_MAX_LABEL-1);
    strncpy(g_cfg.token_label,  _env("HSM_TOKEN_LABEL", "HSM-CST"),                             HSM_MAX_LABEL-1);
    strncpy(g_cfg.token_pin,    _env("HSM_TOKEN_PIN",   "changeme"),                            HSM_MAX_LABEL-1);

    const char *tls = _env("HSM_TLS_VERIFY", "false");
    g_cfg.tls_verify = (strcmp(tls, "true") == 0 || strcmp(tls, "1") == 0) ? 1 : 0;

    const char *srk_pem = _env("HSM_SRK_CERT_PATH", "");
    const char *csf_pem = _env("HSM_CSF_CERT_PATH", "");
    const char *img_pem = _env("HSM_IMG_CERT_PATH", "");

    if (srk_pem[0]) g_cfg.srk_cert_len = _pem_to_der(srk_pem, g_cfg.srk_cert_der, HSM_MAX_CERT_BYTES);
    if (csf_pem[0]) g_cfg.csf_cert_len = _pem_to_der(csf_pem, g_cfg.csf_cert_der, HSM_MAX_CERT_BYTES);
    if (img_pem[0]) g_cfg.img_cert_len = _pem_to_der(img_pem, g_cfg.img_cert_der, HSM_MAX_CERT_BYTES);

    /* Extract RSA public key components for the private key objects */
    if (g_cfg.csf_cert_len)
        _extract_rsa_pub(g_cfg.csf_cert_der, g_cfg.csf_cert_len,
                         g_cfg.csf_modulus, &g_cfg.csf_modulus_len,
                         g_cfg.csf_exponent, &g_cfg.csf_exponent_len);
    if (g_cfg.img_cert_len)
        _extract_rsa_pub(g_cfg.img_cert_der, g_cfg.img_cert_len,
                         g_cfg.img_modulus, &g_cfg.img_modulus_len,
                         g_cfg.img_exponent, &g_cfg.img_exponent_len);

    fprintf(stderr, "[HSM-PKCS11] Cert DER sizes: SRK=%zu CSF=%zu IMG=%zu\n",
            g_cfg.srk_cert_len, g_cfg.csf_cert_len, g_cfg.img_cert_len);

    if (g_cfg.csf_key_id[0] == '\0' || g_cfg.img_key_id[0] == '\0') {
        fprintf(stderr, "[HSM-PKCS11] WARNING: HSM_CSF_KEY_ID or HSM_IMG_KEY_ID not set\n");
    }
    return 0;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* Object handle → key/cert mapping                                           */
/*                                                                             */
/*  Handle  Class            Label   Key ID / Cert                            */
/*  ------  ---------------  ------  ---------                                 */
/*    1     CKO_CERTIFICATE  SRK     srk_cert_der                             */
/*    2     CKO_PRIVATE_KEY  CSF     csf_key_id                               */
/*    3     CKO_CERTIFICATE  CSF     csf_cert_der                             */
/*    4     CKO_PRIVATE_KEY  IMG     img_key_id                               */
/*    5     CKO_CERTIFICATE  IMG     img_cert_der                             */
/* ─────────────────────────────────────────────────────────────────────────── */

#define OBJ_SRK_CERT  1UL
#define OBJ_CSF_KEY   2UL
#define OBJ_CSF_CERT  3UL
#define OBJ_IMG_KEY   4UL
#define OBJ_IMG_CERT  5UL

static CK_OBJECT_CLASS _obj_class(CK_OBJECT_HANDLE h) {
    if (h == OBJ_SRK_CERT || h == OBJ_CSF_CERT || h == OBJ_IMG_CERT)
        return CKO_CERTIFICATE;
    return CKO_PRIVATE_KEY;
}

static const char *_obj_label(CK_OBJECT_HANDLE h) {
    switch (h) {
        case OBJ_SRK_CERT: return "SRK";
        case OBJ_CSF_KEY:  return "CSF";
        case OBJ_CSF_CERT: return "CSF";
        case OBJ_IMG_KEY:  return "IMG";
        case OBJ_IMG_CERT: return "IMG";
    }
    return "";
}

static const char *_obj_key_id(CK_OBJECT_HANDLE h) {
    if (h == OBJ_CSF_KEY) return g_cfg.csf_key_id;
    if (h == OBJ_IMG_KEY) return g_cfg.img_key_id;
    return "";
}

static const unsigned char *_obj_cert_der(CK_OBJECT_HANDLE h, size_t *len) {
    if (h == OBJ_SRK_CERT) { *len = g_cfg.srk_cert_len; return g_cfg.srk_cert_der; }
    if (h == OBJ_CSF_CERT) { *len = g_cfg.csf_cert_len; return g_cfg.csf_cert_der; }
    if (h == OBJ_IMG_CERT) { *len = g_cfg.img_cert_len; return g_cfg.img_cert_der; }
    *len = 0; return NULL;
}

/* ─────────────────────────────────────────────────────────────────────────── */
/* PKCS#11 function implementations                                           */
/* ─────────────────────────────────────────────────────────────────────────── */

#define UNUSED(x) (void)(x)

CK_EXPORT CK_RV CK_CALL C_Initialize(CK_VOID_PTR pInitArgs)
{
    UNUSED(pInitArgs);
    if (g_cfg.initialized) return CKR_OK;
    curl_global_init(CURL_GLOBAL_ALL);
    _load_config();
    g_cfg.initialized = 1;
    fprintf(stderr, "[HSM-PKCS11] Initialized. HSM base: %s\n", g_cfg.base_url);
    return CKR_OK;
}

CK_EXPORT CK_RV CK_CALL C_Finalize(CK_VOID_PTR pReserved)
{
    UNUSED(pReserved);
    curl_global_cleanup();
    g_cfg.initialized = 0;
    return CKR_OK;
}

CK_EXPORT CK_RV CK_CALL C_GetInfo(CK_INFO_PTR pInfo)
{
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    memset(pInfo, ' ', sizeof(*pInfo));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    memcpy(pInfo->manufacturerID,    "HSM PKI Bridge              ", 32);
    memcpy(pInfo->libraryDescription, "HSM REST → PKCS#11 Bridge   ", 32);
    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;
    pInfo->flags = 0;
    return CKR_OK;
}

CK_EXPORT CK_RV CK_CALL C_GetSlotList(CK_BBOOL tokenPresent,
                                        CK_SLOT_ID *pSlotList,
                                        CK_ULONG *pulCount)
{
    UNUSED(tokenPresent);
    if (!pulCount) return CKR_ARGUMENTS_BAD;
    if (pSlotList) pSlotList[0] = 0;
    *pulCount = 1;
    return CKR_OK;
}

CK_EXPORT CK_RV CK_CALL C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    if (slotID != 0) return CKR_SLOT_ID_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    memset(pInfo, ' ', sizeof(*pInfo));
    memcpy(pInfo->slotDescription, "HSM REST Virtual Slot           "
                                   "                                ", 64);
    memcpy(pInfo->manufacturerID,  "HSM PKI Bridge              ", 32);
    pInfo->flags = CKF_TOKEN_PRESENT;
    pInfo->hardwareVersion.major = 1;
    pInfo->firmwareVersion.major = 1;
    return CKR_OK;
}

CK_EXPORT CK_RV CK_CALL C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    if (slotID != 0) return CKR_SLOT_ID_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;
    memset(pInfo, ' ', sizeof(*pInfo));
    /* Pad label to 32 chars */
    char label[33];
    snprintf(label, sizeof(label), "%-32s", g_cfg.token_label);
    memcpy(pInfo->label, label, 32);
    memcpy(pInfo->manufacturerID, "HSM REST Bridge             ", 32);
    memcpy(pInfo->model,          "HSM-v1          ", 16);
    memcpy(pInfo->serialNumber,   "0000000000000001", 16);
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;
    pInfo->ulMaxSessionCount    = 16;
    pInfo->ulMaxPinLen          = 64;
    pInfo->ulMinPinLen          = 4;
    pInfo->ulTotalPublicMemory  = (CK_ULONG)-1;
    pInfo->ulFreePublicMemory   = (CK_ULONG)-1;
    pInfo->ulTotalPrivateMemory = (CK_ULONG)-1;
    pInfo->ulFreePrivateMemory  = (CK_ULONG)-1;
    return CKR_OK;
}

static CK_SESSION_HANDLE g_next_session = 1;

CK_EXPORT CK_RV CK_CALL C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                                        CK_VOID_PTR pApp, CK_NOTIFY notify,
                                        CK_SESSION_HANDLE *phSession)
{
    UNUSED(pApp); UNUSED(notify);
    if (slotID != 0) return CKR_SLOT_ID_INVALID;
    if (!phSession) return CKR_ARGUMENTS_BAD;
    if (!(flags & CKF_SERIAL_SESSION)) return CKR_SESSION_HANDLE_INVALID;
    *phSession = g_next_session++;
    return CKR_OK;
}

CK_EXPORT CK_RV CK_CALL C_CloseSession(CK_SESSION_HANDLE hSession)
{
    UNUSED(hSession);
    return CKR_OK;
}

CK_EXPORT CK_RV CK_CALL C_CloseAllSessions(CK_SLOT_ID slotID)
{
    UNUSED(slotID);
    return CKR_OK;
}

CK_EXPORT CK_RV CK_CALL C_Login(CK_SESSION_HANDLE hSession, CK_ULONG userType,
                                  CK_BYTE_PTR pPin, CK_ULONG ulPinLen)
{
    UNUSED(hSession); UNUSED(userType); UNUSED(pPin); UNUSED(ulPinLen);
    return CKR_OK;  /* Always succeed — HSM auth is via bearer token */
}

CK_EXPORT CK_RV CK_CALL C_Logout(CK_SESSION_HANDLE hSession)
{
    UNUSED(hSession);
    return CKR_OK;
}

/* FindObjects: match by CKA_CLASS and optionally CKA_LABEL */
CK_EXPORT CK_RV CK_CALL C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                                            CK_ATTRIBUTE_PTR pTemplate,
                                            CK_ULONG ulCount)
{
    UNUSED(hSession);
    g_find_state.count = 0;
    g_find_state.pos   = 0;

    CK_OBJECT_CLASS want_class = (CK_OBJECT_CLASS)-1;
    char want_label[HSM_MAX_LABEL] = {0};
    CK_BYTE want_id = 0;        /* 0 = don't filter by ID */
    int     have_id_filter = 0;

    for (CK_ULONG i = 0; i < ulCount; i++) {
        if (pTemplate[i].type == CKA_CLASS && pTemplate[i].pValue)
            want_class = *(CK_OBJECT_CLASS *)pTemplate[i].pValue;
        if (pTemplate[i].type == CKA_LABEL && pTemplate[i].pValue) {
            size_t l = pTemplate[i].ulValueLen;
            if (l >= HSM_MAX_LABEL) l = HSM_MAX_LABEL - 1;
            memcpy(want_label, pTemplate[i].pValue, l);
            want_label[l] = '\0';
        }
        if (pTemplate[i].type == CKA_ID && pTemplate[i].pValue && pTemplate[i].ulValueLen >= 1) {
            want_id = *(CK_BYTE *)pTemplate[i].pValue;
            have_id_filter = 1;
        }
    }

    /* Helper: group ID for each handle (must match CKA_ID in GetAttributeValue) */
    CK_BYTE obj_id[6] = {0, 1, 2, 2, 3, 3}; /* index 0 unused; OBJ_SRK_CERT=1, CSF=2, IMG=3 */

    CK_OBJECT_HANDLE all[] = { OBJ_SRK_CERT, OBJ_CSF_KEY, OBJ_CSF_CERT,
                                OBJ_IMG_KEY,  OBJ_IMG_CERT };
    for (size_t i = 0; i < sizeof(all)/sizeof(all[0]); i++) {
        CK_OBJECT_HANDLE h = all[i];
        if (want_class != (CK_OBJECT_CLASS)-1 && _obj_class(h) != want_class)
            continue;
        if (want_label[0] && strcmp(_obj_label(h), want_label) != 0)
            continue;
        if (have_id_filter && obj_id[h] != want_id)
            continue;
        g_find_state.matches[g_find_state.count++] = h;
    }
    return CKR_OK;
}

CK_EXPORT CK_RV CK_CALL C_FindObjects(CK_SESSION_HANDLE hSession,
                                        CK_OBJECT_HANDLE *phObject,
                                        CK_ULONG ulMaxObjectCount,
                                        CK_ULONG *pulObjectCount)
{
    UNUSED(hSession);
    CK_ULONG n = 0;
    while (n < ulMaxObjectCount && g_find_state.pos < g_find_state.count) {
        phObject[n++] = g_find_state.matches[g_find_state.pos++];
    }
    *pulObjectCount = n;
    return CKR_OK;
}

CK_EXPORT CK_RV CK_CALL C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    UNUSED(hSession);
    g_find_state.count = g_find_state.pos = 0;
    return CKR_OK;
}

CK_EXPORT CK_RV CK_CALL C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                                              CK_OBJECT_HANDLE hObject,
                                              CK_ATTRIBUTE_PTR pTemplate,
                                              CK_ULONG ulCount)
{
    UNUSED(hSession);
    if (hObject < 1 || hObject > 5) return CKR_OBJECT_HANDLE_INVALID;

    int err = 0;  /* set to 1 if any attribute is unavailable */
    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_ATTRIBUTE *a = &pTemplate[i];
        switch (a->type) {
            case CKA_CLASS: {
                CK_OBJECT_CLASS cls = _obj_class(hObject);
                if (!a->pValue) { a->ulValueLen = sizeof(cls); break; }
                if (a->ulValueLen < sizeof(cls)) { a->ulValueLen = (CK_ULONG)-1; break; }
                memcpy(a->pValue, &cls, sizeof(cls));
                a->ulValueLen = sizeof(cls);
                break;
            }
            case CKA_LABEL: {
                const char *lbl = _obj_label(hObject);
                size_t ll = strlen(lbl);
                if (!a->pValue) { a->ulValueLen = ll; break; }
                if (a->ulValueLen < ll) { a->ulValueLen = (CK_ULONG)-1; break; }
                memcpy(a->pValue, lbl, ll);
                a->ulValueLen = ll;
                break;
            }
            case CKA_VALUE: {
                /* Used by CST to retrieve certificate DER bytes */
                size_t cert_len = 0;
                const unsigned char *cert_der = _obj_cert_der(hObject, &cert_len);
                if (!cert_der) { a->ulValueLen = (CK_ULONG)-1; break; }
                if (!a->pValue) { a->ulValueLen = cert_len; break; }
                if (a->ulValueLen < cert_len) { a->ulValueLen = (CK_ULONG)-1; break; }
                memcpy(a->pValue, cert_der, cert_len);
                a->ulValueLen = cert_len;
                break;
            }
            case CKA_KEY_TYPE: {
                CK_KEY_TYPE kt = CKK_RSA;
                if (!a->pValue) { a->ulValueLen = sizeof(kt); break; }
                memcpy(a->pValue, &kt, sizeof(kt));
                a->ulValueLen = sizeof(kt);
                break;
            }
            case CKA_MODULUS: {
                /* Only for private key objects — return RSA modulus */
                const unsigned char *mod = NULL;
                size_t mod_len = 0;
                if (hObject == OBJ_CSF_KEY) { mod = g_cfg.csf_modulus; mod_len = g_cfg.csf_modulus_len; }
                else if (hObject == OBJ_IMG_KEY) { mod = g_cfg.img_modulus; mod_len = g_cfg.img_modulus_len; }
                if (!mod || !mod_len) { a->ulValueLen = (CK_ULONG)-1; err = 1; break; }
                if (!a->pValue) { a->ulValueLen = mod_len; break; }
                if (a->ulValueLen < mod_len) { a->ulValueLen = (CK_ULONG)-1; err = 1; break; }
                memcpy(a->pValue, mod, mod_len);
                a->ulValueLen = mod_len;
                break;
            }
            case CKA_PUBLIC_EXPONENT: {
                const unsigned char *exp = NULL;
                size_t exp_len = 0;
                if (hObject == OBJ_CSF_KEY) { exp = g_cfg.csf_exponent; exp_len = g_cfg.csf_exponent_len; }
                else if (hObject == OBJ_IMG_KEY) { exp = g_cfg.img_exponent; exp_len = g_cfg.img_exponent_len; }
                if (!exp || !exp_len) { a->ulValueLen = (CK_ULONG)-1; err = 1; break; }
                if (!a->pValue) { a->ulValueLen = exp_len; break; }
                if (a->ulValueLen < exp_len) { a->ulValueLen = (CK_ULONG)-1; err = 1; break; }
                memcpy(a->pValue, exp, exp_len);
                a->ulValueLen = exp_len;
                break;
            }
            case CKA_MODULUS_BITS: {
                /* Return modulus bit length */
                size_t mod_len = 0;
                if (hObject == OBJ_CSF_KEY) mod_len = g_cfg.csf_modulus_len;
                else if (hObject == OBJ_IMG_KEY) mod_len = g_cfg.img_modulus_len;
                CK_ULONG bits = (CK_ULONG)(mod_len * 8);
                if (!a->pValue) { a->ulValueLen = sizeof(bits); break; }
                memcpy(a->pValue, &bits, sizeof(bits));
                a->ulValueLen = sizeof(bits);
                break;
            }
            case CKA_SIGN: {
                CK_BBOOL b = (hObject == OBJ_CSF_KEY || hObject == OBJ_IMG_KEY) ? CK_TRUE : CK_FALSE;
                if (!a->pValue) { a->ulValueLen = sizeof(b); break; }
                memcpy(a->pValue, &b, sizeof(b));
                a->ulValueLen = sizeof(b);
                break;
            }
            case CKA_TOKEN: {
                CK_BBOOL b = CK_TRUE;
                if (!a->pValue) { a->ulValueLen = sizeof(b); break; }
                memcpy(a->pValue, &b, sizeof(b));
                a->ulValueLen = sizeof(b);
                break;
            }
            case CKA_CERTIFICATE_TYPE: {
                CK_CERTIFICATE_TYPE ct = CKC_X_509;
                if (!a->pValue) { a->ulValueLen = sizeof(ct); break; }
                if (a->ulValueLen < sizeof(ct)) { a->ulValueLen = (CK_ULONG)-1; break; }
                memcpy(a->pValue, &ct, sizeof(ct));
                a->ulValueLen = sizeof(ct);
                break;
            }
            case CKA_ID: {
                /* Group IDs: 1=SRK, 2=CSF, 3=IMG — must match between key and cert */
                CK_BYTE id;
                if (hObject == OBJ_SRK_CERT)              id = 1;
                else if (hObject == OBJ_CSF_KEY || hObject == OBJ_CSF_CERT) id = 2;
                else if (hObject == OBJ_IMG_KEY || hObject == OBJ_IMG_CERT) id = 3;
                else { a->ulValueLen = (CK_ULONG)-1; err = 1; break; }
                if (!a->pValue) { a->ulValueLen = sizeof(id); break; }
                memcpy(a->pValue, &id, sizeof(id));
                a->ulValueLen = sizeof(id);
                break;
            }
            default:
                a->ulValueLen = (CK_ULONG)-1;
                err = 1;
                break;
        }
    }
    return err ? CKR_ATTRIBUTE_TYPE_INVALID : CKR_OK;
}

CK_EXPORT CK_RV CK_CALL C_SignInit(CK_SESSION_HANDLE hSession,
                                     CK_MECHANISM_PTR pMechanism,
                                     CK_OBJECT_HANDLE hKey)
{
    UNUSED(hSession);
    if (!pMechanism) return CKR_ARGUMENTS_BAD;
    if (hKey != OBJ_CSF_KEY && hKey != OBJ_IMG_KEY)
        return CKR_KEY_HANDLE_INVALID;

    g_sign_state.session   = hSession;
    g_sign_state.key_handle = hKey;
    g_sign_state.mechanism  = pMechanism->mechanism;
    return CKR_OK;
}

CK_EXPORT CK_RV CK_CALL C_Sign(CK_SESSION_HANDLE hSession,
                                 CK_BYTE_PTR pData, CK_ULONG ulDataLen,
                                 CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
    UNUSED(hSession);
    if (!pData || !pulSignatureLen) return CKR_ARGUMENTS_BAD;
    if (g_sign_state.key_handle == CK_INVALID_HANDLE)
        return CKR_OPERATION_NOT_INITIALIZED;

    const char *key_id = _obj_key_id(g_sign_state.key_handle);
    if (!key_id || key_id[0] == '\0') return CKR_KEY_HANDLE_INVALID;

    /* If caller passes NULL pSignature, return required size first */
    if (!pSignature) {
        *pulSignatureLen = HSM_MAX_SIG_BYTES;
        return CKR_OK;
    }

    if (_hsm_sign(key_id, pData, ulDataLen, pSignature, pulSignatureLen) != 0)
        return CKR_FUNCTION_FAILED;

    g_sign_state.key_handle = CK_INVALID_HANDLE;  /* one-shot */
    return CKR_OK;
}

/* Stubs for functions CST may call but we don't need to implement fully */
CK_EXPORT CK_RV CK_CALL C_GetMechanismList(CK_SLOT_ID s, CK_MECHANISM_TYPE_PTR p, CK_ULONG_PTR n)
{ UNUSED(s); UNUSED(p); if(n) *n=0; return CKR_OK; }

CK_EXPORT CK_RV CK_CALL C_GetMechanismInfo(CK_SLOT_ID s, CK_MECHANISM_TYPE t, CK_MECHANISM_INFO_PTR p)
{ UNUSED(s); UNUSED(t); UNUSED(p); return CKR_MECHANISM_INVALID; }

CK_EXPORT CK_RV CK_CALL C_GetSessionInfo(CK_SESSION_HANDLE h, CK_SESSION_INFO_PTR p)
{ UNUSED(h); if(p){ p->slotID=0; p->state=0; p->flags=CKF_SERIAL_SESSION; p->ulDeviceError=0; } return CKR_OK; }

CK_EXPORT CK_RV CK_CALL C_SignUpdate(CK_SESSION_HANDLE h, CK_BYTE_PTR p, CK_ULONG l)
{ UNUSED(h); UNUSED(p); UNUSED(l); return CKR_FUNCTION_NOT_SUPPORTED; }

CK_EXPORT CK_RV CK_CALL C_SignFinal(CK_SESSION_HANDLE h, CK_BYTE_PTR p, CK_ULONG_PTR l)
{ UNUSED(h); UNUSED(p); UNUSED(l); return CKR_FUNCTION_NOT_SUPPORTED; }

CK_EXPORT CK_RV CK_CALL C_DigestInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m)
{ UNUSED(h); UNUSED(m); return CKR_FUNCTION_NOT_SUPPORTED; }

CK_EXPORT CK_RV CK_CALL C_Digest(CK_SESSION_HANDLE h, CK_BYTE_PTR d, CK_ULONG dl, CK_BYTE_PTR p, CK_ULONG_PTR l)
{ UNUSED(h);UNUSED(d);UNUSED(dl);UNUSED(p);UNUSED(l); return CKR_FUNCTION_NOT_SUPPORTED; }

CK_EXPORT CK_RV CK_CALL C_VerifyInit(CK_SESSION_HANDLE h, CK_MECHANISM_PTR m, CK_OBJECT_HANDLE k)
{ UNUSED(h);UNUSED(m);UNUSED(k); return CKR_FUNCTION_NOT_SUPPORTED; }

CK_EXPORT CK_RV CK_CALL C_Verify(CK_SESSION_HANDLE h, CK_BYTE_PTR d, CK_ULONG dl, CK_BYTE_PTR s, CK_ULONG sl)
{ UNUSED(h);UNUSED(d);UNUSED(dl);UNUSED(s);UNUSED(sl); return CKR_FUNCTION_NOT_SUPPORTED; }

/* ─────────────────────────────────────────────────────────────────────────── */
/* C_GetFunctionList — mandatory PKCS#11 entry point                          */
/* ─────────────────────────────────────────────────────────────────────────── */

static CK_FUNCTION_LIST g_func_list;  /* zeroed at startup */

CK_EXPORT CK_RV CK_CALL C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
    if (!ppFunctionList) return CKR_ARGUMENTS_BAD;

    g_func_list.version.major = 2;
    g_func_list.version.minor = 40;

    /* General-purpose */
    g_func_list.C_Initialize      = C_Initialize;
    g_func_list.C_Finalize        = C_Finalize;
    g_func_list.C_GetInfo         = C_GetInfo;
    g_func_list.C_GetFunctionList = C_GetFunctionList;

    /* Slot/token */
    g_func_list.C_GetSlotList     = C_GetSlotList;
    g_func_list.C_GetSlotInfo     = C_GetSlotInfo;
    g_func_list.C_GetTokenInfo    = C_GetTokenInfo;
    g_func_list.C_GetMechanismList = C_GetMechanismList;
    g_func_list.C_GetMechanismInfo = C_GetMechanismInfo;
    g_func_list.C_InitToken       = NULL_PTR;   /* not supported */
    g_func_list.C_InitPIN         = NULL_PTR;
    g_func_list.C_SetPIN          = NULL_PTR;

    /* Session */
    g_func_list.C_OpenSession      = C_OpenSession;
    g_func_list.C_CloseSession     = C_CloseSession;
    g_func_list.C_CloseAllSessions = C_CloseAllSessions;
    g_func_list.C_GetSessionInfo   = C_GetSessionInfo;
    g_func_list.C_GetOperationState = NULL_PTR;
    g_func_list.C_SetOperationState = NULL_PTR;
    g_func_list.C_Login            = C_Login;
    g_func_list.C_Logout           = C_Logout;

    /* Object */
    g_func_list.C_CreateObject    = NULL_PTR;
    g_func_list.C_CopyObject      = NULL_PTR;
    g_func_list.C_DestroyObject   = NULL_PTR;
    g_func_list.C_GetObjectSize   = NULL_PTR;
    g_func_list.C_GetAttributeValue = C_GetAttributeValue;
    g_func_list.C_SetAttributeValue = NULL_PTR;
    g_func_list.C_FindObjectsInit  = C_FindObjectsInit;
    g_func_list.C_FindObjects      = C_FindObjects;
    g_func_list.C_FindObjectsFinal = C_FindObjectsFinal;

    /* Encryption / decryption — not used for signing */
    g_func_list.C_EncryptInit     = NULL_PTR;
    g_func_list.C_Encrypt         = NULL_PTR;
    g_func_list.C_EncryptUpdate   = NULL_PTR;
    g_func_list.C_EncryptFinal    = NULL_PTR;
    g_func_list.C_DecryptInit     = NULL_PTR;
    g_func_list.C_Decrypt         = NULL_PTR;
    g_func_list.C_DecryptUpdate   = NULL_PTR;
    g_func_list.C_DecryptFinal    = NULL_PTR;

    /* Digest */
    g_func_list.C_DigestInit      = C_DigestInit;
    g_func_list.C_Digest          = C_Digest;
    g_func_list.C_DigestUpdate    = NULL_PTR;
    g_func_list.C_DigestKey       = NULL_PTR;
    g_func_list.C_DigestFinal     = NULL_PTR;

    /* Signing — core functionality */
    g_func_list.C_SignInit        = C_SignInit;
    g_func_list.C_Sign            = C_Sign;
    g_func_list.C_SignUpdate      = C_SignUpdate;
    g_func_list.C_SignFinal       = C_SignFinal;
    g_func_list.C_SignRecoverInit = NULL_PTR;
    g_func_list.C_SignRecover     = NULL_PTR;

    /* Verification */
    g_func_list.C_VerifyInit      = C_VerifyInit;
    g_func_list.C_Verify          = C_Verify;
    g_func_list.C_VerifyUpdate    = NULL_PTR;
    g_func_list.C_VerifyFinal     = NULL_PTR;
    g_func_list.C_VerifyRecoverInit = NULL_PTR;
    g_func_list.C_VerifyRecover   = NULL_PTR;

    /* Combined — not needed */
    g_func_list.C_DigestEncryptUpdate  = NULL_PTR;
    g_func_list.C_DecryptDigestUpdate  = NULL_PTR;
    g_func_list.C_SignEncryptUpdate    = NULL_PTR;
    g_func_list.C_DecryptVerifyUpdate  = NULL_PTR;

    /* Key management */
    g_func_list.C_GenerateKey     = NULL_PTR;
    g_func_list.C_GenerateKeyPair = NULL_PTR;
    g_func_list.C_WrapKey         = NULL_PTR;
    g_func_list.C_UnwrapKey       = NULL_PTR;
    g_func_list.C_DeriveKey       = NULL_PTR;

    /* Random */
    g_func_list.C_SeedRandom      = NULL_PTR;
    g_func_list.C_GenerateRandom  = NULL_PTR;

    /* Parallel — not supported */
    g_func_list.C_GetFunctionStatus = NULL_PTR;
    g_func_list.C_CancelFunction    = NULL_PTR;
    g_func_list.C_WaitForSlotEvent  = NULL_PTR;

    *ppFunctionList = &g_func_list;
    return CKR_OK;
}
