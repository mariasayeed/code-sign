# OP-TEE + Internal PKI/HSM Investigation Summary

## Goal

Build a production-quality OP-TEE Trusted Application signing tool that:

- Uses internal PKI REST APIs
- Uses internal HSM REST APIs
- Never exports private keys
- Supports per-product signing keys
- Stores key mappings in `optee_key_map.json`
- Produces valid OP-TEE `.ta` files
- Supports both possible HSM signing semantics until validated

---

## Current Script

The current implementation:

```python
signature = hsm_sign(
    ...
    data_to_sign=unsigned_elf
)
```

Computes:

```python
digest = SHA256(ELF)
```

And generates:

```text
shdr
digest
signature
elf
```

---

## Legacy OP-TEE Signer Reference

Found legacy OP-TEE signer code that computes:

```python
h.update(shdr)
h.update(shdr_uuid)
h.update(shdr_version)
h.update(img)

img_digest = h.finalize()
```

And then signs:

```python
img_digest
```

using:

```python
utils.Prehashed(SHA256)
```

The generated TA layout is:

```text
shdr
digest
signature
uuid
ta_version
image
```

Not:

```text
shdr
digest
signature
image
```

---

## Official OP-TEE References Found

Official OP-TEE signed header:

```c
struct shdr {
    uint32_t magic;
    uint32_t img_type;
    uint32_t img_size;
    uint32_t algo;
    uint16_t hash_size;
    uint16_t sig_size;
};
```

Layout:

```text
shdr
hash
signature
payload
```

Documentation and sources indicate OP-TEE signing is handled by:

```text
optee_os/scripts/sign_encrypt.py
```

and

```text
core/include/signed_hdr.h
```

---

## Confirmed Bug

Current script:

```python
SHDR_MAGIC = 0x52444853
```

Legacy OP-TEE:

```python
SHDR_MAGIC = 0x4F545348
```

Official OP-TEE:

```c
#define SHDR_MAGIC 0x4f545348
```

This is highly likely a bug and should be corrected.

---

## UUID Understanding

UUID is:

```text
Trusted Application identifier
```

Example:

```text
8aaaf200-2450-11e4-abe2-0002a5d5c51b
```

Used by OP-TEE for:

```text
/lib/optee_armtz/<uuid>.ta
```

The UUID is NOT:

- certificate ID
- key ID
- PKI object ID

The UUID identifies the TA itself.

---

## Important Unknown

Internal HSM API supports:

```json
{
  "signatureParameters": "SHA256WITHRSA",
  "signatureFormat": "RAW"
}
```

Question:

Does HSM perform:

```text
RSA_SIGN(SHA256(uploaded_data))
```

or:

```text
RSA_SIGN(uploaded_digest)
```

This was not proven.

---

## Two Possible Signing Models

### Model A

Upload:

```text
ELF
```

to HSM.

HSM performs:

```text
SHA256(ELF)
RSA Sign
```

Current script is closer to this.

### Model B

Generate OP-TEE digest:

```text
SHA256(
    shdr +
    uuid +
    version +
    image
)
```

Upload digest.

HSM signs digest.

Legacy OP-TEE script is closer to this.

---

## Recommendation

Support both modes.

CLI:

```bash
--sign-mode optee-digest
```

and

```bash
--sign-mode raw-image
```

---

## Production Features To Preserve

Keep from original implementation:

- PKI creation
- Keypair creation
- Product mapping via `optee_key_map.json`
- Reuse logic via `--no-create-key`

---

## HSM APIs Confirmed

Create context:

```http
POST /context
```

Upload bytes:

```http
POST /context/{id}/data
```

Sign:

```http
POST /context/{id}/ds/creator
```

Download signature:

```http
GET /context/{id}/ds/creator/data/base64
```

Cleanup:

```http
DELETE /context/{id}
```

---

## New CLI Options Needed

```python
--ta-version
```

Default:

```python
0
```

and:

```python
--sign-mode
```

Choices:

```text
optee-digest
raw-image
```

---

## Manifest Improvements

Add:

```json
{
  "ta_version": 0,
  "signature_size": 512,
  "signature_sha256": "...",
  "sign_mode": "optee-digest"
}
```

---

## Validation Steps

### Test 1

Generate:

```bash
--sign-mode optee-digest
```

Attempt TA load.

### Test 2

Generate:

```bash
--sign-mode raw-image
```

Attempt TA load.

### Test 3

Compare against official OP-TEE output if available.

---

## Final Desired Script Characteristics

- full original PKI integration
- full original HSM integration
- key-map JSON support
- per-product key reuse
- HSM context cleanup
- corrected magic value
- TA version support
- dual signing modes
- detailed manifest
- TLS CA option instead of hardcoded `verify=False`
- request timeouts
- logging
- robust error handling
- no private key export
- OP-TEE-compatible TA packaging investigation path
