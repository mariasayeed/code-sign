# OP-TEE + Internal PKI/HSM Signing Audit

## Conclusion

`optee_new.py` originally did not produce the current OP-TEE bootstrap TA
format. The implementation has been corrected to match the official
`optee_os/scripts/sign_encrypt.py` behavior for RSA PKCS#1 v1.5 with SHA-256.

The required digest is:

```text
SHA256(
    shdr +
    ta_uuid +
    little_endian_uint32(ta_version) +
    stripped_elf
)
```

The required output layout is:

```text
shdr
digest
signature
ta_uuid
ta_version
stripped_elf
```

The UUID identifies the TA and normally also names the installed file:

```text
/lib/optee_armtz/<uuid>.ta
```

It is not a certificate, key, or PKI object ID.

## Legacy Screenshot Review

The four screenshots in `optee_legacy/` appear to show an older fork of the
OP-TEE/Linaro signing script with support for a private key held in KMS. The
visible implementation is technically consistent with the official bootstrap
TA format:

- `SHDR_MAGIC` is `0x4F545348`.
- `SHDR_BOOTSTRAP_TA` is `1`.
- The signed header uses `struct.pack("<IIIIHH", ...)`.
- The UUID uses `args.uuid.bytes`.
- The TA version uses little-endian `struct.pack("<I", ta_version)`.
- The digest update order is header, UUID, version, then image.
- Signing uses `utils.Prehashed(SHA256)`.
- The output order is header, digest, signature, UUID, version, then image.
- Both RSA-PSS and RSA PKCS#1 v1.5 SHA-256 identifiers are present.
- Offline `digest`, `stitch`, and `verify` operations are present.

The encrypted-TA branch visible in the screenshots also follows the expected
high-level layout: AES-GCM ciphertext, a 12-byte nonce, a 16-byte tag, and the
encrypted subheader included in the digest.

Based on the visible code, the old signer could have produced a valid TA. The
screenshots cannot establish that it ever did so in the deployed environment.
Successful loading would still have depended on:

- the matching public key being embedded in the target OP-TEE OS
- the correct stripped ELF and TA UUID
- the same TA version being used during digest and stitch operations
- KMS returning the requested RSA padding/signature semantics
- correct PSS salt/MGF settings when RSA-PSS was selected
- complete, untampered source beyond the photographed portions

One useful distinction is that the old private-key/KMS abstraction signs an
already-computed digest with `Prehashed(SHA256)`. The current REST API declares
`SHA256WITHRSA`, which ordinarily hashes uploaded bytes itself. This is why the
current default uploads the complete OP-TEE digest preimage instead of uploading
the digest or raw ELF.

## Confirmed Corrections

The official values and format are:

```python
SHDR_MAGIC = 0x4F545348
SHDR_BOOTSTRAP_TA = 1
TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 = 0x70004830
```

The previous values were wrong:

```python
SHDR_MAGIC = 0x52444853
SHDR_TA = 0
```

The previous digest `SHA256(ELF)` was also wrong for a bootstrap TA because it
did not cover the signed header, UUID, or TA version.

The official signed header is:

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

The bootstrap subheader is:

```c
struct shdr_bootstrap_ta {
    uint8_t uuid[sizeof(TEE_UUID)];
    uint32_t ta_version;
};
```

`img_size` is the ELF/image length. It does not include the UUID and version
subheader.

## HSM Signing Semantics

The REST request uses:

```json
{
  "publicKeyId": "<key-id>",
  "signatureParameters": "SHA256WITHRSA",
  "signatureFormat": "RAW"
}
```

The normal interpretation of `SHA256WITHRSA` is that the service hashes the
uploaded message and then applies RSA PKCS#1 v1.5 signing. Therefore the
default `--sign-mode hsm-message` uploads:

```text
shdr + ta_uuid + ta_version + stripped_elf
```

This produces a signature over the same SHA-256 digest stored in the TA.

`--sign-mode optee-digest` remains available only for an internal service that
has been independently confirmed to treat the uploaded 32-byte value as a
prehashed SHA-256 digest despite the `SHA256WITHRSA` parameter. With an API
that hashes its input, that mode would sign `SHA256(optee_digest)` and the TA
would fail verification.

Uploading only the raw ELF is not a valid alternative: its signature omits
the OP-TEE header, UUID, and version.

## Preserved Internal REST Paths

PKI creation:

```http
POST /pki
```

Application keypair creation:

```http
POST /pki/{pki_id}/keypair
```

Public signing-certificate export:

```http
GET /keypair/{keypair_id}/certificate/textual
```

HSM context creation:

```http
POST /context
```

HSM data upload:

```http
POST /context/{id}/data
```

Signature creation:

```http
POST /context/{id}/ds/creator
```

Signature download:

```http
GET /context/{id}/ds/creator/data/base64
```

Context cleanup:

```http
DELETE /context/{id}
```

No existing PKI or HSM endpoint was renamed or removed.

## Preserved Product-Key Behavior

- PKI creation is retained.
- Application keypair creation is retained.
- Product mappings remain in `optee_key_map.json`.
- Existing mappings are reused.
- `--no-create-key` still prevents accidental key creation.
- Private keys are never exported.

The RSA signature size is inferred from the mapped algorithm, for example
`RSA_4096` produces a 512-byte signature. `--signature-size` can override this
when an older key-map entry does not describe the key size.

## CLI and Transport Controls

The corrected implementation provides:

```text
--ta-version <uint32>
--sign-mode hsm-message|optee-digest
--signature-size <bytes>
--ca-bundle <path>
--insecure
```

TLS verification is enabled by default. `--ca-bundle` supports an internal CA.
`--insecure` is an explicit compatibility escape hatch.

All REST operations have timeouts. HSM contexts are deleted in a `finally`
block, including when signing or decoding fails.

## Output Validation and Manifest

Before writing a `.ta`, the script re-parses the generated bytes and checks:

- signed-header magic
- bootstrap image type
- signature algorithm
- hash and signature sizes
- total package size
- UUID and TA version placement
- embedded digest against the complete OP-TEE digest preimage

The manifest records the TA version, embedded digest, actual signature size,
signature SHA-256, selected HSM input mode, public-certificate path, and
public-certificate SHA-256.

Each signing run also writes:

```text
optee_ta_public_certificate.pem
```

beside the `.ta` output. To generate the standalone public-key PEM required by
an OP-TEE OS build:

```bash
openssl x509 -in optee_ta_public_certificate.pem -pubkey -noout \
  > optee_ta_public_key.pem
```

Use the resulting key when building OP-TEE OS:

```bash
make TA_PUBLIC_KEY=/path/to/optee_ta_public_key.pem
```

Cryptographic signature verification still requires the public key embedded
in the matching OP-TEE OS build. The final integration test is to load the TA
on that target, or verify/stitch it with the matching official OP-TEE tooling
and public key.

## Official References

- [OP-TEE `scripts/sign_encrypt.py`](https://github.com/OP-TEE/optee_os/blob/master/scripts/sign_encrypt.py)
- [OP-TEE `core/include/signed_hdr.h`](https://github.com/OP-TEE/optee_os/blob/master/core/include/signed_hdr.h)
- [OP-TEE documentation: Offline Signing of TAs](https://optee.readthedocs.io/en/latest/building/trusted_applications.html#offline-signing-of-tas)
