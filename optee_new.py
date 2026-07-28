#!/usr/bin/env python3
"""
Standalone OP-TEE TA signing script using internal PKI + HSM REST APIs.

Run:

  python3 optee_sign_standalone.py app.elf \
    --uuid 8aaaf200-2450-11e4-abe2-0002a5d5c51b \
    --product-code product-a \
    --key-map optee_key_map.json \
    --pki-base "$PKI_BASE" \
    --pki-token "$PKI_AUTH_TOKEN" \
    --hsm-base "$HSM_BASE" \
    --hsm-token "$HSM_AUTH_TOKEN" \
    --out-dir remote-optee/results

Production locked mode:

  python3 optee_sign_standalone.py app.elf \
    --uuid 8aaaf200-2450-11e4-abe2-0002a5d5c51b \
    --product-code product-a \
    --key-map optee_key_map.json \
    --no-create-key

Env vars match HAB script:
  PKI_BASE
  PKI_AUTH_TOKEN
  HSM_BASE
  HSM_AUTH_TOKEN

Output:
  remote-optee/results/<product-code>/<uuid>.ta
  remote-optee/results/<product-code>/<uuid>.ta.sha256
  remote-optee/results/<product-code>/optee_ta_public_certificate.pem
  remote-optee/results/<product-code>/optee_signing_manifest.json

Notes:
- No CST.
- No srktool.
- No SRK fuse/hash logic.
- No private key export.
- Reuses PKI/HSM API style from HAB script.
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import struct
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Union

try:
    import requests
except ImportError:
    sys.exit("pip install requests")


DEFAULT_APP_KEY_ALG = "RSA_4096"
DEFAULT_SIG_ALG = "SHA256WITHRSA"

# OP-TEE signed bootstrap TA header values. These match
# optee_os/core/include/signed_hdr.h and scripts/sign_encrypt.py.
SHDR_MAGIC = 0x4F545348
SHDR_BOOTSTRAP_TA = 1
TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 = 0x70004830
HASH_SIZE = 32
SHDR_SIZE = struct.calcsize("<IIIIHH")
BOOTSTRAP_HEADER_SIZE = 16 + struct.calcsize("<I")

DEFAULT_TIMEOUT = 60
DATA_TIMEOUT = 120


def log(msg: str, level: str = "INFO") -> None:
    print(f"[{level:<5}] {msg}", flush=True)


def now_utc() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def validate_uuid(value: str) -> str:
    pat = re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    if not pat.match(value):
        raise argparse.ArgumentTypeError(f"Invalid UUID: {value}")
    return value.lower()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ── PKI REST helpers: matches HAB script exactly ───────────────────────────────

def _pki_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def create_pki(
    pki_base: str,
    token: str,
    product_code: str,
    tls_verify: Union[bool, str],
) -> dict:
    """
    POST {pki_base}/pki
    Returns JSON with 'pkid' or 'id'.
    """
    body = {
        "signatureParameters": DEFAULT_SIG_ALG,
        "organisation": "CPI",
        "organisationUnit": "NPD",
        "commonName": f"OPTEE TA {product_code}",
        "locality": "Malvern",
        "country": "US",
    }

    r = requests.post(
        f"{pki_base}/pki",
        json=body,
        headers=_pki_headers(token),
        verify=tls_verify,
        timeout=DEFAULT_TIMEOUT,
    )
    r.raise_for_status()

    resp = r.json()
    pki_id = resp.get("pkid") or resp.get("id")
    if not pki_id:
        raise RuntimeError(f"create_pki: missing 'pkid'/'id' in response: {resp}")

    return {"pki_id": pki_id, "raw": resp}


def create_application_keypair(
    pki_base: str,
    token: str,
    pki_id: str,
    label: str,
    tls_verify: Union[bool, str],
) -> dict:
    """
    POST {pki_base}/pki/{pki_id}/keypair
    Returns JSON with 'publicKeyId' or 'keyPairId'.
    """
    body = {
        "keyPairParameters": DEFAULT_APP_KEY_ALG,
        "ownerId": pki_id,
        "notBefore": "2025-12-03T10:15:30+01:00",
        "notAfter": "2050-12-03T10:15:30+01:00",
        "subjectC": "US",
        "subjectO": "ITSec",
        "subjectCn": f"KP {label}",
        "subjects": "Malvern",
        "subject": "US",
    }

    r = requests.post(
        f"{pki_base}/pki/{pki_id}/keypair",
        json=body,
        headers=_pki_headers(token),
        verify=tls_verify,
        timeout=DEFAULT_TIMEOUT,
    )
    r.raise_for_status()

    resp = r.json()
    kp_id = resp.get("publicKeyId") or resp.get("keyPairId")
    if not kp_id:
        raise RuntimeError(
            f"create_application_keypair({label}): missing id in response: {resp}"
        )

    return {"keypair_id": kp_id, "raw": resp}


def export_certificate(
    pki_base: str,
    token: str,
    keypair_id: str,
    tls_verify: Union[bool, str],
) -> str:
    """
    GET {pki_base}/keypair/{keypair_id}/certificate/textual
    Returns the public certificate as plain PEM text.
    """
    r = requests.get(
        f"{pki_base}/keypair/{keypair_id}/certificate/textual",
        headers=_pki_headers(token),
        verify=tls_verify,
        timeout=DEFAULT_TIMEOUT,
    )
    r.raise_for_status()

    certificate_pem = r.text.strip()
    if (
        "-----BEGIN CERTIFICATE-----" not in certificate_pem
        or "-----END CERTIFICATE-----" not in certificate_pem
    ):
        raise RuntimeError(
            f"Certificate export for keypair {keypair_id} did not return PEM"
        )
    return certificate_pem + "\n"


# ── Product key map ────────────────────────────────────────────────────────────

def load_key_map(path: Path) -> dict:
    if not path.is_file():
        return {"version": 1, "products": {}}

    with path.open() as f:
        data = json.load(f)

    data.setdefault("version", 1)
    data.setdefault("products", {})
    return data


def save_key_map(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w") as f:
        json.dump(data, f, indent=2)
    tmp.replace(path)


def setup_or_reuse_optee_key(
    pki_base: str,
    pki_token: str,
    product_code: str,
    key_map_path: Path,
    create_if_missing: bool,
    tls_verify: Union[bool, str],
) -> dict:
    key_map = load_key_map(key_map_path)
    products = key_map.setdefault("products", {})

    if product_code in products:
        cfg = products[product_code]

        if not cfg.get("pki_id") or not cfg.get("optee_ta_key_id"):
            raise RuntimeError(
                f"Invalid key map entry for {product_code}: missing pki_id/optee_ta_key_id"
            )

        log(f"Reusing OPTEE_TA key for product: {product_code}")
        log(f"  PKI ID: {cfg['pki_id']}")
        log(f"  OPTEE_TA key ID: {cfg['optee_ta_key_id']}")
        return cfg

    if not create_if_missing:
        raise RuntimeError(
            f"No key mapping found for product_code={product_code}; --no-create-key set"
        )

    log(f"No OPTEE_TA key found for product: {product_code}")
    log("Creating new PKI + OPTEE_TA application keypair")

    pki = create_pki(pki_base, pki_token, product_code, tls_verify)
    pki_id = pki["pki_id"]
    log(f"Created PKI: {pki_id}")

    key = create_application_keypair(
        pki_base=pki_base,
        token=pki_token,
        pki_id=pki_id,
        label=f"OPTEE_TA_{product_code}",
        tls_verify=tls_verify,
    )
    key_id = key["keypair_id"]
    log(f"Created OPTEE_TA keypair: {key_id}")

    cfg = {
        "product_code": product_code,
        "pki_id": pki_id,
        "optee_ta_key_id": key_id,
        "algorithm": DEFAULT_APP_KEY_ALG,
        "signature_algorithm": DEFAULT_SIG_ALG,
        "created_at": now_utc(),
    }

    products[product_code] = cfg
    save_key_map(key_map_path, key_map)

    log(f"Key map updated: {key_map_path}", "OK")
    return cfg


# ── HSM REST helpers ───────────────────────────────────────────────────────────

def _hsm_json_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _hsm_raw_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/octet-stream",
    }


def _hsm_auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def hsm_sign(
    hsm_base: str,
    hsm_token: str,
    key_id: str,
    data_to_sign: bytes,
    tls_verify: Union[bool, str],
) -> bytes:
    """
    HSM flow matching PKCS#11 bridge:
      1. POST /context
      2. POST /context/{id}/data
      3. POST /context/{id}/ds/creator
      4. GET  /context/{id}/ds/creator/data/base64
    """

    ctx_id = None

    try:
        r = requests.post(
            f"{hsm_base}/context",
            json={},
            headers=_hsm_json_headers(hsm_token),
            verify=tls_verify,
            timeout=DEFAULT_TIMEOUT,
        )
        r.raise_for_status()

        resp = r.json()
        ctx_id = resp.get("contextId") or resp.get("id")
        if not ctx_id:
            raise RuntimeError(f"/context: missing contextId/id in response: {resp}")

        log(f"HSM context: {ctx_id}")

        r = requests.post(
            f"{hsm_base}/context/{ctx_id}/data",
            data=data_to_sign,
            headers=_hsm_raw_headers(hsm_token),
            verify=tls_verify,
            timeout=DATA_TIMEOUT,
        )
        r.raise_for_status()

        body = {
            "publicKeyId": key_id,
            "signatureParameters": DEFAULT_SIG_ALG,
            "signatureFormat": "RAW",
        }

        r = requests.post(
            f"{hsm_base}/context/{ctx_id}/ds/creator",
            json=body,
            headers=_hsm_json_headers(hsm_token),
            verify=tls_verify,
            timeout=DATA_TIMEOUT,
        )
        r.raise_for_status()

        r = requests.get(
            f"{hsm_base}/context/{ctx_id}/ds/creator/data/base64",
            headers=_hsm_auth_headers(hsm_token),
            verify=tls_verify,
            timeout=DATA_TIMEOUT,
        )
        r.raise_for_status()

        text = r.text.strip()

        try:
            obj = r.json()
            b64 = (
                obj.get("Base64Data")
                or obj.get("base64Data")
                or obj.get("data")
            )
            if not b64:
                b64 = text
        except (ValueError, TypeError):
            b64 = text

        try:
            sig = base64.b64decode(
                "".join(str(b64).split()),
                validate=True,
            )
        except (binascii.Error, ValueError) as exc:
            raise RuntimeError("HSM returned invalid base64 signature data") from exc

        if not sig:
            raise RuntimeError("HSM returned empty signature")

        log(f"HSM signature size: {len(sig)} bytes", "OK")
        return sig

    finally:
        if ctx_id:
            try:
                r = requests.delete(
                    f"{hsm_base}/context/{ctx_id}",
                    headers=_hsm_auth_headers(hsm_token),
                    verify=tls_verify,
                    timeout=DEFAULT_TIMEOUT,
                )
                r.raise_for_status()
            except requests.RequestException as exc:
                log(f"Could not delete HSM context {ctx_id}: {exc}", "WARN")


# ── OP-TEE TA packaging ────────────────────────────────────────────────────────

def signature_size_for_key(key_cfg: dict, override: int = None) -> int:
    if override is not None:
        if not 1 <= override <= 0xFFFF:
            raise ValueError("--signature-size must be between 1 and 65535")
        return override

    algorithm = str(key_cfg.get("algorithm", DEFAULT_APP_KEY_ALG))
    match = re.fullmatch(r"RSA[_-]?(\d+)", algorithm, re.IGNORECASE)
    if not match:
        raise RuntimeError(
            f"Cannot infer RSA signature size from key algorithm {algorithm!r}; "
            "use --signature-size"
        )

    bits = int(match.group(1))
    if bits % 8:
        raise RuntimeError(f"Invalid RSA key size in algorithm {algorithm!r}")
    return bits // 8


def build_bootstrap_ta_parts(
    unsigned_elf: bytes,
    ta_uuid: str,
    ta_version: int,
    signature_size: int,
) -> Dict[str, bytes]:
    """Build the exact fields hashed by OP-TEE's sign_encrypt.py."""
    if not 0 <= ta_version <= 0xFFFFFFFF:
        raise ValueError("--ta-version must be an unsigned 32-bit integer")
    if not 1 <= signature_size <= 0xFFFF:
        raise ValueError("Signature size must fit the OP-TEE uint16_t field")

    shdr = struct.pack(
        "<IIIIHH",
        SHDR_MAGIC,
        SHDR_BOOTSTRAP_TA,
        len(unsigned_elf),
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
        HASH_SIZE,
        signature_size,
    )
    uuid_bytes = uuid.UUID(ta_uuid).bytes
    version_bytes = struct.pack("<I", ta_version)
    signing_preimage = shdr + uuid_bytes + version_bytes + unsigned_elf
    digest = hashlib.sha256(signing_preimage).digest()

    return {
        "shdr": shdr,
        "uuid": uuid_bytes,
        "version": version_bytes,
        "image": unsigned_elf,
        "signing_preimage": signing_preimage,
        "digest": digest,
    }


def build_signed_ta(parts: Dict[str, bytes], signature: bytes) -> bytes:
    """Stitch an OP-TEE bootstrap TA in the official field order."""
    expected_size = struct.unpack("<IIIIHH", parts["shdr"])[5]
    if len(signature) != expected_size:
        raise RuntimeError(
            f"HSM returned a {len(signature)}-byte signature, but the OP-TEE "
            f"header was built for {expected_size} bytes"
        )

    return (
        parts["shdr"]
        + parts["digest"]
        + signature
        + parts["uuid"]
        + parts["version"]
        + parts["image"]
    )


def inspect_bootstrap_ta(signed_ta: bytes) -> Dict[str, Any]:
    """Validate the package structure and embedded digest before writing it."""
    minimum_size = SHDR_SIZE + HASH_SIZE + BOOTSTRAP_HEADER_SIZE
    if len(signed_ta) < minimum_size:
        raise RuntimeError("Generated TA is shorter than its required headers")

    fields = struct.unpack("<IIIIHH", signed_ta[:SHDR_SIZE])
    magic, image_type, image_size, algorithm, hash_size, signature_size = fields

    if magic != SHDR_MAGIC:
        raise RuntimeError(f"Generated TA has invalid magic {magic:#x}")
    if image_type != SHDR_BOOTSTRAP_TA:
        raise RuntimeError(f"Generated TA has invalid image type {image_type}")
    if algorithm != TEE_ALG_RSASSA_PKCS1_V1_5_SHA256:
        raise RuntimeError(f"Generated TA has invalid algorithm {algorithm:#x}")
    if hash_size != HASH_SIZE:
        raise RuntimeError(f"Generated TA has invalid hash size {hash_size}")

    digest_offset = SHDR_SIZE
    signature_offset = digest_offset + hash_size
    bootstrap_offset = signature_offset + signature_size
    image_offset = bootstrap_offset + BOOTSTRAP_HEADER_SIZE
    expected_total = image_offset + image_size
    if len(signed_ta) != expected_total:
        raise RuntimeError(
            f"Generated TA size is {len(signed_ta)}, expected {expected_total}"
        )

    embedded_digest = signed_ta[digest_offset:signature_offset]
    digest_preimage = (
        signed_ta[:SHDR_SIZE]
        + signed_ta[bootstrap_offset:bootstrap_offset + BOOTSTRAP_HEADER_SIZE]
        + signed_ta[image_offset:]
    )
    calculated_digest = hashlib.sha256(digest_preimage).digest()
    if embedded_digest != calculated_digest:
        raise RuntimeError("Generated TA embedded digest does not match its content")

    ta_uuid = str(
        uuid.UUID(bytes=signed_ta[bootstrap_offset:bootstrap_offset + 16])
    )
    ta_version = struct.unpack(
        "<I", signed_ta[bootstrap_offset + 16:image_offset]
    )[0]
    return {
        "magic": magic,
        "image_type": image_type,
        "image_size": image_size,
        "algorithm": algorithm,
        "hash_size": hash_size,
        "signature_size": signature_size,
        "digest": embedded_digest,
        "ta_uuid": ta_uuid,
        "ta_version": ta_version,
    }


def write_outputs(
    out_dir: Path,
    product_code: str,
    ta_uuid: str,
    input_path: Path,
    unsigned_elf: bytes,
    signature: bytes,
    signed_ta: bytes,
    key_cfg: dict,
    ta_info: Dict[str, Any],
    sign_mode: str,
    certificate_pem: str,
) -> None:
    product_dir = out_dir / product_code
    product_dir.mkdir(parents=True, exist_ok=True)

    ta_name = f"{ta_uuid}.ta"
    ta_path = product_dir / ta_name
    ta_path.write_bytes(signed_ta)

    ta_sha = sha256_file(ta_path)

    checksum_path = product_dir / f"{ta_name}.sha256"
    checksum_path.write_text(f"{ta_sha}  {ta_name}\n")

    certificate_path = product_dir / "optee_ta_public_certificate.pem"
    certificate_path.write_text(certificate_pem, encoding="ascii")

    manifest = {
        "product_code": product_code,
        "ta_uuid": ta_uuid,
        "input_file": str(input_path),
        "input_sha256": sha256_bytes(unsigned_elf),
        "input_size_bytes": len(unsigned_elf),
        "output_file": str(ta_path),
        "output_sha256": ta_sha,
        "output_size_bytes": len(signed_ta),
        "optee_header": {
            "magic": hex(SHDR_MAGIC),
            "img_type": SHDR_BOOTSTRAP_TA,
            "img_size": len(unsigned_elf),
            "algo": hex(TEE_ALG_RSASSA_PKCS1_V1_5_SHA256),
            "hash_algorithm": "SHA256",
            "hash_size": HASH_SIZE,
            "signature_size": len(signature),
            "ta_version": ta_info["ta_version"],
            "signed_digest_sha256": ta_info["digest"].hex(),
        },
        "signing": {
            "pki_id": key_cfg["pki_id"],
            "key_id": key_cfg["optee_ta_key_id"],
            "key_label": "OPTEE_TA",
            "key_algorithm": key_cfg.get("algorithm", DEFAULT_APP_KEY_ALG),
            "signature_algorithm": key_cfg.get("signature_algorithm", DEFAULT_SIG_ALG),
            "signature_format": "RAW",
            "signature_sha256": sha256_bytes(signature),
            "hsm_input_mode": sign_mode,
            "public_certificate_file": str(certificate_path),
            "public_certificate_sha256": sha256_bytes(
                certificate_pem.encode("ascii")
            ),
        },
        "created_at": now_utc(),
        "install_hint": f"copy {ta_name} to /lib/optee_armtz/{ta_name}",
        "public_key_hint": (
            "openssl x509 -in optee_ta_public_certificate.pem -pubkey "
            "-noout > optee_ta_public_key.pem"
        ),
    }

    manifest_path = product_dir / "optee_signing_manifest.json"
    with manifest_path.open("w") as f:
        json.dump(manifest, f, indent=2)

    log(f"Signed TA: {ta_path}", "OK")
    log(f"Checksum:  {checksum_path}", "OK")
    log(f"Certificate: {certificate_path}", "OK")
    log(f"Manifest:  {manifest_path}", "OK")


# ── Args ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="Sign OP-TEE TA ELF using internal PKI/HSM REST APIs"
    )

    p.add_argument("input", help="Unsigned OP-TEE TA ELF")
    p.add_argument("--uuid", required=True, type=validate_uuid)
    p.add_argument("--product-code", required=True)
    p.add_argument("--key-map", default="optee_key_map.json")
    p.add_argument("--no-create-key", action="store_true")
    p.add_argument("--out-dir", default="remote-optee/results")
    p.add_argument(
        "--ta-version",
        type=lambda value: int(value, 0),
        default=0,
        help="Unsigned 32-bit TA rollback-protection version (default: 0)",
    )
    p.add_argument(
        "--signature-size",
        type=int,
        help="RSA signature size in bytes; inferred from the key map by default",
    )
    p.add_argument(
        "--sign-mode",
        choices=["hsm-message", "optee-digest"],
        default="hsm-message",
        help=(
            "hsm-message uploads the OP-TEE digest preimage for SHA256WITHRSA; "
            "optee-digest uploads the 32-byte digest for an API known to accept "
            "prehashed input"
        ),
    )

    # Match HAB script env names
    p.add_argument("--hsm-base", default=os.environ.get("HSM_BASE", ""))
    p.add_argument("--hsm-token", default=os.environ.get("HSM_AUTH_TOKEN", ""))
    p.add_argument("--pki-base", default=os.environ.get("PKI_BASE", ""))
    p.add_argument("--pki-token", default=os.environ.get("PKI_AUTH_TOKEN", ""))
    tls = p.add_mutually_exclusive_group()
    tls.add_argument(
        "--ca-bundle",
        default=os.environ.get("REQUESTS_CA_BUNDLE"),
        help="CA bundle used to verify PKI/HSM HTTPS certificates",
    )
    tls.add_argument(
        "--insecure",
        action="store_true",
        help="Disable PKI/HSM TLS certificate verification",
    )

    return p.parse_args()


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    pki_token = args.pki_token or args.hsm_token

    if not args.pki_base:
        sys.exit("--pki-base is required or set PKI_BASE")

    if not args.hsm_base:
        sys.exit("--hsm-base is required or set HSM_BASE")

    if not pki_token:
        sys.exit("--pki-token/PKI_AUTH_TOKEN or --hsm-token/HSM_AUTH_TOKEN is required")

    if not args.hsm_token:
        sys.exit("--hsm-token is required or set HSM_AUTH_TOKEN")
    if not 0 <= args.ta_version <= 0xFFFFFFFF:
        sys.exit("--ta-version must be an unsigned 32-bit integer")

    tls_verify = False if args.insecure else (args.ca_bundle or True)

    input_path = Path(args.input)
    if not input_path.is_file():
        sys.exit(f"Input file not found: {input_path}")

    unsigned_elf = input_path.read_bytes()
    if not unsigned_elf:
        sys.exit(f"Input file is empty: {input_path}")

    log(f"Input ELF: {input_path}")
    log(f"Input SHA256: {sha256_bytes(unsigned_elf)}")
    log(f"Product code: {args.product_code}")
    log(f"TA UUID: {args.uuid}")

    key_cfg = setup_or_reuse_optee_key(
        pki_base=args.pki_base.rstrip("/"),
        pki_token=pki_token,
        product_code=args.product_code,
        key_map_path=Path(args.key_map),
        create_if_missing=not args.no_create_key,
        tls_verify=tls_verify,
    )

    certificate_pem = export_certificate(
        pki_base=args.pki_base.rstrip("/"),
        token=pki_token,
        keypair_id=key_cfg["optee_ta_key_id"],
        tls_verify=tls_verify,
    )

    signature_size = signature_size_for_key(key_cfg, args.signature_size)
    parts = build_bootstrap_ta_parts(
        unsigned_elf=unsigned_elf,
        ta_uuid=args.uuid,
        ta_version=args.ta_version,
        signature_size=signature_size,
    )

    if args.sign_mode == "hsm-message":
        data_to_sign = parts["signing_preimage"]
        log("HSM will SHA-256 the OP-TEE signed-data preimage")
    else:
        data_to_sign = parts["digest"]
        log(
            "Uploading a precomputed digest; use only if the HSM API does not "
            "hash SHA256WITHRSA input",
            "WARN",
        )

    signature = hsm_sign(
        hsm_base=args.hsm_base.rstrip("/"),
        hsm_token=args.hsm_token,
        key_id=key_cfg["optee_ta_key_id"],
        data_to_sign=data_to_sign,
        tls_verify=tls_verify,
    )

    signed_ta = build_signed_ta(parts, signature)
    ta_info = inspect_bootstrap_ta(signed_ta)

    write_outputs(
        out_dir=Path(args.out_dir),
        product_code=args.product_code,
        ta_uuid=args.uuid,
        input_path=input_path,
        unsigned_elf=unsigned_elf,
        signature=signature,
        signed_ta=signed_ta,
        key_cfg=key_cfg,
        ta_info=ta_info,
        sign_mode=args.sign_mode,
        certificate_pem=certificate_pem,
    )


if __name__ == "__main__":
    main()
