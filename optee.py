#!/usr/bin/env python3
"""
Standalone OP-TEE TA signing script using internal PKI + HSM REST APIs.

Input:
  unsigned OP-TEE TA ELF

Output:
  remote-optee/results/<product-code>/<uuid>.ta
  remote-optee/results/<product-code>/<uuid>.ta.sha256
  remote-optee/results/<product-code>/optee_signing_manifest.json

Key reuse:
  Uses --key-map to map product_code -> OPTEE_TA keypair.

Key map example:
{
  "version": 1,
  "products": {
    "product-a": {
      "product_code": "product-a",
      "pki_id": "pki-123",
      "optee_ta_key_id": "key-abc",
      "algorithm": "RSA_4096",
      "signature_algorithm": "SHA256WITHRSA",
      "created_at": "2026-06-21T00:00:00Z"
    }
  }
}

Notes:
- No CST.
- No srktool.
- No HAB IVT/CSF logic.
- No private key export.
- Signing happens through HSM REST API only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    sys.exit("Missing dependency: pip install requests")


# OP-TEE signed TA header constants.
# "SHDR" as little-endian integer.
SHDR_MAGIC = 0x52444853

# Standard TA image type.
SHDR_TA = 0

# TEE_ALG_RSASSA_PKCS1_V1_5_SHA256
TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 = 0x70004830

HASH_SIZE = 32

DEFAULT_APP_KEY_ALG = "RSA_4096"
DEFAULT_SIG_ALG = "SHA256WITHRSA"


def log(msg: str, level: str = "INFO") -> None:
    print(f"[{level:<5}] {msg}", flush=True)


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def validate_uuid(value: str) -> str:
    pattern = re.compile(
        r"^[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}$"
    )
    if not pattern.match(value):
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


def atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


# ---------------------------------------------------------------------
# PKI REST helpers
# Same API shape as the HAB script:
#   POST /pki
#   POST /pki/{pki_id}/keypair
# ---------------------------------------------------------------------

def pki_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def create_pki(
    pki_base: str,
    token: str,
    product_code: str,
    verify_tls: bool,
) -> Dict[str, Any]:
    body = {
        "signatureParameters": DEFAULT_SIG_ALG,
        "organisation": "CPI",
        "organisationUnit": "NPD",
        "commonName": f"OPTEE TA Signing PKI {product_code}",
        "locality": "Malvern",
        "country": "US",
    }

    r = requests.post(
        f"{pki_base}/pki",
        json=body,
        headers=pki_headers(token),
        verify=verify_tls,
        timeout=60,
    )
    r.raise_for_status()
    resp = r.json()

    pki_id = resp.get("pkid") or resp.get("id")
    if not pki_id:
        raise RuntimeError(f"create_pki: missing pkid/id in response: {resp}")

    return {
        "pki_id": pki_id,
        "raw": resp,
    }


def create_application_keypair(
    pki_base: str,
    token: str,
    pki_id: str,
    label: str,
    verify_tls: bool,
) -> Dict[str, Any]:
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
        headers=pki_headers(token),
        verify=verify_tls,
        timeout=60,
    )
    r.raise_for_status()
    resp = r.json()

    keypair_id = resp.get("publicKeyId") or resp.get("keyPairId")
    if not keypair_id:
        raise RuntimeError(
            f"create_application_keypair({label}): "
            f"missing publicKeyId/keyPairId in response: {resp}"
        )

    return {
        "keypair_id": keypair_id,
        "raw": resp,
    }


# ---------------------------------------------------------------------
# Product key map
# ---------------------------------------------------------------------

def load_key_map(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {
            "version": 1,
            "products": {},
        }

    with path.open() as f:
        data = json.load(f)

    data.setdefault("version", 1)
    data.setdefault("products", {})
    return data


def save_key_map(path: Path, key_map: Dict[str, Any]) -> None:
    atomic_write_json(path, key_map)


def setup_or_reuse_product_key(
    *,
    pki_base: str,
    pki_token: str,
    product_code: str,
    key_map_path: Path,
    create_if_missing: bool,
    verify_tls: bool,
) -> Dict[str, Any]:
    key_map = load_key_map(key_map_path)
    products = key_map.setdefault("products", {})

    if product_code in products:
        cfg = products[product_code]

        required = ["pki_id", "optee_ta_key_id"]
        missing = [name for name in required if not cfg.get(name)]
        if missing:
            raise RuntimeError(
                f"Product {product_code} exists in {key_map_path}, "
                f"but missing fields: {missing}"
            )

        log(f"Reusing OPTEE_TA key for product_code={product_code}")
        log(f"PKI ID: {cfg['pki_id']}")
        log(f"OPTEE_TA key ID: {cfg['optee_ta_key_id']}")

        return cfg

    if not create_if_missing:
        raise RuntimeError(
            f"No OPTEE_TA key mapping found for product_code={product_code}; "
            f"--no-create-key was set"
        )

    log(f"No key mapping found for product_code={product_code}")
    log("Creating new PKI and OPTEE_TA application keypair")

    pki = create_pki(
        pki_base=pki_base,
        token=pki_token,
        product_code=product_code,
        verify_tls=verify_tls,
    )
    pki_id = pki["pki_id"]
    log(f"Created PKI: {pki_id}")

    key = create_application_keypair(
        pki_base=pki_base,
        token=pki_token,
        pki_id=pki_id,
        label=f"OPTEE_TA_{product_code}",
        verify_tls=verify_tls,
    )
    key_id = key["keypair_id"]
    log(f"Created OPTEE_TA keypair: {key_id}")

    cfg = {
        "product_code": product_code,
        "pki_id": pki_id,
        "optee_ta_key_id": key_id,
        "algorithm": DEFAULT_APP_KEY_ALG,
        "signature_algorithm": DEFAULT_SIG_ALG,
        "created_at": utc_now(),
    }

    products[product_code] = cfg
    save_key_map(key_map_path, key_map)

    log(f"Updated key map: {key_map_path}", "OK")

    return cfg


# ---------------------------------------------------------------------
# HSM REST signing helpers
# Same HSM pattern as the PKCS#11 bridge:
#   POST /context
#   POST /context/{id}/data
#   POST /context/{id}/ds/creator
#   GET  /context/{id}/ds/creator/data/base64
# ---------------------------------------------------------------------

def hsm_headers(token: str, content_type: Optional[str]) -> Dict[str, str]:
    headers = {
        "Authorization": f"Bearer {token}",
    }

    if content_type:
        headers["Content-Type"] = content_type

    return headers


def hsm_create_context(
    hsm_base: str,
    hsm_token: str,
    verify_tls: bool,
) -> str:
    r = requests.post(
        f"{hsm_base}/context",
        json={},
        headers=hsm_headers(hsm_token, "application/json"),
        verify=verify_tls,
        timeout=60,
    )
    r.raise_for_status()

    resp = r.json()
    context_id = resp.get("contextId") or resp.get("id")
    if not context_id:
        raise RuntimeError(f"/context response missing contextId/id: {resp}")

    return context_id


def hsm_upload_data(
    hsm_base: str,
    hsm_token: str,
    context_id: str,
    data: bytes,
    verify_tls: bool,
) -> None:
    r = requests.post(
        f"{hsm_base}/context/{context_id}/data",
        data=data,
        headers=hsm_headers(hsm_token, "application/octet-stream"),
        verify=verify_tls,
        timeout=120,
    )
    r.raise_for_status()


def hsm_trigger_signature(
    hsm_base: str,
    hsm_token: str,
    context_id: str,
    key_id: str,
    verify_tls: bool,
) -> None:
    body = {
        "publicKeyId": key_id,
        "signatureParameters": DEFAULT_SIG_ALG,
        "signatureFormat": "RAW",
    }

    r = requests.post(
        f"{hsm_base}/context/{context_id}/ds/creator",
        json=body,
        headers=hsm_headers(hsm_token, "application/json"),
        verify=verify_tls,
        timeout=120,
    )
    r.raise_for_status()


def hsm_get_signature(
    hsm_base: str,
    hsm_token: str,
    context_id: str,
    verify_tls: bool,
) -> bytes:
    r = requests.get(
        f"{hsm_base}/context/{context_id}/ds/creator/data/base64",
        headers=hsm_headers(hsm_token, None),
        verify=verify_tls,
        timeout=120,
    )
    r.raise_for_status()

    text = r.text.strip()

    try:
        obj = r.json()
        b64_value = (
            obj.get("Base64Data")
            or obj.get("base64Data")
            or obj.get("data")
        )
        if not b64_value:
            b64_value = text
    except Exception:
        b64_value = text

    b64_value = "".join(str(b64_value).split())
    return base64.b64decode(b64_value)


def hsm_sign(
    *,
    hsm_base: str,
    hsm_token: str,
    key_id: str,
    data_to_sign: bytes,
    verify_tls: bool,
) -> bytes:
    context_id = hsm_create_context(
        hsm_base=hsm_base,
        hsm_token=hsm_token,
        verify_tls=verify_tls,
    )
    log(f"HSM context: {context_id}")

    hsm_upload_data(
        hsm_base=hsm_base,
        hsm_token=hsm_token,
        context_id=context_id,
        data=data_to_sign,
        verify_tls=verify_tls,
    )

    hsm_trigger_signature(
        hsm_base=hsm_base,
        hsm_token=hsm_token,
        context_id=context_id,
        key_id=key_id,
        verify_tls=verify_tls,
    )

    signature = hsm_get_signature(
        hsm_base=hsm_base,
        hsm_token=hsm_token,
        context_id=context_id,
        verify_tls=verify_tls,
    )

    if not signature:
        raise RuntimeError("HSM returned empty signature")

    log(f"HSM signature size: {len(signature)} bytes", "OK")

    return signature


# ---------------------------------------------------------------------
# OP-TEE TA packaging
# ---------------------------------------------------------------------

def build_signed_ta(unsigned_elf: bytes, signature: bytes) -> bytes:
    """
    Build OP-TEE signed TA layout:

      struct shdr {
          uint32_t magic;
          uint32_t img_type;
          uint32_t img_size;
          uint32_t algo;
          uint16_t hash_size;
          uint16_t sig_size;
      };

    followed by:

      hash[hash_size]
      sig[sig_size]
      image[img_size]

    The hash field is SHA256(unsigned ELF).
    """

    image_hash = hashlib.sha256(unsigned_elf).digest()

    if len(image_hash) != HASH_SIZE:
        raise RuntimeError("Unexpected SHA256 digest length")

    if not signature:
        raise RuntimeError("Empty signature")

    shdr = struct.pack(
        "<IIIIHH",
        SHDR_MAGIC,
        SHDR_TA,
        len(unsigned_elf),
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
        len(image_hash),
        len(signature),
    )

    return shdr + image_hash + signature + unsigned_elf


def write_outputs(
    *,
    out_dir: Path,
    product_code: str,
    ta_uuid: str,
    input_path: Path,
    unsigned_elf: bytes,
    signature: bytes,
    signed_ta: bytes,
    key_cfg: Dict[str, Any],
) -> Dict[str, Any]:
    product_dir = out_dir / product_code
    product_dir.mkdir(parents=True, exist_ok=True)

    ta_name = f"{ta_uuid}.ta"
    ta_path = product_dir / ta_name
    ta_path.write_bytes(signed_ta)

    ta_sha256 = sha256_file(ta_path)

    checksum_path = product_dir / f"{ta_name}.sha256"
    checksum_path.write_text(f"{ta_sha256}  {ta_name}\n")

    manifest = {
        "product_code": product_code,
        "ta_uuid": ta_uuid,
        "input_file": str(input_path),
        "input_sha256": sha256_bytes(unsigned_elf),
        "input_size_bytes": len(unsigned_elf),
        "output_file": str(ta_path),
        "output_sha256": ta_sha256,
        "output_size_bytes": len(signed_ta),
        "optee_header": {
            "magic": hex(SHDR_MAGIC),
            "img_type": SHDR_TA,
            "img_size": len(unsigned_elf),
            "algo": hex(TEE_ALG_RSASSA_PKCS1_V1_5_SHA256),
            "hash_algorithm": "SHA256",
            "hash_size": HASH_SIZE,
            "signature_size": len(signature),
        },
        "signing": {
            "pki_id": key_cfg.get("pki_id"),
            "key_id": key_cfg.get("optee_ta_key_id"),
            "key_label": "OPTEE_TA",
            "key_algorithm": key_cfg.get("algorithm"),
            "signature_algorithm": key_cfg.get("signature_algorithm"),
            "signature_format": "RAW",
        },
        "created_at_utc": utc_now(),
        "install_hint": f"copy {ta_name} to /lib/optee_armtz/{ta_name}",
        "do_not_publish": [
            "private keys",
            "hsm token",
            "pki token",
        ],
    }

    manifest_path = product_dir / "optee_signing_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    log(f"Signed TA: {ta_path}", "OK")
    log(f"Checksum:  {checksum_path}", "OK")
    log(f"Manifest:  {manifest_path}", "OK")

    return manifest


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sign an OP-TEE Trusted Application ELF using internal PKI/HSM REST APIs"
    )

    parser.add_argument(
        "input",
        help="Unsigned OP-TEE TA ELF input",
    )

    parser.add_argument(
        "--uuid",
        required=True,
        type=validate_uuid,
        help="TA UUID; output is <uuid>.ta",
    )

    parser.add_argument(
        "--product-code",
        required=True,
        help="Product code/type used to select OPTEE_TA key",
    )

    parser.add_argument(
        "--key-map",
        default="optee_key_map.json",
        help="JSON product_code -> OPTEE_TA key map",
    )

    parser.add_argument(
        "--no-create-key",
        action="store_true",
        help="Fail if product code is missing from key map",
    )

    parser.add_argument(
        "--out-dir",
        default="remote-optee/results",
        help="Output directory",
    )

    parser.add_argument(
        "--pki-base",
        required=True,
        help="PKI REST base URL",
    )

    parser.add_argument(
        "--pki-token",
        required=True,
        help="PKI bearer token",
    )

    parser.add_argument(
        "--hsm-base",
        required=True,
        help="HSM REST base URL",
    )

    parser.add_argument(
        "--hsm-token",
        required=True,
        help="HSM bearer token",
    )

    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify TLS certs for PKI/HSM calls; default is false",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    input_path = Path(args.input)
    if not input_path.is_file():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    out_dir = Path(args.out_dir)
    key_map_path = Path(args.key_map)

    unsigned_elf = input_path.read_bytes()
    if not unsigned_elf:
        raise RuntimeError(f"Input file is empty: {input_path}")

    log(f"Input ELF: {input_path}")
    log(f"Input size: {len(unsigned_elf)} bytes")
    log(f"Input SHA256: {sha256_bytes(unsigned_elf)}")
    log(f"Product code: {args.product_code}")
    log(f"TA UUID: {args.uuid}")

    key_cfg = setup_or_reuse_product_key(
        pki_base=args.pki_base.rstrip("/"),
        pki_token=args.pki_token,
        product_code=args.product_code,
        key_map_path=key_map_path,
        create_if_missing=not args.no_create_key,
        verify_tls=args.verify_tls,
    )

    key_id = key_cfg["optee_ta_key_id"]
    log(f"Signing with OPTEE_TA key ID: {key_id}")

    signature = hsm_sign(
        hsm_base=args.hsm_base.rstrip("/"),
        hsm_token=args.hsm_token,
        key_id=key_id,
        data_to_sign=unsigned_elf,
        verify_tls=args.verify_tls,
    )

    signed_ta = build_signed_ta(
        unsigned_elf=unsigned_elf,
        signature=signature,
    )

    write_outputs(
        out_dir=out_dir,
        product_code=args.product_code,
        ta_uuid=args.uuid,
        input_path=input_path,
        unsigned_elf=unsigned_elf,
        signature=signature,
        signed_ta=signed_ta,
        key_cfg=key_cfg,
    )


if __name__ == "__main__":
    main()
