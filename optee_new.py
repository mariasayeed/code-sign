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
import hashlib
import json
import os
import re
import struct
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    sys.exit("pip install requests")


DEFAULT_APP_KEY_ALG = "RSA_4096"
DEFAULT_SIG_ALG = "SHA256WITHRSA"

# OP-TEE signed TA header values
SHDR_MAGIC = 0x52444853  # "SHDR"
SHDR_TA = 0
TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 = 0x70004830
HASH_SIZE = 32


def log(msg: str, level: str = "INFO") -> None:
    print(f"[{level:<5}] {msg}", flush=True)


def now_utc() -> str:
    return datetime.utcnow().isoformat()


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


def create_pki(pki_base: str, token: str, product_code: str) -> dict:
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
        verify=False,
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
        verify=False,
    )
    r.raise_for_status()

    resp = r.json()
    kp_id = resp.get("publicKeyId") or resp.get("keyPairId")
    if not kp_id:
        raise RuntimeError(
            f"create_application_keypair({label}): missing id in response: {resp}"
        )

    return {"keypair_id": kp_id, "raw": resp}


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

    pki = create_pki(pki_base, pki_token, product_code)
    pki_id = pki["pki_id"]
    log(f"Created PKI: {pki_id}")

    key = create_application_keypair(
        pki_base=pki_base,
        token=pki_token,
        pki_id=pki_id,
        label=f"OPTEE_TA_{product_code}",
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
) -> bytes:
    """
    HSM flow matching PKCS#11 bridge:
      1. POST /context
      2. POST /context/{id}/data
      3. POST /context/{id}/ds/creator
      4. GET  /context/{id}/ds/creator/data/base64
    """

    r = requests.post(
        f"{hsm_base}/context",
        json={},
        headers=_hsm_json_headers(hsm_token),
        verify=False,
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
        verify=False,
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
        verify=False,
    )
    r.raise_for_status()

    r = requests.get(
        f"{hsm_base}/context/{ctx_id}/ds/creator/data/base64",
        headers=_hsm_auth_headers(hsm_token),
        verify=False,
    )
    r.raise_for_status()

    text = r.text.strip()

    try:
        obj = r.json()
        b64 = obj.get("Base64Data") or obj.get("base64Data") or obj.get("data")
        if not b64:
            b64 = text
    except Exception:
        b64 = text

    b64 = "".join(str(b64).split())
    sig = base64.b64decode(b64)

    if not sig:
        raise RuntimeError("HSM returned empty signature")

    log(f"HSM signature size: {len(sig)} bytes", "OK")
    return sig


# ── OP-TEE TA packaging ────────────────────────────────────────────────────────

def build_signed_ta(unsigned_elf: bytes, signature: bytes) -> bytes:
    """
    OP-TEE signed TA layout:

      struct shdr {
          uint32_t magic;
          uint32_t img_type;
          uint32_t img_size;
          uint32_t algo;
          uint16_t hash_size;
          uint16_t sig_size;
      }

      followed by:
        hash
        signature
        ELF payload
    """

    digest = hashlib.sha256(unsigned_elf).digest()

    shdr = struct.pack(
        "<IIIIHH",
        SHDR_MAGIC,
        SHDR_TA,
        len(unsigned_elf),
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
        len(digest),
        len(signature),
    )

    return shdr + digest + signature + unsigned_elf


def write_outputs(
    out_dir: Path,
    product_code: str,
    ta_uuid: str,
    input_path: Path,
    unsigned_elf: bytes,
    signature: bytes,
    signed_ta: bytes,
    key_cfg: dict,
) -> None:
    product_dir = out_dir / product_code
    product_dir.mkdir(parents=True, exist_ok=True)

    ta_name = f"{ta_uuid}.ta"
    ta_path = product_dir / ta_name
    ta_path.write_bytes(signed_ta)

    ta_sha = sha256_file(ta_path)

    checksum_path = product_dir / f"{ta_name}.sha256"
    checksum_path.write_text(f"{ta_sha}  {ta_name}\n")

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
            "img_type": SHDR_TA,
            "img_size": len(unsigned_elf),
            "algo": hex(TEE_ALG_RSASSA_PKCS1_V1_5_SHA256),
            "hash_algorithm": "SHA256",
            "hash_size": HASH_SIZE,
            "signature_size": len(signature),
        },
        "signing": {
            "pki_id": key_cfg["pki_id"],
            "key_id": key_cfg["optee_ta_key_id"],
            "key_label": "OPTEE_TA",
            "key_algorithm": key_cfg.get("algorithm", DEFAULT_APP_KEY_ALG),
            "signature_algorithm": key_cfg.get("signature_algorithm", DEFAULT_SIG_ALG),
            "signature_format": "RAW",
        },
        "created_at": now_utc(),
        "install_hint": f"copy {ta_name} to /lib/optee_armtz/{ta_name}",
    }

    manifest_path = product_dir / "optee_signing_manifest.json"
    with manifest_path.open("w") as f:
        json.dump(manifest, f, indent=2)

    log(f"Signed TA: {ta_path}", "OK")
    log(f"Checksum:  {checksum_path}", "OK")
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

    # Match HAB script env names
    p.add_argument("--hsm-base", default=os.environ.get("HSM_BASE", ""))
    p.add_argument("--hsm-token", default=os.environ.get("HSM_AUTH_TOKEN", ""))
    p.add_argument("--pki-base", default=os.environ.get("PKI_BASE", ""))
    p.add_argument("--pki-token", default=os.environ.get("PKI_AUTH_TOKEN", ""))

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
    )

    signature = hsm_sign(
        hsm_base=args.hsm_base.rstrip("/"),
        hsm_token=args.hsm_token,
        key_id=key_cfg["optee_ta_key_id"],
        data_to_sign=unsigned_elf,
    )

    signed_ta = build_signed_ta(unsigned_elf, signature)

    write_outputs(
        out_dir=Path(args.out_dir),
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
