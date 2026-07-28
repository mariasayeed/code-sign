#!/usr/bin/env python3

import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests

requests.packages.urllib3.disable_warnings()

# ----------------------------------------------------------------------
# PKI/HSM defaults
# ----------------------------------------------------------------------

DEFAULT_APP_KEY_ALG = "RSA_4096"
DEFAULT_SIG_ALG = "SHA256WITHRSA"

# ----------------------------------------------------------------------
# OPTEE constants
# ----------------------------------------------------------------------

SHDR_MAGIC = 0x4F545348
SHDR_BOOTSTRAP_TA = 1

TEE_ALG_RSASSA_PKCS1_V1_5_SHA256 = 0x70004830

HASH_SIZE = 32

# ----------------------------------------------------------------------
# Utils
# ----------------------------------------------------------------------


def log(msg, level="INFO"):
    print(f"[{level:<5}] {msg}", flush=True)


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def validate_uuid(value):
    pat = re.compile(
        r"^[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}$"
    )

    if not pat.match(value):
        raise argparse.ArgumentTypeError(f"Invalid UUID: {value}")

    return value.lower()


def sha256_bytes(data: bytes):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path):
    h = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


# ----------------------------------------------------------------------
# PKI
# ----------------------------------------------------------------------


def pki_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def create_pki(pki_base, token, product_code):

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
        headers=pki_headers(token),
        verify=False,
    )

    r.raise_for_status()

    resp = r.json()

    pki_id = resp.get("pkid") or resp.get("id")

    if not pki_id:
        raise RuntimeError("PKI create response missing ID")

    return pki_id


def create_application_keypair(
    pki_base,
    token,
    pki_id,
    label,
):

    body = {
        "keyPairParameters": DEFAULT_APP_KEY_ALG,
        "ownerId": pki_id,
        "subjectC": "US",
        "subjectO": "ITSec",
        "subjectCn": label,
    }

    r = requests.post(
        f"{pki_base}/pki/{pki_id}/keypair",
        json=body,
        headers=pki_headers(token),
        verify=False,
    )

    r.raise_for_status()

    resp = r.json()

    key_id = (
        resp.get("publicKeyId")
        or resp.get("keyPairId")
    )

    if not key_id:
        raise RuntimeError("Keypair response missing ID")

    return key_id


def load_key_map(path):

    if not path.exists():
        return {
            "version": 1,
            "products": {},
        }

    with path.open() as f:
        return json.load(f)


def save_key_map(path, data):

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w") as f:
        json.dump(data, f, indent=2)


def setup_or_reuse_optee_key(
    pki_base,
    pki_token,
    product_code,
    key_map_path,
    create_if_missing,
):

    key_map = load_key_map(key_map_path)

    products = key_map.setdefault("products", {})

    if product_code in products:

        log(f"Reusing key for {product_code}")

        return products[product_code]

    if not create_if_missing:
        raise RuntimeError(
            f"No key mapping for {product_code}"
        )

    pki_id = create_pki(
        pki_base,
        pki_token,
        product_code,
    )

    key_id = create_application_keypair(
        pki_base,
        pki_token,
        pki_id,
        f"OPTEE_TA_{product_code}",
    )

    cfg = {
        "product_code": product_code,
        "pki_id": pki_id,
        "optee_ta_key_id": key_id,
        "created_at": now_utc(),
    }

    products[product_code] = cfg

    save_key_map(key_map_path, key_map)

    return cfg


# ----------------------------------------------------------------------
# HSM
# ----------------------------------------------------------------------


def hsm_json_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def hsm_raw_headers(token):
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/octet-stream",
    }


def hsm_auth_headers(token):
    return {
        "Authorization": f"Bearer {token}",
    }


def hsm_delete_context(
    hsm_base,
    hsm_token,
    ctx_id,
):
    try:
        requests.delete(
            f"{hsm_base}/context/{ctx_id}",
            headers=hsm_auth_headers(hsm_token),
            verify=False,
            timeout=15,
        )
    except Exception:
        pass


def hsm_sign(
    hsm_base,
    hsm_token,
    key_id,
    data_to_sign,
):

    ctx_id = None

    try:

        r = requests.post(
            f"{hsm_base}/context",
            json={},
            headers=hsm_json_headers(hsm_token),
            verify=False,
        )

        r.raise_for_status()

        obj = r.json()

        ctx_id = (
            obj.get("contextId")
            or obj.get("id")
        )

        log(f"HSM Context: {ctx_id}")

        r = requests.post(
            f"{hsm_base}/context/{ctx_id}/data",
            data=data_to_sign,
            headers=hsm_raw_headers(hsm_token),
            verify=False,
        )

        r.raise_for_status()

        body = {
            "publicKeyId": key_id,
            "signatureParameters": "SHA256WITHRSA",
            "signatureFormat": "RAW",
        }

        r = requests.post(
            f"{hsm_base}/context/{ctx_id}/ds/creator",
            json=body,
            headers=hsm_json_headers(hsm_token),
            verify=False,
        )

        r.raise_for_status()

        r = requests.get(
            f"{hsm_base}/context/{ctx_id}/ds/creator/data/base64",
            headers=hsm_auth_headers(hsm_token),
            verify=False,
        )

        r.raise_for_status()

        try:
            obj = r.json()

            b64 = (
                obj.get("base64Data")
                or obj.get("Base64Data")
                or obj.get("data")
            )
        except Exception:
            b64 = r.text.strip()

        sig = base64.b64decode(
            "".join(str(b64).split())
        )

        return sig

    finally:

        if ctx_id:
            hsm_delete_context(
                hsm_base,
                hsm_token,
                ctx_id,
            )


# ----------------------------------------------------------------------
# OPTEE digest
# ----------------------------------------------------------------------


def build_optee_digest(
    image,
    ta_uuid,
    ta_version,
    sig_size,
):

    shdr = struct.pack(
        "<IIIIHH",
        SHDR_MAGIC,
        SHDR_BOOTSTRAP_TA,
        len(image),
        TEE_ALG_RSASSA_PKCS1_V1_5_SHA256,
        HASH_SIZE,
        sig_size,
    )

    uuid_bytes = uuid.UUID(
        ta_uuid
    ).bytes

    version_bytes = struct.pack(
        "store_true(
        "--sign-mode",
        choices=[
            "optee-digest",
            "raw-image",
        ],
        default="optee-digest",
    )

    p.add_argument(
        "--hsm-base",
        default=os.environ.get(
            "HSM_BASE",
            "",
        ),
    )

    p.add_argument(
        "--hsm-token",
        default=os.environ.get(
            "HSM_AUTH_TOKEN",
            "",
        ),
    )

    p.add_argument(
        "--pki-base",
        default=os.environ.get(
            "PKI_BASE",
            "",
        ),
    )

    p.add_argument(
        "--pki-token",
        default=os.environ.get(
            "PKI_AUTH_TOKEN",
            "",
        ),
    )

    return p.parse_args()


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------


def main():

    args = parse_args()

    unsigned_elf = Path(
        args.input
    ).read_bytes()

    key_cfg = setup_or_reuse_optee_key(
        pki_base=args.pki_base.rstrip("/"),
        pki_token=args.pki_token,
        product_code=args.product_code,
        key_map_path=Path(args.key_map),
        create_if_missing=not args.no_create_key,
    )

    sig_size = 512

    optee = build_optee_digest(
        image=unsigned_elf,
        ta_uuid=args.uuid,
        ta_version=args.ta_version,
        sig_size=sig_size,
    )

    if args.sign_mode == "raw-image":

        sign_blob = unsigned_elf

        log(
            "Signing raw ELF image",
            "WARN",
        )

    else:

        sign_blob = optee["digest"]

        log(
            "Signing OPTEE digest",
            "INFO",
        )

    signature = hsm_sign(
        hsm_base=args.hsm_base.rstrip("/"),
        hsm_token=args.hsm_token,
        key_id=key_cfg["optee_ta_key_id"],
        data_to_sign=sign_blob,
    )

    ta_binary = build_ta(
        optee["shdr"],
        optee["digest"],
        signature,
        optee["uuid_bytes"],
        optee["version_bytes"],
        unsigned_elf,
    )

    write_outputs(
        Path(args.out_dir),
        args.product_code,
        args.uuid,
        ta_binary,
        key_cfg,
        args.sign_mode,
    )

    log("TA generation complete", "OK")


if __name__ == "__main__":
    main()
