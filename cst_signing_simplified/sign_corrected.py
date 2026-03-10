#!/usr/bin/env python3
"""
HAB4 signing — corrected single-file orchestrator
===================================================
Accepts an unsigned boot container (flash.bin) produced by imx-mkimage
and produces a HAB-signed container using:

  • PKI REST API   — create 4 PKIs each with SRK + CSF + IMG keys
  • srktool        — build the SRK table from the 4 SRK certs (one per PKI)
  • NXP CST        — generate CSF blob  (cst -b pkcs11 …)
  • PKCS#11 bridge — route CST's sign() call to the HSM REST API

Usage
-----
  python3 sign_corrected.py flash.bin \\
      --pkcs11-lib  ./pkcs11_bridge/build/hsm_pkcs11.so \\
      --cst         /usr/bin/cst \\
      --srktool     /usr/bin/srktool \\
      --pki-base    https://192.168.1.159:7008/pki/api/v1  \\
      --pki-token   somekey \\
      --hsm-base    https://192.168.1.159:7008/crypto/api/v1 \\
      --hsm-token   somekey

Re-use keys from a previous run:
  python3 sign_corrected.py flash.bin … --keys-config out/keys_config.json

Key creation model (matches draft_binary_signing.py)
-----------------------------------------------------
Four independent PKIs are created:
  PKI-1: SRK-1 (root keypair)  +  CSF-1 (app keypair)  +  IMG-1 (app keypair)
  PKI-2: SRK-2 + CSF-2 + IMG-2
  PKI-3: SRK-3 + CSF-3 + IMG-3
  PKI-4: SRK-4 + CSF-4 + IMG-4

srktool uses all 4 SRK certs.
Actual signing uses SRK_INDEX-th PKI's CSF and IMG keys (default: PKI-1, index 0).

API endpoints (from draft_binary_signing.py)
--------------------------------------------
  POST   {pki_base}/pki                              → create PKI instance
  POST   {pki_base}/pki/{pki_id}/rootKeyPair         → create SRK
  POST   {pki_base}/pki/{pki_id}/keypair             → create CSF or IMG
  GET    {pki_base}/keypair/{keypair_id}/certificate/textual  → export cert PEM
"""

import argparse
import json
import os
import struct
import subprocess
import sys
from datetime import datetime
from typing import Optional

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    sys.exit("pip install requests")

# ── Constants ──────────────────────────────────────────────────────────────────
IVT_HEADER        = 0x402000D1   # HAB4 IVT magic
IVT_SIZE          = 0x20         # 32 bytes
CSF_PAD_SIZE      = 0x4000       # 16 KiB — enough for RSA-4096 CSF blob
CSF_VERSION       = "4.1"
SRK_COUNT         = 4            # always 4 SRK slots
SRK_INDEX         = 0            # which PKI's CSF/IMG keys sign (0-based)
TIMESTAMP         = datetime.now().strftime("%Y%m%d_%H%M%S")

DEFAULT_SRK_KEY_ALG = "RSA_4096"
DEFAULT_APP_KEY_ALG = "RSA_4096"
DEFAULT_SIG_ALG     = "SHA256WITHRSA"


def log(msg: str, level: str = "INFO") -> None:
    print(f"[{level:<5}] {msg}", flush=True)


# ── PKI REST helpers (matching draft_binary_signing.py exactly) ────────────────
#
#  All PKI lifecycle calls go to {pki_base} with Bearer token.
#  Cert format: plain PEM text returned by /certificate/textual

def _pki_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def create_pki(pki_base: str, token: str, index: int) -> dict:
    """
    POST {pki_base}/pki
    Creates a PKI instance. Returns JSON with 'pkid' or 'id'.
    """
    body = {
        "signatureParameters": DEFAULT_SIG_ALG,
        "organisation": "CPI",
        "organisationUnit": "NPD",
        "commonName": f"Intermediate CA SRK{index}",
        "locality": "Malvern",
        "country": "US",
    }
    r = requests.post(
        f"{pki_base}/pki", json=body, headers=_pki_headers(token), verify=False
    )
    r.raise_for_status()
    resp = r.json()
    pki_id = resp.get("pkid") or resp.get("id")
    if not pki_id:
        raise RuntimeError(f"create_pki: missing 'pkid'/'id' in response: {resp}")
    return {"pki_id": pki_id, "raw": resp}


def create_root_keypair(pki_base: str, token: str, pki_id: str) -> dict:
    """
    POST {pki_base}/pki/{pki_id}/rootKeyPair
    Creates the SRK (root keypair). Returns JSON with 'publicKeyId' or 'keyPairId'.
    """
    body = {"keyPairParameters": DEFAULT_SRK_KEY_ALG}
    r = requests.post(
        f"{pki_base}/pki/{pki_id}/rootKeyPair",
        json=body, headers=_pki_headers(token), verify=False
    )
    r.raise_for_status()
    resp = r.json()
    kp_id = resp.get("publicKeyId") or resp.get("keyPairId")
    if not kp_id:
        raise RuntimeError(f"create_root_keypair: missing id in response: {resp}")
    return {"keypair_id": kp_id, "raw": resp}


def create_application_keypair(pki_base: str, token: str, pki_id: str, label: str) -> dict:
    """
    POST {pki_base}/pki/{pki_id}/keypair
    Creates a CSF or IMG application keypair. Returns JSON with 'publicKeyId' or 'keyPairId'.
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
        json=body, headers=_pki_headers(token), verify=False
    )
    r.raise_for_status()
    resp = r.json()
    kp_id = resp.get("publicKeyId") or resp.get("keyPairId")
    if not kp_id:
        raise RuntimeError(f"create_application_keypair({label}): missing id in response: {resp}")
    return {"keypair_id": kp_id, "raw": resp}


def export_certificate(pki_base: str, token: str, keypair_id: str) -> str:
    """
    GET {pki_base}/keypair/{keypair_id}/certificate/textual
    Returns the PEM certificate as plain text.
    Note: path is /keypair/ (singular), not /keypairs/ — matches draft exactly.
    """
    r = requests.get(
        f"{pki_base}/keypair/{keypair_id}/certificate/textual",
        headers=_pki_headers(token), verify=False
    )
    r.raise_for_status()
    return r.text


# ── Key management ─────────────────────────────────────────────────────────────
#
# keys_config.json layout:
# {
#   "pkis": [
#     {
#       "pki_id":       "<pki instance id>",
#       "srk_key_id":   "<publicKeyId of SRK>",
#       "srk_cert_path": "<path/SRK1.pem>",
#       "csf_key_id":   "<publicKeyId of CSF>",
#       "csf_cert_path": "<path/CSF.pem>",
#       "img_key_id":   "<publicKeyId of IMG>",
#       "img_cert_path": "<path/IMG.pem>"
#     },
#     … × 4
#   ],
#   "srk_cert_paths":  ["SRK1.pem", "SRK2.pem", "SRK3.pem", "SRK4.pem"],
#   "signing_pki_index": 0,
#   "csf_key_id":      "<from pkis[signing_pki_index]>",    ← convenience
#   "csf_cert_path":   "<from pkis[signing_pki_index]>",
#   "img_key_id":      "<from pkis[signing_pki_index]>",
#   "img_cert_path":   "<from pkis[signing_pki_index]>",
#   "created_at":      "<ISO timestamp>"
# }


def setup_keys(pki_base: str, token: str, out_dir: str,
               keys_config: Optional[str]) -> dict:
    """
    Load an existing keys_config.json, or create:
      - 4 PKI instances, each with one SRK root keypair (all 4 feed srktool)
      - CSF + IMG application keypairs only under pkis[SRK_INDEX] (the active slot)
    PKIs at other indices are revocation-only; they contribute SRK certs to the
    fuse table so a future key-revoke can switch Source index without re-burning.
    """
    if keys_config and os.path.isfile(keys_config):
        log(f"Reusing keys: {keys_config}")
        with open(keys_config) as f:
            return json.load(f)

    log(f"Creating {SRK_COUNT} PKIs (each with SRK root keypair) via PKI REST …")
    log(f"CSF + IMG signing keypairs created only under PKI-{SRK_INDEX + 1} (index {SRK_INDEX})")
    certs_dir = os.path.join(out_dir, "certs")
    os.makedirs(certs_dir, exist_ok=True)

    pkis = []
    srk_cert_paths = []

    for i in range(1, SRK_COUNT + 1):
        log(f"\n── PKI {i} of {SRK_COUNT} " + "─" * 40)

        # 1. Create PKI instance
        pki = create_pki(pki_base, token, i)
        pki_id = pki["pki_id"]
        log(f"  PKI instance: {pki_id}")

        # 2. Create SRK root keypair (needed for srktool for ALL 4 PKIs)
        srk = create_root_keypair(pki_base, token, pki_id)
        srk_id = srk["keypair_id"]
        log(f"  SRK keypair:  {srk_id}")
        srk_pem = export_certificate(pki_base, token, srk_id)
        srk_path = os.path.join(certs_dir, f"SRK{i}.pem")
        with open(srk_path, "w") as f:
            f.write(srk_pem)
        srk_cert_paths.append(srk_path)

        pki_entry: dict = {
            "pki_id":        pki_id,
            "srk_key_id":    srk_id,
            "srk_cert_path": srk_path,
        }

        # 3. CSF + IMG application keypairs — only for the active signing PKI.
        #    PKIs at other indices only provide an SRK for the srktool table;
        #    their slots exist purely for future key-revocation scenarios.
        if (i - 1) == SRK_INDEX:
            log(f"  [signing PKI] creating CSF + IMG keypairs")

            csf = create_application_keypair(pki_base, token, pki_id, "CSF")
            csf_id = csf["keypair_id"]
            log(f"  CSF keypair:  {csf_id}")
            csf_pem = export_certificate(pki_base, token, csf_id)
            csf_path = os.path.join(certs_dir, "CSF.pem")
            with open(csf_path, "w") as f:
                f.write(csf_pem)

            img = create_application_keypair(pki_base, token, pki_id, "IMG")
            img_id = img["keypair_id"]
            log(f"  IMG keypair:  {img_id}")
            img_pem = export_certificate(pki_base, token, img_id)
            img_path = os.path.join(certs_dir, "IMG.pem")
            with open(img_path, "w") as f:
                f.write(img_pem)

            pki_entry.update({
                "csf_key_id":    csf_id,
                "csf_cert_path": csf_path,
                "img_key_id":    img_id,
                "img_cert_path": img_path,
            })
        else:
            log(f"  [revocation-only PKI] skipping CSF/IMG keypairs")

        pkis.append(pki_entry)

    # The signing PKI (SRK_INDEX) must have CSF/IMG keys — verify
    signing = pkis[SRK_INDEX]
    if "csf_key_id" not in signing:
        raise RuntimeError(
            f"BUG: pkis[{SRK_INDEX}] has no csf_key_id — SRK_INDEX mismatch in loop"
        )
    cfg = {
        "pkis":             pkis,
        "srk_cert_paths":   srk_cert_paths,
        "signing_pki_index": SRK_INDEX,
        # Convenience fields — run_cst reads these directly
        "csf_key_id":      signing["csf_key_id"],
        "csf_cert_path":   signing["csf_cert_path"],
        "img_key_id":      signing["img_key_id"],
        "img_cert_path":   signing["img_cert_path"],
        "created_at":      datetime.utcnow().isoformat(),
    }
    cfg_path = os.path.join(out_dir, "keys_config.json")
    with open(cfg_path, "w") as f:
        json.dump(cfg, f, indent=2)
    log(f"Keys saved: {cfg_path}", "OK")
    return cfg


# ── SRK table ──────────────────────────────────────────────────────────────────

def make_srk_table(srktool: str, cert_paths: list, out_dir: str) -> str:
    srk_table = os.path.join(out_dir, "srk_table.bin")
    srk_fuses = os.path.join(out_dir, "srk_fuses.bin")
    cmd = [
        srktool, "--hab_ver", "4",
        "--certs", ",".join(cert_paths),
        "--table", srk_table,
        "--efuses", srk_fuses,
        "--digest", "sha256",
    ]
    log(f"$ {' '.join(cmd)}")
    subprocess.run(cmd, check=True)
    sz = os.path.getsize(srk_table)
    log(f"SRK table: {srk_table}  ({sz} bytes)", "OK")
    return srk_table


# ── IVT scanner ────────────────────────────────────────────────────────────────
#
# IVT layout (8 × u32, little-endian):
#   [0] header     (0x402000D1)
#   [1] entry      (entry-point runtime address)
#   [2] reserved1
#   [3] dcd        (DCD runtime address, 0 if absent)
#   [4] boot_data  (boot data runtime address)
#   [5] self        (IVT runtime address — tells us load address)
#   [6] csf         (CSF runtime address)
#   [7] reserved2
#
# auth_length = csf_addr − self_addr   (HAB authenticates IVT..CSF, exclusive)
# csf_file_offset = file_offset + (csf_addr − self_addr)

def scan_ivts(data: bytes) -> list:
    ivts = []
    for off in range(0, len(data) - IVT_SIZE + 1, 4):
        hdr, entry, _, dcd, boot_data, self_addr, csf_addr, _ = \
            struct.unpack_from("<8I", data, off)
        if hdr != IVT_HEADER:
            continue
        if csf_addr == 0 or csf_addr <= self_addr:
            continue
        auth_length = csf_addr - self_addr
        if auth_length > 0x800000:   # >8 MiB unlikely
            continue
        ivts.append({
            "file_offset":     off,
            "self_addr":       self_addr,
            "csf_addr":        csf_addr,
            "auth_length":     auth_length,
            "csf_file_offset": off + auth_length,
        })
        log(f"  IVT #{len(ivts)}: file=0x{off:08X}  "
            f"self=0x{self_addr:08X}  csf=0x{csf_addr:08X}  "
            f"auth_len=0x{auth_length:08X}")
    return ivts


# ── CSF text file ──────────────────────────────────────────────────────────────
#
# Rules CST enforces:
#   • Section headers ([…]) must start at column 0
#   • NO blank lines anywhere in the file
#   • Indented key=value pairs inside each section

def write_csf(path: str, ivt: dict, srk_table: str,
              pkcs11_token: str = "HSM-CST",
              pkcs11_pin: str = "changeme") -> None:
    # PKCS#11 mode: [Install CSFK] and [Install Key] must be PKCS#11 URIs.
    # The PKCS#11 bridge serves these objects by label from the virtual token.
    csf_uri = (f"pkcs11:token={pkcs11_token};"
               f"object=CSF;type=cert;pin-value={pkcs11_pin}")
    img_uri = (f"pkcs11:token={pkcs11_token};"
               f"object=IMG;type=private;pin-value={pkcs11_pin}")
    lines = [
        "[Header]",
        f"    Version = {CSF_VERSION}",
        "    Hash Algorithm = sha256",
        "    Engine = ANY",
        "    Engine Configuration = 0",
        "    Certificate Format = X509",
        "    Signature Format = CMS",
        "[Install SRK]",
        f'    File = "{srk_table}"',
        f"    Source index = {SRK_INDEX}",
        "[Install CSFK]",
        f'    File = "{csf_uri}"',
        "[Authenticate CSF]",
        "[Install Key]",
        f'    File = "{img_uri}"',
        "    Verification index = 0",
        "    Target index = 2",
        "[Authenticate Data]",
        "    Verification index = 2",
        "    Engine = ANY",
        "    Engine Configuration = 0",
        (
            f'    Blocks = '
            f'0x{ivt["self_addr"]:08X} '
            f'0x00000000 '
            f'0x{ivt["auth_length"]:08X} '
            f'"{ivt["sub_bin"]}"'
        ),
    ]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    log(f"  CSF text: {path}", "OK")


# ── CST invocation ─────────────────────────────────────────────────────────────

def run_cst(cst: str, pkcs11_lib: str, csf_txt: str, csf_out: str,
            cfg: dict, hsm_base: str, hsm_token: str) -> None:
    env = {
        **os.environ,
        "PKCS11_MODULE_PATH": pkcs11_lib,
        "HSM_BASE":           hsm_base,
        "HSM_AUTH_TOKEN":     hsm_token,
        "HSM_CSF_KEY_ID":     cfg["csf_key_id"],
        "HSM_IMG_KEY_ID":     cfg["img_key_id"],
        "HSM_CSF_CERT_PATH":  cfg["csf_cert_path"],
        "HSM_IMG_CERT_PATH":  cfg["img_cert_path"],
        "HSM_SRK_CERT_PATH":  cfg["srk_cert_paths"][SRK_INDEX],
        "HSM_TLS_VERIFY":     "false",
        "HSM_TOKEN_LABEL":    "HSM-CST",
    }
    cmd = [cst, "-b", "pkcs11", "--input", csf_txt, "--output", csf_out]
    log(f"$ {' '.join(cmd)}")
    subprocess.run(cmd, check=True, env=env)
    sz = os.path.getsize(csf_out)
    log(f"  CSF blob: {csf_out}  ({sz} bytes)", "OK")
    if sz > CSF_PAD_SIZE:
        log(f"  WARNING: CSF blob ({sz}b) > reserved space ({CSF_PAD_SIZE}b) — "
            "increase HAB_CSF_DATA_SIZE or use smaller keys", "WARN")


# ── CSF injection ──────────────────────────────────────────────────────────────

def inject_csf(data: bytearray, csf_file: str, offset: int) -> None:
    blob = open(csf_file, "rb").read()
    end = offset + len(blob)
    if end > len(data):
        raise RuntimeError(
            f"CSF blob ({len(blob)} bytes) would overflow the container "
            f"at offset 0x{offset:X} (container size 0x{len(data):X})"
        )
    data[offset:end] = blob
    log(f"  Injected {len(blob)} bytes at 0x{offset:08X}  ({os.path.basename(csf_file)})", "OK")


# ── SRK fuse helper ────────────────────────────────────────────────────────────

def print_fuse_cmds(srk_fuses_bin: str) -> None:
    fuses = open(srk_fuses_bin, "rb").read()
    words = struct.unpack_from("<8I", fuses)
    log("=" * 60)
    log("SRK fuse prog commands (U-Boot)")
    log("=" * 60)
    for i, w in enumerate(words):
        bank, word = divmod(i, 4)
        log(f"  fuse prog -y {6 + bank} {word}  0x{w:08X}")
    log("Program ALL 8 words before closing the device!", "WARN")


# ── Argument parser ────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="HAB4 sign a flash.bin produced by imx-mkimage"
    )
    p.add_argument("image", help="Unsigned boot container (e.g. flash.bin)")
    p.add_argument("--pkcs11-lib", required=True,
                   help="Path to hsm_pkcs11.so (the PKCS#11 bridge)")
    p.add_argument("--cst", default=os.environ.get("CST_BIN", "/usr/bin/cst"),
                   help="Path to NXP cst binary")
    p.add_argument("--srktool", default=os.environ.get("SRKTOOL_BIN", "/usr/bin/srktool"),
                   help="Path to NXP srktool binary")
    p.add_argument("--hsm-base", default=os.environ.get("HSM_BASE", ""),
                   help="HSM crypto REST base URL  (e.g. https://host:7008/crypto/api/v1)")
    p.add_argument("--hsm-token", default=os.environ.get("HSM_AUTH_TOKEN", ""),
                   help="HSM bearer token")
    p.add_argument("--pki-base", default=os.environ.get("PKI_BASE", ""),
                   help="PKI REST base URL  (e.g. https://host:7008/pki/api/v1)")
    p.add_argument("--pki-token", default=os.environ.get("PKI_AUTH_TOKEN", ""),
                   help="PKI bearer token")
    p.add_argument("--keys-config", default=None,
                   help="Reuse an existing keys_config.json (skips key creation)")
    p.add_argument("--out-dir", default=None,
                   help="Output directory (default: <image_basename>_signed_<timestamp>/)")
    return p.parse_args()


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    # ── Resolve output directory ───────────────────────────────────────────────
    base = os.path.splitext(os.path.basename(args.image))[0]
    out_dir = args.out_dir or f"{base}_signed_{TIMESTAMP}"
    os.makedirs(out_dir, exist_ok=True)
    blobs_dir = os.path.join(out_dir, "csf_blobs")
    os.makedirs(blobs_dir, exist_ok=True)

    # ── Read the unsigned image ────────────────────────────────────────────────
    log(f"Input image: {args.image}")
    with open(args.image, "rb") as f:
        raw = bytearray(f.read())

    # ── Step 1: Keys ───────────────────────────────────────────────────────────
    log("=" * 60)
    log(f"STEP 1: Key material  (4 PKI×SRK for srktool, CSF+IMG only under PKI-{SRK_INDEX + 1})")
    log("=" * 60)
    # pki-token falls back to hsm-token if not given separately
    pki_token = args.pki_token or args.hsm_token
    if not args.pki_base:
        sys.exit("--pki-base is required (e.g. https://host:7008/pki/api/v1)")
    cfg = setup_keys(args.pki_base, pki_token, out_dir, args.keys_config)

    # ── Step 2: SRK table ─────────────────────────────────────────────────────
    log("=" * 60)
    log("STEP 2: SRK table  (4 SRK certs → srktool)")
    log("=" * 60)
    srk_table = make_srk_table(args.srktool, cfg["srk_cert_paths"], out_dir)
    srk_fuses = os.path.join(out_dir, "srk_fuses.bin")

    # ── Step 3: IVT scan ──────────────────────────────────────────────────────
    log("=" * 60)
    log("STEP 3: Scan IVTs")
    log("=" * 60)
    ivts = scan_ivts(bytes(raw))
    if not ivts:
        sys.exit("No valid IVTs found — is this a HAB4 boot container?")
    log(f"Found {len(ivts)} IVT(s)", "OK")

    # ── Step 4: Sign each IVT ─────────────────────────────────────────────────
    log("=" * 60)
    log(f"STEP 4: Sign IVT(s)  (using PKI-{SRK_INDEX + 1} CSF/IMG keys)")
    log("=" * 60)
    csf_blobs = []   # (csf_bin_path, csf_file_offset)
    for idx, ivt in enumerate(ivts, start=1):
        log(f"\n── IVT #{idx}  (self=0x{ivt['self_addr']:08X}) " + "─" * 30)

        # Extract the authenticated sub-region as a standalone file.
        # CST "Blocks" references this file so offsets are relative to byte 0.
        sub_start = ivt["file_offset"]
        sub_end   = sub_start + ivt["auth_length"]
        sub_bin   = os.path.join(blobs_dir, f"sub_{idx}.bin")
        with open(sub_bin, "wb") as f:
            f.write(raw[sub_start:sub_end])
        log(f"  Sub-image: {sub_bin}  ({ivt['auth_length']} bytes)")
        ivt["sub_bin"] = sub_bin

        # Write CSF text input for cst
        csf_txt = os.path.join(blobs_dir, f"hab_{idx}.csf")
        write_csf(csf_txt, ivt, srk_table)

        # Run CST → produces CSF blob
        csf_bin = os.path.join(blobs_dir, f"csf_{idx}.bin")
        run_cst(
            cst        = args.cst,
            pkcs11_lib = args.pkcs11_lib,
            csf_txt    = csf_txt,
            csf_out    = csf_bin,
            cfg        = cfg,
            hsm_base   = args.hsm_base,
            hsm_token  = args.hsm_token,
        )
        csf_blobs.append((csf_bin, ivt["csf_file_offset"]))

    # ── Step 5: Inject CSF blobs ──────────────────────────────────────────────
    log("=" * 60)
    log("STEP 5: Inject CSF blobs into image")
    log("=" * 60)
    for csf_bin, offset in csf_blobs:
        inject_csf(raw, csf_bin, offset)

    # ── Write signed image ─────────────────────────────────────────────────────
    signed_path = os.path.join(out_dir, f"{base}_signed.bin")
    with open(signed_path, "wb") as f:
        f.write(raw)
    log(f"Signed image: {signed_path}", "OK")

    # ── Fuse commands ──────────────────────────────────────────────────────────
    print_fuse_cmds(srk_fuses)

    log("=" * 60)
    log(f"DONE.  Artifacts: {out_dir}", "OK")
    log("=" * 60)


if __name__ == "__main__":
    main()
