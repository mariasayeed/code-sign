#!/usr/bin/env python3
"""
HAB4 signing — simplified single-file orchestrator
====================================================
Accepts an unsigned boot container (flash.bin) produced by imx-mkimage
and produces a HAB-signed container using:

  • PKI REST API   — create/keep SRK/CSF/IMG keys + download PEM certs
  • srktool        — build the SRK table from the 4 SRK certs
  • NXP CST        — generate CSF blob     (cst -b pkcs11 …)
  • PKCS#11 bridge — route CST's sign() call to the HSM REST API

Usage
-----
  python3 sign.py flash.bin \\
      --pkcs11-lib  ./pkcs11_bridge/build/hsm_pkcs11.so \\
      --cst         /usr/bin/cst \\
      --srktool     /usr/bin/srktool \\
      --hsm-base    https://192.168.1.159:7008/crypto/api/v1 \\
      --pki-base    https://192.168.1.159:7008/pki/api/v1  \\
      --pki-token   somekey

Re-use keys from a previous run:
  python3 sign.py flash.bin … --keys-config out/keys_config.json

What imx-mkimage gives us (and what we use)
-------------------------------------------
imx-mkimage produces flash.bin with:
  • An IVT (Image Vector Table) at a well-known offset – we scan for it
  • A reserved CSF region whose location is stored in the IVT
  • One or more "authenticated blocks" whose address+size we derive from
    the IVT self-address and auth_len field

We do NOT call imx-mkimage; we accept its output as input.
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
IVT_HEADER   = 0x402000D1   # HAB4 IVT magic
IVT_SIZE     = 0x20         # 32 bytes
CSF_PAD_SIZE = 0x4000       # 16 KiB — enough for RSA-4096 CSF blob
CSF_VERSION  = "4.1"
SRK_COUNT    = 4
SRK_INDEX    = 0            # which SRK slot to use (0-based)
TIMESTAMP    = datetime.now().strftime("%Y%m%d_%H%M%S")


def log(msg: str, level: str = "INFO") -> None:
    print(f"[{level:<5}] {msg}", flush=True)


# ── PKI REST helpers (inlined — no separate module needed) ─────────────────────

def _pki(method: str, url: str, token: str, **kwargs):
    """Thin wrapper around requests — raises on non-2xx."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    r = getattr(requests, method)(url, headers=headers, verify=False, **kwargs)
    r.raise_for_status()
    return r


def create_rsa_key(pki_base: str, token: str, label: str) -> dict:
    """Create an RSA-4096 keypair + self-signed cert in the PKI.  Returns the full JSON."""
    body = {
        "label": label,
        "keyAlgorithm": "RSA_4096",
        "selfSigned": True,
        "subject": {"CN": label, "O": "CPI", "OU": "NPD", "C": "US"},
    }
    r = _pki("post", f"{pki_base}/keypairs", token, json=body)
    return r.json()


def get_cert_pem(pki_base: str, token: str, public_key_id: str) -> str:
    """Download the PEM certificate for a key pair."""
    r = _pki("get", f"{pki_base}/keypairs/{public_key_id}/certificate/pem", token)
    return r.text


# ── Key management ─────────────────────────────────────────────────────────────

def setup_keys(pki_base: str, token: str, out_dir: str,
               keys_config: Optional[str]) -> dict:
    """
    Load an existing keys_config.json or create fresh keys and download certs.

    keys_config layout:
      {
        "pki_ids":       [SRK1.publicKeyId … SRK4.publicKeyId],
        "srk_ids":       [SRK1.id … SRK4.id],            # internal PKI IDs
        "srk_cert_paths": ["…/SRK1.pem", …],
        "csf_key_id":    "<IMG-signs-CSF key publicKeyId>",
        "csf_cert_path": "…/CSF.pem",
        "img_key_id":    "<IMG publicKeyId>",
        "img_cert_path": "…/IMG.pem",
      }
    """
    if keys_config and os.path.isfile(keys_config):
        log(f"Reusing keys: {keys_config}")
        with open(keys_config) as f:
            return json.load(f)

    log("Creating new keys via PKI REST …")
    certs_dir = os.path.join(out_dir, "certs")
    os.makedirs(certs_dir, exist_ok=True)

    pki_ids, srk_ids, srk_cert_paths = [], [], []
    for i in range(1, SRK_COUNT + 1):
        kp = create_rsa_key(pki_base, token, f"SRK{i}")
        pki_ids.append(kp["publicKeyId"])
        srk_ids.append(kp["id"])
        pem_path = os.path.join(certs_dir, f"SRK{i}.pem")
        with open(pem_path, "w") as f:
            f.write(get_cert_pem(pki_base, token, kp["publicKeyId"]))
        srk_cert_paths.append(pem_path)
        log(f"  SRK{i} publicKeyId={kp['publicKeyId']}")

    csf_kp = create_rsa_key(pki_base, token, "CSF")
    csf_pem = os.path.join(certs_dir, "CSF.pem")
    with open(csf_pem, "w") as f:
        f.write(get_cert_pem(pki_base, token, csf_kp["publicKeyId"]))

    img_kp = create_rsa_key(pki_base, token, "IMG")
    img_pem = os.path.join(certs_dir, "IMG.pem")
    with open(img_pem, "w") as f:
        f.write(get_cert_pem(pki_base, token, img_kp["publicKeyId"]))

    cfg = {
        "pki_ids":        pki_ids,
        "srk_ids":        srk_ids,
        "srk_cert_paths": srk_cert_paths,
        "csf_key_id":     csf_kp["publicKeyId"],
        "csf_cert_path":  csf_pem,
        "img_key_id":     img_kp["publicKeyId"],
        "img_cert_path":  img_pem,
        "created_at":     datetime.utcnow().isoformat(),
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
#   [5] self       (IVT runtime address — tells us load address)
#   [6] csf        (CSF runtime address)
#   [7] reserved2
#
# auth_length: HAB authenticates from IVT start up to (but not including) CSF.
#   auth_length = csf_addr − self_addr
# csf_file_offset: where to inject csf.bin into the container.
#   csf_file_offset = file_offset + (csf_addr − self_addr)

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
              pkcs11_pin: str  = "changeme") -> None:
    # PKCS#11 mode: [Install CSFK] and [Install Key] must be PKCS#11 URIs.
    # (The PKCS#11 bridge serves these objects by label from the virtual token.)
    # [Install SRK] and [Authenticate Data] Blocks still reference plain files.
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
        "PKCS11_MODULE_PATH":  pkcs11_lib,
        "HSM_BASE":            hsm_base,
        "HSM_AUTH_TOKEN":      hsm_token,
        "HSM_CSF_KEY_ID":      cfg["csf_key_id"],
        "HSM_IMG_KEY_ID":      cfg["img_key_id"],
        "HSM_CSF_CERT_PATH":   cfg["csf_cert_path"],
        "HSM_IMG_CERT_PATH":   cfg["img_cert_path"],
        "HSM_SRK_CERT_PATH":   cfg["srk_cert_paths"][SRK_INDEX],
        "HSM_TLS_VERIFY":      "false",
        "HSM_TOKEN_LABEL":     "HSM-CST",
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


# ── Main ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="HAB4 sign a flash.bin produced by imx-mkimage"
    )
    p.add_argument("image", help="Unsigned boot container (e.g. flash.bin)")
    p.add_argument("--pkcs11-lib",  required=True,
                   help="Path to hsm_pkcs11.so (the PKCS#11 bridge)")
    p.add_argument("--cst",         default=os.environ.get("CST_BIN", "/usr/bin/cst"),
                   help="Path to NXP cst binary")
    p.add_argument("--srktool",     default=os.environ.get("SRKTOOL_BIN", "/usr/bin/srktool"),
                   help="Path to NXP srktool binary")
    p.add_argument("--hsm-base",    default=os.environ.get("HSM_BASE", ""),
                   help="HSM crypto REST base URL")
    p.add_argument("--hsm-token",   default=os.environ.get("HSM_AUTH_TOKEN", ""),
                   help="HSM bearer token")
    p.add_argument("--pki-base",    default=os.environ.get("PKI_BASE", ""),
                   help="PKI REST base URL (for key creation)")
    p.add_argument("--pki-token",   default=os.environ.get("PKI_AUTH_TOKEN", ""),
                   help="PKI bearer token")
    p.add_argument("--keys-config", default=None,
                   help="Reuse an existing keys_config.json (skip key creation)")
    p.add_argument("--out-dir",     default=None,
                   help="Output directory (default: <image_basename>_signed_<timestamp>/)")
    return p.parse_args()


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
    log("STEP 1: Key material")
    log("=" * 60)
    pki_base = args.pki_base or args.hsm_base.replace("/crypto/", "/pki/")
    pki_token = args.pki_token or args.hsm_token
    cfg = setup_keys(pki_base, pki_token, out_dir, args.keys_config)

    # ── Step 2: SRK table ─────────────────────────────────────────────────────
    log("=" * 60)
    log("STEP 2: SRK table")
    log("=" * 60)
    srk_table = make_srk_table(args.srktool, cfg["srk_cert_paths"], out_dir)
    srk_fuses = srk_table.replace("srk_table.bin", "srk_fuses.bin")

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
    log("STEP 4: Sign IVT(s)")
    log("=" * 60)
    csf_blobs = []   # (csf_bin_path, csf_file_offset)
    for idx, ivt in enumerate(ivts, start=1):
        log(f"\n── IVT #{idx}  (self=0x{ivt['self_addr']:08X}) " + "─" * 30)

        # Extract the authenticated sub-region as a standalone file
        # CST "Blocks" references this file so offsets are relative to byte 0
        sub_start = ivt["file_offset"]
        sub_end   = sub_start + ivt["auth_length"]
        sub_bin   = os.path.join(blobs_dir, f"sub_{idx}.bin")
        with open(sub_bin, "wb") as f:
            f.write(raw[sub_start:sub_end])
        log(f"  Sub-image: {sub_bin}  ({ivt['auth_length']} bytes)")
        ivt["sub_bin"] = sub_bin   # store for CSF writer

        # Write CSF text
        csf_txt = os.path.join(blobs_dir, f"hab_{idx}.csf")
        write_csf(csf_txt, ivt, srk_table)

        # Run CST
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
    log("STEP 5: Inject CSF blobs")
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
