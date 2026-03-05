# HAB4 Signing — Simplified

Signs an i.MX8 series boot container (`flash.bin`) produced by **imx-mkimage**
using keys stored in a remote HSM REST API.  No private key material ever
leaves the HSM.

```
flash.bin  →  sign.py  →  flash_signed.bin
                ↑
  pkcs11_bridge/ (C shared lib)
  NXP CST  +  NXP srktool
  PKI REST API  (key creation)
  HSM REST API  (signing)
```

## Directory layout

```
cst_signing_simplified/
├── sign.py               # Single orchestrator script (~250 lines)
├── requirements.txt      # Python deps  (just: requests)
└── pkcs11_bridge/        # C shared library — routes CST sign() → HSM REST
    ├── hsm_pkcs11.c
    ├── pkcs11_types.h
    ├── CMakeLists.txt
    ├── exports.ldscript
    ├── build_bridge.sh
    └── hsm_pkcs11_config.json.example
```

---

## Prerequisites

### System packages (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y \
    gcc cmake make \
    libcurl4-openssl-dev \
    libssl-dev \
    libengine-pkcs11-openssl \
    pkg-config \
    python3 python3-pip python3-venv
```

> **Why `libengine-pkcs11-openssl`?**
> NXP CST (`cst -b pkcs11`) uses the OpenSSL PKCS#11 engine to discover our
> bridge via the `PKCS11_MODULE_PATH` environment variable.  This package
> provides that engine.

### NXP CST + srktool

Install the NXP Code Signing Tool package for your platform.  On the internal
Ubuntu signing VM, both binaries are already at:

```
/usr/bin/cst
/usr/bin/srktool
```

If installed elsewhere, pass `--cst` and `--srktool` flags (see Usage below).

### Python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Step 1 — Build the PKCS#11 bridge

The bridge is a small C shared library that intercepts CST's `C_Sign()` call
and forwards it to the HSM REST API.  It must be compiled once per machine.

```bash
cd pkcs11_bridge
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
# → produces: pkcs11_bridge/build/hsm_pkcs11.so
```

Or use the convenience script:

```bash
cd pkcs11_bridge
bash build_bridge.sh
```

Verify:

```bash
file build/hsm_pkcs11.so
# → ELF 64-bit LSB shared object …
```

---

## Step 2 — First-time key creation (one per root-of-trust)

On the first run, `sign.py` will:

1. Create **SRK1–SRK4** RSA-4096 keypairs via PKI REST + download PEM certs
2. Create a **CSF** keypair + cert
3. Create an **IMG** keypair + cert
4. Save `keys_config.json` in the output directory

**The PKI REST API controls key generation; private keys never leave the HSM.**

To trigger key creation, run without `--keys-config` (see Usage below).

To **reuse existing keys** on subsequent runs, pass the saved config:

```bash
--keys-config ./my_output/keys_config.json
```

---

## Usage

### Minimal (fresh keys)

```bash
python3 sign.py flash.bin \
    --pkcs11-lib pkcs11_bridge/build/hsm_pkcs11.so \
    --hsm-base   https://192.168.1.159:7008/crypto/api/v1 \
    --hsm-token  somekey \
    --pki-base   https://192.168.1.159:7008/pki/api/v1 \
    --pki-token  somekey
```

### Reuse existing keys

```bash
python3 sign.py flash.bin \
    --pkcs11-lib  pkcs11_bridge/build/hsm_pkcs11.so \
    --hsm-base    https://192.168.1.159:7008/crypto/api/v1 \
    --hsm-token   somekey \
    --keys-config ./out_20260301_142233/keys_config.json
```

### Custom CST / srktool paths

```bash
python3 sign.py flash.bin \
    --pkcs11-lib pkcs11_bridge/build/hsm_pkcs11.so \
    --cst        /opt/cst/linux64/bin/cst \
    --srktool    /opt/cst/linux64/bin/srktool \
    --hsm-base   https://192.168.1.159:7008/crypto/api/v1 \
    --hsm-token  somekey \
    --pki-base   https://192.168.1.159:7008/pki/api/v1 \
    --pki-token  somekey
```

### All flags

| Flag | Default | Description |
|---|---|---|
| `image` | *(required)* | Unsigned boot container from imx-mkimage |
| `--pkcs11-lib` | *(required)* | Path to `hsm_pkcs11.so` |
| `--cst` | `/usr/bin/cst` | NXP CST binary |
| `--srktool` | `/usr/bin/srktool` | NXP srktool binary |
| `--hsm-base` | `$HSM_BASE` | HSM crypto REST base URL |
| `--hsm-token` | `$HSM_AUTH_TOKEN` | HSM bearer token |
| `--pki-base` | `$PKI_BASE` | PKI REST base URL (key creation only) |
| `--pki-token` | `$PKI_AUTH_TOKEN` | PKI bearer token |
| `--keys-config` | *(none)* | Reuse a previous `keys_config.json` |
| `--out-dir` | `<image>_signed_<ts>/` | Output directory |

---

## Output

```
flash_signed_20260302_004806/
├── flash_signed.bin          ← Flash this to the boot device
├── srk_table.bin             ← Embedded in CSF (auto-handled)
├── srk_fuses.bin             ← 32 bytes: 8 × u32 fuse words
├── keys_config.json          ← Key IDs + cert paths (save for future runs)
├── certs/
│   ├── SRK1.pem … SRK4.pem
│   ├── CSF.pem
│   └── IMG.pem
└── csf_blobs/
    ├── sub_1.bin             ← Authenticated sub-image (IVT#1)
    ├── hab_1.csf             ← CSF text descriptor
    ├── csf_1.bin             ← CSF binary (injected into signed image)
    ├── sub_2.bin             ← (repeated for each IVT found)
    ├── hab_2.csf
    └── csf_2.bin
```

---

## Burning SRK fuses (U-Boot)

The script prints the exact commands at the end:

```
fuse prog -y 6 0  0x622D29C9
fuse prog -y 6 1  0xB2019C86
fuse prog -y 6 2  0x2377A9A1
fuse prog -y 6 3  0x30C764BE
fuse prog -y 7 0  0xE1C9D813
fuse prog -y 7 1  0xB86BA440
fuse prog -y 7 2  0x2B09A7B1
fuse prog -y 7 3  0xCF11AA6A
```

> **Warning:** Program all 8 words in a single session.  Fuses are one-time
> write.  Test in open/HAB-open mode first.

---

## How it works

```
sign.py
  │
  ├─ PKI REST  →  create SRK1-4, CSF, IMG keypairs + download PEM certs
  ├─ srktool   →  srk_table.bin + srk_fuses.bin
  ├─ IVT scan  →  locate Image Vector Tables in flash.bin by magic (0x402000D1)
  │               derive: authenticated block ranges, CSF injection offsets
  ├─ per IVT:
  │     write hab_N.csf  (NXP CSF text descriptor, no blank lines, col-0 headers)
  │     cst -b pkcs11 …  →  csf_N.bin
  │           ↓
  │     hsm_pkcs11.so (loaded via PKCS11_MODULE_PATH)
  │           ↓
  │     HSM REST API  →  C_Sign()  →  512-byte RSA-4096 signature
  │
  └─ inject csf_N.bin at CSF offsets in flash.bin  →  flash_signed.bin
```

The PKCS#11 bridge (`hsm_pkcs11.so`) implements only the slots NXP CST
actually calls:

`C_Initialize` → `C_GetSlotList` → `C_OpenSession` → `C_Login` →
`C_FindObjectsInit/FindObjects/Final` → `C_GetAttributeValue` →
`C_SignInit` → `C_Sign` → `C_Finalize`

All certificate DER bytes are loaded from the PEM files on disk into the
bridge's virtual token at `C_Initialize` time; no cert export from HSM is
needed for the signing operation itself.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `No valid IVTs found` | Input is not a ROM-bootable container | Confirm `flash.bin` was produced by imx-mkimage, not a raw kernel/FIT |
| `CSF blob would overflow` | CSF reserved region too small | Increase `HAB_CSF_DATA_SIZE` in imx-mkimage or switch to RSA-2048 keys |
| `Unable to enumerate certificates` | Bridge not loaded / wrong `PKCS11_MODULE_PATH` | Check that `hsm_pkcs11.so` exists and `PKCS11_MODULE_PATH` is set by the script |
| `Host memory error (p11_attr.c)` | `C_GetAttributeValue` returned an unknown attr size | Bridge version mismatch — rebuild from source |
| HSM REST 401 | Wrong bearer token | Check `--hsm-token` |
| HSM REST 503/timeout | HSM unreachable | Check network to HSM host |
