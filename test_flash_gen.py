#!/usr/bin/env python3
"""
test_flash_gen.py — Generate a synthetic flash.bin for testing hab4_sign.py

Creates a 2 MiB binary with two valid HAB4 IVTs (mimicking the SPL + FIT
structure produced by imx-mkimage for iMX8M Plus), with pre-allocated CSF
holes large enough for real CSF blobs.

This binary will NOT boot on hardware but is sufficient to:
  - Test IVT auto-detection in hab4_sign.py
  - Test HSM/PKI API calls (dry-run or live)
  - Test BD config generation
  - Test CSF blob injection logic

Usage:
    python test_flash_gen.py               # creates test_flash.bin
    python test_flash_gen.py --output my.bin
    python test_flash_gen.py --show        # just print IVT details, don't write

After generating:
    python hab4_sign.py test_flash.bin --dry-run ...
"""

import argparse
import struct
import os
import sys

# ── iMX8M Plus typical addresses (from imx-mkimage output) ────────────────────

# IVT #1 — SPL
SPL_FILE_OFFSET  = 0x8000       # imx-mkimage places SPL at 32 KiB into flash.bin
SPL_LOAD_ADDR    = 0x00920000   # OCRAM load address on iMX8M Plus
SPL_ENTRY_ADDR   = 0x00920000
SPL_CSF_OFFSET   = 0x24000      # relative to SPL_LOAD_ADDR  (csf_addr = load + offset)

# IVT #2 — FIT (U-Boot proper + ATF + DTB)
FIT_FILE_OFFSET  = 0x60000      # FIT image starts here in flash.bin
FIT_LOAD_ADDR    = 0x40200000   # DDR load address
FIT_ENTRY_ADDR   = 0x40200000
FIT_CSF_OFFSET   = 0x10000      # relative to FIT_LOAD_ADDR

# Total binary size
FLASH_SIZE       = 0x200000     # 2 MiB (enough for testing)
CSF_HOLE_FILL    = 0x00         # byte value used to fill CSF-reserved regions

IVT_MAGIC = 0x402000D1
IVT_SIZE  = 32


def build_ivt(self_addr: int, entry_addr: int, csf_addr: int) -> bytes:
    """
    Pack a 32-byte HAB4 IVT structure.

    Layout (all 32-bit little-endian):
        +0x00  header    = 0x402000D1
        +0x04  entry     = entry point address
        +0x08  reserved1 = 0
        +0x0C  dcd       = 0  (always NULL on iMX8M)
        +0x10  boot_data = self_addr + 0x20  (boot data struct right after IVT)
        +0x14  self      = IVT own load address
        +0x18  csf       = CSF blob load address
        +0x1C  reserved2 = 0
    """
    return struct.pack(
        "<8I",
        IVT_MAGIC,
        entry_addr,
        0,                    # reserved1
        0,                    # dcd (NULL)
        self_addr + 0x20,     # boot_data (immediately after IVT)
        self_addr,            # self
        csf_addr,             # csf pointer
        0,                    # reserved2
    )


def generate(output: str, verbose: bool = True) -> None:
    data = bytearray(FLASH_SIZE)

    # Fill CSF holes with a recognisable pattern so injection is visible in hexdump
    csf_hole_pattern = bytes([0xDE, 0xAD, 0xBE, 0xEF])

    ivt_configs = [
        {
            "name":          "SPL (IVT #1)",
            "file_offset":   SPL_FILE_OFFSET,
            "self_addr":     SPL_LOAD_ADDR,
            "entry_addr":    SPL_ENTRY_ADDR,
            "csf_rel":       SPL_CSF_OFFSET,
        },
        {
            "name":          "FIT / U-Boot (IVT #2)",
            "file_offset":   FIT_FILE_OFFSET,
            "self_addr":     FIT_LOAD_ADDR,
            "entry_addr":    FIT_ENTRY_ADDR,
            "csf_rel":       FIT_CSF_OFFSET,
        },
    ]

    for cfg in ivt_configs:
        ivt_file_off  = cfg["file_offset"]
        self_addr     = cfg["self_addr"]
        entry_addr    = cfg["entry_addr"]
        csf_addr      = self_addr + cfg["csf_rel"]
        csf_file_off  = ivt_file_off + cfg["csf_rel"]
        auth_length   = cfg["csf_rel"]   # authenticated: from IVT up to (not incl.) CSF

        if ivt_file_off + IVT_SIZE > FLASH_SIZE:
            print(f"  [!] IVT for {cfg['name']} would exceed flash size — skipping")
            continue

        if csf_file_off + 0x2000 > FLASH_SIZE:
            print(f"  [!] CSF hole for {cfg['name']} would exceed flash size — skipping")
            continue

        # Write IVT
        ivt_bytes = build_ivt(self_addr, entry_addr, csf_addr)
        data[ivt_file_off:ivt_file_off + IVT_SIZE] = ivt_bytes

        # Fill CSF hole with marker pattern (8 KiB)
        for i in range(0x2000):
            data[csf_file_off + i] = csf_hole_pattern[i % 4]

        if verbose:
            print(f"  IVT: {cfg['name']}")
            print(f"       file_offset  = 0x{ivt_file_off:08X}")
            print(f"       self_addr    = 0x{self_addr:08X}")
            print(f"       entry_addr   = 0x{entry_addr:08X}")
            print(f"       csf_addr     = 0x{csf_addr:08X}")
            print(f"       csf_file_off = 0x{csf_file_off:08X}")
            print(f"       auth_length  = 0x{auth_length:08X}")
            print()

    with open(output, "wb") as f:
        f.write(data)

    size_kb = len(data) // 1024
    print(f"Written: {output}  ({size_kb} KiB)")
    print()
    print("Verify IVTs are present:")
    print(f"  python -c \"import struct,sys; d=open('{output}','rb').read(); "
          f"[print(hex(o)) for o in range(0,len(d)-4,4) "
          f"if struct.unpack_from('<I',d,o)[0]==0x402000D1]\"")
    print()
    print("Next — test signing (dry-run, no nxpimage needed):")
    print(f"  python hab4_sign.py {output} --dry-run "
          f"--pki-base https://... --pki-token <jwt> "
          f"--hsm-base https://... --hsm-token <jwt>")


def show_only() -> None:
    """Print expected IVT values without writing any file."""
    print("Expected IVT layout in test_flash.bin:")
    print()
    for name, foff, saddr, eaddr, crel in [
        ("SPL (IVT #1)", SPL_FILE_OFFSET, SPL_LOAD_ADDR, SPL_ENTRY_ADDR, SPL_CSF_OFFSET),
        ("FIT (IVT #2)", FIT_FILE_OFFSET, FIT_LOAD_ADDR, FIT_ENTRY_ADDR, FIT_CSF_OFFSET),
    ]:
        print(f"  {name}")
        print(f"    file_offset  : 0x{foff:08X}")
        print(f"    self_addr    : 0x{saddr:08X}")
        print(f"    entry_addr   : 0x{eaddr:08X}")
        print(f"    csf_addr     : 0x{saddr + crel:08X}")
        print(f"    csf_file_off : 0x{foff + crel:08X}")
        print(f"    auth_length  : 0x{crel:08X}")
        print()


def main() -> int:
    p = argparse.ArgumentParser(description="Generate a synthetic iMX8M Plus flash.bin for testing")
    p.add_argument("--output", "-o", default="test_flash.bin", help="Output binary path")
    p.add_argument("--show", action="store_true", help="Print IVT details only, do not write file")
    args = p.parse_args()

    if args.show:
        show_only()
        return 0

    print(f"Generating synthetic iMX8M Plus flash.bin → {args.output}")
    print(f"  Size       : {FLASH_SIZE // 1024} KiB")
    print(f"  IVT count  : 2  (SPL + FIT)")
    print()
    generate(args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
