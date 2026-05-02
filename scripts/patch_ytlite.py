#!/usr/bin/env python3
"""
Patch YTLite.dylib inside a Debian package (.deb).

Targets: YTLite 5.2.1 (com.dvntm.ytlite)
Binary:  Mach-O 64-bit arm64, ~19MB

Gate logic: 0 = locked (default __bss), 1 = unlocked
All patches force gate functions to return 1 (unlocked).

Patch levels:
  minimal - Patch _dvnLocked + _dvnCheck (2 functions, 24 bytes)
  medium  - minimal + stub Login/Logout/OpenDevices (recommended)
  full    - medium + NOP all 4 call-sites (maximum coverage)

Usage:
  python3 patch_ytlite.py ytplus.deb --level medium --output ytplus.deb
  python3 patch_ytlite.py ytplus.deb --verify --level medium
  python3 patch_ytlite.py ytplus.deb --level medium --dry-run
"""

from __future__ import annotations

import argparse
import bz2
import copy
import gzip
import io
import logging
import lzma
import os
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Sequence, Tuple

LOGGER = logging.getLogger("patch_ytlite")

AR_MAGIC = b"!<arch>\n"
MACHO_MAGIC_64_LE = b"\xCF\xFA\xED\xFE"
FAT_MACHO_MAGICS = {
    b"\xCA\xFE\xBA\xBE",
    b"\xBE\xBA\xFE\xCA",
    b"\xCA\xFE\xBA\xBF",
    b"\xBF\xBA\xFE\xCA",
}


class PatchError(Exception):
    """Base error for patching failures."""


class VerificationFailed(PatchError):
    """Raised when verify mode does not match the requested state."""


@dataclass
class BinaryPatch:
    patch_id: str
    name: str
    offset: int
    original: bytes
    patched: bytes
    description: str


@dataclass
class ArMember:
    name: str
    timestamp: int
    owner_id: int
    group_id: int
    mode: int
    data: bytes


# =============================================================================
# Patch definitions — auto-detected by binary variant
# Rootless (var/jb/): gate @ 0x12241a9, logic 0=locked 1=unlocked
# Rootful (GitHub releases): gate @ 0x11564f1, inverted via BIC, 0=unlocked 1=locked
# =============================================================================

PATCHES_ROOTLESS: List[BinaryPatch] = [
    BinaryPatch("A", "_dvnLocked", 0x1EB10,
        bytes.fromhex("289000D000A54639C0035FD6"),
        bytes.fromhex("20008052C0035FD61F2003D5"),
        "Always return 1 (unlocked). mov w0,#1; ret; nop"),
    BinaryPatch("B", "_dvnCheck", 0x1EB1C,
        bytes.fromhex("F44FBEA9FD7B01A9FD430091"),
        bytes.fromhex("20008052C0035FD61F2003D5"),
        "Always return 1 (authorized). mov w0,#1; ret; nop"),
    BinaryPatch("C", "_DVNPatreonLogout gate write", 0x1F020,
        bytes.fromhex("1FA50639"),
        bytes.fromhex("1F2003D5"),
        "NOP the strb that re-locks gate on logout."),
    BinaryPatch("D", "_DVNPatreonLogin", 0x1F384,
        bytes.fromhex("FF8302D1FC6F04A9FA6705A9"),
        bytes.fromhex("E0031FAAC0035FD61F2003D5"),
        "Stub login: mov x0,xzr; ret; nop. No OAuth flow."),
    BinaryPatch("E", "_DVNPatreonOpenDevices", 0x219E4,
        bytes.fromhex("FF8302D1FC6F04A9FA6705A9"),
        bytes.fromhex("E0031FAAC0035FD61F2003D5"),
        "Stub devices: mov x0,xzr; ret; nop. No WebView."),
    BinaryPatch("F1", "call-site bl _dvnCheck (hooks)", 0x0CEA74,
        bytes.fromhex("2A40FD97"), bytes.fromhex("20008052"),
        "Replace BL _dvnCheck with mov w0,#1."),
    BinaryPatch("F2", "call-site bl _dvnLocked (hooks)", 0x0CEB18,
        bytes.fromhex("FE3FFD97"), bytes.fromhex("20008052"),
        "Replace BL _dvnLocked with mov w0,#1."),
    BinaryPatch("F3", "call-site bl _dvnCheck (UI)", 0x187D8C,
        bytes.fromhex("645BFA97"), bytes.fromhex("20008052"),
        "Replace BL _dvnCheck with mov w0,#1."),
    BinaryPatch("F4", "call-site bl _dvnLocked (UI)", 0x187F08,
        bytes.fromhex("025BFA97"), bytes.fromhex("20008052"),
        "Replace BL _dvnLocked with mov w0,#1."),
]

PATCHES_ROOTFUL: List[BinaryPatch] = [
    BinaryPatch("A", "_dvnLocked", 0x1EB4C,
        bytes.fromhex("C889009008C55339290080522001280AC0035FD6"),
        bytes.fromhex("20008052C0035FD61F2003D51F2003D51F2003D5"),
        "Always return 1 (unlocked). mov w0,#1; ret; nop*3"),
    BinaryPatch("B", "_dvnCheck", 0x1EB60,
        bytes.fromhex("F44FBEA9FD7B01A9FD430091"),
        bytes.fromhex("20008052C0035FD61F2003D5"),
        "Always return 1 (authorized). mov w0,#1; ret; nop"),
    BinaryPatch("C", "_DVNPatreonLogout gate write", 0x1F06C,
        bytes.fromhex("09C51339"),
        bytes.fromhex("1F2003D5"),
        "NOP the strb that writes to inverted gate on logout."),
    BinaryPatch("D", "_DVNPatreonLogin", 0x1F3D8,
        bytes.fromhex("FF8302D1FC6F04A9FA6705A9"),
        bytes.fromhex("E0031FAAC0035FD61F2003D5"),
        "Stub login: mov x0,xzr; ret; nop. No OAuth flow."),
    BinaryPatch("E", "_DVNPatreonOpenDevices", 0x21A34,
        bytes.fromhex("FF8302D1FC6F04A9FA6705A9"),
        bytes.fromhex("E0031FAAC0035FD61F2003D5"),
        "Stub devices: mov x0,xzr; ret; nop. No WebView."),
    BinaryPatch("F1", "call-site bl _dvnCheck (hooks)", 0x0CE9E0,
        bytes.fromhex("6040FD97"), bytes.fromhex("20008052"),
        "Replace BL _dvnCheck with mov w0,#1."),
    BinaryPatch("F2", "call-site bl _dvnLocked (hooks)", 0x0CE974,
        bytes.fromhex("7640FD97"), bytes.fromhex("20008052"),
        "Replace BL _dvnLocked with mov w0,#1."),
    BinaryPatch("F3", "call-site bl _dvnCheck (UI)", 0x187C50,
        bytes.fromhex("C45BFA97"), bytes.fromhex("20008052"),
        "Replace BL _dvnCheck with mov w0,#1."),
    BinaryPatch("F4", "call-site bl _dvnLocked (UI)", 0x187F2C,
        bytes.fromhex("085BFA97"), bytes.fromhex("20008052"),
        "Replace BL _dvnLocked with mov w0,#1."),
]

VARIANT_SIGNATURES = {
    "rootless": (0x1EB10, [bytes.fromhex("289000D0"), bytes.fromhex("20008052")]),
    "rootful":  (0x1EB4C, [bytes.fromhex("C8890090"), bytes.fromhex("20008052")]),
}


def detect_variant(binary: bytes) -> str:
    for name, (offset, sigs) in VARIANT_SIGNATURES.items():
        if offset + len(sigs[0]) <= len(binary):
            chunk = binary[offset:offset + len(sigs[0])]
            if any(chunk == s for s in sigs):
                return name
    raise PatchError(
        "Unknown binary variant. Expected rootless (_dvnLocked @ 0x1EB10) "
        "or rootful (_dvnLocked @ 0x1EB4C). Binary may be a different version."
    )


def get_patches_for_variant(variant: str) -> List[BinaryPatch]:
    if variant == "rootless":
        return PATCHES_ROOTLESS
    if variant == "rootful":
        return PATCHES_ROOTFUL
    raise PatchError(f"Unknown variant: {variant}")


ALL_PATCHES: List[BinaryPatch] = []

PATCH_LEVELS: Dict[str, List[str]] = {
    "minimal": ["A", "B"],
    "medium": ["A", "B", "C", "D", "E"],
    "full": ["A", "B", "C", "D", "E", "F1", "F2", "F3", "F4"],
}


# =============================================================================
# Logging
# =============================================================================

def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")


# =============================================================================
# CLI
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Patch YTLite.dylib inside a .deb package.",
        epilog="Levels: minimal (gate only), medium (+ auth stubs), full (+ call-site NOPs)",
    )
    parser.add_argument("deb_path", help="Path to the input .deb file.")
    parser.add_argument("--output", help="Output .deb path. Default: <input>.patched.deb")
    parser.add_argument(
        "--level",
        choices=sorted(PATCH_LEVELS.keys()),
        help="Patch level to apply or verify.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Show changes without writing.")
    parser.add_argument("--verify", action="store_true", help="Check current patch state.")
    parser.add_argument("--verbose", action="store_true", help="Debug logging.")
    args = parser.parse_args()

    if args.verify and args.dry_run:
        parser.error("--verify and --dry-run cannot be used together")
    if not args.verify and args.level is None:
        args.level = "minimal"

    return args


# =============================================================================
# Patch helpers
# =============================================================================

def get_patches_for_level(level: str, variant_patches: List[BinaryPatch]) -> List[BinaryPatch]:
    by_id = {p.patch_id: p for p in variant_patches}
    return [by_id[pid] for pid in PATCH_LEVELS[level]]


def slice_at(data: bytes, offset: int, length: int) -> bytes:
    end = offset + length
    if end > len(data):
        raise PatchError(
            f"Binary too small for offset 0x{offset:X} length {length} "
            f"(size={len(data)})"
        )
    return data[offset:end]


def get_patch_status(binary: bytes, patch: BinaryPatch) -> str:
    current = slice_at(binary, patch.offset, len(patch.original))
    if current == patch.original:
        return "original"
    if current == patch.patched:
        return "patched"
    return "unknown"


def collect_patch_statuses(binary: bytes, variant_patches: List[BinaryPatch]) -> Dict[str, str]:
    return {p.patch_id: get_patch_status(binary, p) for p in variant_patches}


def log_patch_statuses(statuses: Dict[str, str], variant_patches: List[BinaryPatch]) -> None:
    for patch in variant_patches:
        LOGGER.info(
            "  [%s] %-35s @ 0x%06X -> %s",
            patch.patch_id, patch.name, patch.offset, statuses[patch.patch_id],
        )


def infer_patch_state(statuses: Dict[str, str]) -> str:
    minimal_ids = PATCH_LEVELS["minimal"]
    medium_ids = PATCH_LEVELS["medium"]
    full_ids = PATCH_LEVELS["full"]
    medium_extra = [pid for pid in medium_ids if pid not in minimal_ids]
    full_extra = [pid for pid in full_ids if pid not in medium_ids]

    if any(s == "unknown" for s in statuses.values()):
        return "mixed-or-unknown"
    if all(statuses[pid] == "original" for pid in full_ids):
        return "original"
    if all(statuses[pid] == "patched" for pid in full_ids):
        return "full"
    if (all(statuses[pid] == "patched" for pid in medium_ids)
            and all(statuses[pid] == "original" for pid in full_extra)):
        return "medium"
    if (all(statuses[pid] == "patched" for pid in minimal_ids)
            and all(statuses[pid] == "original" for pid in medium_extra + full_extra)):
        return "minimal"
    return "mixed-or-unknown"


def verify_requested_level(statuses: Dict[str, str], level: str) -> None:
    required = PATCH_LEVELS[level]
    missing = [pid for pid in required if statuses[pid] != "patched"]
    if missing:
        raise VerificationFailed(
            f"Verify failed for level '{level}': "
            f"not patched: {', '.join(missing)}"
        )


# =============================================================================
# Mach-O validation
# =============================================================================

def validate_macho(binary: bytes, patches: Sequence[BinaryPatch]) -> None:
    LOGGER.info("Validating Mach-O binary...")
    if len(binary) < 4:
        raise PatchError("Binary too small for Mach-O magic")

    magic = binary[:4]
    if magic in FAT_MACHO_MAGICS:
        raise PatchError("Fat/universal Mach-O not supported; need thin arm64")
    if magic != MACHO_MAGIC_64_LE:
        raise PatchError(f"Bad Mach-O magic: {magic.hex(' ')}")

    max_end = max(p.offset + len(p.original) for p in patches)
    if len(binary) < max_end:
        raise PatchError(
            f"Binary too small: {len(binary)} bytes, need at least 0x{max_end:X}"
        )
    LOGGER.info("  Mach-O OK: %d bytes, max patch end 0x%X", len(binary), max_end)


# =============================================================================
# ar archive (deb) parsing and building
# =============================================================================

def parse_decimal(raw: bytes) -> int:
    return int(raw.decode("ascii").strip() or "0", 10)


def parse_octal(raw: bytes) -> int:
    return int(raw.decode("ascii").strip() or "0", 8)


def parse_ar_archive(raw: bytes) -> List[ArMember]:
    LOGGER.info("Parsing .deb ar archive...")
    if not raw.startswith(AR_MAGIC):
        raise PatchError("Not a valid ar archive (.deb)")

    members: List[ArMember] = []
    offset = len(AR_MAGIC)

    while offset < len(raw):
        if offset + 60 > len(raw):
            raise PatchError("Truncated ar header")

        hdr = raw[offset:offset + 60]
        offset += 60

        name = hdr[0:16].decode("ascii").strip().rstrip("/")
        timestamp = parse_decimal(hdr[16:28])
        owner_id = parse_decimal(hdr[28:34])
        group_id = parse_decimal(hdr[34:40])
        mode = parse_octal(hdr[40:48])
        size = parse_decimal(hdr[48:58])

        if hdr[58:60] != b"`\n":
            raise PatchError(f"Bad ar trailer for member '{name}'")
        if offset + size > len(raw):
            raise PatchError(f"Truncated data for member '{name}'")

        members.append(ArMember(
            name=name, timestamp=timestamp, owner_id=owner_id,
            group_id=group_id, mode=mode, data=raw[offset:offset + size],
        ))
        LOGGER.debug("  ar member: %s (%d bytes)", name, size)
        offset += size
        if size % 2 == 1:
            offset += 1

    return members


def build_ar_archive(members: Sequence[ArMember]) -> bytes:
    LOGGER.info("Rebuilding .deb ar archive...")
    buf = io.BytesIO()
    buf.write(AR_MAGIC)

    for m in members:
        enc_name = f"{m.name}/".encode("ascii")
        if len(enc_name) > 16:
            raise PatchError(f"ar name too long: '{m.name}'")

        hdr = b"".join([
            enc_name.ljust(16, b" "),
            str(m.timestamp).encode("ascii").ljust(12, b" "),
            str(m.owner_id).encode("ascii").ljust(6, b" "),
            str(m.group_id).encode("ascii").ljust(6, b" "),
            format(m.mode, "o").encode("ascii").ljust(8, b" "),
            str(len(m.data)).encode("ascii").ljust(10, b" "),
            b"`\n",
        ])
        buf.write(hdr)
        buf.write(m.data)
        if len(m.data) % 2 == 1:
            buf.write(b"\n")

    return buf.getvalue()


# =============================================================================
# tar payload handling
# =============================================================================

def find_data_member(members: Sequence[ArMember]) -> Tuple[int, ArMember]:
    candidates = [(i, m) for i, m in enumerate(members) if m.name.startswith("data.tar")]
    if not candidates:
        raise PatchError("No data.tar* in .deb")
    if len(candidates) > 1:
        raise PatchError(f"Multiple data.tar* members: {[m.name for _, m in candidates]}")
    return candidates[0]


def decompress_tar(name: str, data: bytes) -> bytes:
    LOGGER.info("Decompressing %s...", name)
    if name.endswith(".tar"):
        return data
    if name.endswith(".tar.gz"):
        return gzip.decompress(data)
    if name.endswith(".tar.bz2"):
        return bz2.decompress(data)
    if name.endswith(".tar.xz"):
        return lzma.decompress(data)
    if name.endswith(".tar.lzma"):
        return lzma.decompress(data, format=lzma.FORMAT_ALONE)
    raise PatchError(f"Unsupported format: '{name}'")


def compress_tar(name: str, tar_data: bytes) -> bytes:
    LOGGER.info("Recompressing %s...", name)
    if name.endswith(".tar"):
        return tar_data
    if name.endswith(".tar.gz"):
        return gzip.compress(tar_data, compresslevel=9)
    if name.endswith(".tar.bz2"):
        return bz2.compress(tar_data, compresslevel=9)
    if name.endswith(".tar.xz"):
        return lzma.compress(tar_data, preset=9)
    if name.endswith(".tar.lzma"):
        return lzma.compress(tar_data, format=lzma.FORMAT_ALONE, preset=9)
    raise PatchError(f"Unsupported format: '{name}'")


def find_ytlite_in_tar(tar_data: bytes) -> Tuple[str, bytes]:
    LOGGER.info("Searching for YTLite.dylib in tar payload...")
    with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as tar:
        candidates = [
            m for m in tar.getmembers()
            if m.isfile() and PurePosixPath(m.name).name == "YTLite.dylib"
        ]
        if not candidates:
            raise PatchError("YTLite.dylib not found in tar")
        if len(candidates) > 1:
            raise PatchError(f"Multiple YTLite.dylib: {[m.name for m in candidates]}")

        target = candidates[0]
        f = tar.extractfile(target)
        if f is None:
            raise PatchError(f"Failed to extract '{target.name}'")
        binary = f.read()
        LOGGER.info("  Found: %s (%d bytes)", target.name, len(binary))
        return target.name, binary


def rebuild_tar(tar_data: bytes, target_name: str, replacement: bytes) -> bytes:
    LOGGER.info("Rebuilding tar with patched binary...")
    src_buf = io.BytesIO(tar_data)
    dst_buf = io.BytesIO()

    with tarfile.open(fileobj=src_buf, mode="r:") as src:
        fmt = getattr(src, "format", tarfile.PAX_FORMAT)
        with tarfile.open(fileobj=dst_buf, mode="w", format=fmt) as dst:
            replaced = False
            for member in src.getmembers():
                new_member = copy.copy(member)
                new_member.pax_headers = dict(getattr(member, "pax_headers", {}) or {})

                if member.isfile():
                    f = src.extractfile(member)
                    if f is None:
                        raise PatchError(f"Failed to extract '{member.name}'")
                    data = f.read()
                    if member.name == target_name:
                        data = replacement
                        replaced = True
                    new_member.size = len(data)
                    dst.addfile(new_member, io.BytesIO(data))
                else:
                    dst.addfile(new_member)

            if not replaced:
                raise PatchError(f"'{target_name}' not replaced in tar rebuild")

    return dst_buf.getvalue()


# =============================================================================
# File I/O
# =============================================================================

def read_file(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as e:
        raise PatchError(f"Cannot read '{path}': {e}") from e


def write_file_atomic(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except OSError as e:
        raise PatchError(f"Cannot write '{path}': {e}") from e
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# =============================================================================
# Core operations
# =============================================================================

def inspect_deb(deb_path: Path):
    LOGGER.info("Reading: %s", deb_path)
    raw = read_file(deb_path)
    members = parse_ar_archive(raw)
    idx, data_member = find_data_member(members)
    tar_payload = decompress_tar(data_member.name, data_member.data)
    target_name, dylib = find_ytlite_in_tar(tar_payload)
    return members, idx, data_member, tar_payload, target_name, dylib


def apply_patches(
    binary: bytes,
    patches: Sequence[BinaryPatch],
    dry_run: bool,
) -> Tuple[bytes, int]:
    LOGGER.info("Applying patches...")
    buf = bytearray(binary)
    changes = 0

    for patch in patches:
        status = get_patch_status(bytes(buf), patch)
        LOGGER.info(
            "  [%s] %s @ 0x%06X: %s",
            patch.patch_id, patch.name, patch.offset, status,
        )

        if status == "patched":
            LOGGER.info("       Already patched, skipping")
            continue

        if status == "original":
            LOGGER.info("       -> %s", patch.description)
            if not dry_run:
                start = patch.offset
                buf[start:start + len(patch.patched)] = patch.patched
            changes += 1
            continue

        current = slice_at(bytes(buf), patch.offset, len(patch.original))
        raise PatchError(
            f"Unexpected bytes at [{patch.patch_id}] {patch.name} "
            f"offset 0x{patch.offset:X}:\n"
            f"  got:      {current.hex(' ')}\n"
            f"  expected: {patch.original.hex(' ')}\n"
            f"  Binary version mismatch? Aborting."
        )

    return bytes(buf), changes


# =============================================================================
# Run modes
# =============================================================================

def run_verify(args: argparse.Namespace) -> int:
    deb_path = Path(args.deb_path)
    if not deb_path.is_file():
        raise PatchError(f"File not found: '{deb_path}'")

    _, _, _, _, _, dylib = inspect_deb(deb_path)
    variant = detect_variant(dylib)
    LOGGER.info("Detected binary variant: %s", variant)
    variant_patches = get_patches_for_variant(variant)
    validate_macho(dylib, variant_patches)

    statuses = collect_patch_statuses(dylib, variant_patches)
    LOGGER.info("Patch status for all points:")
    log_patch_statuses(statuses, variant_patches)

    state = infer_patch_state(statuses)
    LOGGER.info("Detected state: %s", state)

    if args.level:
        verify_requested_level(statuses, args.level)
        LOGGER.info("Verify PASSED for level '%s'", args.level)

    return 0


def run_patch(args: argparse.Namespace) -> int:
    deb_path = Path(args.deb_path)
    if not deb_path.is_file():
        raise PatchError(f"File not found: '{deb_path}'")

    level = args.level
    output_path = Path(args.output) if args.output else deb_path.with_name(
        f"{deb_path.stem}.patched{deb_path.suffix}"
    )

    members, idx, data_member, tar_payload, target_name, dylib = inspect_deb(deb_path)
    variant = detect_variant(dylib)
    LOGGER.info("Detected binary variant: %s", variant)
    variant_patches = get_patches_for_variant(variant)
    patches = get_patches_for_level(level, variant_patches)
    validate_macho(dylib, patches)

    pre_state = infer_patch_state(collect_patch_statuses(dylib, variant_patches))
    LOGGER.info("Pre-patch state: %s", pre_state)

    patched_binary, change_count = apply_patches(dylib, patches, dry_run=args.dry_run)

    if args.dry_run:
        LOGGER.info("Dry-run complete: %d locations would change", change_count)
        return 0

    post_statuses = collect_patch_statuses(patched_binary, variant_patches)
    verify_requested_level(post_statuses, level)
    LOGGER.info("In-memory verification PASSED for level '%s'", level)

    # Rebuild
    new_tar = rebuild_tar(tar_payload, target_name, patched_binary)
    members[idx] = ArMember(
        name=data_member.name,
        timestamp=data_member.timestamp,
        owner_id=data_member.owner_id,
        group_id=data_member.group_id,
        mode=data_member.mode,
        data=compress_tar(data_member.name, new_tar),
    )
    rebuilt = build_ar_archive(members)

    LOGGER.info("Writing: %s", output_path)
    write_file_atomic(output_path, rebuilt)

    # Post-write verification
    LOGGER.info("Post-write verification...")
    verify_args = argparse.Namespace(deb_path=str(output_path), level=level, verbose=False)
    run_verify(verify_args)

    LOGGER.info(
        "SUCCESS: %s -> %s (level=%s, %d patches applied)",
        deb_path.name, output_path.name, level, change_count,
    )
    return 0


def main() -> int:
    args = parse_args()
    configure_logging(args.verbose)

    try:
        if args.verify:
            return run_verify(args)
        return run_patch(args)
    except VerificationFailed as e:
        LOGGER.error(str(e))
        return 2
    except PatchError as e:
        LOGGER.error(str(e))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
