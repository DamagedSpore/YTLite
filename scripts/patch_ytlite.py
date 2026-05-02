#!/usr/bin/env python3
"""patch_ytlite.py — Patch YTLite 5.2.1 .deb (rootful, GitHub releases build)."""
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
from typing import Dict, List, Sequence, Tuple

LOGGER = logging.getLogger("patch_ytlite")
AR_MAGIC = b"!<arch>\n"
MACHO_MAGIC_64_LE = b"\xCF\xFA\xED\xFE"


class PatchError(Exception):
    pass


class VerificationFailed(PatchError):
    pass


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


# YTLite 5.2.1 rootful — gate @ 0x11564f1, inverted BIC (0=unlocked, 1=locked)
ALL_PATCHES: List[BinaryPatch] = [
    BinaryPatch("A", "_dvnLocked", 0x1EB4C,
        bytes.fromhex("C889009008C55339290080522001280AC0035FD6"),
        bytes.fromhex("20008052C0035FD61F2003D51F2003D51F2003D5"),
        "mov w0,#1; ret; nop*3"),
    BinaryPatch("B", "_dvnCheck", 0x1EB60,
        bytes.fromhex("F44FBEA9FD7B01A9FD430091"),
        bytes.fromhex("20008052C0035FD61F2003D5"),
        "mov w0,#1; ret; nop"),
    BinaryPatch("C", "_DVNPatreonLogout gate", 0x1F06C,
        bytes.fromhex("09C51339"), bytes.fromhex("1F2003D5"),
        "NOP strb"),
    BinaryPatch("C2", "startup alert branch", 0x1E990,
        bytes.fromhex("08010052"), bytes.fromhex("08008052"),
        "mov w8,#0 skip alert"),
    BinaryPatch("D", "_DVNPatreonLogin", 0x1F3D8,
        bytes.fromhex("FF8302D1FC6F04A9FA6705A9"),
        bytes.fromhex("E0031FAAC0035FD61F2003D5"),
        "ret stub"),
    BinaryPatch("E", "_DVNPatreonOpenDevices", 0x21A34,
        bytes.fromhex("FF8302D1FC6F04A9FA6705A9"),
        bytes.fromhex("E0031FAAC0035FD61F2003D5"),
        "ret stub"),
    BinaryPatch("F1", "call-site dvnCheck hooks", 0x0CE9E0,
        bytes.fromhex("6040FD97"), bytes.fromhex("20008052"), "mov w0,#1"),
    BinaryPatch("F2", "call-site dvnLocked hooks", 0x0CE974,
        bytes.fromhex("7640FD97"), bytes.fromhex("20008052"), "mov w0,#1"),
    BinaryPatch("F3", "call-site dvnCheck UI", 0x187C50,
        bytes.fromhex("C45BFA97"), bytes.fromhex("20008052"), "mov w0,#1"),
    BinaryPatch("F4", "call-site dvnLocked UI", 0x187F2C,
        bytes.fromhex("085BFA97"), bytes.fromhex("20008052"), "mov w0,#1"),
]

PATCHES_BY_ID: Dict[str, BinaryPatch] = {p.patch_id: p for p in ALL_PATCHES}
PATCH_LEVELS: Dict[str, List[str]] = {
    "minimal": ["A", "B"],
    "medium": ["A", "B", "C", "C2", "D", "E"],
    "full": ["A", "B", "C", "C2", "D", "E", "F1", "F2", "F3", "F4"],
}
SIGNATURE_OFFSET = 0x1EB4C
SIGNATURE_BYTES = [bytes.fromhex("C8890090"), bytes.fromhex("20008052")]


def validate_binary(binary: bytes, patches: Sequence[BinaryPatch]) -> None:
    if len(binary) < 4 or binary[:4] != MACHO_MAGIC_64_LE:
        raise PatchError("Not a valid thin arm64 Mach-O")
    max_end = max(p.offset + len(p.original) for p in patches)
    if len(binary) < max_end:
        raise PatchError(f"Binary too small: {len(binary)} < 0x{max_end:X}")
    chunk = binary[SIGNATURE_OFFSET:SIGNATURE_OFFSET + 4]
    if not any(chunk == s for s in SIGNATURE_BYTES):
        raise PatchError(f"Binary signature mismatch at 0x{SIGNATURE_OFFSET:X}: {chunk.hex()}")
    LOGGER.info("Binary OK: %d bytes, signature matched", len(binary))


def get_patches_for_level(level: str) -> List[BinaryPatch]:
    return [PATCHES_BY_ID[pid] for pid in PATCH_LEVELS[level]]


def get_patch_status(binary: bytes, patch: BinaryPatch) -> str:
    end = patch.offset + len(patch.original)
    if end > len(binary):
        raise PatchError(f"Binary too small for patch {patch.patch_id}")
    current = binary[patch.offset:end]
    if current == patch.original:
        return "original"
    if current == patch.patched:
        return "patched"
    return "unknown"


def collect_statuses(binary: bytes) -> Dict[str, str]:
    return {p.patch_id: get_patch_status(binary, p) for p in ALL_PATCHES}


def log_statuses(statuses: Dict[str, str]) -> None:
    for p in ALL_PATCHES:
        LOGGER.info("  [%s] %-28s @ 0x%06X -> %s", p.patch_id, p.name, p.offset, statuses[p.patch_id])


def infer_state(statuses: Dict[str, str]) -> str:
    if any(s == "unknown" for s in statuses.values()):
        return "mixed-or-unknown"
    for level in ["full", "medium", "minimal"]:
        ids = PATCH_LEVELS[level]
        others = [pid for pid in PATCHES_BY_ID if pid not in ids]
        if all(statuses[x] == "patched" for x in ids) and all(statuses[x] == "original" for x in others):
            return level
    if all(s == "original" for s in statuses.values()):
        return "original"
    return "mixed-or-unknown"


def verify_level(statuses: Dict[str, str], level: str) -> None:
    missing = [pid for pid in PATCH_LEVELS[level] if statuses[pid] != "patched"]
    if missing:
        raise VerificationFailed(f"Verify failed for '{level}': not patched: {', '.join(missing)}")


def apply_patches(binary: bytes, patches: Sequence[BinaryPatch], dry_run: bool) -> Tuple[bytes, int]:
    buf = bytearray(binary)
    changes = 0
    for p in patches:
        status = get_patch_status(bytes(buf), p)
        LOGGER.info("  [%s] %s @ 0x%06X: %s", p.patch_id, p.name, p.offset, status)
        if status == "patched":
            continue
        if status == "original":
            LOGGER.info("       -> %s", p.description)
            if not dry_run:
                buf[p.offset:p.offset + len(p.patched)] = p.patched
            changes += 1
            continue
        current = binary[p.offset:p.offset + len(p.original)]
        raise PatchError(
            f"Unexpected bytes at [{p.patch_id}] {p.name} 0x{p.offset:X}:\n"
            f"  got:      {current.hex(' ')}\n"
            f"  expected: {p.original.hex(' ')}")
    return bytes(buf), changes


def parse_decimal(raw: bytes) -> int:
    return int(raw.decode("ascii").strip() or "0", 10)


def parse_octal(raw: bytes) -> int:
    return int(raw.decode("ascii").strip() or "0", 8)


def parse_ar(raw: bytes) -> List[ArMember]:
    if not raw.startswith(AR_MAGIC):
        raise PatchError("Not a valid .deb (ar archive)")
    members, offset = [], len(AR_MAGIC)
    while offset < len(raw):
        if offset + 60 > len(raw):
            raise PatchError("Truncated ar header")
        hdr = raw[offset:offset + 60]
        offset += 60
        name = hdr[0:16].decode("ascii").strip().rstrip("/")
        ts = parse_decimal(hdr[16:28])
        uid = parse_decimal(hdr[28:34])
        gid = parse_decimal(hdr[34:40])
        mode = parse_octal(hdr[40:48])
        size = parse_decimal(hdr[48:58])
        if hdr[58:60] != b"`\n" or offset + size > len(raw):
            raise PatchError(f"Bad ar member: '{name}'")
        members.append(ArMember(name, ts, uid, gid, mode, raw[offset:offset + size]))
        offset += size + (size % 2)
    return members


def build_ar(members: Sequence[ArMember]) -> bytes:
    buf = io.BytesIO()
    buf.write(AR_MAGIC)
    for m in members:
        enc = f"{m.name}/".encode("ascii")
        hdr = b"".join([enc.ljust(16), str(m.timestamp).encode().ljust(12),
            str(m.owner_id).encode().ljust(6), str(m.group_id).encode().ljust(6),
            format(m.mode, "o").encode().ljust(8), str(len(m.data)).encode().ljust(10), b"`\n"])
        buf.write(hdr)
        buf.write(m.data)
        if len(m.data) % 2:
            buf.write(b"\n")
    return buf.getvalue()


def find_data_member(members: Sequence[ArMember]) -> Tuple[int, ArMember]:
    cands = [(i, m) for i, m in enumerate(members) if m.name.startswith("data.tar")]
    if len(cands) != 1:
        raise PatchError(f"Expected 1 data.tar*, found {len(cands)}")
    return cands[0]


def decompress_tar(name: str, data: bytes) -> bytes:
    LOGGER.info("Decompressing %s...", name)
    if name.endswith(".tar"): return data
    if name.endswith(".tar.gz"): return gzip.decompress(data)
    if name.endswith(".tar.bz2"): return bz2.decompress(data)
    if name.endswith(".tar.xz"): return lzma.decompress(data)
    if name.endswith(".tar.lzma"): return lzma.decompress(data, format=lzma.FORMAT_ALONE)
    raise PatchError(f"Unsupported: '{name}'")


def compress_tar(name: str, data: bytes) -> bytes:
    LOGGER.info("Recompressing %s...", name)
    if name.endswith(".tar"): return data
    if name.endswith(".tar.gz"): return gzip.compress(data, compresslevel=9)
    if name.endswith(".tar.bz2"): return bz2.compress(data, compresslevel=9)
    if name.endswith(".tar.xz"): return lzma.compress(data, preset=9)
    if name.endswith(".tar.lzma"): return lzma.compress(data, format=lzma.FORMAT_ALONE, preset=9)
    raise PatchError(f"Unsupported: '{name}'")


def find_dylib(tar_data: bytes) -> Tuple[str, bytes]:
    LOGGER.info("Searching for YTLite.dylib...")
    with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as tar:
        cands = [m for m in tar.getmembers() if m.isfile() and PurePosixPath(m.name).name == "YTLite.dylib"]
        if len(cands) != 1:
            raise PatchError(f"Expected 1 YTLite.dylib, found {len(cands)}")
        f = tar.extractfile(cands[0])
        if not f:
            raise PatchError("Cannot extract YTLite.dylib")
        data = f.read()
        LOGGER.info("  Found: %s (%d bytes)", cands[0].name, len(data))
        return cands[0].name, data


def rebuild_tar(tar_data: bytes, target: str, replacement: bytes) -> bytes:
    LOGGER.info("Rebuilding tar...")
    src, dst = io.BytesIO(tar_data), io.BytesIO()
    with tarfile.open(fileobj=src, mode="r:") as s:
        with tarfile.open(fileobj=dst, mode="w", format=getattr(s, "format", tarfile.PAX_FORMAT)) as d:
            replaced = False
            for member in s.getmembers():
                nm = copy.copy(member)
                nm.pax_headers = dict(getattr(member, "pax_headers", {}) or {})
                if member.isfile():
                    f = s.extractfile(member)
                    if not f:
                        raise PatchError(f"Cannot extract '{member.name}'")
                    data = f.read()
                    if member.name == target:
                        data, replaced = replacement, True
                    nm.size = len(data)
                    d.addfile(nm, io.BytesIO(data))
                else:
                    d.addfile(nm)
            if not replaced:
                raise PatchError(f"'{target}' not replaced")
    return dst.getvalue()


def write_atomic(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(prefix=f"{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def inspect_deb(path: Path):
    LOGGER.info("Reading: %s", path)
    members = parse_ar(path.read_bytes())
    idx, dm = find_data_member(members)
    tar = decompress_tar(dm.name, dm.data)
    name, dylib = find_dylib(tar)
    return members, idx, dm, tar, name, dylib


def run_verify(deb_path: str, level: str = None) -> int:
    path = Path(deb_path)
    if not path.is_file():
        raise PatchError(f"Not found: '{path}'")
    _, _, _, _, _, dylib = inspect_deb(path)
    validate_binary(dylib, ALL_PATCHES)
    statuses = collect_statuses(dylib)
    LOGGER.info("Patch status:")
    log_statuses(statuses)
    LOGGER.info("State: %s", infer_state(statuses))
    if level:
        verify_level(statuses, level)
        LOGGER.info("Verify PASSED for '%s'", level)
    return 0


def run_patch(deb_path: str, level: str, output: str = None, dry_run: bool = False) -> int:
    path = Path(deb_path)
    if not path.is_file():
        raise PatchError(f"Not found: '{path}'")
    out = Path(output) if output else path.with_name(f"{path.stem}.patched{path.suffix}")

    members, idx, dm, tar, target, dylib = inspect_deb(path)
    patches = get_patches_for_level(level)
    validate_binary(dylib, patches)
    LOGGER.info("Pre-patch: %s", infer_state(collect_statuses(dylib)))

    patched, changes = apply_patches(dylib, patches, dry_run)
    if dry_run:
        LOGGER.info("Dry-run: %d locations would change", changes)
        return 0

    verify_level(collect_statuses(patched), level)
    LOGGER.info("In-memory verify PASSED")

    new_tar = rebuild_tar(tar, target, patched)
    members[idx] = ArMember(dm.name, dm.timestamp, dm.owner_id, dm.group_id, dm.mode,
                            compress_tar(dm.name, new_tar))
    LOGGER.info("Writing: %s", out)
    write_atomic(out, build_ar(members))

    LOGGER.info("Post-write verify...")
    run_verify(str(out), level)
    LOGGER.info("SUCCESS: %s -> %s (level=%s, %d patched)", path.name, out.name, level, changes)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Patch YTLite.dylib inside a .deb package.")
    p.add_argument("deb_path")
    p.add_argument("--output", help="Output .deb path")
    p.add_argument("--level", choices=sorted(PATCH_LEVELS), help="Patch level")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--verify", action="store_true")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()
    if args.verify and args.dry_run:
        p.error("--verify and --dry-run cannot be used together")
    if not args.verify and not args.level:
        args.level = "minimal"

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="[%(levelname)s] %(message)s")
    try:
        if args.verify:
            return run_verify(args.deb_path, args.level)
        return run_patch(args.deb_path, args.level, args.output, args.dry_run)
    except VerificationFailed as e:
        LOGGER.error(str(e))
        return 2
    except PatchError as e:
        LOGGER.error(str(e))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
