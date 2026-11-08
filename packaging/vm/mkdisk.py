#!/usr/bin/env python3
"""Write a raw UEFI-bootable disk: a GPT with one FAT32 EFI System Partition.

This is the userspace stand-in for `sgdisk` + `mkfs.vfat` + `mcopy` that
`build-image.sh --format disk` uses, so the disk image is built without root,
without loop devices and without any tool outside the Python standard library.

    mkdisk.py write --out disk.raw --file EFI/BOOT/BOOTX64.EFI=bzImage [--esp-mib 64]
    mkdisk.py verify disk.raw --file EFI/BOOT/BOOTX64.EFI=bzImage
    mkdisk.py list disk.raw

`write` is deterministic: the same files give the same bytes (the disk and
partition GUIDs and the volume serial are derived from the contents, every
timestamp is 1980-01-01 00:00), so a rebuilt image hashes the same.

Scope, on purpose: 512-byte sectors, one partition, 8.3 upper-case names only
(no long file names — `EFI/BOOT/BOOTX64.EFI` is all a firmware needs), files are
written once and never modified. `verify` re-reads the image with the parser in
this module (CRC32 of both GPT headers and entry arrays, the FAT chains, the
file bytes); CI additionally checks it with `sgdisk -v`, `fsck.fat -n` and
`mtools` so the writer is not only checked against itself.
"""

import argparse
import hashlib
import os
import struct
import sys
import uuid
import zlib

SECTOR = 512
ALIGN_LBA = 2048  # 1 MiB: first partition start, and the tail kept for the backup GPT
ESP_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
GPT_ENTRIES = 128
GPT_ENTRY_SIZE = 128
GPT_ENTRY_SECTORS = GPT_ENTRIES * GPT_ENTRY_SIZE // SECTOR  # 32
FAT32_MIN_CLUSTERS = 65525
FAT32_MAX_CLUSTERS = 0x0FFFFFF5
EOC = 0x0FFFFFFF
RESERVED_SECTORS = 32
NUM_FATS = 2
DOS_DATE_1980_01_01 = (0 << 9) | (1 << 5) | 1
ATTR_DIR = 0x10
ATTR_ARCHIVE = 0x20
ATTR_VOLUME = 0x08
_83_OK = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'()-@^_`{}~")


class DiskError(Exception):
    pass


# ── helpers ─────────────────────────────────────────────────────────────────


def stable_uuid(*parts):
    """A random-format (v4 layout) UUID derived from `parts`, for reproducible images."""
    h = hashlib.sha256(b"seagent-mkdisk\0" + b"\0".join(parts)).digest()
    return uuid.UUID(bytes=h[:16], version=4)


def name83(component):
    """`BOOTX64.EFI` -> the 11-byte directory name; anything else is refused."""
    if component in (".", ".."):
        raise DiskError("'.' and '..' are not file names")
    base, dot, ext = component.partition(".")
    if "." in ext or not base or len(base) > 8 or len(ext) > 3 or (dot and not ext):
        raise DiskError(f"{component!r} is not an 8.3 name (no long file names on this ESP)")
    for ch in base + ext:
        if ch not in _83_OK:
            raise DiskError(f"{component!r}: use upper-case 8.3 names (bad character {ch!r})")
    return (base.ljust(8) + ext.ljust(3)).encode("ascii")


def split_path(path):
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    if not parts:
        raise DiskError(f"empty path {path!r}")
    for p in parts:
        name83(p)
    return parts


def dirent(name11, attr, cluster, size):
    return struct.pack(
        "<11sBBBHHHHHHHI",
        name11,
        attr,
        0,  # NTRes
        0,  # CrtTimeTenth
        0,  # CrtTime
        DOS_DATE_1980_01_01,  # CrtDate
        DOS_DATE_1980_01_01,  # LstAccDate
        (cluster >> 16) & 0xFFFF,
        0,  # WrtTime
        DOS_DATE_1980_01_01,  # WrtDate
        cluster & 0xFFFF,
        size,
    )


# ── FAT32 ───────────────────────────────────────────────────────────────────


def fat32_geometry(total_sectors):
    """(sectors_per_cluster, fat_sectors, cluster_count) for a FAT32 volume, or DiskError."""
    for spc in (64, 32, 16, 8, 4, 2, 1):
        # Microsoft's FAT spec formula (fatgen103, "FAT Volume Initialization").
        tmp1 = total_sectors - RESERVED_SECTORS
        tmp2 = (256 * spc + NUM_FATS) // 2
        fatsz = -(-tmp1 // tmp2)
        clusters = (total_sectors - RESERVED_SECTORS - NUM_FATS * fatsz) // spc
        if FAT32_MIN_CLUSTERS <= clusters < FAT32_MAX_CLUSTERS and (clusters + 2) * 4 <= fatsz * SECTOR:
            return spc, fatsz, clusters
    raise DiskError(f"{total_sectors * SECTOR} bytes is too small for FAT32 (needs > {FAT32_MIN_CLUSTERS} clusters)")


class _Node:
    def __init__(self, name11, data=None):
        self.name11 = name11
        self.data = data  # bytes for a file, None for a directory
        self.children = {}  # name11 -> _Node (directories only)
        self.cluster = 0


def build_fat32(files, total_sectors, hidden_sectors, label="SEAGENT", serial=None):
    """The FAT32 volume (bytes) holding `files` ({"A/B.EFI": bytes}), `total_sectors` long."""
    spc, fatsz, clusters = fat32_geometry(total_sectors)
    csize = spc * SECTOR
    data_start = RESERVED_SECTORS + NUM_FATS * fatsz

    root = _Node(b"")
    for path in sorted(files):
        parts = split_path(path)
        node = root
        for comp in parts[:-1]:
            key = name83(comp)
            child = node.children.get(key)
            if child is None:
                child = node.children[key] = _Node(key)
            elif child.data is not None:
                raise DiskError(f"{path}: {comp} is a file")
            node = child
        key = name83(parts[-1])
        if key in node.children:
            raise DiskError(f"{path} given twice")
        node.children[key] = _Node(key, bytes(files[path]))

    fat = [0] * (clusters + 2)
    fat[0] = 0x0FFFFF00 | 0xF8
    fat[1] = EOC
    next_free = [2]
    blobs = []  # (cluster, bytes)

    def alloc(nbytes):
        n = max(1, -(-nbytes // csize))
        first = next_free[0]
        if first + n > clusters + 2:
            raise DiskError(f"the ESP is full: grow it with --esp-mib (needs {n} more clusters of {csize} bytes)")
        for c in range(first, first + n - 1):
            fat[c] = c + 1
        fat[first + n - 1] = EOC
        next_free[0] = first + n
        return first

    def dir_entries_len(node, is_root):
        return 32 * (len(node.children) + (1 if is_root else 2))

    # Allocate breadth-first, root at cluster 2 (RootClus), then write directory bodies.
    order = [(root, None)]
    i = 0
    while i < len(order):
        node, parent = order[i]
        i += 1
        if node.data is not None:
            node.cluster = alloc(len(node.data)) if node.data else 0
            continue
        node.cluster = alloc(dir_entries_len(node, parent is None))
        for key in sorted(node.children):
            order.append((node.children[key], node))
    for node, parent in order:
        if node.data is not None:
            if node.data:
                blobs.append((node.cluster, node.data))
            continue
        body = bytearray()
        if parent is None:
            body += dirent(label.upper().ljust(11)[:11].encode("ascii"), ATTR_VOLUME, 0, 0)
        else:
            body += dirent(b".          ", ATTR_DIR, node.cluster, 0)
            body += dirent(b"..         ", ATTR_DIR, 0 if parent is root else parent.cluster, 0)
        for key in sorted(node.children):
            ch = node.children[key]
            if ch.data is None:
                body += dirent(key, ATTR_DIR, ch.cluster, 0)
            else:
                body += dirent(key, ATTR_ARCHIVE, ch.cluster, len(ch.data))
        blobs.append((node.cluster, bytes(body)))

    used = next_free[0] - 2
    if serial is None:
        serial = struct.unpack("<I", hashlib.sha256(b"".join(files[p] for p in sorted(files))).digest()[:4])[0]

    vol = bytearray(total_sectors * SECTOR)
    bs = bytearray(SECTOR)
    bs[0:3] = b"\xeb\x58\x90"
    bs[3:11] = b"SEAGENT "
    struct.pack_into("<HBHBHHBHHHII", bs, 11, SECTOR, spc, RESERVED_SECTORS, NUM_FATS, 0, 0, 0xF8, 0, 63, 255, hidden_sectors, total_sectors)
    struct.pack_into("<IHHIHH12s", bs, 36, fatsz, 0, 0, 2, 1, 6, b"\0" * 12)
    struct.pack_into("<BBBI11s8s", bs, 64, 0x80, 0, 0x29, serial, label.upper().ljust(11)[:11].encode("ascii"), b"FAT32   ")
    bs[510:512] = b"\x55\xaa"
    fsinfo = bytearray(SECTOR)
    struct.pack_into("<I", fsinfo, 0, 0x41615252)
    struct.pack_into("<III", fsinfo, 484, 0x61417272, clusters - used, next_free[0])
    struct.pack_into("<I", fsinfo, 508, 0xAA550000)
    third = bytearray(SECTOR)
    third[510:512] = b"\x55\xaa"
    for base in (0, 6):  # primary boot record and its backup (BkBootSec = 6)
        vol[(base + 0) * SECTOR:(base + 1) * SECTOR] = bs
        vol[(base + 1) * SECTOR:(base + 2) * SECTOR] = fsinfo
        vol[(base + 2) * SECTOR:(base + 3) * SECTOR] = third

    fat_bytes = struct.pack(f"<{len(fat)}I", *fat)
    for n in range(NUM_FATS):
        off = (RESERVED_SECTORS + n * fatsz) * SECTOR
        vol[off:off + len(fat_bytes)] = fat_bytes
    for cluster, data in blobs:
        off = (data_start + (cluster - 2) * spc) * SECTOR
        vol[off:off + len(data)] = data
    return bytes(vol)


# ── GPT ─────────────────────────────────────────────────────────────────────


def _gpt_header(disk_guid, current, backup, first_usable, last_usable, entries_lba, entries_crc):
    h = bytearray(92)
    struct.pack_into(
        "<8sIIIIQQQQ16sQIII",
        h,
        0,
        b"EFI PART",
        0x00010000,
        92,
        0,  # CRC, filled below
        0,
        current,
        backup,
        first_usable,
        last_usable,
        disk_guid.bytes_le,
        entries_lba,
        GPT_ENTRIES,
        GPT_ENTRY_SIZE,
        entries_crc,
    )
    struct.pack_into("<I", h, 16, zlib.crc32(bytes(h)) & 0xFFFFFFFF)
    return bytes(h).ljust(SECTOR, b"\0")


def write_disk(out_path, files, esp_mib=64, label="SEAGENT"):
    """Write the disk image to `out_path` (via `<out>.part`, renamed when complete)."""
    if esp_mib < 34:
        raise DiskError("--esp-mib must be at least 34 (FAT32 needs 65525 clusters)")
    esp_sectors = esp_mib * 2048
    total = ALIGN_LBA + esp_sectors + ALIGN_LBA
    last = total - 1
    first_lba, last_lba = ALIGN_LBA, ALIGN_LBA + esp_sectors - 1

    content = hashlib.sha256()
    for p in sorted(files):
        content.update(p.encode() + b"\0" + hashlib.sha256(files[p]).digest())
    digest = content.digest()
    disk_guid = stable_uuid(b"disk", digest)
    part_guid = stable_uuid(b"esp", digest)

    esp = build_fat32(files, esp_sectors, first_lba, label=label)

    entries = bytearray(GPT_ENTRIES * GPT_ENTRY_SIZE)
    name = "EFI System Partition".encode("utf-16-le").ljust(72, b"\0")
    struct.pack_into("<16s16sQQQ72s", entries, 0, ESP_TYPE.bytes_le, part_guid.bytes_le, first_lba, last_lba, 0, name)
    entries_crc = zlib.crc32(bytes(entries)) & 0xFFFFFFFF
    first_usable = 2 + GPT_ENTRY_SECTORS
    last_usable = last - 1 - GPT_ENTRY_SECTORS

    mbr = bytearray(SECTOR)
    struct.pack_into("<B3sB3sII", mbr, 446, 0, b"\x00\x02\x00", 0xEE, b"\xff\xff\xff", 1, min(total - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"

    primary = _gpt_header(disk_guid, 1, last, first_usable, last_usable, 2, entries_crc)
    backup = _gpt_header(disk_guid, last, 1, first_usable, last_usable, last - GPT_ENTRY_SECTORS, entries_crc)

    part = out_path + ".part"
    with open(part, "wb") as f:
        f.truncate(total * SECTOR)  # sparse where the filesystem allows it
        f.write(mbr)
        f.write(primary)
        f.write(entries)
        f.seek(first_lba * SECTOR)
        f.write(esp)
        f.seek((last - GPT_ENTRY_SECTORS) * SECTOR)
        f.write(entries)
        f.write(backup)
    os.replace(part, out_path)
    return {"size": total * SECTOR, "disk_guid": str(disk_guid), "esp_guid": str(part_guid), "esp_first_lba": first_lba, "esp_last_lba": last_lba}


# ── reader (verify / list) ──────────────────────────────────────────────────


def _crc_ok(header):
    h = bytearray(header[:92])
    want = struct.unpack_from("<I", h, 16)[0]
    struct.pack_into("<I", h, 16, 0)
    return zlib.crc32(bytes(h)) & 0xFFFFFFFF == want


def read_gpt(img):
    """Parse and check both GPT copies; returns (header dict, [partition dicts])."""
    if len(img) % SECTOR or len(img) < 68 * SECTOR:
        raise DiskError("not a whole number of sectors, or too small for a GPT")
    if img[510:512] != b"\x55\xaa" or img[446 + 4] != 0xEE:
        raise DiskError("no protective MBR")
    last = len(img) // SECTOR - 1
    out = []
    for lba in (1, last):
        h = img[lba * SECTOR:(lba + 1) * SECTOR]
        sig, rev, hsize, _crc, _r, cur, alt, fu, lu, dguid, elba, n, esz, ecrc = struct.unpack_from("<8sIIIIQQQQ16sQIII", h, 0)
        if sig != b"EFI PART" or hsize != 92 or not _crc_ok(h):
            raise DiskError(f"bad GPT header at LBA {lba}")
        if cur != lba or alt != (last if lba == 1 else 1):
            raise DiskError(f"GPT header at LBA {lba} points to the wrong places")
        ents = img[elba * SECTOR:elba * SECTOR + n * esz]
        if zlib.crc32(ents) & 0xFFFFFFFF != ecrc:
            raise DiskError(f"GPT entry array CRC mismatch (header at LBA {lba})")
        out.append((dict(disk_guid=uuid.UUID(bytes_le=dguid), first_usable=fu, last_usable=lu, entries=ents, n=n, esz=esz), rev))
    (p, _), (b, _) = out
    if p["entries"] != b["entries"] or p["disk_guid"] != b["disk_guid"]:
        raise DiskError("primary and backup GPT differ")
    parts = []
    for i in range(p["n"]):
        e = p["entries"][i * p["esz"]:(i + 1) * p["esz"]]
        t = uuid.UUID(bytes_le=e[:16])
        if t.int == 0:
            continue
        first, lastl = struct.unpack_from("<QQ", e, 32)
        if not (p["first_usable"] <= first <= lastl <= p["last_usable"]):
            raise DiskError(f"partition {i + 1} lies outside the usable area")
        parts.append(dict(type=t, guid=uuid.UUID(bytes_le=e[16:32]), first=first, last=lastl, name=e[56:128].decode("utf-16-le").rstrip("\0")))
    return p, parts


class Fat32:
    def __init__(self, vol):
        self.vol = vol
        if vol[510:512] != b"\x55\xaa" or vol[82:90] != b"FAT32   ":
            raise DiskError("not a FAT32 boot sector")
        bps, self.spc, rsv, nf, rootent, tot16, _m, fz16 = struct.unpack_from("<HBHBHHBH", vol, 11)
        tot32, = struct.unpack_from("<I", vol, 32)
        self.fatsz, = struct.unpack_from("<I", vol, 36)
        self.root, = struct.unpack_from("<I", vol, 44)
        if bps != SECTOR or rootent or tot16 or fz16 or nf != 2:
            raise DiskError("unexpected FAT32 BPB")
        self.rsv, self.tot = rsv, tot32
        self.data = rsv + nf * self.fatsz
        self.clusters = (tot32 - self.data) // self.spc
        if self.clusters < FAT32_MIN_CLUSTERS:
            raise DiskError("too few clusters for FAT32")
        f0 = vol[rsv * SECTOR:(rsv + self.fatsz) * SECTOR]
        f1 = vol[(rsv + self.fatsz) * SECTOR:(rsv + 2 * self.fatsz) * SECTOR]
        if f0 != f1:
            raise DiskError("the two FATs differ")
        if vol[6 * SECTOR:7 * SECTOR] != vol[0:SECTOR]:
            raise DiskError("backup boot sector differs")
        self.fat = struct.unpack_from(f"<{self.clusters + 2}I", f0, 0)
        self.free_hint, = struct.unpack_from("<I", vol, SECTOR + 488)

    def chain(self, c):
        seen = []
        while True:
            if not 2 <= c < self.clusters + 2 or c in seen:
                raise DiskError(f"broken cluster chain at {c}")
            seen.append(c)
            n = self.fat[c] & 0x0FFFFFFF
            if n >= 0x0FFFFFF8:
                return seen
            c = n

    def read(self, c, size=None):
        out = bytearray()
        cs = self.spc * SECTOR
        for cl in self.chain(c):
            off = (self.data + (cl - 2) * self.spc) * SECTOR
            out += self.vol[off:off + cs]
        return bytes(out if size is None else out[:size])

    def listdir(self, c):
        body = self.read(c)
        for i in range(0, len(body), 32):
            e = body[i:i + 32]
            if e[0] == 0:
                break
            if e[0] == 0xE5 or e[11] == 0x0F or e[11] & ATTR_VOLUME:
                continue
            name = e[:8].decode("ascii").rstrip()
            ext = e[8:11].decode("ascii").rstrip()
            hi, lo, size = struct.unpack_from("<H", e, 20)[0], struct.unpack_from("<H", e, 26)[0], struct.unpack_from("<I", e, 28)[0]
            yield (name + ("." + ext if ext else "")), e[11], (hi << 16) | lo, size

    def walk(self, c=None, prefix=""):
        for name, attr, cl, size in self.listdir(self.root if c is None else c):
            if name in (".", ".."):
                continue
            path = prefix + name
            if attr & ATTR_DIR:
                yield from self.walk(cl, path + "/")
            else:
                yield path, (self.read(cl, size) if cl else b"")

    def used_clusters(self):
        return sum(1 for v in self.fat[2:] if v & 0x0FFFFFFF)


def read_esp(img):
    _hdr, parts = read_gpt(img)
    esps = [p for p in parts if p["type"] == ESP_TYPE]
    if len(esps) != 1:
        raise DiskError(f"expected exactly one EFI System Partition, found {len(esps)}")
    p = esps[0]
    vol = img[p["first"] * SECTOR:(p["last"] + 1) * SECTOR]
    fs = Fat32(vol)
    hidden, = struct.unpack_from("<I", vol, 28)
    if hidden != p["first"]:
        raise DiskError("FAT hidden-sector count does not match the partition start")
    if fs.free_hint != fs.clusters - fs.used_clusters():
        raise DiskError("FSInfo free-cluster count is wrong")
    return p, fs


def verify(path, files):
    with open(path, "rb") as f:
        img = f.read()
    _p, fs = read_esp(img)
    got = dict(fs.walk())
    want = {"/".join(split_path(k)): v for k, v in files.items()}
    if set(got) != set(want):
        raise DiskError(f"ESP holds {sorted(got)}, expected {sorted(want)}")
    for k, v in want.items():
        if got[k] != v:
            raise DiskError(f"{k} on the ESP differs from its source")
    return sorted(got)


# ── CLI ─────────────────────────────────────────────────────────────────────


def _files_arg(specs):
    files = {}
    for spec in specs or []:
        dest, sep, src = spec.partition("=")
        if not sep or not dest or not src:
            raise DiskError(f"--file wants ESP/PATH=SOURCE, got {spec!r}")
        split_path(dest)
        with open(src, "rb") as f:
            files[dest] = f.read()
    return files


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("write", help="write a GPT disk with one FAT32 ESP")
    w.add_argument("--out", required=True)
    w.add_argument("--file", action="append", required=True, metavar="ESP/PATH=SOURCE")
    w.add_argument("--esp-mib", type=int, default=64)
    w.add_argument("--label", default="SEAGENT")
    v = sub.add_parser("verify", help="check a disk and compare the ESP with the given files")
    v.add_argument("disk")
    v.add_argument("--file", action="append", required=True, metavar="ESP/PATH=SOURCE")
    ls = sub.add_parser("list", help="print the GPT and the ESP's files")
    ls.add_argument("disk")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "write":
            info = write_disk(a.out, _files_arg(a.file), a.esp_mib, a.label)
            for k, val in info.items():
                print(f"{k}={val}")
        elif a.cmd == "verify":
            for p in verify(a.disk, _files_arg(a.file)):
                print(f"ok {p}")
        else:
            with open(a.disk, "rb") as f:
                img = f.read()
            p, fs = read_esp(img)
            print(f"esp lba {p['first']}-{p['last']} guid {p['guid']} clusters {fs.clusters} x {fs.spc * SECTOR} B")
            for path, data in fs.walk():
                print(f"{len(data):>10}  {path}  sha256 {hashlib.sha256(data).hexdigest()}")
    except (DiskError, OSError) as e:
        print(f"mkdisk: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
