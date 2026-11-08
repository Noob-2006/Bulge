#!/usr/bin/env python3
"""Unit tests for mkdisk.py.   python3 -I packaging/vm/test_mkdisk.py

The checks below parse the image with code written against the on-disk formats
(UEFI spec 2.10 §5.3 for GPT, fatgen103 for FAT32), not only through
mkdisk.read_esp, so a mistake shared by the writer and its own reader still
shows up as a wrong offset or CRC here.
"""

import importlib.util
import os
import struct
import sys
import tempfile
import unittest
import uuid
import zlib

sys.dont_write_bytecode = True  # no __pycache__ in the source tree
HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("mkdisk", os.path.join(HERE, "mkdisk.py"))
mkdisk = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mkdisk)

S = 512


def kernel_like(n, seed=1):
    """`n` bytes that start like a PE image (MZ ... PE\\0\\0) and are not compressible."""
    out = bytearray(b"MZ" + b"\0" * 58 + struct.pack("<I", 64) + b"PE\0\0")
    x = seed
    while len(out) < n:
        x = (x * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out += x.to_bytes(8, "little")
    return bytes(out[:n])


class Image:
    def __init__(self, files, esp_mib=64):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "disk.raw")
        self.info = mkdisk.write_disk(self.path, files, esp_mib)
        with open(self.path, "rb") as f:
            self.img = f.read()

    def close(self):
        self.tmp.cleanup()


class GptLayout(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.efi = kernel_like(5 * 1024 * 1024 + 123)
        cls.d = Image({"EFI/BOOT/BOOTX64.EFI": cls.efi})

    @classmethod
    def tearDownClass(cls):
        cls.d.close()

    def test_size_is_esp_plus_two_mib(self):
        self.assertEqual(len(self.d.img), (64 + 2) * 1024 * 1024)
        self.assertEqual(self.d.info["size"], len(self.d.img))
        self.assertFalse(os.path.exists(self.d.path + ".part"))

    def test_protective_mbr(self):
        img = self.d.img
        self.assertEqual(img[510:512], b"\x55\xaa")
        status, ptype, start, count = img[446], img[450], *struct.unpack_from("<II", img, 454)
        self.assertEqual((status, ptype, start), (0, 0xEE, 1))
        self.assertEqual(count, len(img) // S - 1)
        self.assertEqual(img[462:510], b"\0" * 48, "only one MBR entry")

    def _header(self, lba):
        h = self.d.img[lba * S:lba * S + 92]
        crc = struct.unpack_from("<I", h, 16)[0]
        zeroed = h[:16] + b"\0\0\0\0" + h[20:]
        self.assertEqual(zlib.crc32(zeroed) & 0xFFFFFFFF, crc, f"header CRC at LBA {lba}")
        self.assertEqual(h[:8], b"EFI PART")
        self.assertEqual(struct.unpack_from("<II", h, 8), (0x00010000, 92))
        return struct.unpack_from("<QQQQ16sQIII", h, 24)

    def test_primary_and_backup_headers(self):
        last = len(self.d.img) // S - 1
        cur, alt, fu, lu, guid, elba, n, esz, ecrc = self._header(1)
        self.assertEqual((cur, alt, fu, lu, elba, n, esz), (1, last, 34, last - 33, 2, 128, 128))
        bcur, balt, bfu, blu, bguid, belba, *_ = self._header(last)
        self.assertEqual((bcur, balt, bfu, blu, bguid, belba), (last, 1, fu, lu, guid, last - 32))
        ents = self.d.img[2 * S:34 * S]
        self.assertEqual(zlib.crc32(ents) & 0xFFFFFFFF, ecrc)
        self.assertEqual(self.d.img[(last - 32) * S:last * S], ents)
        self.assertEqual(str(uuid.UUID(bytes_le=guid)), self.d.info["disk_guid"])

    def test_single_esp_entry_aligned(self):
        e = self.d.img[2 * S:2 * S + 128]
        self.assertEqual(uuid.UUID(bytes_le=e[:16]), uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"))
        first, last = struct.unpack_from("<QQ", e, 32)
        self.assertEqual((first, last), (2048, 2048 + 64 * 2048 - 1))
        self.assertEqual(e[56:56 + 40].decode("utf-16-le"), "EFI System Partition")
        self.assertEqual(self.d.img[2 * S + 128:34 * S], b"\0" * (32 * S - 128), "no other entries")

    def test_fat32_boot_sector_by_the_spec(self):
        v = self.d.img[2048 * S:]
        self.assertEqual(v[0], 0xEB)
        bps, spc, rsv, nfat, rootent, tot16, media, fz16 = struct.unpack_from("<HBHBHHBH", v, 11)
        hidden, tot32, fz32 = struct.unpack_from("<III", v, 28)
        rootclus, fsinfo, bkboot = struct.unpack_from("<IHH", v, 44)
        self.assertEqual((bps, rsv, nfat, rootent, tot16, media, fz16), (512, 32, 2, 0, 0, 0xF8, 0))
        self.assertEqual((hidden, tot32, rootclus, fsinfo, bkboot), (2048, 64 * 2048, 2, 1, 6))
        self.assertEqual(v[66], 0x29)
        self.assertEqual(v[82:90], b"FAT32   ")
        clusters = (tot32 - rsv - nfat * fz32) // spc
        self.assertGreaterEqual(clusters, 65525, "FAT32 by cluster count, not just by label")
        self.assertGreaterEqual(fz32 * 512 // 4, clusters + 2, "the FAT covers every cluster")
        self.assertEqual(struct.unpack_from("<I", v, 512)[0], 0x41615252)
        self.assertEqual(struct.unpack_from("<I", v, 512 + 484)[0], 0x61417272)
        self.assertEqual(v[6 * S:9 * S], v[0:3 * S], "backup boot record")
        fat = struct.unpack_from("<4I", v, rsv * S)
        self.assertEqual(fat[0] & 0x0FFFFFFF, 0x0FFFFFF8)
        self.assertEqual(v[rsv * S:(rsv + fz32) * S], v[(rsv + fz32) * S:(rsv + 2 * fz32) * S], "FAT copies")

    def test_file_reads_back_through_an_independent_walk(self):
        v = self.d.img[2048 * S:]
        spc = v[13]
        rsv, = struct.unpack_from("<H", v, 14)
        fz32, = struct.unpack_from("<I", v, 36)
        data = rsv + 2 * fz32

        def clus(c):
            return v[(data + (c - 2) * spc) * S:(data + (c - 1) * spc) * S]

        def fatent(c):
            return struct.unpack_from("<I", v, rsv * S + 4 * c)[0] & 0x0FFFFFFF

        def find(dir_cluster, name11):
            body = clus(dir_cluster)
            for i in range(0, len(body), 32):
                if body[i:i + 11] == name11:
                    return (struct.unpack_from("<H", body, i + 20)[0] << 16) | struct.unpack_from("<H", body, i + 26)[0], struct.unpack_from("<I", body, i + 28)[0], body[i + 11]
            self.fail(f"{name11!r} not found")

        efi, _, a1 = find(2, b"EFI        ")
        boot, _, a2 = find(efi, b"BOOT       ")
        f, size, a3 = find(boot, b"BOOTX64 EFI")
        self.assertEqual((a1, a2, a3 & 0x10), (0x10, 0x10, 0))
        self.assertEqual(size, len(self.efi))
        out = bytearray()
        c = f
        while c < 0x0FFFFFF8:
            out += clus(c)
            c = fatent(c)
        self.assertEqual(bytes(out[:size]), self.efi)
        self.assertEqual(mkdisk.verify(self.d.path, {"EFI/BOOT/BOOTX64.EFI": self.efi}), ["EFI/BOOT/BOOTX64.EFI"])

    def test_verify_catches_a_flipped_byte_and_a_wrong_file(self):
        with self.assertRaises(mkdisk.DiskError):
            mkdisk.verify(self.d.path, {"EFI/BOOT/BOOTX64.EFI": self.efi[:-1] + b"x"})
        with self.assertRaises(mkdisk.DiskError):
            mkdisk.verify(self.d.path, {"EFI/BOOT/BOOTAA64.EFI": self.efi})
        bad = bytearray(self.d.img)
        bad[1 * S + 40] ^= 1  # inside the primary header
        p = os.path.join(self.d.tmp.name, "bad.raw")
        with open(p, "wb") as f:
            f.write(bad)
        with self.assertRaisesRegex(mkdisk.DiskError, "bad GPT header"):
            mkdisk.verify(p, {"EFI/BOOT/BOOTX64.EFI": self.efi})


class Behaviour(unittest.TestCase):
    def test_deterministic_and_content_addressed(self):
        a, b, c = Image({"EFI/BOOT/BOOTAA64.EFI": kernel_like(1000)}, 40), Image({"EFI/BOOT/BOOTAA64.EFI": kernel_like(1000)}, 40), Image({"EFI/BOOT/BOOTAA64.EFI": kernel_like(1000, 2)}, 40)
        try:
            self.assertEqual(a.img, b.img)
            self.assertNotEqual(a.info["disk_guid"], c.info["disk_guid"])
            self.assertEqual(uuid.UUID(a.info["disk_guid"]).version, 4)
        finally:
            for x in (a, b, c):
                x.close()

    def test_several_files_and_an_empty_one(self):
        files = {"EFI/BOOT/BOOTX64.EFI": kernel_like(70000), "SEAGENT/CMDLINE.TXT": b"console=ttyS0\n", "SEAGENT/EMPTY": b""}
        d = Image(files, 34)
        try:
            self.assertEqual(mkdisk.verify(d.path, files), sorted(files))
        finally:
            d.close()

    def test_refuses_long_names_small_esp_and_overflow(self):
        for bad in ("efi/boot/bootx64.efi", "EFI/BOOT/TOOLONGNAME.EFI", "A/B.TOOL", "A/../B", ""):
            with self.assertRaises(mkdisk.DiskError, msg=bad):
                mkdisk.split_path(bad)
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(mkdisk.DiskError):
                mkdisk.write_disk(os.path.join(t, "d"), {"A.EFI": b"x"}, 16)
            with self.assertRaisesRegex(mkdisk.DiskError, "full"):
                mkdisk.write_disk(os.path.join(t, "d"), {"A.EFI": b"x" * (40 * 1024 * 1024)}, 34)
            self.assertFalse(os.path.exists(os.path.join(t, "d")))

    def test_cli_write_verify_list(self):
        with tempfile.TemporaryDirectory() as t:
            src = os.path.join(t, "Image")
            with open(src, "wb") as f:
                f.write(kernel_like(4096))
            disk = os.path.join(t, "disk.raw")
            spec = f"EFI/BOOT/BOOTAA64.EFI={src}"
            self.assertEqual(mkdisk.main(["write", "--out", disk, "--file", spec, "--esp-mib", "34"]), 0)
            self.assertEqual(mkdisk.main(["verify", disk, "--file", spec]), 0)
            self.assertEqual(mkdisk.main(["list", disk]), 0)
            self.assertEqual(mkdisk.main(["verify", disk, "--file", f"EFI/BOOT/BOOTX64.EFI={src}"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
