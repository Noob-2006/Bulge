#!/usr/bin/env python3
"""Render ui/icon.svg (galaxy-navy rounded square, gold four-pointed star, four small stars) to the
icon files Tauri needs, with the standard library only (no cairo/Pillow/Inkscape needed):

  src-tauri/icons/{32x32,64x64,128x128,128x128@2x,icon}.png, icon.ico, icon.icns

The geometry below mirrors ui/icon.svg; if that file changes, change it here too (or use
`cargo tauri icon ../../ui/icon.svg`, which also writes the Android/iOS icon sets — see
scripts/icons.sh).
"""
import math
import os
import struct
import sys
import zlib

MASTER = 1024
SS = 2  # supersampling per axis for the shape masks

BG_STOPS = [(0.0, (0x2A, 0x41, 0x70)), (0.45, (0x0E, 0x16, 0x29)), (1.0, (0x04, 0x06, 0x0D))]
STAR_STOPS = [(0.0, (0xFF, 0xE9, 0xA3)), (0.55, (0xFF, 0xD6, 0x6B)), (1.0, (0xC9, 0x8A, 0x1B))]
SMALL = (0xFF, 0xD6, 0x6B)


def lerp_stops(stops, t):
    t = min(max(t, 0.0), 1.0)
    for (t0, c0), (t1, c1) in zip(stops, stops[1:]):
        if t <= t1:
            f = 0.0 if t1 == t0 else (t - t0) / (t1 - t0)
            return tuple(c0[i] + (c1[i] - c0[i]) * f for i in range(3))
    return stops[-1][1]


def cubic(p0, p1, p2, p3, n=24):
    out = []
    for i in range(1, n + 1):
        t = i / n
        a, b, c, d = (1 - t) ** 3, 3 * (1 - t) ** 2 * t, 3 * (1 - t) * t * t, t ** 3
        out.append((a * p0[0] + b * p1[0] + c * p2[0] + d * p3[0], a * p0[1] + b * p1[1] + c * p2[1] + d * p3[1]))
    return out


def star_polygon(cx, cy, s):
    """M0-100C8-30 30-8 100 0C30 8 8 30 0 100C-8 30-30 8-100 0C-30-8-8-30 0-100Z, scaled."""
    segs = [((0, -100), (8, -30), (30, -8), (100, 0)), ((100, 0), (30, 8), (8, 30), (0, 100)),
            ((0, 100), (-8, 30), (-30, 8), (-100, 0)), ((-100, 0), (-30, -8), (-8, -30), (0, -100))]
    pts = [(0, -100)]
    for seg in segs:
        pts += cubic(*seg)
    return [(cx + x * s, cy + y * s) for x, y in pts]


def fill_polygon(mask, w, poly):
    """Even-odd scanline fill into a bytearray mask of width w (rows = len(mask)//w)."""
    h = len(mask) // w
    ys = [p[1] for p in poly]
    y0, y1 = max(0, int(min(ys))), min(h - 1, int(max(ys)) + 1)
    edges = list(zip(poly, poly[1:] + poly[:1]))
    for y in range(y0, y1 + 1):
        sy = y + 0.5
        xs = []
        for (ax, ay), (bx, by) in edges:
            if (ay <= sy < by) or (by <= sy < ay):
                xs.append(ax + (sy - ay) * (bx - ax) / (by - ay))
        xs.sort()
        for a, b in zip(xs[::2], xs[1::2]):
            xa, xb = max(0, int(math.ceil(a - 0.5))), min(w, int(math.floor(b - 0.5)) + 1)
            if xb > xa:
                mask[y * w + xa:y * w + xb] = b"\x01" * (xb - xa)


def rounded_rect_mask(w, r):
    m = bytearray(w * w)
    for y in range(w):
        sy = y + 0.5
        if sy < r:
            dx = r - math.sqrt(max(0.0, r * r - (r - sy) ** 2))
        elif sy > w - r:
            dx = r - math.sqrt(max(0.0, r * r - (sy - (w - r)) ** 2))
        else:
            dx = 0.0
        a, b = int(round(dx)), int(round(w - dx))
        if b > a:
            m[y * w + a:y * w + b] = b"\x01" * (b - a)
    return m


def coverage(mask, w, n):
    """Downsample an (n*SS)^2 mask to n^2 coverage floats."""
    out = [0.0] * (n * n)
    inv = 1.0 / (SS * SS)
    for y in range(n):
        rows = [mask[(y * SS + k) * w:(y * SS + k + 1) * w] for k in range(SS)]
        for x in range(n):
            s = 0
            for r in rows:
                s += sum(r[x * SS:(x + 1) * SS])
            out[y * n + x] = s * inv
    return out


def render_master():
    n = MASTER
    w = n * SS
    k = w / 512.0  # svg units → mask pixels
    bg = coverage(rounded_rect_mask(w, 112 * k), w, n)
    big = bytearray(w * w)
    fill_polygon(big, w, star_polygon(256 * k, 256 * k, 1.75 * k))
    big = coverage(big, w, n)
    small = bytearray(w * w)
    for cx, cy in [(92, 92), (420, 92), (92, 420), (420, 420)]:
        fill_polygon(small, w, star_polygon(cx * k, cy * k, 0.22 * k))
    small = coverage(small, w, n)

    px = bytearray(n * n * 4)
    u = n / 512.0
    # bg gradient: objectBoundingBox cx=30% cy=15% r=95%
    bcx, bcy, br = 0.30 * n, 0.15 * n, 0.95 * n
    # star gradient: bbox of the big star (256±175), cx=50% cy=45% r=60%
    sx0, sw = (256 - 175) * u, 350 * u
    scx, scy, sr = sx0 + 0.5 * sw, sx0 + 0.45 * sw, 0.6 * sw
    for y in range(n):
        for x in range(n):
            i = y * n + x
            a = bg[i]
            if a <= 0.0:
                continue
            fx, fy = x + 0.5, y + 0.5
            col = lerp_stops(BG_STOPS, math.hypot(fx - bcx, fy - bcy) / br)
            cs = small[i] * 0.85
            if cs > 0:
                col = tuple(col[j] * (1 - cs) + SMALL[j] * cs for j in range(3))
            cb = big[i]
            if cb > 0:
                g = lerp_stops(STAR_STOPS, math.hypot(fx - scx, fy - scy) / sr)
                col = tuple(col[j] * (1 - cb) + g[j] * cb for j in range(3))
            o = i * 4
            px[o:o + 4] = bytes((int(col[0] + 0.5), int(col[1] + 0.5), int(col[2] + 0.5), int(a * 255 + 0.5)))
    return px


def downscale(px, n, m):
    """Box-filter an n×n RGBA image to m×m (n divisible by m), premultiplied."""
    f = n // m
    out = bytearray(m * m * 4)
    area = f * f
    for y in range(m):
        for x in range(m):
            r = g = b = a = 0
            for yy in range(y * f, (y + 1) * f):
                o = (yy * n + x * f) * 4
                for xx in range(f):
                    al = px[o + 3]
                    r += px[o] * al
                    g += px[o + 1] * al
                    b += px[o + 2] * al
                    a += al
                    o += 4
            q = (y * m + x) * 4
            if a:
                out[q:q + 4] = bytes((r // a, g // a, b // a, a // area))
    return out


def png(px, n):
    raw = b"".join(b"\x00" + bytes(px[y * n * 4:(y + 1) * n * 4]) for y in range(n))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def ico(pngs):
    """ICO with PNG-compressed entries (Windows Vista+)."""
    head = struct.pack("<HHH", 0, 1, len(pngs))
    off = 6 + 16 * len(pngs)
    dirs, blobs = b"", b""
    for n, data in pngs:
        dirs += struct.pack("<BBBBHHII", n % 256, n % 256, 0, 0, 1, 32, len(data), off + len(blobs))
        blobs += data
    return head + dirs + blobs


def icns(entries):
    body = b"".join(t + struct.pack(">I", 8 + len(d)) + d for t, d in entries)
    return b"icns" + struct.pack(">I", 8 + len(body)) + body


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "src-tauri", "icons")
    os.makedirs(out, exist_ok=True)
    master = render_master()
    sizes = {}
    for m in (16, 32, 64, 128, 256, 512, 1024):
        sizes[m] = png(master if m == MASTER else downscale(master, MASTER, m), m)
    files = {"32x32.png": 32, "64x64.png": 64, "128x128.png": 128, "128x128@2x.png": 256, "icon.png": 512}
    for name, m in files.items():
        with open(os.path.join(out, name), "wb") as f:
            f.write(sizes[m])
    with open(os.path.join(out, "icon.ico"), "wb") as f:
        f.write(ico([(m, sizes[m]) for m in (16, 32, 64, 128, 256)]))
    with open(os.path.join(out, "icon.icns"), "wb") as f:
        f.write(icns([(b"icp4", sizes[16]), (b"icp5", sizes[32]), (b"icp6", sizes[64]), (b"ic07", sizes[128]), (b"ic08", sizes[256]), (b"ic09", sizes[512]), (b"ic10", sizes[1024]), (b"ic11", sizes[32]), (b"ic12", sizes[64]), (b"ic13", sizes[256]), (b"ic14", sizes[512])]))
    print("wrote", ", ".join(sorted(list(files) + ["icon.ico", "icon.icns"])), "to", os.path.normpath(out))


if __name__ == "__main__":
    main()
