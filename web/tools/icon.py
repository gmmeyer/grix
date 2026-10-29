"""grix's icon, from its 16x16 pixel map: favicon.svg, favicon-32.png,
favicon.ico (16, 32 and 48) and apple-touch-icon.png (180, square: iOS
rounds it), into DIR. No dependencies.

    python3 -I icon.py DIR
"""

import struct
import sys
import zlib

# The wordmark's g and its cursor (grix_), on GitHub's dark.
TILE = "#0d1117"
COLOURS = {"W": "#f0f6fc", "B": "#4493f8"}
PIXELS = [
    "................",
    "................",
    "................",
    "....WWWWWW......",
    "...WWWWWWW......",
    "...WW...WW......",
    "...WW...WW......",
    "...WW...WW......",
    "...WWWWWWW......",
    "....WWWWWW......",
    "........WW......",
    "...WWWWWWW.BBBB.",
    "....WWWWW..BBBB.",
    "................",
    "................",
    "................",
]
RADIUS = 3  # the tile's corners, in pixels of the map


def rgb(hex_):
    return tuple(int(hex_[i:i + 2], 16) for i in (1, 3, 5))


def svg():
    out = ['<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" shape-rendering="crispEdges">',
           f'<rect width="16" height="16" rx="{RADIUS}" fill="{TILE}"/>']
    for y, row in enumerate(PIXELS):
        x = 0
        while x < 16:
            if row[x] == ".":
                x += 1
                continue
            end = x
            while end < 16 and row[end] == row[x]:
                end += 1
            out.append(f'<rect x="{x}" y="{y}" width="{end - x}" height="1" fill="{COLOURS[row[x]]}"/>')
            x = end
    return "".join(out) + "</svg>\n"


def raster(size, rounded=True):
    """RGBA rows: each map pixel a block, the tile's corners antialiased."""
    scale = size / 16
    r = RADIUS * scale
    rows = []
    for py in range(size):
        row = bytearray()
        for px in range(size):
            ch = PIXELS[min(15, int(py / scale))][min(15, int(px / scale))]
            colour = rgb(COLOURS[ch]) if ch != "." else rgb(TILE)
            alpha = 255
            if rounded:
                # Coverage of this pixel by the rounded tile, 4x4 samples.
                inside = 0
                for sy in range(4):
                    for sx in range(4):
                        x, y = px + (sx + .5) / 4, py + (sy + .5) / 4
                        cx = min(max(x, r), size - r)
                        cy = min(max(y, r), size - r)
                        inside += (x - cx) ** 2 + (y - cy) ** 2 <= r * r
                alpha = round(255 * inside / 16)
            row += bytes(colour) + bytes([alpha])
        rows.append(bytes(row))
    return rows


def png(rows):
    size = len(rows)

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    raw = b"".join(b"\0" + row for row in rows)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def ico(images):
    """An .ico of PNG images (Vista and later read those)."""
    head = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, data = b"", b""
    for size, blob in images:
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(blob), offset + len(data))
        data += blob
    return head + entries + data


def main(out):
    assert len(PIXELS) == 16 and all(len(row) == 16 for row in PIXELS)
    with open(f"{out}/favicon.svg", "w") as f:
        f.write(svg())
    with open(f"{out}/favicon-32.png", "wb") as f:
        f.write(png(raster(32)))
    with open(f"{out}/favicon.ico", "wb") as f:
        f.write(ico([(s, png(raster(s))) for s in (16, 32, 48)]))
    # Full-bleed for iOS, which rounds it itself: 176 for whole pixels, then
    # 2 more of the tile around it.
    inner = raster(176, rounded=False)
    pad = bytes(rgb(TILE)) + b"\xff"
    rows = [pad * 180] * 2 + [pad * 2 + row + pad * 2 for row in inner] + [pad * 180] * 2
    with open(f"{out}/apple-touch-icon.png", "wb") as f:
        f.write(png(rows))


if __name__ == "__main__":
    main(sys.argv[1])
