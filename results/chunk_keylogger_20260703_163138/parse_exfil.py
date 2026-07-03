#!/usr/bin/env python3
"""Parse exfil .bin blob into individual files per section.

Extracts text sections as .txt and the screenshot BMP as .png (if Pillow
is available) or .bmp.

Usage:
    python3 parse_exfil.py exfil_20260703_123520.bin [output_dir]
"""

import os
import re
import struct
import sys


def parse(blob_path, out_dir=None):
    data = open(blob_path, "rb").read()
    if not out_dir:
        base = os.path.splitext(os.path.basename(blob_path))[0]
        out_dir = base + "_parsed"
    os.makedirs(out_dir, exist_ok=True)

    sections = []
    for m in re.finditer(b"=== ([A-Z_ ]+) ===", data):
        sections.append((m.start(), m.group(1).decode().strip()))
    sections.append((len(data), "END"))

    for i in range(len(sections) - 1):
        start, name = sections[i]
        end = sections[i + 1][0]
        slug = name.lower().replace(" ", "_")
        chunk = data[start:end]

        if name == "SCREENSHOT":
            # Find the real BMP header — skip "BM" that appears in text like "BMP (N bytes)"
            bm_idx = 0
            real_bmp = -1
            while bm_idx < len(chunk) - 14:
                bm_idx = chunk.find(b"BM", bm_idx)
                if bm_idx < 0:
                    break
                off = struct.unpack_from("<I", chunk, bm_idx + 10)[0]
                if off == 54:  # standard BITMAPFILEHEADER + BITMAPINFOHEADER
                    real_bmp = bm_idx
                    break
                bm_idx += 2
            if real_bmp >= 0:
                bmp_data = chunk[real_bmp:]
                claimed = struct.unpack_from("<I", bmp_data, 2)[0]
                bmp_data = bmp_data[:claimed]
                bmp_path = os.path.join(out_dir, "screenshot.bmp")
                with open(bmp_path, "wb") as f:
                    f.write(bmp_data)
                try:
                    from PIL import Image
                    img = Image.open(bmp_path)
                    png_path = os.path.join(out_dir, "screenshot.png")
                    img.save(png_path, "PNG")
                    os.remove(bmp_path)
                    print(f"  screenshot.png  ({img.size[0]}x{img.size[1]})")
                except ImportError:
                    print(f"  screenshot.bmp  (install Pillow for PNG conversion)")
            else:
                txt_path = os.path.join(out_dir, f"{slug}.txt")
                with open(txt_path, "w") as f:
                    f.write(chunk.decode("utf-8", errors="replace"))
                print(f"  {slug}.txt  (no BMP data — likely skipped)")
        elif name == "BROWSER DATA":
            txt_path = os.path.join(out_dir, f"{slug}.txt")
            with open(txt_path, "wb") as f:
                f.write(chunk)
            sqlite_offsets = [m.start() for m in re.finditer(b"SQLite format 3", chunk)]
            for j, off in enumerate(sqlite_offsets):
                db_data = chunk[off:]
                if j + 1 < len(sqlite_offsets):
                    db_data = chunk[off:sqlite_offsets[j + 1]]
                db_path = os.path.join(out_dir, f"browser_db_{j}.sqlite")
                with open(db_path, "wb") as f:
                    f.write(db_data)
            print(f"  {slug}.txt  ({len(chunk):,} bytes, {len(sqlite_offsets)} SQLite DBs extracted)")
        else:
            text = chunk.decode("utf-8", errors="replace")
            txt_path = os.path.join(out_dir, f"{slug}.txt")
            with open(txt_path, "w") as f:
                f.write(text)
            lines = len(text.strip().splitlines())
            print(f"  {slug}.txt  ({lines} lines)")

    print(f"\nParsed {len(sections)-1} sections -> {out_dir}/")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <exfil.bin> [output_dir]")
        sys.exit(1)
    parse(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
