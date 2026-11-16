"""Draws the add-on's icons (a server with three log lines): static/appIcon*.png."""
import os
import sys
from PIL import Image, ImageDraw

BLUE = (31, 78, 121, 255)


def draw(size, background):
    s = size * 8
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    fg = (255, 255, 255, 255)
    if background:
        d.rounded_rectangle([0, 0, s - 1, s - 1], radius=s // 6, fill=BLUE)
    else:
        fg = BLUE
    w = max(2, s // 24)
    # three stacked server units, each with a status light and a log line
    top, unit, gap = s * 0.18, s * 0.19, s * 0.04
    for i in range(3):
        y0 = top + i * (unit + gap)
        d.rounded_rectangle([s * 0.16, y0, s * 0.84, y0 + unit], radius=s // 30, outline=fg, width=w)
        r = unit * 0.16
        cx, cy = s * 0.27, y0 + unit / 2
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fg)
        d.rounded_rectangle([s * 0.38, cy - w * 0.6, s * (0.74 - 0.08 * i), cy + w * 0.6], radius=w // 2, fill=fg)
    return img.resize((size, size), Image.LANCZOS)


def main(folder):
    os.makedirs(folder, exist_ok=True)
    for name, size, bg in (("appIcon.png", 36, True), ("appIcon_2x.png", 72, True),
                           ("appIconAlt.png", 36, False), ("appIconAlt_2x.png", 72, False)):
        draw(size, bg).save(os.path.join(folder, name), optimize=True)


if __name__ == "__main__":
    main(sys.argv[1])
