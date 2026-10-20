"""Generates the MSIX tile/logo PNGs and the .exe icon from one drawn master image.

Run once after changing the design:  python packaging/msix/make_assets.py
Requires Pillow (not needed for normal builds; the PNGs are committed).
"""

from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent
OUT = HERE / "Assets"
NAVY = (18, 52, 96, 255)
ACCENT = (255, 176, 32, 255)
WHITE = (255, 255, 255, 255)


def master(size: int = 1024) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    s = size / 1024
    # Shield
    shield = [(512, 70), (880, 200), (860, 560), (512, 960), (164, 560), (144, 200)]
    d.polygon([(x * s, y * s) for x, y in shield], fill=NAVY)
    # Envelope
    box = (300 * s, 330 * s, 724 * s, 610 * s)
    d.rectangle(box, fill=WHITE)
    d.line([(300 * s, 330 * s), (512 * s, 480 * s), (724 * s, 330 * s)], fill=NAVY, width=int(22 * s))
    # Magnifier over the envelope corner
    cx, cy, r = 640 * s, 600 * s, 120 * s
    d.ellipse((cx - r, cy - r, cx + r, cy + r), outline=ACCENT, width=int(44 * s))
    d.line([(cx + r * 0.7, cy + r * 0.7), (cx + r * 1.65, cy + r * 1.65)], fill=ACCENT, width=int(60 * s))
    return img


def fit(img: Image.Image, w: int, h: int, scale: float = 0.8) -> Image.Image:
    side = int(min(w, h) * scale)
    icon = img.resize((side, side), Image.LANCZOS)
    canvas = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    canvas.paste(icon, ((w - side) // 2, (h - side) // 2), icon)
    return canvas


def main() -> None:
    OUT.mkdir(exist_ok=True)
    m = master()
    fit(m, 50, 50, 0.9).save(OUT / "StoreLogo.png")
    fit(m, 44, 44, 0.9).save(OUT / "Square44x44Logo.png")
    for t in (16, 24, 32, 48, 256):
        icon = fit(m, t, t, 1.0)
        icon.save(OUT / f"Square44x44Logo.targetsize-{t}.png")
        icon.save(OUT / f"Square44x44Logo.targetsize-{t}_altform-unplated.png")
    fit(m, 150, 150, 0.66).save(OUT / "Square150x150Logo.png")
    fit(m, 310, 150, 0.66).save(OUT / "Wide310x150Logo.png")
    fit(m, 300, 300, 0.9).save(OUT / "StoreListing300x300.png")
    m.save(HERE / "app.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])


if __name__ == "__main__":
    main()
