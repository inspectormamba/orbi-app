from PIL import Image, ImageDraw
def icon(size):
    s = size / 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, size - 1, size - 1), radius=int(14 * s), fill=(31, 111, 235, 255))
    w = max(2, int(5 * s))
    for r in (25, 15):  # arcs centred at (32, 47.5) like the SVG
        cx, cy = 32 * s, 47.5 * s
        d.arc((cx - r * 1.44 * s, cy - r * 1.44 * s, cx + r * 1.44 * s, cy + r * 1.44 * s), 225, 315, fill="white", width=w)
    d.ellipse((27.5 * s, 40.5 * s, 36.5 * s, 49.5 * s), fill="white")
    return img
for n in (180, 192, 512):
    icon(n).save(f"web/icon-{n}.png")
print("ok")
