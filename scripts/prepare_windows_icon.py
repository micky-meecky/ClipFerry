"""Build the transparent Windows application icon from the generated source art."""

from collections.abc import Iterable
from pathlib import Path

from PIL import Image, ImageChops, ImageFilter


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "assets" / "brand" / "clipferry-icon-generated.png"
PNG_OUTPUT = ROOT / "assets" / "brand" / "clipferry-icon-512.png"
ICO_OUTPUT = ROOT / "assets" / "brand" / "clipferry.ico"
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256)
EDGE_COLOR = (1, 13, 62)


def content_spans(image: Image.Image, threshold: int = 180) -> Iterable[tuple[int, int, int]]:
    pixels = image.convert("RGB").load()
    for y in range(image.height):
        xs = [x for x in range(image.width) if min(pixels[x, y]) < threshold]
        if xs:
            yield y, min(xs), max(xs)


def make_transparent_icon(source: Image.Image) -> Image.Image:
    image = source.convert("RGBA").resize((512, 512), Image.Resampling.LANCZOS)
    mask = Image.new("L", image.size, 0)
    mask_pixels = mask.load()

    # The generated artwork has a white canvas. Fill between the dark outer
    # silhouette on every row so white details inside the logo remain opaque.
    for y, left, right in content_spans(image):
        for x in range(left, right + 1):
            mask_pixels[x, y] = 255

    # Repaint only the outer edge with the logo's navy color. This avoids a
    # white fringe from the original canvas when Windows downsamples the icon.
    eroded = mask.filter(ImageFilter.MinFilter(7))
    edge = ImageChops.subtract(mask, eroded)
    edge_pixels = edge.load()
    output_pixels = image.load()
    for y in range(image.height):
        for x in range(image.width):
            if mask_pixels[x, y] == 0:
                output_pixels[x, y] = (*EDGE_COLOR, 0)
            elif edge_pixels[x, y]:
                output_pixels[x, y] = (*EDGE_COLOR, 255)

    image.putalpha(mask)
    return image


def main() -> None:
    icon = make_transparent_icon(Image.open(SOURCE))
    icon.save(PNG_OUTPUT)
    icon.save(ICO_OUTPUT, format="ICO", sizes=[(size, size) for size in ICON_SIZES])


if __name__ == "__main__":
    main()
