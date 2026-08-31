"""Build the two-shape Windows application icon from the generated source art."""

from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "assets" / "brand" / "clipferry-icon-generated.png"
PNG_OUTPUT = ROOT / "assets" / "brand" / "clipferry-icon-512.png"
ICO_OUTPUT = ROOT / "assets" / "brand" / "clipferry.ico"
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256)
BACKGROUND_COLOR = (1, 13, 62)
WHITE_SHAPE_COLOR = (254, 254, 254)


def make_transparent_icon(source: Image.Image) -> Image.Image:
    image = source.convert("RGB").resize((512, 512), Image.Resampling.LANCZOS)
    output = Image.new("RGBA", image.size, (0, 0, 0, 0))
    source_pixels = image.load()
    output_pixels = output.load()

    # Only the white shape on the left and the blue shape on the right belong
    # to the application icon. The generated white canvas and navy rounded
    # square are both deliberately discarded.
    for y in range(80, 432):
        for x in range(80, 440):
            red, green, blue = source_pixels[x, y]
            if x < 264 and red > 12 and green > 20:
                alpha = (red - BACKGROUND_COLOR[0]) / (
                    WHITE_SHAPE_COLOR[0] - BACKGROUND_COLOR[0]
                )
                alpha = max(0.0, min(1.0, alpha))
                if alpha > 0.025:
                    output_pixels[x, y] = (*WHITE_SHAPE_COLOR, round(alpha * 255))
            elif x >= 264 and green > 20 and blue > 75 and blue > red * 1.25:
                alpha = (green - BACKGROUND_COLOR[1]) / (123 - BACKGROUND_COLOR[1])
                alpha = max(0.0, min(1.0, alpha))
                if alpha <= 0.025:
                    continue

                # Undo the navy-background blend at anti-aliased edge pixels
                # so the isolated blue shape has no dark fringe.
                foreground = []
                for channel, background in zip(
                    (red, green, blue), BACKGROUND_COLOR, strict=True
                ):
                    value = (channel - background * (1 - alpha)) / alpha
                    foreground.append(max(0, min(255, round(value))))
                output_pixels[x, y] = (*foreground, round(alpha * 255))

    return output


def main() -> None:
    icon = make_transparent_icon(Image.open(SOURCE))
    icon.save(PNG_OUTPUT)
    icon.save(ICO_OUTPUT, format="ICO", sizes=[(size, size) for size in ICON_SIZES])


if __name__ == "__main__":
    main()
