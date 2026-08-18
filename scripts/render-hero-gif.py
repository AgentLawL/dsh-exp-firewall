"""Render the deterministic README lifecycle animation from verified text."""

from pathlib import Path
import sys

from PIL import Image, ImageDraw, ImageFont


WIDTH, HEIGHT = 960, 504
LINES = [
    ("A/call-a", "failure:FS_NOT_FOUND", "-> suspected (1 supporter)"),
    ("B/call-b", "failure:FS_NOT_FOUND", "-> corroborated (2 supporters)"),
    ("C/call-c", "decision=deny", "reason=corroborated"),
    ("FS/event", "absent -> present:v2", "corroborated -> stale"),
    ("C/call-v", "decision=verify", "evidence-changed · lease=granted"),
    ("C/call-v", "outcome=success", "verifying -> resolved"),
]


def font_path() -> str:
    candidates = (
        "/System/Library/Fonts/Menlo.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf",
    )
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    raise RuntimeError("no supported monospace font found")


def render(visible: int, complete: bool) -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT), "#101820")
    draw = ImageDraw.Draw(image)
    regular = ImageFont.truetype(font_path(), 18)
    title = ImageFont.truetype(font_path(), 24)
    draw.rounded_rectangle((24, 22, 936, 482), radius=14, fill="#0d141c", outline="#273444", width=2)
    for x, color in ((53, "#ff6b6b"), (74, "#ffd166"), (95, "#6ee7b7")):
        draw.ellipse((x - 6, 43, x + 6, 55), fill=color)
    draw.text((49, 70), "EXP FIREWALL — EVIDENCE-GATED RECOVERY", font=title, fill="#6ee7b7")
    draw.text((49, 107), "redacted preview=read /target · raw output omitted", font=regular, fill="#718096")
    for index, (actor, action, result) in enumerate(LINES[:visible]):
        y = 145 + index * 43
        draw.text((49, y), actor, font=regular, fill="#8bd5ff")
        draw.text((160, y), action, font=regular, fill="#e6edf3")
        draw.text((448, y), result, font=regular, fill="#d7b7ff")
    footer = "OLD EXPERIENCE REVOKED · EXECUTION RECOVERED" if complete else "policy trace |"
    draw.text((49, 444), footer, font=title if complete else regular, fill="#6ee7b7" if complete else "#718096")
    return image


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: render-hero-gif.py <output.gif>")
    output = Path(sys.argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    frames = [render(min(index, len(LINES)), index >= len(LINES)) for index in range(8)]
    frames[0].save(
        output,
        save_all=True,
        append_images=frames[1:],
        duration=1000,
        loop=0,
        disposal=2,
        optimize=False,
    )


if __name__ == "__main__":
    main()
