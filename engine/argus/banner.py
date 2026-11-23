"""ARGUS startup banner. by HaiND from the Post and Telecommunication Institute of Technology"""
from __future__ import annotations

import os
import sys

ASCII_LOGO = r"""
     _     ____    ____  _   _  ____
    / \   |  _ \  / ___|| | | |/ ___|
   / _ \  | |_) || |  _ | | | |\___ \
  / ___ \ |  _ < | |_| || |_| | ___) |
 /_/   \_\|_| \_\ \____| \___/ |____/
"""
BLOCK_LOGO = [
    " █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗",
    "██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝",
    "███████║██████╔╝██║  ███╗██║   ██║███████╗",
    "██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║",
    "██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║",
    "╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝",
]
LOGO = "\n" + "\n".join(BLOCK_LOGO) + "\n"
GRADIENT = [(0, 229, 255), (0, 200, 255), (0, 170, 250), (30, 140, 245), (60, 110, 235), (90, 85, 220)]

TAGLINE = "  defensive threat hunting  |  detect-only  |  MITRE ATT&CK"
SIGNATURE_LINE = "  by HaiND from the Post and Telecommunication Institute of Technology"


def _frame(line: str) -> list[str]:
    w = len(line) + 4
    return ["  ╭" + "─" * (w - 2) + "╮", "  │ " + line + " │", "  ╰" + "─" * (w - 2) + "╯"]


def text(version: str = "", ascii_only: bool = False) -> str:
    v = f"  v{version}" if version else ""
    if ascii_only:
        return f"{ASCII_LOGO.rstrip()}\n{TAGLINE}{v}\n{SIGNATURE_LINE}\n"
    body = [" " + l for l in BLOCK_LOGO]
    return "\n" + "\n".join(body + ["", f"   {TAGLINE.strip()}{v}"] + _frame(SIGNATURE_LINE.strip())) + "\n"


def _can_encode(stream, sample: str) -> bool:
    enc = getattr(stream, "encoding", None) or "ascii"
    try:
        sample.encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def show(version: str = "", stream=None) -> None:
    """Print to stderr (keeps JSON on stdout clean). Disable with ARGUS_NO_BANNER=1."""
    if os.environ.get("ARGUS_NO_BANNER") == "1":
        return
    stream = stream or sys.stderr
    unicode_ok = _can_encode(stream, "█╗╚═╭─│")
    t = text(version, ascii_only=not unicode_ok)
    color = hasattr(stream, "isatty") and stream.isatty() and os.environ.get("NO_COLOR") is None
    if color and unicode_ok:
        out = []
        for line in t.split("\n"):
            if "█" in line:
                i = len([x for x in out if "█" in x])
                r, g, b = GRADIENT[min(i, len(GRADIENT) - 1)]
                out.append(f"\033[1;38;2;{r};{g};{b}m{line}\033[0m")
            elif "HaiND" in line or "╭" in line or "╰" in line:
                out.append(f"\033[38;2;255;204;102m{line}\033[0m")
            else:
                out.append(f"\033[38;2;170;178;190m{line}\033[0m")
        t = "\n".join(out)
    try:
        print(t, file=stream)
    except UnicodeEncodeError:
        print(text(version, ascii_only=True), file=stream)
