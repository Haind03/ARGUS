"""ARGUS startup banner. by HaiND from the Post and Telecommunication Institute of Technology"""
from __future__ import annotations

import os
import sys

LOGO = r"""
     ___      .______        _______  __    __       _______.
    /   \     |   _  \      /  _____||  |  |  |     /       |
   /  ^  \    |  |_)  |    |  |  __  |  |  |  |    |   (----`
  /  /_\  \   |      /     |  | |_ | |  |  |  |     \   \
 /  _____  \  |  |\  \----.|  |__| | |  `--'  | .----)   |
/__/     \__\ | _| `._____| \______|  \______/  |_______/
"""
TAGLINE = "  defensive threat hunting  |  detect-only  |  MITRE ATT&CK"
SIGNATURE_LINE = "  by HaiND from the Post and Telecommunication Institute of Technology"


def text(version: str = "") -> str:
    v = f"  v{version}" if version else ""
    return f"{LOGO.rstrip()}\n{TAGLINE}{v}\n{SIGNATURE_LINE}\n"


def show(version: str = "", stream=None) -> None:
    """Print to stderr (keeps JSON on stdout clean). Disable with ARGUS_NO_BANNER=1."""
    if os.environ.get("ARGUS_NO_BANNER") == "1":
        return
    stream = stream or sys.stderr
    use_color = hasattr(stream, "isatty") and stream.isatty() and os.environ.get("NO_COLOR") is None
    t = text(version)
    if use_color:
        lines = t.split("\n")
        n = len(LOGO.strip("\n").split("\n"))
        t = "\n".join([f"\033[96m{l}\033[0m" if i <= n else f"\033[93m{l}\033[0m" for i, l in enumerate(lines)])
    try:
        print(t, file=stream)
    except UnicodeEncodeError:
        pass
