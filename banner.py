# language: Python 3.11, file: banner.py
"""Banner and terminal helpers for KEITH TECH SCANNER."""
import os, sys

_USE_COLOR = (
    os.environ.get("NO_COLOR") is None
    and os.environ.get("TERM", "") not in ("", "dumb")
    and sys.stdout.isatty()
)

RED    = "\033[1;91m" if _USE_COLOR else ""
DIM    = "\033[2m"    if _USE_COLOR else ""
CYAN   = "\033[1;96m" if _USE_COLOR else ""
GREEN  = "\033[1;92m" if _USE_COLOR else ""
YELLOW = "\033[1;93m" if _USE_COLOR else ""
GREY   = "\033[90m"   if _USE_COLOR else ""
RESET  = "\033[0m"    if _USE_COLOR else ""

SKELETON = r"""
        ▄▄▄▄▄▄▄▄▄
      ▄███████████▄
     ███▀▀▀▀▀▀▀▀███
    ███   ██   ██  ███
    ███   ▀▀   ▀▀  ███
     ███▄▄▄▄▄▄▄▄▄███
      ▀███████████▀
        ▀▀█▀█▀█▀▀
          █ █ █
"""

NAME = r"""
██╗  ██╗███████╗██╗████████╗██╗  ██╗    ████████╗███████╗ ██████╗██╗  ██╗
██║ ██╔╝██╔════╝██║╚══██╔══╝██║  ██║    ╚══██╔══╝██╔════╝██╔════╝██║  ██║
█████╔╝ █████╗  ██║   ██║   ███████║       ██║   █████╗  ██║     ███████║
██╔═██╗ ██╔══╝  ██║   ██║   ██╔══██║       ██║   ██╔══╝  ██║     ██╔══██║
██║  ██╗███████╗██║   ██║   ██║  ██║       ██║   ███████╗╚██████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝       ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝
"""

SUBTITLE = "              S C A N N E R   ·   V 1 . 2               "


def clear():
    os.system("cls" if os.name == "nt" else "clear")


def show_banner():
    clear()
    print(f"{RED}{SKELETON}{RESET}")
    print(f"{RED}{NAME}{RESET}")
    print(f"{GREY}{SUBTITLE}{RESET}")
    print(f"{DIM}        by Keith Tech ^_~ · Termux / Linux / macOS{RESET}\n")


def cprint(tag: str, msg: str, color: str = GREY):
    print(f"{color}[{tag}]{RESET} {msg}")
