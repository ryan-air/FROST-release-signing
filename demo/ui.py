"""Terminal output helpers shared by the attack scripts and the stage demo."""

from __future__ import annotations

import os

from rich.console import Console
from rich.panel import Panel

console = Console(highlight=False)
PAUSE = os.environ.get("DEMO_PAUSE", "0") == "1"


def short(b: bytes | int, n: int = 16) -> str:
    if isinstance(b, int):
        b = int.to_bytes(b % (1 << 256), 32, "little")
    h = b.hex()
    return h[:n] + "…" if len(h) > n else h


def title(text: str) -> None:
    console.rule(f"[bold cyan]{text}")


def step(text: str) -> None:
    console.print(f"[bold]›[/bold] {text}")
    if PAUSE:
        console.input("[dim]   (enter)[/dim]")


def info(label: str, value: str) -> None:
    console.print(f"    [dim]{label:<22}[/dim] {value}")


def good(text: str) -> None:
    console.print(Panel(f"[bold green]✔ {text}", border_style="green", expand=False))


def bad(text: str) -> None:
    console.print(Panel(f"[bold red]✘ {text}", border_style="red", expand=False))


def note(text: str) -> None:
    console.print(f"    [italic yellow]{text}[/italic yellow]")
