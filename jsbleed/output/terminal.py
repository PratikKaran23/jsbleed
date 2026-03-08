"""
Terminal output with colors using rich
"""

try:
    from rich.console import Console
    from rich.table import Table
    from rich import print as rprint
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

import sys

BANNER = r"""
     _ _     _     _               _
    (_) |   | |   | |             | |
     _ ___  | |__ | | ___  ___  __| |
    | / __| | '_ \| |/ _ \/ _ \/ _` |
    | \__ \ | |_) | |  __/  __/ (_| |
    | |___/ |_.__/|_|\___|\___|\__,_|
   _/ |
  |__/   recon & JS analysis tool  v1.0
"""

RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "dim white",
}

RISK_ICONS = {
    "CRITICAL": "💀",
    "HIGH":     "🔴",
    "MEDIUM":   "🟡",
    "LOW":      "⚪",
}


def print_banner():
    if HAS_RICH:
        console = Console()
        console.print(f"[bold red]{BANNER}[/bold red]")
        console.print("[dim]  by PratikKaran | github.com/PratikKaran23/jsbleed[/dim]\n")
    else:
        print(BANNER)
        print("  by PratikKaran | github.com/PratikKaran23/jsbleed\n")


def print_section(title, no_color=False):
    if HAS_RICH and not no_color:
        console = Console()
        console.print(f"\n[bold cyan]━━━ {title} ━━━[/bold cyan]")
    else:
        print(f"\n--- {title} ---")


def _print_subdomains(data, no_color):
    if not data:
        print("  [*] No subdomains found")
        return
    if HAS_RICH and not no_color:
        console = Console()
        for item in data:
            console.print(f"  [green]+[/green] {item['subdomain']}")
    else:
        for item in data:
            print(f"  + {item['subdomain']}")


def _print_js_files(data, no_color):
    if not data:
        print("  [*] No JS files found")
        return
    if HAS_RICH and not no_color:
        console = Console()
        console.print(f"  [green]Found {len(data)} JS files[/green]")
    else:
        print(f"  Found {len(data)} JS files")


def _print_secrets(data, no_color):
    if not data:
        return
    if HAS_RICH and not no_color:
        console = Console()
        console.print(f"\n  [bold red]🔑 SECRETS DETECTED ({len(data)})[/bold red]")
        for item in data:
            icon = RISK_ICONS.get(item["risk"], "")
            color = RISK_COLORS.get(item["risk"], "white")
            console.print(f"  [{color}]{icon} [{item['risk']}] {item['type']}[/{color}]")
            console.print(f"    Value   : [yellow]{item['value']}[/yellow]")
            console.print(f"    Source  : [dim]{item['source']}[/dim]")
            console.print(f"    Context : [dim italic]{item['context'][:100]}...[/dim italic]")
            console.print()
    else:
        print(f"\n  SECRETS DETECTED ({len(data)})")
        for item in data:
            print(f"  [{item['risk']}] {item['type']}")
            print(f"    Value  : {item['value']}")
            print(f"    Source : {item['source']}")
            print()


def _print_endpoints(data, no_color):
    if not data:
        return
    if HAS_RICH and not no_color:
        console = Console()
        console.print(f"\n  [bold cyan]🔗 ENDPOINTS ({len(data)})[/bold cyan]")

        high = [e for e in data if e["risk"] == "HIGH"]
        medium = [e for e in data if e["risk"] == "MEDIUM"]
        low = [e for e in data if e["risk"] == "LOW"]

        for item in high:
            console.print(f"  [red][HIGH] {item['endpoint']}[/red]  [dim]{item['source']}[/dim]")
        for item in medium:
            console.print(f"  [yellow][MED]  {item['endpoint']}[/yellow]  [dim]{item['source']}[/dim]")
        for item in low[:20]:  # cap low output
            console.print(f"  [dim][LOW]  {item['endpoint']}[/dim]")
        if len(low) > 20:
            console.print(f"  [dim]... and {len(low) - 20} more low-priority endpoints[/dim]")
    else:
        print(f"\n  ENDPOINTS ({len(data)})")
        for item in data:
            print(f"  [{item['risk']}] {item['endpoint']}")


def _print_sourcemaps(data, no_color):
    if not data:
        return
    if HAS_RICH and not no_color:
        console = Console()
        console.print(f"\n  [bold yellow]🗺  SOURCE MAPS ({len(data)})[/bold yellow]")
        for item in data:
            console.print(f"  [yellow][HIGH] {item['map_url']}[/yellow]")
            console.print(f"    JS File : [dim]{item['js_file']}[/dim]")
            console.print(f"    Sources : {item['total_sources']} original files exposed")
            if item['source_files']:
                for sf in item['source_files'][:5]:
                    console.print(f"    [dim]  • {sf}[/dim]")
                if len(item['source_files']) > 5:
                    console.print(f"    [dim]  ... and {item['total_sources'] - 5} more[/dim]")
    else:
        print(f"\n  SOURCE MAPS ({len(data)})")
        for item in data:
            print(f"  [HIGH] {item['map_url']} ({item['total_sources']} source files)")


def _print_auth_patterns(data, no_color):
    if not data:
        return
    if HAS_RICH and not no_color:
        console = Console()
        console.print(f"\n  [bold magenta]🔐 AUTH PATTERNS ({len(data)})[/bold magenta]")
        for item in data:
            icon = RISK_ICONS.get(item["risk"], "")
            color = RISK_COLORS.get(item["risk"], "white")
            console.print(f"  [{color}]{icon} [{item['risk']}] {item['type']}[/{color}]")
            console.print(f"    Note    : {item['note']}")
            console.print(f"    Snippet : [dim italic]{item['snippet'][:120]}[/dim italic]")
            console.print(f"    Source  : [dim]{item['source']}[/dim]")
            console.print()
    else:
        print(f"\n  AUTH PATTERNS ({len(data)})")
        for item in data:
            print(f"  [{item['risk']}] {item['type']}: {item['note']}")


def _print_parameters(data, no_color):
    if not data:
        return
    if HAS_RICH and not no_color:
        console = Console()
        high = [p for p in data if p["interest"] == "HIGH"]
        low = [p for p in data if p["interest"] == "LOW"]
        console.print(f"\n  [bold blue]📋 PARAMETERS ({len(data)})[/bold blue]")
        if high:
            console.print(f"  [red]High-interest ({len(high)}):[/red] " + ", ".join(f"[red]{p['param']}[/red]" for p in high))
        if low:
            names = ", ".join(p["param"] for p in low[:30])
            suffix = f"... +{len(low)-30}" if len(low) > 30 else ""
            console.print(f"  [dim]Others: {names}{suffix}[/dim]")
    else:
        high = [p["param"] for p in data if p["interest"] == "HIGH"]
        all_p = [p["param"] for p in data]
        print(f"\n  PARAMETERS ({len(data)})")
        if high:
            print(f"  High-interest: {', '.join(high)}")
        print(f"  All: {', '.join(all_p[:30])}")


PRINTERS = {
    "subdomains":    _print_subdomains,
    "js_files":      _print_js_files,
    "secrets":       _print_secrets,
    "endpoints":     _print_endpoints,
    "sourcemaps":    _print_sourcemaps,
    "auth_patterns": _print_auth_patterns,
    "parameters":    _print_parameters,
}


def print_results(section, data, no_color=False):
    printer = PRINTERS.get(section)
    if printer:
        printer(data, no_color)
