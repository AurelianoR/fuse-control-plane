import json
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table
from rich.text import Text

from collector.models import Grant

console = Console()


def print_report(
    grants: list[Grant], diff: dict | None, output_format: str = "table"
) -> None:
    if output_format == "json":
        _print_json(grants, diff)
    else:
        _print_table(grants, diff)


def _print_table(grants: list[Grant], diff: dict | None) -> None:
    if diff:
        _print_diff_summary(diff)

    table = Table(title="OAuth Grant Inventory", show_lines=True, expand=False)
    table.add_column("Vendor App", style="cyan", min_width=20)
    table.add_column("Type", width=4)
    table.add_column("Resource", style="blue", min_width=14)
    table.add_column("Permissions")
    table.add_column("Consent", width=7)
    table.add_column("Last Used", width=12)
    table.add_column("Risk", style="yellow")

    now = datetime.now(timezone.utc)

    for g in sorted(grants, key=lambda x: x.client_display_name.lower()):
        app_id_short = g.client_app_id[:8] + "…" if g.client_app_id else ""
        vendor_cell = Text()
        vendor_cell.append(g.client_display_name)
        vendor_cell.append(f"\n{app_id_short}", style="dim")

        perm_lines = g.permissions[:5]
        if len(g.permissions) > 5:
            perm_lines = perm_lines + [f"+{len(g.permissions) - 5} more"]

        table.add_row(
            vendor_cell,
            g.grant_type[:3],
            g.resource_display_name,
            "\n".join(perm_lines),
            g.consent_type or "",
            _format_last_used(g, now),
            ", ".join(g.risk_signals),
        )

    console.print(table)

    n_del = sum(1 for g in grants if g.grant_type == "delegated")
    n_app = sum(1 for g in grants if g.grant_type == "application")
    console.print(
        f"\n[dim]Total: {len(grants)} grants "
        f"({n_del} delegated, {n_app} application)[/dim]"
    )


def _format_last_used(g: Grant, now: datetime) -> str:
    if g.activity is None:
        return "[dim]unknown[/dim]"
    last = g.activity.last_sign_in
    if last is None:
        return "[red]never[/red]"
    days = (now - last).days
    if days == 0:
        return "[green]today[/green]"
    if days < 30:
        return f"[green]{days}d ago[/green]"
    if days < 90:
        return f"[yellow]{days}d ago[/yellow]"
    return f"[red]{days}d ago[/red]"


def _print_diff_summary(diff: dict) -> None:
    if diff["new"]:
        console.print(f"\n[green bold]+ {len(diff['new'])} new grant(s)[/green bold]")
        for g in diff["new"]:
            perms = ", ".join(g.permissions[:3])
            suffix = f"+{len(g.permissions)-3} more" if len(g.permissions) > 3 else ""
            console.print(
                f"  [green]+[/green] {g.client_display_name} → "
                f"{g.resource_display_name}: {perms}{suffix}"
            )

    if diff["removed"]:
        console.print(f"\n[red bold]- {len(diff['removed'])} removed grant(s)[/red bold]")
        for g in diff["removed"]:
            console.print(
                f"  [red]-[/red] {g.client_display_name} → {g.resource_display_name}"
            )

    if diff["changed"]:
        console.print(
            f"\n[yellow bold]~ {len(diff['changed'])} changed grant(s)[/yellow bold]"
        )
        for c in diff["changed"]:
            if c["added_permissions"]:
                console.print(
                    f"  [yellow]~[/yellow] {c['display_name']}: "
                    f"added {', '.join(c['added_permissions'])}"
                )
            if c["removed_permissions"]:
                console.print(
                    f"  [yellow]~[/yellow] {c['display_name']}: "
                    f"removed {', '.join(c['removed_permissions'])}"
                )
    console.print()


def _print_json(grants: list[Grant], diff: dict | None) -> None:
    output: dict = {"grants": [_grant_to_dict(g) for g in grants]}
    if diff:
        output["diff"] = {
            "new": [_grant_to_dict(g) for g in diff["new"]],
            "removed": [_grant_to_dict(g) for g in diff["removed"]],
            "changed": diff["changed"],
        }
    print(json.dumps(output, indent=2, default=str))


def _grant_to_dict(g: Grant) -> dict:
    return {
        "id": g.id,
        "type": g.grant_type,
        "vendor": g.client_display_name,
        "app_id": g.client_app_id,
        "verified_publisher": g.client_verified_publisher,
        "resource": g.resource_display_name,
        "permissions": g.permissions,
        "consent_type": g.consent_type,
        "created_at": g.created_at.isoformat() if g.created_at else None,
        "first_seen_at": g.first_seen_at.isoformat(),
        "last_used": (
            g.activity.last_sign_in.isoformat()
            if g.activity and g.activity.last_sign_in
            else None
        ),
        "risk_signals": g.risk_signals,
    }
