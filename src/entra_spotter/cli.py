"""CLI entry point, configuration, runner, and output formatting."""

import asyncio
import json
import os
import sys
from datetime import datetime, timezone

import click

from msgraph import GraphServiceClient

from entra_spotter import __version__
from entra_spotter.checks import ALL_CHECKS, Check, CheckResult
from entra_spotter.graph import create_graph_client


def get_config(
    tenant_id: str | None,
    client_id: str | None,
    client_secret: str | None,
) -> tuple[str, str, str]:
    """Get configuration from CLI flags or environment variables.

    CLI flags take precedence over environment variables.

    Returns:
        Tuple of (tenant_id, client_id, client_secret)

    Raises:
        click.ClickException: If any required config is missing
    """
    tenant = tenant_id or os.environ.get("AZURE_TENANT_ID")
    client = client_id or os.environ.get("AZURE_CLIENT_ID")
    secret = client_secret or os.environ.get("AZURE_CLIENT_SECRET")

    missing = []
    if not tenant:
        missing.append("AZURE_TENANT_ID (or --tenant-id)")
    if not client:
        missing.append("AZURE_CLIENT_ID (or --client-id)")
    if not secret:
        missing.append("AZURE_CLIENT_SECRET (or --client-secret)")

    if missing:
        raise click.ClickException(f"Missing required configuration: {', '.join(missing)}")

    return tenant, client, secret


async def run_checks_async(
    client: GraphServiceClient,
    checks: list[Check],
) -> list[tuple[Check, CheckResult]]:
    """Run checks asynchronously and return results.

    If a check raises an exception, it's caught and returned as an error result.
    """
    results: list[tuple[Check, CheckResult]] = []

    for check in checks:
        try:
            result = await check.run(client)
        except Exception as e:
            result = CheckResult(
                check_id=check.id,
                status="error",
                message=f"Check failed: {e}",
            )
        results.append((check, result))

    return results


def format_text_output(results: list[tuple[Check, CheckResult]]) -> str:
    """Format results as human-readable text."""
    lines = [
        f"Entra ID Misconfiguration Spotter v{__version__}",
        "=" * 40,
        "",
    ]

    status_symbols = {
        "pass": "[PASS]",
        "fail": "[FAIL]",
        "warning": "[WARN]",
        "error": "[ERROR]",
    }

    for check, result in results:
        symbol = status_symbols.get(result.status, "[????]")
        lines.append(f"{symbol} {check.name}")
        lines.append(f"       {result.message}")

        if result.recommendation:
            lines.append(f"       Recommendation: {result.recommendation}")

        if result.details and result.status in ("fail", "warning"):
            lines.extend(_format_details(result.details))


        lines.append("")

    # Summary
    passed = sum(1 for _, r in results if r.status == "pass")
    failed = sum(1 for _, r in results if r.status == "fail")
    warnings = sum(1 for _, r in results if r.status == "warning")
    errors = sum(1 for _, r in results if r.status == "error")

    lines.append("─" * 40)
    summary_parts = []
    if failed:
        summary_parts.append(f"{failed} failed")
    if warnings:
        summary_parts.append(f"{warnings} warning(s)")
    if errors:
        summary_parts.append(f"{errors} error(s)")
    if passed:
        summary_parts.append(f"{passed} passed")

    lines.append(f"Summary: {', '.join(summary_parts)}")

    return "\n".join(lines)


def _format_details(details: dict) -> list[str]:
    """Format details for text output."""
    if not details:
        return []

    summary = details.get("details_summary")
    if isinstance(summary, str) and summary.strip():
        return [f"       {line}" for line in summary.splitlines()]

    lines: list[str] = []
    for key, value in details.items():
        if key == "details_summary":
            continue
        if isinstance(value, list):
            lines.append(f"       {key}:")
            if not value:
                lines.append("         - (none)")
                continue
            for item in value:
                lines.append(f"         - {_format_detail_item(item)}")
        elif isinstance(value, dict):
            lines.append(f"       {key}: {_format_detail_item(value)}")
        else:
            lines.append(f"       {key}: {value}")

    return lines


def _format_detail_item(value: object) -> str:
    if isinstance(value, dict):
        parts = []
        for key in sorted(value.keys()):
            item = value[key]
            if isinstance(item, (dict, list)):
                parts.append(f"{key}={json.dumps(item, ensure_ascii=True)}")
            else:
                parts.append(f"{key}={item}")
        return ", ".join(parts)
    if isinstance(value, list):
        return json.dumps(value, ensure_ascii=True)
    return str(value)


def format_json_output(
    results: list[tuple[Check, CheckResult]],
    tenant_id: str,
) -> str:
    """Format results as JSON."""
    output = {
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "results": [
            {
                "check_id": result.check_id,
                "name": check.name,
                "status": result.status,
                "message": result.message,
                "recommendation": result.recommendation,
                "details": result.details,
            }
            for check, result in results
        ],
        "summary": {
            "total": len(results),
            "passed": sum(1 for _, r in results if r.status == "pass"),
            "failed": sum(1 for _, r in results if r.status == "fail"),
            "warnings": sum(1 for _, r in results if r.status == "warning"),
            "errors": sum(1 for _, r in results if r.status == "error"),
        },
    }

    return json.dumps(output, indent=2)


def get_exit_code(results: list[tuple[Check, CheckResult]]) -> int:
    """Determine exit code based on results.

    0 = All checks passed
    1 = One or more checks returned fail or warning
    2 = One or more checks returned error
    """
    has_error = any(r.status == "error" for _, r in results)
    has_fail_or_warning = any(r.status in ("fail", "warning") for _, r in results)

    if has_error:
        return 2
    if has_fail_or_warning:
        return 1
    return 0


@click.command()
@click.option(
    "--tenant-id", "-t",
    help="Azure tenant ID (or set AZURE_TENANT_ID)",
)
@click.option(
    "--client-id", "-c",
    help="Service principal client ID (or set AZURE_CLIENT_ID)",
)
@click.option(
    "--client-secret", "-s",
    help="Service principal client secret (or set AZURE_CLIENT_SECRET)",
)
@click.option(
    "--json", "output_json",
    is_flag=True,
    help="Output results as JSON",
)
@click.option(
    "--check",
    "check_ids",
    multiple=True,
    help="Run specific check by ID (can be repeated)",
)
@click.option(
    "--list-checks",
    is_flag=True,
    help="List available checks and exit",
)
@click.version_option(version=__version__)
def main(
    tenant_id: str | None,
    client_id: str | None,
    client_secret: str | None,
    output_json: bool,
    check_ids: tuple[str, ...],
    list_checks: bool,
) -> None:
    """Audit Entra ID for security misconfigurations."""
    # Handle --list-checks
    if list_checks:
        click.echo("Available checks:")
        max_width = max(len(c.id) for c in ALL_CHECKS)
        for check in ALL_CHECKS:
            click.echo(f"  {check.id:<{max_width}}  {check.name}")
        return

    # Get and validate configuration
    try:
        tenant, client, secret = get_config(tenant_id, client_id, client_secret)
    except click.ClickException as e:
        click.echo(f"Error: {e.message}", err=True)
        sys.exit(2)

    # Filter checks if specific ones requested
    if check_ids:
        available_ids = {c.id for c in ALL_CHECKS}
        invalid_ids = set(check_ids) - available_ids
        if invalid_ids:
            raise click.ClickException(
                f"Unknown check ID(s): {', '.join(invalid_ids)}. "
                f"Use --list-checks to see available checks."
            )
        checks_to_run = [c for c in ALL_CHECKS if c.id in check_ids]
    else:
        checks_to_run = ALL_CHECKS

    # Create Graph client
    try:
        graph_client = create_graph_client(tenant, client, secret)
    except Exception as e:
        click.echo(f"Error: Failed to create Graph client: {e}", err=True)
        sys.exit(2)

    # Run checks in a single async context
    results = asyncio.run(run_checks_async(graph_client, checks_to_run))

    # Output results
    if output_json:
        click.echo(format_json_output(results, tenant))
    else:
        click.echo(format_text_output(results))

    # Exit with appropriate code
    sys.exit(get_exit_code(results))


if __name__ == "__main__":
    main()
