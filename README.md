# Entra ID Misconfiguration Spotter

A lightweight CLI tool that audits Microsoft Entra ID for security misconfigurations.

## Installation

```bash
uv sync
```

## Usage

```bash
# Set credentials
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"

# Run all checks
uv run entra-spotter

# Run with JSON output
uv run entra-spotter --json

# Run specific checks
uv run entra-spotter --check user-consent --check sp-admin-roles

# List available checks
uv run entra-spotter --list-checks
```

## Checks

| ID | Description |
|----|-------------|
| `user-consent` | Checks if users can consent to apps accessing company data |
| `admin-consent-workflow` | Verifies admin consent workflow is enabled with reviewers |
| `sp-admin-roles` | Identifies service principals in privileged admin roles |

## Required Permissions

The service principal needs these MS Graph application permissions:

- `Policy.Read.All`
- `RoleManagement.Read.Directory`

## Development

```bash
# Run tests
uv run pytest

# Run with verbose output
uv run pytest -v
```

See [SPEC.md](SPEC.md) for the full specification.
