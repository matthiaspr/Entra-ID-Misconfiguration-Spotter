# Entra ID Misconfiguration Spotter

A lightweight CLI tool that audits Microsoft Entra ID for security misconfigurations.

## Installation

Requires [uv](https://docs.astral.sh/uv/) and Python 3.10+.

```bash
# Clone and enter the repository
git clone <repository-url>
cd Entra-ID-Misconfiguration-Spotter

# Install dependencies (run once, or after pyproject.toml changes)
uv sync
```

All `uv run` commands below should be run from this directory.

## Usage

### Authentication

You can provide credentials via CLI flags or environment variables (flags take precedence):

**CLI flags:**
```bash
uv run entra-spotter -t <tenant-id> -c <client-id> -s <client-secret>
```

**Environment variables:**
```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"

uv run entra-spotter
```

### Running Checks

```bash
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
| `sp-graph-roles` | Identifies service principals with sensitive MS Graph app roles |
| `legacy-auth-blocked` | Verifies a CA policy blocks legacy authentication protocols |
| `device-code-blocked` | Verifies a CA policy blocks device code flow authentication |
| `privileged-roles-mfa` | Verifies MFA is required for all 14 privileged admin roles |
| `global-admin-count` | Verifies 2-8 cloud-only users in Global Administrator role |
| `guest-invite-policy` | Checks who can invite guest users to the tenant |
| `guest-access` | Checks that guest users do not have the same access as members |
| `privileged-roles-phishing-resistant-mfa` | Verifies phishing-resistant MFA is required for privileged admin roles |
| `shadow-admins-app-owners` | Identifies users who own service principals with privileged roles or sensitive Graph permissions |
| `shadow-admins-group-owners` | Identifies users who own role-assignable groups with privileged roles |
| `dynamic-group-hijack` | Detects dynamic groups with privileged roles using mutable membership rule attributes |
| `unused-apps-cleanup` | Identifies privileged service principals inactive for over 180 days |
| `auth-methods-number-matching` | Verifies number matching is enforced in Microsoft Authenticator |
| `break-glass-exclusion` | Verifies emergency access accounts are excluded from all CA policies |

## Required Permissions

The service principal needs these MS Graph application permissions:

- `Policy.Read.All`
- `RoleManagement.Read.Directory`
- `Application.Read.All`
- `User.Read.All` - for resolving reviewer display names
- `Group.Read.All` - for resolving reviewer display names and group ownership
- `AuthenticationMethodsPolicy.Read` - for reading authentication method configurations

## Development

```bash
# Run tests
uv run pytest

# Run with verbose output
uv run pytest -v
```

See [SPEC.md](SPEC.md) for the full specification.
