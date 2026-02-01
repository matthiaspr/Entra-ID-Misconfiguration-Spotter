# Entra ID Misconfiguration Spotter - Specification

## Overview

A lightweight CLI tool that audits Microsoft Entra ID for common security misconfigurations using the MS Graph API.

**Goals:**
- Small, easy to maintain
- Internal use only
- Read-only operations
- Least privilege principle

---

## Technology Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Python 3.10+ | Maintainability, good Graph SDK |
| Package Manager | `uv` | Fast, modern, replaces pip/venv |
| MS Graph | `msgraph-sdk` | Official Microsoft SDK |
| CLI Framework | `click` | Simple, well-documented |
| HTTP Auth | `azure-identity` | Standard Azure auth library |

---

## Project Structure

```
entra-id-spotter/
├── pyproject.toml          # Project config, dependencies (uv)
├── uv.lock                  # Lock file
├── README.md
├── src/
│   └── entra_spotter/
│       ├── __init__.py     # Version
│       ├── cli.py          # CLI entry point
│       ├── auth.py         # MS Graph authentication
│       ├── config.py       # Configuration from env/flags
│       ├── runner.py       # Executes checks, collects results
│       ├── output.py       # Text/JSON formatters
│       ├── models.py       # Result dataclasses
│       └── checks/
│           ├── __init__.py # Check registry & auto-discovery
│           ├── base.py     # BaseCheck abstract class
│           ├── user_consent.py
│           ├── admin_consent_workflow.py
│           └── sp_admin_roles.py
└── tests/
    ├── conftest.py
    ├── test_checks/
    │   ├── test_user_consent.py
    │   ├── test_admin_consent_workflow.py
    │   └── test_sp_admin_roles.py
    └── test_cli.py
```

---

## Development with uv

```bash
# Create project
uv init entra-id-spotter
cd entra-id-spotter

# Add dependencies
uv add msgraph-sdk azure-identity click

# Add dev dependencies
uv add --dev pytest pytest-mock

# Run the tool
uv run entra-spotter

# Run tests
uv run pytest
```

**pyproject.toml** (key sections):
```toml
[project]
name = "entra-id-spotter"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
    "msgraph-sdk>=1.0.0",
    "azure-identity>=1.15.0",
    "click>=8.0.0",
]

[project.scripts]
entra-spotter = "entra_spotter.cli:main"

[tool.uv]
dev-dependencies = [
    "pytest>=8.0.0",
    "pytest-mock>=3.12.0",
]
```

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_TENANT_ID` | Yes | Entra ID tenant ID |
| `AZURE_CLIENT_ID` | Yes | Service principal app ID |
| `AZURE_CLIENT_SECRET` | Yes | Service principal secret |

### CLI Flags

```
--tenant-id, -t TEXT      Azure tenant ID
--client-id, -c TEXT      Service principal client ID
--client-secret, -s TEXT  Service principal client secret
--json                    Output as JSON
--check TEXT              Run specific check by ID (repeatable)
--list-checks             List available checks and exit
--version                 Show version and exit
--help                    Show help and exit
```

**Precedence**: CLI flags > Environment variables

---

## CLI Usage

```bash
# Run all checks (text output)
entra-spotter

# Run all checks (JSON output)
entra-spotter --json

# Run specific checks only
entra-spotter --check user-consent --check sp-admin-roles

# List available checks
entra-spotter --list-checks

# Override credentials via CLI
entra-spotter -t <tenant> -c <client-id> -s <secret>

# Show version
entra-spotter --version
```

---

## Output Formats

### Text Output (default)

```
Entra ID Misconfiguration Spotter v0.1.0
========================================

[FAIL] User Consent Settings
       Users can consent to apps accessing company data.
       Recommendation: Set to "Do not allow user consent"

[PASS] Admin Consent Workflow
       Admin consent workflow is enabled with 2 reviewer(s).

[WARN] Service Principal Admin Roles
       1 service principal(s) in privileged roles:
         - "Backup Service" → Global Administrator
       Recommendation: Review if this access is necessary.

────────────────────────────────────────
Summary: 1 failed, 1 warning, 1 passed
```

### JSON Output (`--json`)

```json
{
  "version": "0.1.0",
  "timestamp": "2024-01-15T10:30:00Z",
  "tenant_id": "abc-123",
  "results": [
    {
      "check_id": "user-consent",
      "name": "User Consent Settings",
      "status": "fail",
      "message": "Users can consent to apps accessing company data.",
      "recommendation": "Set to 'Do not allow user consent'",
      "details": {
        "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]
      }
    }
  ],
  "summary": {
    "total": 3,
    "passed": 1,
    "failed": 1,
    "warnings": 1
  }
}
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | One or more checks returned `fail` or `warning` |
| `2` | Error (authentication failure, API error, invalid config) |

---

## Adding New Checks

To add a new check:

1. **Create file** `src/entra_spotter/checks/my_new_check.py`:

```python
from entra_spotter.checks.base import BaseCheck, CheckResult

class MyNewCheck(BaseCheck):
    id = "my-new-check"
    name = "My New Check"
    description = "Checks for something important"
    permissions = ["SomePermission.Read.All"]

    def run(self, graph_client) -> CheckResult:
        # Call Graph API
        # Analyze response
        # Return result
        return CheckResult(
            check_id=self.id,
            status="pass",  # or "fail" or "warning"
            message="Everything looks good.",
            recommendation=None,
            details={}
        )
```

2. **Done.** The check is auto-discovered and included in runs.

---

## Check Specifications

### 1. User Consent Settings (`user-consent`)

| | |
|---|---|
| **API** | `GET /policies/authorizationPolicy` |
| **Permission** | `Policy.Read.All` |
| **Logic** | Check `defaultUserRolePermissions.permissionGrantPoliciesAssigned` |
| **PASS** | Empty array (users cannot consent) |
| **FAIL** | Contains any consent policy (users can consent) |

### 2. Admin Consent Workflow (`admin-consent-workflow`)

| | |
|---|---|
| **API** | `GET /policies/adminConsentRequestPolicy` |
| **Permission** | `Policy.Read.All` |
| **Logic** | Check `isEnabled` and `reviewers` array |
| **PASS** | `isEnabled: true` AND `reviewers` is non-empty |
| **FAIL** | `isEnabled: false` |
| **WARN** | `isEnabled: true` but `reviewers` is empty |

### 3. Service Principal Admin Roles (`sp-admin-roles`)

| | |
|---|---|
| **API** | `GET /directoryRoles` → `GET /directoryRoles/{id}/members` |
| **Permission** | `RoleManagement.Read.Directory` |
| **Privileged Roles** | Global Administrator, Privileged Role Administrator, Application Administrator, Cloud Application Administrator |
| **PASS** | No service principals in privileged roles |
| **WARN** | One or more service principals found in privileged roles |

---

## Required MS Graph Permissions

| Permission | Type | Description |
|------------|------|-------------|
| `Policy.Read.All` | Application | Read authorization and consent policies |
| `RoleManagement.Read.Directory` | Application | Read directory role assignments |

**Total: 2 application permissions** (read-only)

---

## Service Principal Setup

The tool requires a service principal with the above permissions. Setup steps:

1. Register an app in Entra ID
2. Add application permissions: `Policy.Read.All`, `RoleManagement.Read.Directory`
3. Grant admin consent
4. Create a client secret
5. Note: Tenant ID, Client ID, Client Secret

---

## Testing Strategy

- **Unit tests**: Mock Graph API responses, test check logic
- **No integration tests**: Avoid requiring real tenant access
- **Test fixtures**: Sample API responses in `tests/fixtures/`
