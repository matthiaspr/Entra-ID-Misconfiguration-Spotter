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
| Package Manager | `uv` | Fast, modern Python tooling |
| MS Graph | `msgraph-sdk` | Official Microsoft SDK |
| CLI Framework | `click` | Simple, well-documented |
| HTTP Auth | `azure-identity` | Standard Azure auth library |

---

## Project Structure

```
entra-id-spotter/
├── pyproject.toml
├── uv.lock
├── README.md
├── src/
│   └── entra_spotter/
│       ├── __init__.py         # Version
│       ├── cli.py              # CLI entry point, config, runner, output
│       ├── graph.py            # MS Graph authentication and client
│       └── checks/
│           ├── __init__.py     # CheckResult, Check dataclass, ALL_CHECKS registry
│           ├── _shared.py      # Shared constants and helpers
│           ├── user_consent.py
│           ├── admin_consent_workflow.py
│           ├── sp_admin_roles.py
│           ├── sp_graph_roles.py
│           ├── legacy_auth_blocked.py
│           ├── device_code_blocked.py
│           ├── privileged_roles_mfa.py
│           ├── privileged_roles_phishing_resistant_mfa.py
│           ├── global_admin_count.py
│           ├── guest_invite_policy.py
│           ├── guest_access.py
│           ├── shadow_admins_app_owners.py
│           ├── shadow_admins_group_owners.py
│           ├── dynamic_group_hijack.py
│           ├── auth_methods_number_matching.py
│           ├── privileged_roles_license.py
│           └── break_glass_exclusion.py
└── tests/
    ├── conftest.py             # Shared fixtures, mocked Graph client
    ├── test_checks.py          # All check tests
    └── test_cli.py             # CLI tests
```

**Design notes:**
- Configuration, runner logic, and output formatting live in `cli.py` to avoid over-fragmentation
- Each check is a separate file for maintainability as the number of checks grows
- Checks are explicitly registered in `ALL_CHECKS` (no auto-discovery magic)

---

## Development with uv

```bash
# Create project
uv init entra-id-spotter
cd entra-id-spotter

# Add dependencies
uv add msgraph-sdk azure-identity click

# Add dev dependencies
uv add --group dev pytest pytest-mock

# Run the tool
uv run entra-spotter

# Run tests
uv run pytest
```

**pyproject.toml:**
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

[dependency-groups]
dev = [
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

**When a check errors:**

```
[ERROR] User Consent Settings
        API request failed: 403 Forbidden
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
    },
    {
      "check_id": "admin-consent-workflow",
      "name": "Admin Consent Workflow",
      "status": "error",
      "message": "API request failed: 403 Forbidden",
      "recommendation": null,
      "details": null
    }
  ],
  "summary": {
    "total": 3,
    "passed": 1,
    "failed": 1,
    "warnings": 0,
    "errors": 1
  }
}
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | One or more checks returned `fail` or `warning` |
| `2` | One or more checks returned `error`, or fatal error (auth failure, invalid config) |

---

## Error Handling

**Per-check errors:**
- If a check throws an exception (e.g., API error, timeout), catch it
- Mark that check's status as `error` with the exception message
- Continue running remaining checks
- Exit with code `2` at the end

**Fatal errors:**
- Authentication failure → print error, exit `2` immediately
- Invalid configuration (missing credentials) → print error, exit `2` immediately

**No custom timeouts:** The MS Graph SDK handles timeouts internally. Users can Ctrl+C if needed.

---

## Check Architecture

### Core Types

Defined in `checks/__init__.py`:

```python
from dataclasses import dataclass
from typing import Callable, Literal
from msgraph import GraphServiceClient

Status = Literal["pass", "fail", "warning", "error"]

@dataclass
class CheckResult:
    check_id: str
    status: Status
    message: str
    recommendation: str | None = None
    details: dict | None = None

@dataclass
class Check:
    id: str
    name: str
    run: Callable[[GraphServiceClient], CheckResult]
```

### Check Registry

Checks are explicitly registered in `checks/__init__.py`:

```python
from entra_spotter.checks.user_consent import check_user_consent
from entra_spotter.checks.admin_consent_workflow import check_admin_consent_workflow
from entra_spotter.checks.sp_admin_roles import check_sp_admin_roles

ALL_CHECKS: list[Check] = [
    Check(id="user-consent", name="User Consent Settings", run=check_user_consent),
    Check(id="admin-consent-workflow", name="Admin Consent Workflow", run=check_admin_consent_workflow),
    Check(id="sp-admin-roles", name="Service Principal Admin Roles", run=check_sp_admin_roles),
]
```

**No auto-discovery.** Explicit registration is simple and debuggable.

---

## Adding New Checks

1. **Create file** `src/entra_spotter/checks/my_new_check.py`:

```python
from msgraph import GraphServiceClient
from entra_spotter.checks import CheckResult

def check_my_thing(client: GraphServiceClient) -> CheckResult:
    # Call Graph API
    response = client.some.endpoint.get()

    # Analyze and return result
    if some_condition:
        return CheckResult(
            check_id="my-thing",
            status="pass",
            message="Everything looks good.",
        )

    return CheckResult(
        check_id="my-thing",
        status="fail",
        message="Something is misconfigured.",
        recommendation="Do X to fix it.",
        details={"key": "value"},
    )
```

2. **Register in** `checks/__init__.py`:

```python
from entra_spotter.checks.my_new_check import check_my_thing

ALL_CHECKS: list[Check] = [
    # ... existing checks ...
    Check(id="my-thing", name="My Thing Check", run=check_my_thing),
]
```

3. **Add test** in `tests/test_checks.py`.

4. **Update documentation** if new MS Graph permissions are required.

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
| **API** | `GET /policies/adminConsentRequestPolicy`, plus `/users/{id}`, `/groups/{id}`, `/directoryRoles/{id}` to resolve reviewer names |
| **Permission** | `Policy.Read.All`, `User.Read.All`, `Group.Read.All` |
| **Logic** | Check `isEnabled` and `reviewers` array; resolve reviewer display names |
| **PASS** | `isEnabled: true` AND `reviewers` is non-empty (displays reviewer names) |
| **FAIL** | `isEnabled: false` |
| **WARN** | `isEnabled: true` but `reviewers` is empty |

### 3. Service Principal Admin Roles (`sp-admin-roles`)

| | |
|---|---|
| **API** | `GET /roleManagement/directory/roleAssignments?$expand=principal` |
| **Permission** | `RoleManagement.Read.Directory` |
| **Privileged Roles** | 14 roles defined in `_shared.PRIVILEGED_ROLES` (Global Administrator, Application Administrator, Authentication Administrator, Billing Administrator, Cloud Application Administrator, Conditional Access Administrator, Exchange Administrator, Helpdesk Administrator, Password Administrator, Privileged Authentication Administrator, Privileged Role Administrator, Security Administrator, SharePoint Administrator, User Administrator) |
| **PASS** | No service principals in privileged roles |
| **WARN** | One or more service principals found in privileged roles |

### 4. Service Principal MS Graph Roles (`sp-graph-roles`)

| | |
|---|---|
| **API** | `GET /servicePrincipals?$expand=appRoleAssignments` |
| **Permission** | `Application.Read.All` |
| **Sensitive Roles** | `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `UserAuthenticationMethod.ReadWrite.All` |
| **PASS** | No service principals have these sensitive app roles |
| **WARN** | One or more service principals have sensitive app roles |

These roles are dangerous because they allow privilege escalation:
- **RoleManagement.ReadWrite.Directory**: Can assign any directory role (including Global Admin)
- **AppRoleAssignment.ReadWrite.All**: Can grant any app role to any service principal
- **UserAuthenticationMethod.ReadWrite.All**: Can generate a Temporary Access Pass (TAP) to take over any user account

> **Note:** The tool now implements 16 checks total. Detailed specifications for checks beyond the original 4 are documented in `CLAUDE.md`.

---

## Required MS Graph Permissions

| Permission | Type | Description |
|------------|------|-------------|
| `Policy.Read.All` | Application | Read authorization and consent policies |
| `RoleManagement.Read.Directory` | Application | Read directory role assignments |
| `Application.Read.All` | Application | Read service principal app role assignments |
| `User.Read.All` | Application | Resolve reviewer user display names |
| `Group.Read.All` | Application | Resolve reviewer group display names |

**Total: 5 application permissions** (read-only)

---

## Service Principal Setup

1. Register an app in Entra ID
2. Add application permissions: `Policy.Read.All`, `RoleManagement.Read.Directory`, `Application.Read.All`, `User.Read.All`, `Group.Read.All`
3. Grant admin consent
4. Create a client secret
5. Note: Tenant ID, Client ID, Client Secret

---

## Testing Strategy

- **Unit tests**: Mock `GraphServiceClient`, test check logic in isolation
- **No integration tests**: Avoid requiring real tenant access
- **Shared fixtures**: Mocked client and sample API responses in `conftest.py`

Example test structure:

```python
# tests/test_checks.py

def test_user_consent_pass(mock_graph_client):
    """User consent check passes when no policies assigned."""
    mock_graph_client.policies.authorization_policy.get.return_value = MockAuthPolicy(
        permission_grant_policies_assigned=[]
    )

    result = check_user_consent(mock_graph_client)

    assert result.status == "pass"

def test_user_consent_fail(mock_graph_client):
    """User consent check fails when policies allow user consent."""
    mock_graph_client.policies.authorization_policy.get.return_value = MockAuthPolicy(
        permission_grant_policies_assigned=["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]
    )

    result = check_user_consent(mock_graph_client)

    assert result.status == "fail"
```
