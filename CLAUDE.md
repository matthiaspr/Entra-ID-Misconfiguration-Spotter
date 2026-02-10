# CLAUDE.md

This file provides context for AI-assisted development of the Entra ID Misconfiguration Spotter.

## Project Overview

A lightweight Python CLI tool that audits Microsoft Entra ID (Azure AD) for security misconfigurations using the MS Graph API. Designed for internal use, easy maintenance, and extensibility.

## Quick Reference

```bash
# Install dependencies
uv sync

# Run the tool
uv run entra-spotter

# Run tests
uv run pytest
```

## Architecture

### Key Files

- `src/entra_spotter/__init__.py` - Version
- `src/entra_spotter/cli.py` - CLI entry point, config, runner, output formatting
- `src/entra_spotter/graph.py` - MS Graph authentication and client setup
- `src/entra_spotter/checks/__init__.py` - CheckResult, Check dataclass, ALL_CHECKS registry
- `src/entra_spotter/checks/_shared.py` - Shared helpers and constants (privileged role definitions, sensitive app roles, CA policy exclusion extraction)
- `src/entra_spotter/checks/*.py` - Individual check implementations

### Check Pattern

Checks are async functions that return a `CheckResult` (async required by msgraph-sdk):

```python
from msgraph import GraphServiceClient
from entra_spotter.checks import CheckResult

async def check_my_thing(client: GraphServiceClient) -> CheckResult:
    # Call Graph API (must await)
    response = await client.some.endpoint.get()

    # Analyze and return result
    if condition_met:
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

Checks are explicitly registered in `checks/__init__.py` (no auto-discovery).

## Current Checks

| ID | File | MS Graph API |
|----|------|--------------|
| `user-consent` | `user_consent.py` | `GET /policies/authorizationPolicy` |
| `admin-consent-workflow` | `admin_consent_workflow.py` | `GET /policies/adminConsentRequestPolicy`, resolves `/users/{id}`, `/groups/{id}`, `/directoryRoles/{id}` |
| `sp-admin-roles` | `sp_admin_roles.py` | `GET /roleManagement/directory/roleAssignments?$expand=principal` |
| `sp-graph-roles` | `sp_graph_roles.py` | `GET /servicePrincipals?$expand=appRoleAssignments` |
| `legacy-auth-blocked` | `legacy_auth_blocked.py` | `GET /identity/conditionalAccess/policies` |
| `device-code-blocked` | `device_code_blocked.py` | `GET /identity/conditionalAccess/policies` |
| `privileged-roles-mfa` | `privileged_roles_mfa.py` | `GET /identity/conditionalAccess/policies` |
| `global-admin-count` | `global_admin_count.py` | `GET /roleManagement/directory/roleAssignments?$filter=...&$expand=principal`, `/groups/{id}/members`, `/users/{id}` |
| `guest-invite-policy` | `guest_invite_policy.py` | `GET /policies/authorizationPolicy` (allowInvitesFrom property) |
| `guest-access` | `guest_access.py` | `GET /policies/authorizationPolicy` (guestUserRoleId property) |
| `privileged-roles-phishing-resistant-mfa` | `privileged_roles_phishing_resistant_mfa.py` | `GET /identity/conditionalAccess/policies` |
| `shadow-admins-app-owners` | `shadow_admins_app_owners.py` | `GET /roleManagement/directory/roleAssignments?$expand=principal`, `GET /servicePrincipals?$expand=appRoleAssignments`, `GET /servicePrincipals/{id}/owners` |
| `shadow-admins-group-owners` | `shadow_admins_group_owners.py` | `GET /roleManagement/directory/roleAssignments?$expand=principal`, `GET /groups/{id}/owners` |
| `dynamic-group-hijack` | `dynamic_group_hijack.py` | `GET /roleManagement/directory/roleAssignments?$expand=principal`, `GET /groups/{id}` |
| `auth-methods-number-matching` | `auth_methods_number_matching.py` | `GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator` |
| `break-glass-exclusion` | `break_glass_exclusion.py` | `GET /identity/conditionalAccess/policies` |

## Design Decisions

1. **Async checks** - Required by msgraph-sdk; all checks run in a single `asyncio.run()` call
2. **uv for packaging** - Fast, modern Python tooling
3. **No .env file support** - Use actual environment variables
4. **Check IDs for CLI** - Use `--check user-consent` not `--check "User Consent Settings"`
5. **Explicit registration** - Checks are added to `ALL_CHECKS` list manually (no magic)
6. **Function-based checks** - Simple functions, not classes with inheritance
7. **Unified RBAC API** - Use `/roleManagement/directory/roleAssignments` instead of legacy `/directoryRoles` for role membership checks
8. **Shared helpers** - Checks share `get_policy_exclusions()`, `has_any_exclusions()`, `PRIVILEGED_ROLES`, and `SENSITIVE_APP_ROLES` via `_shared.py` to avoid duplication across check files

## Environment Variables

```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
```

## MS Graph Permissions Required

- `Policy.Read.All` (Application)
- `RoleManagement.Read.Directory` (Application)
- `Application.Read.All` (Application)
- `User.Read.All` (Application) - for resolving reviewer display names
- `Group.Read.All` (Application) - for resolving reviewer display names and group ownership

All are read-only. The tool never modifies any Entra ID configuration.

## Testing

- Mock `GraphServiceClient` in tests
- No integration tests requiring real tenants
- Shared fixtures in `tests/conftest.py`
- Use `pytest-mock` for mocking

## Exit Codes

- `0` - All checks passed
- `1` - One or more checks failed or warned
- `2` - Error (auth failure, API error, bad config, or check raised exception)

## Error Handling

- Per-check exceptions are caught, marked as `error` status, and remaining checks continue
- Fatal errors (auth failure, missing config) exit immediately with code `2`

## Adding a New Check

1. Create `src/entra_spotter/checks/my_new_check.py` with a function returning `CheckResult`
2. Register in `checks/__init__.py` by adding to `ALL_CHECKS` list
3. Add tests in `tests/test_checks.py`
4. Update `SPEC.md` if new MS Graph permissions are required
5. For shared constants and helpers, reuse from `checks/_shared.py` (privileged role definitions, sensitive app roles, CA policy exclusion extraction)

## Code Style

- Type hints everywhere
- Keep it simple - this is a small internal tool
- Prefer functions over classes where practical
- **Avoid over-engineering**: No abstract base classes, auto-discovery, plugin systems, or unnecessary abstractions. If a simple list or function works, use that. Add complexity only when there's a clear, immediate need - not for hypothetical future requirements. The tool should remain professional and well-structured, but lean.
