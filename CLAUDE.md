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

# Run specific test
uv run pytest tests/test_checks/test_user_consent.py
```

## Architecture

### Key Files

- `src/entra_spotter/cli.py` - CLI entry point using Click
- `src/entra_spotter/auth.py` - MS Graph authentication (service principal + client secret)
- `src/entra_spotter/config.py` - Configuration from env vars and CLI flags
- `src/entra_spotter/runner.py` - Orchestrates check execution
- `src/entra_spotter/output.py` - Text and JSON output formatters
- `src/entra_spotter/models.py` - Data classes (CheckResult, etc.)
- `src/entra_spotter/checks/base.py` - BaseCheck abstract class
- `src/entra_spotter/checks/__init__.py` - Auto-discovers checks

### Check Pattern

All checks inherit from `BaseCheck` and implement `run()`:

```python
from entra_spotter.checks.base import BaseCheck, CheckResult

class MyCheck(BaseCheck):
    id = "my-check"
    name = "My Check"
    description = "What this check does"
    permissions = ["Permission.Read.All"]

    def run(self, graph_client) -> CheckResult:
        # API calls and logic here
        return CheckResult(
            check_id=self.id,
            status="pass",  # "pass", "fail", or "warning"
            message="Result message",
            recommendation=None,  # Optional
            details={}  # Optional dict with extra context
        )
```

Checks are auto-discovered from the `checks/` directory.

## Current Checks

| ID | File | MS Graph API |
|----|------|--------------|
| `user-consent` | `user_consent.py` | `GET /policies/authorizationPolicy` |
| `admin-consent-workflow` | `admin_consent_workflow.py` | `GET /policies/adminConsentRequestPolicy` |
| `sp-admin-roles` | `sp_admin_roles.py` | `GET /directoryRoles`, `GET /directoryRoles/{id}/members` |

## Design Decisions

1. **Sync, not async** - Simpler code, easier maintenance
2. **uv for packaging** - Fast, modern Python tooling
3. **No .env file support** - Use actual environment variables
4. **Check IDs for CLI** - Use `--check user-consent` not `--check "User Consent Settings"`
5. **Auto-discovery** - New checks just need to be added to `checks/` directory

## Environment Variables

```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
```

## MS Graph Permissions Required

- `Policy.Read.All` (Application)
- `RoleManagement.Read.Directory` (Application)

Both are read-only. The tool never modifies any Entra ID configuration.

## Testing

- Mock all MS Graph API calls
- No integration tests requiring real tenants
- Test fixtures go in `tests/fixtures/`
- Use `pytest-mock` for mocking

## Exit Codes

- `0` - All checks passed
- `1` - One or more checks failed or warned
- `2` - Error (auth failure, API error, bad config)

## Adding a New Check

1. Create `src/entra_spotter/checks/my_new_check.py`
2. Inherit from `BaseCheck`, implement `run()`
3. Add tests in `tests/test_checks/test_my_new_check.py`
4. Update `SPEC.md` with check documentation
5. If new permissions needed, document in SPEC.md

## Code Style

- Type hints everywhere
- Docstrings for public methods
- Keep it simple - this is a small internal tool
