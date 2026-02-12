Python CLI tool that audits Microsoft Entra ID for security misconfigurations via the MS Graph API.

## Commands

```bash
uv sync              # Install dependencies
uv run entra-spotter # Run the tool
uv run pytest        # Run tests
```

## Environment Variables

No .env file support — use actual environment variables.

```bash
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
```

## Adding or Modifying Checks

1. Create `src/entra_spotter/checks/my_new_check.py` — follow the async pattern in any existing check file (async is required by msgraph-sdk)
2. Register in `checks/__init__.py` by adding to `ALL_CHECKS` list — no auto-discovery
3. Reuse helpers from `checks/_shared.py` where applicable
4. Use `/roleManagement/directory/roleAssignments` for role lookups, never the legacy `/directoryRoles` API
5. Add tests in `tests/test_checks.py` — mock `GraphServiceClient`, see `tests/conftest.py` for shared fixtures

## Avoid Over-engineering

This is the most important guidance for this project. Keep it lean:

- No abstract base classes, plugin systems, auto-discovery, or unnecessary abstractions
- No helpers, utilities, or wrappers for one-time operations
- No designing for hypothetical future requirements
- If a simple list or function works, use that — three similar lines of code is better than a premature abstraction
- Only add complexity when there's a clear, immediate need
