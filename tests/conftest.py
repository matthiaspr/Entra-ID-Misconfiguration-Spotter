"""Shared test fixtures."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_graph_client():
    """Create a mock GraphServiceClient."""
    return MagicMock()


@pytest.fixture(autouse=True)
def mock_run_sync():
    """Patch run_sync to return the mock value directly.

    Since mocks return values directly (not coroutines), we need to
    bypass asyncio.run() in tests. We patch in each module where it's imported.
    """
    with (
        patch("entra_spotter.checks.user_consent.run_sync", side_effect=lambda x: x),
        patch("entra_spotter.checks.admin_consent_workflow.run_sync", side_effect=lambda x: x),
        patch("entra_spotter.checks.sp_admin_roles.run_sync", side_effect=lambda x: x),
        patch("entra_spotter.checks.sp_graph_roles.run_sync", side_effect=lambda x: x),
    ):
        yield


# Mock response classes to simulate Graph API responses

class MockDefaultUserRolePermissions:
    def __init__(self, permission_grant_policies_assigned: list[str] | None = None):
        self.permission_grant_policies_assigned = permission_grant_policies_assigned


class MockAuthorizationPolicy:
    def __init__(self, permission_grant_policies_assigned: list[str] | None = None):
        self.default_user_role_permissions = MockDefaultUserRolePermissions(
            permission_grant_policies_assigned
        )


class MockAdminConsentRequestPolicy:
    def __init__(self, is_enabled: bool, reviewers: list | None = None):
        self.is_enabled = is_enabled
        self.reviewers = reviewers


class MockDirectoryRole:
    def __init__(self, id: str, role_template_id: str, display_name: str):
        self.id = id
        self.role_template_id = role_template_id
        self.display_name = display_name


class MockDirectoryRolesResponse:
    def __init__(self, roles: list[MockDirectoryRole]):
        self.value = roles


class MockRoleMember:
    def __init__(self, id: str, display_name: str, odata_type: str):
        self.id = id
        self.display_name = display_name
        self.odata_type = odata_type


class MockRoleMembersResponse:
    def __init__(self, members: list[MockRoleMember]):
        self.value = members


class MockAppRoleAssignment:
    def __init__(self, app_role_id: str, resource_display_name: str = "Microsoft Graph"):
        self.app_role_id = app_role_id
        self.resource_display_name = resource_display_name


class MockServicePrincipal:
    def __init__(
        self,
        id: str,
        display_name: str,
        app_role_assignments: list[MockAppRoleAssignment] | None = None,
    ):
        self.id = id
        self.display_name = display_name
        self.app_role_assignments = app_role_assignments


class MockServicePrincipalsResponse:
    def __init__(self, service_principals: list[MockServicePrincipal]):
        self.value = service_principals
