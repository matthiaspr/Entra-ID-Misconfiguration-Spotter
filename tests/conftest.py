"""Shared test fixtures."""

from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture
def mock_graph_client():
    """Create a mock GraphServiceClient with async methods."""
    client = MagicMock()
    # Make the .get() methods return AsyncMock so they can be awaited
    client.policies.authorization_policy.get = AsyncMock()
    client.policies.admin_consent_request_policy.get = AsyncMock()
    client.role_management.directory.role_assignments.get = AsyncMock()
    client.service_principals.get = AsyncMock()
    return client


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


class MockRoleAssignment:
    def __init__(
        self,
        role_definition_id: str,
        principal_id: str,
        principal: MockRoleMember | None = None,
    ):
        self.role_definition_id = role_definition_id
        self.principal_id = principal_id
        self.principal = principal


class MockRoleAssignmentsResponse:
    def __init__(self, assignments: list[MockRoleAssignment]):
        self.value = assignments


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
