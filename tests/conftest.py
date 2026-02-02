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
    client.identity.conditional_access.policies.get = AsyncMock()
    # For reviewer resolution
    client.users.by_user_id = MagicMock(return_value=MagicMock(get=AsyncMock()))
    client.groups.by_group_id = MagicMock(return_value=MagicMock(get=AsyncMock()))
    client.directory_roles.by_directory_role_id = MagicMock(return_value=MagicMock(get=AsyncMock()))
    # For role definition resolution
    client.role_management.directory.role_definitions.by_unified_role_definition_id = MagicMock(
        return_value=MagicMock(get=AsyncMock())
    )
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


class MockReviewerScope:
    def __init__(self, query: str):
        self.query = query
        self.query_type = "MicrosoftGraph"
        self.query_root = None


class MockAdminConsentRequestPolicy:
    def __init__(self, is_enabled: bool, reviewers: list | None = None):
        self.is_enabled = is_enabled
        self.reviewers = reviewers


class MockUser:
    def __init__(self, id: str, user_principal_name: str, display_name: str | None = None):
        self.id = id
        self.user_principal_name = user_principal_name
        self.display_name = display_name or user_principal_name


class MockGroup:
    def __init__(self, id: str, display_name: str):
        self.id = id
        self.display_name = display_name


class MockDirectoryRoleInfo:
    def __init__(self, id: str, display_name: str):
        self.id = id
        self.display_name = display_name


class MockRoleDefinition:
    def __init__(self, id: str, display_name: str):
        self.id = id
        self.display_name = display_name


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


# Conditional Access Policy mock classes


class MockCAGrantControls:
    def __init__(self, built_in_controls: list[str] | None = None):
        self.built_in_controls = built_in_controls


class MockCAUsers:
    def __init__(
        self,
        include_users: list[str] | None = None,
        include_roles: list[str] | None = None,
        exclude_users: list[str] | None = None,
        exclude_groups: list[str] | None = None,
        exclude_roles: list[str] | None = None,
    ):
        self.include_users = include_users
        self.include_roles = include_roles
        self.exclude_users = exclude_users
        self.exclude_groups = exclude_groups
        self.exclude_roles = exclude_roles


class MockCAApplications:
    def __init__(
        self,
        include_applications: list[str] | None = None,
        exclude_applications: list[str] | None = None,
    ):
        self.include_applications = include_applications
        self.exclude_applications = exclude_applications


class MockCAAuthenticationFlows:
    def __init__(self, transfer_methods: list[str] | None = None):
        self.transfer_methods = transfer_methods


class MockCAConditions:
    def __init__(
        self,
        client_app_types: list[str] | None = None,
        users: MockCAUsers | None = None,
        applications: MockCAApplications | None = None,
        authentication_flows: MockCAAuthenticationFlows | None = None,
    ):
        self.client_app_types = client_app_types
        self.users = users
        self.applications = applications
        self.authentication_flows = authentication_flows


class MockConditionalAccessPolicy:
    def __init__(
        self,
        id: str,
        display_name: str,
        state: str,
        conditions: MockCAConditions | None = None,
        grant_controls: MockCAGrantControls | None = None,
    ):
        self.id = id
        self.display_name = display_name
        self.state = state
        self.conditions = conditions
        self.grant_controls = grant_controls


class MockCAPoliciesResponse:
    def __init__(self, policies: list[MockConditionalAccessPolicy]):
        self.value = policies
