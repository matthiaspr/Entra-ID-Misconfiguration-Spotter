"""Shared test fixtures."""

from unittest.mock import MagicMock

import pytest


@pytest.fixture
def mock_graph_client():
    """Create a mock GraphServiceClient."""
    return MagicMock()


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
