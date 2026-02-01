"""Tests for all checks."""

import pytest

from entra_spotter.checks.user_consent import check_user_consent
from entra_spotter.checks.admin_consent_workflow import check_admin_consent_workflow
from entra_spotter.checks.sp_admin_roles import check_sp_admin_roles
from entra_spotter.checks.sp_graph_roles import check_sp_graph_roles

from conftest import (
    MockAuthorizationPolicy,
    MockAdminConsentRequestPolicy,
    MockDirectoryRole,
    MockDirectoryRolesResponse,
    MockRoleMember,
    MockRoleMembersResponse,
    MockAppRoleAssignment,
    MockServicePrincipal,
    MockServicePrincipalsResponse,
)


class TestUserConsent:
    """Tests for user consent check."""

    def test_pass_when_no_policies_assigned(self, mock_graph_client):
        """Should pass when no consent policies are assigned."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(permission_grant_policies_assigned=[])
        )

        result = check_user_consent(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "user-consent"

    def test_pass_when_policies_is_none(self, mock_graph_client):
        """Should pass when policies field is None."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(permission_grant_policies_assigned=None)
        )

        result = check_user_consent(mock_graph_client)

        assert result.status == "pass"

    def test_fail_when_policies_assigned(self, mock_graph_client):
        """Should fail when consent policies are assigned."""
        mock_graph_client.policies.authorization_policy.get.return_value = (
            MockAuthorizationPolicy(
                permission_grant_policies_assigned=[
                    "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"
                ]
            )
        )

        result = check_user_consent(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "user-consent"
        assert result.recommendation is not None
        assert "permission_grant_policies_assigned" in result.details


class TestAdminConsentWorkflow:
    """Tests for admin consent workflow check."""

    def test_pass_when_enabled_with_reviewers(self, mock_graph_client):
        """Should pass when workflow is enabled with reviewers."""
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(is_enabled=True, reviewers=["reviewer1", "reviewer2"])
        )

        result = check_admin_consent_workflow(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "admin-consent-workflow"
        assert "2 reviewer(s)" in result.message

    def test_fail_when_disabled(self, mock_graph_client):
        """Should fail when workflow is disabled."""
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(is_enabled=False, reviewers=[])
        )

        result = check_admin_consent_workflow(mock_graph_client)

        assert result.status == "fail"
        assert result.check_id == "admin-consent-workflow"
        assert result.recommendation is not None

    def test_warning_when_enabled_but_no_reviewers(self, mock_graph_client):
        """Should warn when workflow is enabled but has no reviewers."""
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(is_enabled=True, reviewers=[])
        )

        result = check_admin_consent_workflow(mock_graph_client)

        assert result.status == "warning"
        assert result.check_id == "admin-consent-workflow"
        assert result.recommendation is not None

    def test_warning_when_enabled_but_reviewers_is_none(self, mock_graph_client):
        """Should warn when workflow is enabled but reviewers is None."""
        mock_graph_client.policies.admin_consent_request_policy.get.return_value = (
            MockAdminConsentRequestPolicy(is_enabled=True, reviewers=None)
        )

        result = check_admin_consent_workflow(mock_graph_client)

        assert result.status == "warning"


class TestServicePrincipalAdminRoles:
    """Tests for service principal admin roles check."""

    def test_pass_when_no_privileged_roles(self, mock_graph_client):
        """Should pass when no service principals are in privileged roles."""
        # Return a non-privileged role
        mock_graph_client.directory_roles.get.return_value = MockDirectoryRolesResponse([
            MockDirectoryRole(
                id="role-1",
                role_template_id="some-other-template-id",
                display_name="Some Other Role",
            )
        ])

        result = check_sp_admin_roles(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "sp-admin-roles"

    def test_pass_when_privileged_role_has_only_users(self, mock_graph_client):
        """Should pass when privileged roles have only user members."""
        # Global Administrator template ID
        mock_graph_client.directory_roles.get.return_value = MockDirectoryRolesResponse([
            MockDirectoryRole(
                id="role-1",
                role_template_id="62e90394-69f5-4237-9190-012177145e10",
                display_name="Global Administrator",
            )
        ])

        # Members are users, not service principals
        mock_graph_client.directory_roles.by_directory_role_id.return_value.members.get.return_value = (
            MockRoleMembersResponse([
                MockRoleMember(
                    id="user-1",
                    display_name="John Doe",
                    odata_type="#microsoft.graph.user",
                )
            ])
        )

        result = check_sp_admin_roles(mock_graph_client)

        assert result.status == "pass"

    def test_warning_when_sp_in_global_admin(self, mock_graph_client):
        """Should warn when a service principal is in Global Administrator role."""
        mock_graph_client.directory_roles.get.return_value = MockDirectoryRolesResponse([
            MockDirectoryRole(
                id="role-1",
                role_template_id="62e90394-69f5-4237-9190-012177145e10",
                display_name="Global Administrator",
            )
        ])

        mock_graph_client.directory_roles.by_directory_role_id.return_value.members.get.return_value = (
            MockRoleMembersResponse([
                MockRoleMember(
                    id="sp-1",
                    display_name="My Service Principal",
                    odata_type="#microsoft.graph.servicePrincipal",
                )
            ])
        )

        result = check_sp_admin_roles(mock_graph_client)

        assert result.status == "warning"
        assert result.check_id == "sp-admin-roles"
        assert result.recommendation is not None
        assert len(result.details["service_principals"]) == 1
        assert result.details["service_principals"][0]["display_name"] == "My Service Principal"
        assert result.details["service_principals"][0]["role"] == "Global Administrator"

    def test_warning_with_multiple_sps_in_multiple_roles(self, mock_graph_client):
        """Should warn and list all service principals in privileged roles."""
        mock_graph_client.directory_roles.get.return_value = MockDirectoryRolesResponse([
            MockDirectoryRole(
                id="role-1",
                role_template_id="62e90394-69f5-4237-9190-012177145e10",
                display_name="Global Administrator",
            ),
            MockDirectoryRole(
                id="role-2",
                role_template_id="9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                display_name="Application Administrator",
            ),
        ])

        def mock_members(role_id):
            mock = type("Mock", (), {})()
            mock.members = type("Mock", (), {})()

            if role_id == "role-1":
                mock.members.get = lambda: MockRoleMembersResponse([
                    MockRoleMember("sp-1", "SP One", "#microsoft.graph.servicePrincipal")
                ])
            else:
                mock.members.get = lambda: MockRoleMembersResponse([
                    MockRoleMember("sp-2", "SP Two", "#microsoft.graph.servicePrincipal")
                ])
            return mock

        mock_graph_client.directory_roles.by_directory_role_id.side_effect = mock_members

        result = check_sp_admin_roles(mock_graph_client)

        assert result.status == "warning"
        assert len(result.details["service_principals"]) == 2

    def test_pass_when_no_roles_exist(self, mock_graph_client):
        """Should pass when no directory roles exist."""
        mock_graph_client.directory_roles.get.return_value = MockDirectoryRolesResponse([])

        result = check_sp_admin_roles(mock_graph_client)

        assert result.status == "pass"


class TestServicePrincipalGraphRoles:
    """Tests for service principal MS Graph app roles check."""

    def test_pass_when_no_service_principals(self, mock_graph_client):
        """Should pass when no service principals exist."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([])

        result = check_sp_graph_roles(mock_graph_client)

        assert result.status == "pass"
        assert result.check_id == "sp-graph-roles"

    def test_pass_when_no_sensitive_roles(self, mock_graph_client):
        """Should pass when SPs have no sensitive app roles."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="Safe App",
                app_role_assignments=[
                    MockAppRoleAssignment(app_role_id="some-harmless-role-id"),
                ],
            )
        ])

        result = check_sp_graph_roles(mock_graph_client)

        assert result.status == "pass"

    def test_pass_when_no_app_role_assignments(self, mock_graph_client):
        """Should pass when SPs have no app role assignments."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="App Without Roles",
                app_role_assignments=None,
            )
        ])

        result = check_sp_graph_roles(mock_graph_client)

        assert result.status == "pass"

    def test_warning_when_sp_has_role_management_role(self, mock_graph_client):
        """Should warn when SP has RoleManagement.ReadWrite.Directory."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="Privileged App",
                app_role_assignments=[
                    MockAppRoleAssignment(
                        app_role_id="9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",  # RoleManagement.ReadWrite.Directory
                    ),
                ],
            )
        ])

        result = check_sp_graph_roles(mock_graph_client)

        assert result.status == "warning"
        assert result.check_id == "sp-graph-roles"
        assert len(result.details["service_principals"]) == 1
        assert result.details["service_principals"][0]["app_role"] == "RoleManagement.ReadWrite.Directory"

    def test_warning_when_sp_has_app_role_assignment_role(self, mock_graph_client):
        """Should warn when SP has AppRoleAssignment.ReadWrite.All."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="Another Privileged App",
                app_role_assignments=[
                    MockAppRoleAssignment(
                        app_role_id="06b708a9-e830-4db3-a914-8e69da51d44f",  # AppRoleAssignment.ReadWrite.All
                    ),
                ],
            )
        ])

        result = check_sp_graph_roles(mock_graph_client)

        assert result.status == "warning"
        assert result.details["service_principals"][0]["app_role"] == "AppRoleAssignment.ReadWrite.All"

    def test_warning_with_multiple_sps_and_roles(self, mock_graph_client):
        """Should warn and list all SPs with sensitive roles."""
        mock_graph_client.service_principals.get.return_value = MockServicePrincipalsResponse([
            MockServicePrincipal(
                id="sp-1",
                display_name="App One",
                app_role_assignments=[
                    MockAppRoleAssignment(app_role_id="9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"),
                ],
            ),
            MockServicePrincipal(
                id="sp-2",
                display_name="App Two",
                app_role_assignments=[
                    MockAppRoleAssignment(app_role_id="06b708a9-e830-4db3-a914-8e69da51d44f"),
                ],
            ),
        ])

        result = check_sp_graph_roles(mock_graph_client)

        assert result.status == "warning"
        assert len(result.details["service_principals"]) == 2
        assert "2 service principal(s)" in result.message
