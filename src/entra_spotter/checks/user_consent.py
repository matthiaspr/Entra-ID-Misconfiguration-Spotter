"""Check for user consent settings."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult


def check_user_consent(client: GraphServiceClient) -> CheckResult:
    """Check if users can consent to apps accessing company data.

    Calls GET /policies/authorizationPolicy and checks
    defaultUserRolePermissions.permissionGrantPoliciesAssigned.

    Pass: Empty array (users cannot consent)
    Fail: Contains any consent policy (users can consent)
    """
    response = client.policies.authorization_policy.get()

    policies = (
        response.default_user_role_permissions.permission_grant_policies_assigned or []
    )

    if not policies:
        return CheckResult(
            check_id="user-consent",
            status="pass",
            message="Users cannot consent to apps accessing company data.",
        )

    return CheckResult(
        check_id="user-consent",
        status="fail",
        message="Users can consent to apps accessing company data.",
        recommendation="Set user consent to 'Do not allow user consent' in Entra ID.",
        details={"permission_grant_policies_assigned": policies},
    )
