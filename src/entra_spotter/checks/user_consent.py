"""Check for user consent settings."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult

# Policies that ENABLE user consent (these should trigger a fail)
# See: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent
USER_CONSENT_ENABLING_POLICIES = {
    # Allow user consent for all apps (legacy default)
    "ManagePermissionGrantsForSelf.microsoft-user-default-legacy",
    # Allow user consent for apps from verified publishers
    "ManagePermissionGrantsForSelf.microsoft-user-default-low",
}

# Policy that DISABLES user consent (this is safe)
USER_CONSENT_DISABLED_POLICY = "ManagePermissionGrantsForSelf.microsoft-user-default-recommended"


async def check_user_consent(client: GraphServiceClient) -> CheckResult:
    """Check if users can consent to apps accessing company data.

    Calls GET /policies/authorizationPolicy and checks
    defaultUserRolePermissions.permissionGrantPoliciesAssigned.

    Pass: No user consent policies OR only the 'microsoft-user-default-recommended' policy
    Fail: Contains a policy that enables user consent (legacy or low)
    Warning: Contains custom ManagePermissionGrantsForSelf policies that need review
    """
    response = await client.policies.authorization_policy.get()

    policies = (
        response.default_user_role_permissions.permission_grant_policies_assigned or []
    )

    # Filter to only ManagePermissionGrantsForSelf policies (user consent policies)
    user_consent_policies = [
        p for p in policies if p.startswith("ManagePermissionGrantsForSelf.")
    ]

    # Check for known enabling policies
    enabling_policies = [p for p in user_consent_policies if p in USER_CONSENT_ENABLING_POLICIES]

    if enabling_policies:
        # Determine message based on which policy is present
        if "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" in enabling_policies:
            consent_level = "all apps"
        else:
            consent_level = "apps from verified publishers"

        return CheckResult(
            check_id="user-consent",
            status="fail",
            message=f"Users can consent to {consent_level} accessing company data.",
            recommendation="Set user consent to 'Do not allow user consent' in Entra ID.",
            details={"permission_grant_policies_assigned": policies},
        )

    # Check for custom policies (not the known disabled policy)
    custom_policies = [
        p for p in user_consent_policies
        if p != USER_CONSENT_DISABLED_POLICY
    ]

    if custom_policies:
        return CheckResult(
            check_id="user-consent",
            status="warning",
            message="Custom user consent policy detected.",
            recommendation="Review the custom consent policy to ensure it aligns with security requirements.",
            details={
                "permission_grant_policies_assigned": policies,
                "custom_policies": custom_policies,
            },
        )

    # Either empty, only contains disabled policy, or only non-user-consent policies
    return CheckResult(
        check_id="user-consent",
        status="pass",
        message="Users cannot consent to apps accessing company data.",
        details={"permission_grant_policies_assigned": policies} if policies else None,
    )
