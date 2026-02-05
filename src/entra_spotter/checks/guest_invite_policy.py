"""Check for guest user invitation policy settings."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult

# Mapping of allowInvitesFrom values to human-readable descriptions
# See: https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy
INVITE_SETTINGS = {
    "everyone": "Anyone in the organization (including guests and non-admins)",
    "adminsGuestInvitersAndAllMembers": "Member users and users in specific admin roles",
    "adminsAndGuestInviters": "Only users in specific admin roles and Guest Inviter role",
    "none": "No one in the organization",
}


async def check_guest_invite_policy(client: GraphServiceClient) -> CheckResult:
    """Check who can invite guest users to the tenant.

    Calls GET /policies/authorizationPolicy and checks allowInvitesFrom.

    Pass: No one can invite guests (none)
    Fail: Anyone can invite guests (everyone)
    Warning: Intermediate settings (adminsAndGuestInviters, adminsGuestInvitersAndAllMembers)
    """
    response = await client.policies.authorization_policy.get()

    allow_invites_from = getattr(response, "allow_invites_from", None)

    # Handle enum value - msgraph-sdk returns an enum object
    if allow_invites_from is not None:
        # Convert enum to string value if needed
        if hasattr(allow_invites_from, "value"):
            allow_invites_from = allow_invites_from.value

    if allow_invites_from is None:
        return CheckResult(
            check_id="guest-invite-policy",
            status="error",
            message="Could not determine guest invitation policy.",
            details={"error": "allowInvitesFrom property not found in response"},
        )

    # Get human-readable description
    setting_description = INVITE_SETTINGS.get(
        allow_invites_from, f"Unknown setting: {allow_invites_from}"
    )

    if allow_invites_from == "none":
        return CheckResult(
            check_id="guest-invite-policy",
            status="pass",
            message="Guest invitations are disabled.",
            details={
                "allow_invites_from": allow_invites_from,
                "who_can_invite": setting_description,
            },
        )

    if allow_invites_from == "everyone":
        return CheckResult(
            check_id="guest-invite-policy",
            status="fail",
            message="Anyone in the organization can invite guest users.",
            recommendation="Restrict guest invitations to admins only or disable entirely.",
            details={
                "allow_invites_from": allow_invites_from,
                "who_can_invite": setting_description,
            },
        )

    # Intermediate settings: adminsAndGuestInviters or adminsGuestInvitersAndAllMembers
    return CheckResult(
        check_id="guest-invite-policy",
        status="warning",
        message=f"Guest invitations allowed for: {setting_description}.",
        recommendation="Consider restricting guest invitations further if not required.",
        details={
            "allow_invites_from": allow_invites_from,
            "who_can_invite": setting_description,
        },
    )
