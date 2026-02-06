"""Check for guest user access level settings."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult

# GUIDs that map to guest user access levels in the authorizationPolicy.
# See: https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy
GUEST_ROLE_IDS = {
    "a0b1b346-4d3e-4e8b-98f8-753987be4970": "Guest users have the same access as members",
    "10dae51f-b6af-4016-8d66-8c2a99b929b3": "Guest users have limited access to properties and memberships of directory objects",
    "2af84b1e-32c8-42b7-82bc-daa82404023b": "Guest user access is restricted to properties and memberships of their own directory objects",
}

SAME_AS_MEMBERS_ROLE_ID = "a0b1b346-4d3e-4e8b-98f8-753987be4970"


async def check_guest_access(client: GraphServiceClient) -> CheckResult:
    """Check the access level granted to guest users.

    Calls GET /policies/authorizationPolicy and checks guestUserRoleId.

    Pass: Guest users have limited or restricted access
    Fail: Guest users have the same access as members
    """
    response = await client.policies.authorization_policy.get()

    guest_user_role_id = getattr(response, "guest_user_role_id", None)

    # Handle UUID objects - msgraph-sdk may return a UUID instead of a string
    if guest_user_role_id is not None:
        guest_user_role_id = str(guest_user_role_id)

    if guest_user_role_id is None:
        return CheckResult(
            check_id="guest-access",
            status="error",
            message="Could not determine guest user access level.",
            details={"error": "guestUserRoleId property not found in response"},
        )

    access_description = GUEST_ROLE_IDS.get(
        guest_user_role_id, f"Unknown role ID: {guest_user_role_id}"
    )

    if guest_user_role_id == SAME_AS_MEMBERS_ROLE_ID:
        return CheckResult(
            check_id="guest-access",
            status="fail",
            message="Guest users have the same access as member users.",
            recommendation="Restrict guest access to limited or restricted level.",
            details={
                "guest_user_role_id": guest_user_role_id,
                "access_level": access_description,
            },
        )

    return CheckResult(
        check_id="guest-access",
        status="pass",
        message=f"Guest user access is appropriately restricted: {access_description}.",
        details={
            "guest_user_role_id": guest_user_role_id,
            "access_level": access_description,
        },
    )
