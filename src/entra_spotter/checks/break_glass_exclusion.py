"""Check that break-glass accounts are excluded from Conditional Access policies."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult
from entra_spotter.checks._shared import get_policy_exclusions


async def check_break_glass_exclusion(client: GraphServiceClient) -> CheckResult:
    """Check that emergency access accounts are excluded from all CA policies.

    Verifies that at least 1 (preferably 2) user accounts are excluded from
    ALL enabled Conditional Access policies. These "break glass" accounts
    prevent permanent tenant lockout if a bad CA policy is deployed.

    Pass: At least 2 accounts excluded from all enabled CA policies
    Warning: Only 1 account excluded from all enabled CA policies
    Fail: No account is excluded from all enabled CA policies
    """
    response = await client.identity.conditional_access.policies.get()
    policies = response.value or []

    # Only check enabled policies (not disabled or report-only)
    enabled_policies = [
        p for p in policies
        if getattr(p, "state", None) == "enabled"
    ]

    if not enabled_policies:
        return CheckResult(
            check_id="break-glass-exclusion",
            status="warning",
            message="No enabled Conditional Access policies found.",
            recommendation="Deploy Conditional Access policies and ensure break-glass accounts are excluded.",
            details={"enabled_policy_count": 0},
        )

    # For each policy, collect the set of excluded user IDs
    # A break-glass account must be excluded from ALL enabled policies
    policy_excluded_users: list[set[str]] = []
    policy_names: list[str] = []

    for policy in enabled_policies:
        exclusions = get_policy_exclusions(policy)
        excluded_user_ids = set(exclusions.get("users", []))
        policy_excluded_users.append(excluded_user_ids)
        policy_names.append(getattr(policy, "display_name", "Unknown"))

    # Find users excluded from ALL enabled policies
    if policy_excluded_users:
        common_excluded = policy_excluded_users[0]
        for excluded_set in policy_excluded_users[1:]:
            common_excluded = common_excluded & excluded_set
    else:
        common_excluded = set()

    details = {
        "enabled_policy_count": len(enabled_policies),
        "break_glass_candidates": list(common_excluded),
        "break_glass_count": len(common_excluded),
    }

    if len(common_excluded) == 0:
        return CheckResult(
            check_id="break-glass-exclusion",
            status="fail",
            message=(
                f"No user account is excluded from all {len(enabled_policies)} "
                "enabled Conditional Access policies."
            ),
            recommendation=(
                "Create at least 2 emergency access (break-glass) accounts and exclude "
                "them from ALL Conditional Access policies to prevent tenant lockout."
            ),
            details=details,
        )

    if len(common_excluded) == 1:
        return CheckResult(
            check_id="break-glass-exclusion",
            status="warning",
            message=(
                "Only 1 account is excluded from all enabled Conditional Access policies. "
                "Best practice is to have at least 2 break-glass accounts."
            ),
            recommendation="Create a second emergency access account and exclude it from all CA policies.",
            details=details,
        )

    return CheckResult(
        check_id="break-glass-exclusion",
        status="pass",
        message=(
            f"{len(common_excluded)} account(s) are excluded from all "
            f"{len(enabled_policies)} enabled Conditional Access policies."
        ),
        details=details,
    )
