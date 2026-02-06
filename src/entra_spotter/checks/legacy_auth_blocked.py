"""Check for Conditional Access policy blocking legacy authentication."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult
from entra_spotter.checks._ca_helpers import get_policy_exclusions, has_any_exclusions

# Legacy authentication client app types that should be blocked
LEGACY_CLIENT_TYPES = {"exchangeActiveSync", "other"}


def _is_legacy_auth_blocking_policy(policy: object) -> bool:
    """Check if a policy blocks legacy authentication for all apps."""
    # Must have grant controls with block
    grant_controls = getattr(policy, "grant_controls", None)
    if not grant_controls:
        return False

    built_in_controls = getattr(grant_controls, "built_in_controls", None) or []
    if "block" not in built_in_controls:
        return False

    # Must target legacy client app types (both exchangeActiveSync AND other)
    conditions = getattr(policy, "conditions", None)
    if not conditions:
        return False

    client_app_types = set(getattr(conditions, "client_app_types", None) or [])
    if not LEGACY_CLIENT_TYPES.issubset(client_app_types):
        return False

    # Must target all applications
    applications = getattr(conditions, "applications", None)
    if not applications:
        return False

    include_applications = getattr(applications, "include_applications", None) or []
    if "All" not in include_applications:
        return False

    return True


async def check_legacy_auth_blocked(client: GraphServiceClient) -> CheckResult:
    """Check for Conditional Access policy blocking legacy authentication.

    Looks for CA policies that:
    - Block access (grant controls)
    - Target legacy client apps (exchangeActiveSync AND other)
    - Apply to all applications

    Pass: Enforced policy exists with no exclusions
    Warning: Policy exists but has exclusions OR only report-only policies exist
    Fail: No policy blocks legacy authentication
    """
    response = await client.identity.conditional_access.policies.get()
    policies = response.value or []

    enforced_policies: list[dict] = []
    report_only_policies: list[dict] = []

    for policy in policies:
        if not _is_legacy_auth_blocking_policy(policy):
            continue

        state = getattr(policy, "state", None)
        policy_info = {
            "name": getattr(policy, "display_name", "Unknown"),
            "id": getattr(policy, "id", None),
            "state": state,
            "exclusions": get_policy_exclusions(policy),
        }

        if state == "enabled":
            enforced_policies.append(policy_info)
        elif state == "enabledForReportingButNotEnforced":
            report_only_policies.append(policy_info)

    # No policies found at all
    if not enforced_policies and not report_only_policies:
        return CheckResult(
            check_id="legacy-auth-blocked",
            status="fail",
            message="No Conditional Access policy blocks legacy authentication.",
            recommendation=(
                "Create a CA policy that blocks 'Exchange ActiveSync clients' and "
                "'Other clients' for all cloud apps."
            ),
        )

    # Only report-only policies exist
    if not enforced_policies:
        return CheckResult(
            check_id="legacy-auth-blocked",
            status="warning",
            message=(
                f"{len(report_only_policies)} policy(ies) block legacy auth but are "
                "in report-only mode (not enforced)."
            ),
            recommendation="Enable the policy to enforce blocking of legacy authentication.",
            details={
                "enforced_policies": [],
                "report_only_policies": report_only_policies,
            },
        )

    # Check if any enforced policy has exclusions
    policies_with_exclusions = [
        p for p in enforced_policies if has_any_exclusions(p["exclusions"])
    ]

    if policies_with_exclusions:
        return CheckResult(
            check_id="legacy-auth-blocked",
            status="warning",
            message=(
                f"{len(enforced_policies)} policy(ies) block legacy auth but "
                f"{len(policies_with_exclusions)} have exclusions requiring review."
            ),
            recommendation="Review exclusions to ensure they are necessary and justified.",
            details={
                "enforced_policies": enforced_policies,
                "report_only_policies": report_only_policies,
            },
        )

    # Enforced policy exists with no exclusions
    return CheckResult(
        check_id="legacy-auth-blocked",
        status="pass",
        message=f"{len(enforced_policies)} policy(ies) block legacy authentication.",
        details={
            "enforced_policies": enforced_policies,
            "report_only_policies": report_only_policies,
        },
    )
