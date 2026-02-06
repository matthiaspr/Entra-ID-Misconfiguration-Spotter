"""Check for Conditional Access policy blocking device code flow."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult
from entra_spotter.checks._ca_helpers import get_policy_exclusions, has_any_exclusions


def _is_device_code_blocking_policy(policy: object) -> bool:
    """Check if a policy blocks device code flow for all apps."""
    # Must have grant controls with block
    grant_controls = getattr(policy, "grant_controls", None)
    if not grant_controls:
        return False

    built_in_controls = getattr(grant_controls, "built_in_controls", None) or []
    if "block" not in built_in_controls:
        return False

    conditions = getattr(policy, "conditions", None)
    if not conditions:
        return False

    # Must target device code flow in authentication flows
    auth_flows = getattr(conditions, "authentication_flows", None)
    if not auth_flows:
        return False

    transfer_methods = getattr(auth_flows, "transfer_methods", None) or []
    if "deviceCodeFlow" not in transfer_methods:
        return False

    # Must target all applications
    applications = getattr(conditions, "applications", None)
    if not applications:
        return False

    include_applications = getattr(applications, "include_applications", None) or []
    if "All" not in include_applications:
        return False

    return True


async def check_device_code_blocked(client: GraphServiceClient) -> CheckResult:
    """Check for Conditional Access policy blocking device code flow.

    Looks for CA policies that:
    - Block access (grant controls)
    - Target device code flow (authentication flows condition)
    - Apply to all applications

    Pass: Enforced policy exists with no exclusions
    Warning: Policy exists but has exclusions OR only report-only policies exist
    Fail: No policy blocks device code flow
    """
    response = await client.identity.conditional_access.policies.get()
    policies = response.value or []

    enforced_policies: list[dict] = []
    report_only_policies: list[dict] = []

    for policy in policies:
        if not _is_device_code_blocking_policy(policy):
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
            check_id="device-code-blocked",
            status="fail",
            message="No Conditional Access policy blocks device code flow.",
            recommendation=(
                "Create a CA policy that blocks device code flow authentication "
                "for all cloud apps to prevent phishing attacks."
            ),
        )

    # Only report-only policies exist
    if not enforced_policies:
        return CheckResult(
            check_id="device-code-blocked",
            status="warning",
            message=(
                f"{len(report_only_policies)} policy(ies) block device code flow but are "
                "in report-only mode (not enforced)."
            ),
            recommendation="Enable the policy to enforce blocking of device code flow.",
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
            check_id="device-code-blocked",
            status="warning",
            message=(
                f"{len(enforced_policies)} policy(ies) block device code flow but "
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
        check_id="device-code-blocked",
        status="pass",
        message=f"{len(enforced_policies)} policy(ies) block device code flow.",
        details={
            "enforced_policies": enforced_policies,
            "report_only_policies": report_only_policies,
        },
    )
