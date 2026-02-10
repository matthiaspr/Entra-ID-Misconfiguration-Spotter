"""Check for Conditional Access policy enforcing MFA for privileged roles."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult
from entra_spotter.checks._shared import (
    PRIVILEGED_ROLES,
    collect_ca_policies,
    has_any_exclusions,
    is_strict_mfa,
    targets_all_apps,
)


def _is_mfa_policy_for_roles(policy: object) -> tuple[bool, set[str]]:
    """Check if a policy requires MFA for roles and return covered role IDs.

    Returns:
        Tuple of (is_valid_mfa_policy, set_of_covered_role_ids)
    """
    if not is_strict_mfa(getattr(policy, "grant_controls", None)):
        return False, set()

    conditions = getattr(policy, "conditions", None)
    if not conditions:
        return False, set()

    if not targets_all_apps(conditions):
        return False, set()

    # Must target specific roles
    users = getattr(conditions, "users", None)
    if not users:
        return False, set()

    include_roles = set(getattr(users, "include_roles", None) or [])
    if not include_roles:
        return False, set()

    # Return the intersection of included roles and our privileged roles
    covered_privileged_roles = include_roles & set(PRIVILEGED_ROLES.keys())
    return True, covered_privileged_roles


async def check_privileged_roles_mfa(client: GraphServiceClient) -> CheckResult:
    """Check for Conditional Access policy enforcing MFA for privileged roles.

    Looks for CA policies that:
    - Require MFA (grant controls)
    - Target specific privileged roles (conditions.users.includeRoles)
    - Apply to all applications

    All 14 privileged roles must be covered by one or more policies.

    Pass: All privileged roles covered by MFA policies with no exclusions
    Warning: All roles covered but policies have exclusions
    Fail: One or more privileged roles not covered OR only report-only policies exist
    """
    response = await client.identity.conditional_access.policies.get()
    policies = response.value or []

    def _policy_info(policy: object) -> dict | None:
        is_mfa_policy, covered_roles = _is_mfa_policy_for_roles(policy)
        if not is_mfa_policy or not covered_roles:
            return None
        return {
            "covered_roles": [
                PRIVILEGED_ROLES[r] for r in covered_roles if r in PRIVILEGED_ROLES
            ],
            "covered_role_ids": list(covered_roles),
        }

    enforced_policies, report_only_policies = collect_ca_policies(policies, _policy_info)

    def _covered_role_ids(policy_list: list[dict]) -> set[str]:
        covered: set[str] = set()
        for policy in policy_list:
            covered.update(policy.get("covered_role_ids", []))
        return covered

    enforced_covered_roles = _covered_role_ids(enforced_policies)
    report_only_covered_roles = _covered_role_ids(report_only_policies)

    # Determine which roles are missing coverage
    all_privileged_role_ids = set(PRIVILEGED_ROLES.keys())
    enforced_missing = all_privileged_role_ids - enforced_covered_roles
    report_only_missing = all_privileged_role_ids - report_only_covered_roles

    # Build details
    details = {
        "enforced_policies": enforced_policies,
        "report_only_policies": report_only_policies,
        "total_privileged_roles": len(PRIVILEGED_ROLES),
        "enforced_covered_count": len(enforced_covered_roles),
    }

    # No enforced policies cover any roles
    if not enforced_covered_roles:
        # Check if report-only policies exist
        if report_only_covered_roles:
            missing_names = [PRIVILEGED_ROLES[r] for r in report_only_missing]
            details["roles_not_covered"] = missing_names if missing_names else []
            return CheckResult(
                check_id="privileged-roles-mfa",
                status="fail",
                message=(
                    f"MFA policies for privileged roles exist but are in report-only mode. "
                    f"{len(report_only_covered_roles)}/{len(PRIVILEGED_ROLES)} roles covered."
                ),
                recommendation="Enable the policies to enforce MFA for privileged roles.",
                details=details,
            )

        return CheckResult(
            check_id="privileged-roles-mfa",
            status="fail",
            message="No Conditional Access policy enforces MFA for privileged roles.",
            recommendation=(
                "Create a CA policy that requires MFA for privileged directory roles "
                "targeting all cloud apps."
            ),
            details=details,
        )

    # Some roles not covered by enforced policies
    if enforced_missing:
        missing_names = [PRIVILEGED_ROLES[r] for r in enforced_missing]
        details["roles_not_covered"] = missing_names
        return CheckResult(
            check_id="privileged-roles-mfa",
            status="fail",
            message=(
                f"{len(enforced_missing)}/{len(PRIVILEGED_ROLES)} privileged roles "
                "not covered by MFA policy."
            ),
            recommendation=(
                f"Extend MFA policies to cover: {', '.join(missing_names)}"
            ),
            details=details,
        )

    # All roles covered - check for exclusions
    policies_with_exclusions = [
        p for p in enforced_policies if has_any_exclusions(p["exclusions"])
    ]

    if policies_with_exclusions:
        return CheckResult(
            check_id="privileged-roles-mfa",
            status="warning",
            message=(
                f"All {len(PRIVILEGED_ROLES)} privileged roles require MFA but "
                f"{len(policies_with_exclusions)} policy(ies) have exclusions."
            ),
            recommendation="Review exclusions to ensure they are necessary and justified.",
            details=details,
        )

    # All roles covered, no exclusions
    return CheckResult(
        check_id="privileged-roles-mfa",
        status="pass",
        message=f"All {len(PRIVILEGED_ROLES)} privileged roles require MFA.",
        details=details,
    )
