"""Check for Conditional Access policy enforcing phishing-resistant MFA for privileged roles."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult
from entra_spotter.checks._shared import (
    PRIVILEGED_ROLES,
    collect_ca_policies,
    has_any_exclusions,
)

# Built-in authentication strength policy ID for phishing-resistant MFA.
# See: https://learn.microsoft.com/en-us/graph/api/resources/authenticationstrengths-overview
PHISHING_RESISTANT_STRENGTH_ID = "00000000-0000-0000-0000-000000000004"


def _is_phishing_resistant_mfa_policy_for_roles(policy: object) -> tuple[bool, set[str]]:
    """Check if a policy requires phishing-resistant MFA for roles.

    Returns:
        Tuple of (is_valid_policy, set_of_covered_role_ids)
    """
    # Must have grant controls with authentication strength
    grant_controls = getattr(policy, "grant_controls", None)
    if not grant_controls:
        return False, set()

    auth_strength = getattr(grant_controls, "authentication_strength", None)
    if not auth_strength:
        return False, set()

    strength_id = getattr(auth_strength, "id", None)
    if strength_id is not None:
        strength_id = str(strength_id)
    if strength_id != PHISHING_RESISTANT_STRENGTH_ID:
        return False, set()

    conditions = getattr(policy, "conditions", None)
    if not conditions:
        return False, set()

    # Must target all applications
    applications = getattr(conditions, "applications", None)
    if not applications:
        return False, set()

    include_applications = getattr(applications, "include_applications", None) or []
    if "All" not in include_applications:
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


async def check_privileged_roles_phishing_resistant_mfa(
    client: GraphServiceClient,
) -> CheckResult:
    """Check for CA policy enforcing phishing-resistant MFA for privileged roles.

    Looks for CA policies that:
    - Require phishing-resistant MFA authentication strength (grant controls)
    - Target specific privileged roles (conditions.users.includeRoles)
    - Apply to all applications

    All 14 privileged roles must be covered by one or more policies.

    Pass: All privileged roles covered with no exclusions
    Warning: All roles covered but policies have exclusions OR only report-only
    Fail: One or more privileged roles not covered
    """
    response = await client.identity.conditional_access.policies.get()
    policies = response.value or []

    def _policy_info(policy: object) -> dict | None:
        is_valid, covered_roles = _is_phishing_resistant_mfa_policy_for_roles(policy)
        if not is_valid or not covered_roles:
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

    details = {
        "enforced_policies": enforced_policies,
        "report_only_policies": report_only_policies,
        "total_privileged_roles": len(PRIVILEGED_ROLES),
        "enforced_covered_count": len(enforced_covered_roles),
    }

    # No enforced policies cover any roles
    if not enforced_covered_roles:
        if report_only_covered_roles:
            missing_names = [PRIVILEGED_ROLES[r] for r in report_only_missing]
            details["roles_not_covered"] = missing_names if missing_names else []
            return CheckResult(
                check_id="privileged-roles-phishing-resistant-mfa",
                status="warning",
                message=(
                    "Phishing-resistant MFA policies for privileged roles exist but "
                    "are in report-only mode. "
                    f"{len(report_only_covered_roles)}/{len(PRIVILEGED_ROLES)} "
                    "roles covered."
                ),
                recommendation="Enable the policies to enforce phishing-resistant MFA for privileged roles.",
                details=details,
            )

        return CheckResult(
            check_id="privileged-roles-phishing-resistant-mfa",
            status="fail",
            message="No Conditional Access policy enforces phishing-resistant MFA for privileged roles.",
            recommendation=(
                "Create a CA policy that requires phishing-resistant MFA authentication "
                "strength for privileged directory roles targeting all cloud apps."
            ),
            details=details,
        )

    # Some roles not covered by enforced policies
    if enforced_missing:
        missing_names = [PRIVILEGED_ROLES[r] for r in enforced_missing]
        details["roles_not_covered"] = missing_names
        return CheckResult(
            check_id="privileged-roles-phishing-resistant-mfa",
            status="fail",
            message=(
                f"{len(enforced_missing)}/{len(PRIVILEGED_ROLES)} privileged roles "
                "not covered by phishing-resistant MFA policy."
            ),
            recommendation=(
                f"Extend phishing-resistant MFA policies to cover: {', '.join(missing_names)}"
            ),
            details=details,
        )

    # All roles covered - check for exclusions
    policies_with_exclusions = [
        p for p in enforced_policies if has_any_exclusions(p["exclusions"])
    ]

    if policies_with_exclusions:
        return CheckResult(
            check_id="privileged-roles-phishing-resistant-mfa",
            status="warning",
            message=(
                f"All {len(PRIVILEGED_ROLES)} privileged roles require "
                "phishing-resistant MFA but "
                f"{len(policies_with_exclusions)} policy(ies) have exclusions."
            ),
            recommendation="Review exclusions to ensure they are necessary and justified.",
            details=details,
        )

    return CheckResult(
        check_id="privileged-roles-phishing-resistant-mfa",
        status="pass",
        message=f"All {len(PRIVILEGED_ROLES)} privileged roles require phishing-resistant MFA.",
        details=details,
    )
