"""Check for Conditional Access policy enforcing phishing-resistant MFA for privileged roles."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult

# Built-in authentication strength policy ID for phishing-resistant MFA.
# See: https://learn.microsoft.com/en-us/graph/api/resources/authenticationstrengths-overview
PHISHING_RESISTANT_STRENGTH_ID = "00000000-0000-0000-0000-000000000004"

# Same privileged role template IDs as the regular MFA check.
# https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
PRIVILEGED_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}


def _is_phishing_resistant_mfa_policy_for_roles(policy) -> tuple[bool, set[str]]:
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


def _get_policy_exclusions(policy) -> dict:
    """Extract all exclusions from a policy."""
    exclusions: dict[str, list] = {
        "users": [],
        "groups": [],
        "roles": [],
        "applications": [],
    }

    conditions = getattr(policy, "conditions", None)
    if not conditions:
        return exclusions

    users = getattr(conditions, "users", None)
    if users:
        exclusions["users"] = getattr(users, "exclude_users", None) or []
        exclusions["groups"] = getattr(users, "exclude_groups", None) or []
        exclusions["roles"] = getattr(users, "exclude_roles", None) or []

    applications = getattr(conditions, "applications", None)
    if applications:
        exclusions["applications"] = (
            getattr(applications, "exclude_applications", None) or []
        )

    return exclusions


def _has_any_exclusions(exclusions: dict) -> bool:
    """Check if there are any exclusions."""
    return any(len(v) > 0 for v in exclusions.values())


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

    # Track which roles are covered by enforced vs report-only policies
    enforced_covered_roles: set[str] = set()
    report_only_covered_roles: set[str] = set()

    enforced_policies: list[dict] = []
    report_only_policies: list[dict] = []

    for policy in policies:
        is_valid, covered_roles = _is_phishing_resistant_mfa_policy_for_roles(policy)
        if not is_valid or not covered_roles:
            continue

        state = getattr(policy, "state", None)
        policy_info = {
            "name": getattr(policy, "display_name", "Unknown"),
            "id": getattr(policy, "id", None),
            "state": state,
            "covered_roles": [
                PRIVILEGED_ROLES[r] for r in covered_roles if r in PRIVILEGED_ROLES
            ],
            "exclusions": _get_policy_exclusions(policy),
        }

        if state == "enabled":
            enforced_policies.append(policy_info)
            enforced_covered_roles.update(covered_roles)
        elif state == "enabledForReportingButNotEnforced":
            report_only_policies.append(policy_info)
            report_only_covered_roles.update(covered_roles)

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
        p for p in enforced_policies if _has_any_exclusions(p["exclusions"])
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
