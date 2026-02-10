"""Shared helpers and constants for security checks."""

from typing import Callable

# Privileged role template IDs that should require MFA / phishing-resistant MFA.
# https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
PRIVILEGED_ROLES: dict[str, str] = {
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

# Sensitive MS Graph app role IDs that allow privilege escalation if compromised.
SENSITIVE_APP_ROLES: dict[str, str] = {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "50483e42-d915-4231-9639-7fdb7fd190e5": "UserAuthenticationMethod.ReadWrite.All",
}


def get_policy_exclusions(policy: object) -> dict[str, list]:
    """Extract all exclusions from a Conditional Access policy."""
    exclusions: dict[str, list] = {
        "users": [],
        "groups": [],
        "roles": [],
        "applications": [],
    }

    conditions = getattr(policy, "conditions", None)
    if not conditions:
        return exclusions

    # User exclusions
    users = getattr(conditions, "users", None)
    if users:
        exclusions["users"] = getattr(users, "exclude_users", None) or []
        exclusions["groups"] = getattr(users, "exclude_groups", None) or []
        exclusions["roles"] = getattr(users, "exclude_roles", None) or []

    # Application exclusions
    applications = getattr(conditions, "applications", None)
    if applications:
        exclusions["applications"] = (
            getattr(applications, "exclude_applications", None) or []
        )

    return exclusions


def has_any_exclusions(exclusions: dict[str, list]) -> bool:
    """Check if there are any exclusions."""
    return any(len(v) > 0 for v in exclusions.values())


def collect_ca_policies(
    policies: list[object],
    evaluator: Callable[[object], dict | None],
) -> tuple[list[dict], list[dict]]:
    """Collect matching CA policies partitioned by enforcement state.

    evaluator returns a dict of extra fields to include for matching policies,
    or None to skip a policy.
    """
    enforced_policies: list[dict] = []
    report_only_policies: list[dict] = []

    for policy in policies:
        extra = evaluator(policy)
        if extra is None:
            continue

        state = getattr(policy, "state", None)
        policy_info = {
            "name": getattr(policy, "display_name", "Unknown"),
            "id": getattr(policy, "id", None),
            "state": state,
            "exclusions": get_policy_exclusions(policy),
        }
        policy_info.update(extra)

        if state == "enabled":
            enforced_policies.append(policy_info)
        elif state == "enabledForReportingButNotEnforced":
            report_only_policies.append(policy_info)

    return enforced_policies, report_only_policies


def targets_all_apps(conditions: object | None) -> bool:
    """Return True if CA policy targets all applications."""
    if not conditions:
        return False

    applications = getattr(conditions, "applications", None)
    if not applications:
        return False

    include_applications = getattr(applications, "include_applications", None) or []
    return "All" in include_applications


def targets_all_users(conditions: object | None) -> bool:
    """Return True if CA policy targets all users."""
    if not conditions:
        return False

    users = getattr(conditions, "users", None)
    if not users:
        return False

    include_users = getattr(users, "include_users", None) or []
    return "All" in include_users


def is_strict_mfa(grant_controls: object | None) -> bool:
    """Return True if MFA is strictly required without OR bypass."""
    if not grant_controls:
        return False

    built_in_controls = getattr(grant_controls, "built_in_controls", None) or []
    if "mfa" not in built_in_controls:
        return False

    operator = getattr(grant_controls, "operator", None)
    if operator == "AND":
        return True

    return built_in_controls == ["mfa"]


def is_strict_auth_strength(grant_controls: object | None, strength_id: str) -> bool:
    """Return True if required authentication strength is strictly enforced."""
    if not grant_controls:
        return False

    auth_strength = getattr(grant_controls, "authentication_strength", None)
    if not auth_strength:
        return False

    current_id = getattr(auth_strength, "id", None)
    if current_id is not None:
        current_id = str(current_id)
    if current_id != strength_id:
        return False

    built_in_controls = getattr(grant_controls, "built_in_controls", None) or []
    operator = getattr(grant_controls, "operator", None)
    if operator == "AND":
        return True

    return not built_in_controls
