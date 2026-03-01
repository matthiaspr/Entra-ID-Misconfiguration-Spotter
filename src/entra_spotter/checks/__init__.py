"""Check types and registry."""

from dataclasses import dataclass
from typing import Awaitable, Callable, Literal

from msgraph import GraphServiceClient

Status = Literal["pass", "fail", "warning", "error"]


@dataclass
class CheckResult:
    """Result of a single check."""

    check_id: str
    status: Status
    message: str
    recommendation: str | None = None
    details: dict | None = None


@dataclass
class Check:
    """A check definition."""

    id: str
    name: str
    run: Callable[[GraphServiceClient], Awaitable[CheckResult]]
    category: str = ""


CATEGORIES: list[str] = [
    "Application & Consent",
    "Conditional Access",
    "Privileged Role Security",
    "Shadow Admin Detection",
    "Guest & Authentication",
]


# Import checks - these will be added as we implement them
from entra_spotter.checks.user_consent import check_user_consent
from entra_spotter.checks.admin_consent_workflow import check_admin_consent_workflow
from entra_spotter.checks.sp_admin_roles import check_sp_admin_roles
from entra_spotter.checks.sp_graph_roles import check_sp_graph_roles
from entra_spotter.checks.sp_multiple_secrets import check_sp_multiple_secrets
from entra_spotter.checks.legacy_auth_blocked import check_legacy_auth_blocked
from entra_spotter.checks.device_code_blocked import check_device_code_blocked
from entra_spotter.checks.privileged_roles_mfa import check_privileged_roles_mfa
from entra_spotter.checks.global_admin_count import check_global_admin_count
from entra_spotter.checks.guest_invite_policy import check_guest_invite_policy
from entra_spotter.checks.guest_access import check_guest_access
from entra_spotter.checks.privileged_roles_phishing_resistant_mfa import check_privileged_roles_phishing_resistant_mfa
from entra_spotter.checks.shadow_admins_app_owners import check_shadow_admins_app_owners
from entra_spotter.checks.shadow_admins_group_owners import check_shadow_admins_group_owners
from entra_spotter.checks.dynamic_group_hijack import check_dynamic_group_hijack
from entra_spotter.checks.auth_methods_number_matching import check_auth_methods_number_matching
from entra_spotter.checks.break_glass_exclusion import check_break_glass_exclusion
from entra_spotter.checks.privileged_roles_license import check_privileged_roles_license

ALL_CHECKS: list[Check] = [
    Check(
        id="user-consent",
        name="User Consent Settings",
        run=check_user_consent,
        category="Application & Consent",
    ),
    Check(
        id="admin-consent-workflow",
        name="Admin Consent Workflow",
        run=check_admin_consent_workflow,
        category="Application & Consent",
    ),
    Check(
        id="sp-admin-roles",
        name="Service Principal Admin Roles",
        run=check_sp_admin_roles,
        category="Application & Consent",
    ),
    Check(
        id="sp-graph-roles",
        name="Service Principal MS Graph Roles",
        run=check_sp_graph_roles,
        category="Application & Consent",
    ),
    Check(
        id="sp-multiple-secrets",
        name="Service Principal Multiple Secrets",
        run=check_sp_multiple_secrets,
        category="Application & Consent",
    ),
    Check(
        id="legacy-auth-blocked",
        name="Legacy Authentication Blocked",
        run=check_legacy_auth_blocked,
        category="Conditional Access",
    ),
    Check(
        id="device-code-blocked",
        name="Device Code Flow Blocked",
        run=check_device_code_blocked,
        category="Conditional Access",
    ),
    Check(
        id="privileged-roles-mfa",
        name="MFA for Privileged Roles",
        run=check_privileged_roles_mfa,
        category="Privileged Role Security",
    ),
    Check(
        id="global-admin-count",
        name="Global Administrator Count",
        run=check_global_admin_count,
        category="Privileged Role Security",
    ),
    Check(
        id="guest-invite-policy",
        name="Guest Invitation Policy",
        run=check_guest_invite_policy,
        category="Guest & Authentication",
    ),
    Check(
        id="guest-access",
        name="Guest User Access Level",
        run=check_guest_access,
        category="Guest & Authentication",
    ),
    Check(
        id="privileged-roles-phishing-resistant-mfa",
        name="Phishing-Resistant MFA for Privileged Roles",
        run=check_privileged_roles_phishing_resistant_mfa,
        category="Privileged Role Security",
    ),
    Check(
        id="shadow-admins-app-owners",
        name="Shadow Admins via App Ownership",
        run=check_shadow_admins_app_owners,
        category="Shadow Admin Detection",
    ),
    Check(
        id="shadow-admins-group-owners",
        name="Shadow Admins via Group Ownership",
        run=check_shadow_admins_group_owners,
        category="Shadow Admin Detection",
    ),
    Check(
        id="dynamic-group-hijack",
        name="Dynamic Group Privilege Escalation",
        run=check_dynamic_group_hijack,
        category="Shadow Admin Detection",
    ),
    Check(
        id="auth-methods-number-matching",
        name="Authenticator Number Matching",
        run=check_auth_methods_number_matching,
        category="Guest & Authentication",
    ),
    Check(
        id="break-glass-exclusion",
        name="Break-Glass Account CA Exclusion",
        run=check_break_glass_exclusion,
        category="Conditional Access",
    ),
    Check(
        id="privileged-roles-license",
        name="Entra P1/P2 for Privileged Role Members",
        run=check_privileged_roles_license,
        category="Privileged Role Security",
    ),
]
