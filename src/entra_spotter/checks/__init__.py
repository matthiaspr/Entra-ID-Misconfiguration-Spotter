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


# Import checks - these will be added as we implement them
from entra_spotter.checks.user_consent import check_user_consent
from entra_spotter.checks.admin_consent_workflow import check_admin_consent_workflow
from entra_spotter.checks.sp_admin_roles import check_sp_admin_roles
from entra_spotter.checks.sp_graph_roles import check_sp_graph_roles
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
from entra_spotter.checks.unused_apps_cleanup import check_unused_apps_cleanup
from entra_spotter.checks.auth_methods_number_matching import check_auth_methods_number_matching
from entra_spotter.checks.break_glass_exclusion import check_break_glass_exclusion

ALL_CHECKS: list[Check] = [
    Check(
        id="user-consent",
        name="User Consent Settings",
        run=check_user_consent,
    ),
    Check(
        id="admin-consent-workflow",
        name="Admin Consent Workflow",
        run=check_admin_consent_workflow,
    ),
    Check(
        id="sp-admin-roles",
        name="Service Principal Admin Roles",
        run=check_sp_admin_roles,
    ),
    Check(
        id="sp-graph-roles",
        name="Service Principal MS Graph Roles",
        run=check_sp_graph_roles,
    ),
    Check(
        id="legacy-auth-blocked",
        name="Legacy Authentication Blocked",
        run=check_legacy_auth_blocked,
    ),
    Check(
        id="device-code-blocked",
        name="Device Code Flow Blocked",
        run=check_device_code_blocked,
    ),
    Check(
        id="privileged-roles-mfa",
        name="MFA for Privileged Roles",
        run=check_privileged_roles_mfa,
    ),
    Check(
        id="global-admin-count",
        name="Global Administrator Count",
        run=check_global_admin_count,
    ),
    Check(
        id="guest-invite-policy",
        name="Guest Invitation Policy",
        run=check_guest_invite_policy,
    ),
    Check(
        id="guest-access",
        name="Guest User Access Level",
        run=check_guest_access,
    ),
    Check(
        id="privileged-roles-phishing-resistant-mfa",
        name="Phishing-Resistant MFA for Privileged Roles",
        run=check_privileged_roles_phishing_resistant_mfa,
    ),
    Check(
        id="shadow-admins-app-owners",
        name="Shadow Admins via App Ownership",
        run=check_shadow_admins_app_owners,
    ),
    Check(
        id="shadow-admins-group-owners",
        name="Shadow Admins via Group Ownership",
        run=check_shadow_admins_group_owners,
    ),
    Check(
        id="dynamic-group-hijack",
        name="Dynamic Group Privilege Escalation",
        run=check_dynamic_group_hijack,
    ),
    Check(
        id="unused-apps-cleanup",
        name="Unused Privileged Applications",
        run=check_unused_apps_cleanup,
    ),
    Check(
        id="auth-methods-number-matching",
        name="Authenticator Number Matching",
        run=check_auth_methods_number_matching,
    ),
    Check(
        id="break-glass-exclusion",
        name="Break-Glass Account CA Exclusion",
        run=check_break_glass_exclusion,
    ),
]
