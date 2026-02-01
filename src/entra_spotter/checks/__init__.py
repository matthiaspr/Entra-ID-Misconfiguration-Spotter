"""Check types and registry."""

from dataclasses import dataclass
from typing import Callable, Literal

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
    run: Callable[[GraphServiceClient], CheckResult]


# Import checks - these will be added as we implement them
from entra_spotter.checks.user_consent import check_user_consent
from entra_spotter.checks.admin_consent_workflow import check_admin_consent_workflow
from entra_spotter.checks.sp_admin_roles import check_sp_admin_roles
from entra_spotter.checks.sp_graph_roles import check_sp_graph_roles

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
]
