"""Check for unused privileged service principals."""

from datetime import datetime, timedelta, timezone

from msgraph import GraphServiceClient
from msgraph.generated.role_management.directory.role_assignments.role_assignments_request_builder import (
    RoleAssignmentsRequestBuilder,
)
from msgraph.generated.service_principals.service_principals_request_builder import (
    ServicePrincipalsRequestBuilder,
)

from entra_spotter.checks import CheckResult
from entra_spotter.checks._ca_helpers import PRIVILEGED_ROLES

# Sensitive MS Graph app role IDs
SENSITIVE_APP_ROLES: dict[str, str] = {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "50483e42-d915-4231-9639-7fdb7fd190e5": "UserAuthenticationMethod.ReadWrite.All",
}

INACTIVITY_DAYS = 180


async def check_unused_apps_cleanup(client: GraphServiceClient) -> CheckResult:
    """Check for privileged service principals that have not signed in recently.

    Identifies service principals with privileged directory roles or sensitive
    Graph permissions that have not signed in for >180 days. Forgotten apps
    are targets for credential stuffing or secret leakage.

    Warning: Privileged service principals with no recent sign-in activity
    Pass: All privileged service principals have recent sign-in activity
    """
    # Step 1: Find service principals with privileged directory roles
    query_params = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetQueryParameters(
        expand=["principal"],
    )
    request_config = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    assignments_response = await client.role_management.directory.role_assignments.get(
        request_configuration=request_config
    )
    assignments = assignments_response.value or []

    privileged_sp_ids: dict[str, dict] = {}  # sp_id -> {name, privileges}
    for assignment in assignments:
        if assignment.role_definition_id not in PRIVILEGED_ROLES:
            continue
        principal = assignment.principal
        if not principal:
            continue
        odata_type = getattr(principal, "odata_type", "")
        if odata_type == "#microsoft.graph.servicePrincipal":
            sp_id = principal.id
            role_name = PRIVILEGED_ROLES[assignment.role_definition_id]
            if sp_id not in privileged_sp_ids:
                privileged_sp_ids[sp_id] = {
                    "display_name": getattr(principal, "display_name", "Unknown"),
                    "privileges": [],
                }
            privileged_sp_ids[sp_id]["privileges"].append(role_name)

    # Step 2: Find service principals with sensitive Graph app roles
    sp_query = ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetQueryParameters(
        expand=["appRoleAssignments"],
    )
    sp_config = ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetRequestConfiguration(
        query_parameters=sp_query,
    )
    sp_response = await client.service_principals.get(request_configuration=sp_config)

    while sp_response:
        for sp in sp_response.value or []:
            role_assignments = getattr(sp, "app_role_assignments", None) or []
            for app_assignment in role_assignments:
                role_id = str(app_assignment.app_role_id).lower() if app_assignment.app_role_id else None
                for sensitive_id, role_name in SENSITIVE_APP_ROLES.items():
                    if role_id == sensitive_id.lower():
                        if sp.id not in privileged_sp_ids:
                            privileged_sp_ids[sp.id] = {
                                "display_name": sp.display_name or "Unknown",
                                "privileges": [],
                            }
                        privileged_sp_ids[sp.id]["privileges"].append(f"Graph: {role_name}")

        if sp_response.odata_next_link:
            sp_response = await client.service_principals.with_url(sp_response.odata_next_link).get()
        else:
            break

    if not privileged_sp_ids:
        return CheckResult(
            check_id="unused-apps-cleanup",
            status="pass",
            message="No privileged service principals found.",
        )

    # Step 3: Check sign-in activity for each privileged SP
    cutoff = datetime.now(timezone.utc) - timedelta(days=INACTIVITY_DAYS)
    stale_apps: list[dict] = []

    for sp_id, info in privileged_sp_ids.items():
        try:
            sp = await client.service_principals.by_service_principal_id(sp_id).get()
        except Exception:
            continue

        last_sign_in = None
        sign_in_activity = getattr(sp, "sign_in_activity", None)
        if sign_in_activity:
            # Use lastSuccessfulSignInDateTime (covers both interactive and
            # non-interactive flows) with fallback to the individual timestamps.
            # Service principals typically use client credentials (non-interactive),
            # so lastSignInDateTime alone misses most SP activity.
            candidates = [
                getattr(sign_in_activity, "last_successful_sign_in_date_time", None),
                getattr(sign_in_activity, "last_non_interactive_sign_in_date_time", None),
                getattr(sign_in_activity, "last_sign_in_date_time", None),
            ]
            last_sign_in = max((d for d in candidates if d is not None), default=None)

        if last_sign_in is None or last_sign_in < cutoff:
            days_inactive = None
            if last_sign_in:
                days_inactive = (datetime.now(timezone.utc) - last_sign_in).days
            stale_apps.append({
                "service_principal_id": sp_id,
                "display_name": info["display_name"],
                "privileges": info["privileges"],
                "last_sign_in": last_sign_in.isoformat() if last_sign_in else "Never",
                "days_inactive": days_inactive if days_inactive is not None else "N/A",
            })

    if not stale_apps:
        return CheckResult(
            check_id="unused-apps-cleanup",
            status="pass",
            message=(
                f"All {len(privileged_sp_ids)} privileged service principal(s) have "
                f"signed in within the last {INACTIVITY_DAYS} days."
            ),
        )

    return CheckResult(
        check_id="unused-apps-cleanup",
        status="warning",
        message=(
            f"{len(stale_apps)} privileged service principal(s) have not signed in "
            f"for over {INACTIVITY_DAYS} days."
        ),
        recommendation=(
            "Review and remove unused privileged applications. Rotate credentials "
            "and revoke permissions for apps that are no longer needed."
        ),
        details={"stale_apps": stale_apps},
    )
