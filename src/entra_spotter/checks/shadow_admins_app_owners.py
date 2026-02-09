"""Check for shadow admins via app/service principal ownership."""

from msgraph import GraphServiceClient
from msgraph.generated.role_management.directory.role_assignments.role_assignments_request_builder import (
    RoleAssignmentsRequestBuilder,
)
from msgraph.generated.service_principals.service_principals_request_builder import (
    ServicePrincipalsRequestBuilder,
)

from entra_spotter.checks import CheckResult
from entra_spotter.checks._ca_helpers import PRIVILEGED_ROLES

# Sensitive MS Graph app role IDs (same as sp_graph_roles check)
SENSITIVE_APP_ROLES: dict[str, str] = {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "50483e42-d915-4231-9639-7fdb7fd190e5": "UserAuthenticationMethod.ReadWrite.All",
}


async def check_shadow_admins_app_owners(client: GraphServiceClient) -> CheckResult:
    """Check for standard users who own privileged apps/service principals.

    Identifies users who are owners of Service Principals or App Registrations
    that hold privileged directory roles or sensitive Graph permissions.
    An owner can add credentials to the app and wield its permissions.

    Warning: One or more standard users own privileged apps
    Pass: No standard users own privileged apps
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

    # Collect service principal IDs that hold privileged roles
    privileged_sp_ids: dict[str, list[str]] = {}  # sp_id -> [role_names]
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
            privileged_sp_ids.setdefault(sp_id, []).append(role_name)

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
                        privileged_sp_ids.setdefault(sp.id, []).append(f"Graph: {role_name}")

        if sp_response.odata_next_link:
            sp_response = await client.service_principals.with_url(sp_response.odata_next_link).get()
        else:
            break

    if not privileged_sp_ids:
        return CheckResult(
            check_id="shadow-admins-app-owners",
            status="pass",
            message="No privileged service principals found to check for shadow admin owners.",
        )

    # Step 3: For each privileged SP, get owners and check if any are regular users
    findings: list[dict] = []
    for sp_id, privileges in privileged_sp_ids.items():
        try:
            owners_response = await client.service_principals.by_service_principal_id(
                sp_id
            ).owners.get()
            owners = owners_response.value or []
        except Exception:
            continue

        for owner in owners:
            odata_type = getattr(owner, "odata_type", "")
            if odata_type == "#microsoft.graph.user":
                findings.append({
                    "user_id": owner.id,
                    "user_display_name": getattr(owner, "display_name", "Unknown"),
                    "service_principal_id": sp_id,
                    "privileges": privileges,
                })

    if not findings:
        return CheckResult(
            check_id="shadow-admins-app-owners",
            status="pass",
            message="No standard users own privileged service principals.",
        )

    return CheckResult(
        check_id="shadow-admins-app-owners",
        status="warning",
        message=f"{len(findings)} user(s) are owners of privileged service principals (shadow admins).",
        recommendation=(
            "Review app ownership. Owners can add credentials and act as the app. "
            "Remove unnecessary owners or replace with dedicated admin accounts."
        ),
        details={"shadow_admins": findings},
    )
