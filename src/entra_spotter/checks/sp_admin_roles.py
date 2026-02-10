"""Check for service principals in privileged admin roles."""

from msgraph import GraphServiceClient
from msgraph.generated.role_management.directory.role_assignments.role_assignments_request_builder import (
    RoleAssignmentsRequestBuilder,
)

from entra_spotter.checks import CheckResult
from entra_spotter.checks._shared import PRIVILEGED_ROLES


async def check_sp_admin_roles(client: GraphServiceClient) -> CheckResult:
    """Check for service principals in privileged admin roles.

    Uses the unified RBAC API: GET /roleManagement/directory/roleAssignments
    with $expand=principal to find service principals in privileged roles.

    Pass: No service principals in privileged roles
    Warning: One or more service principals found in privileged roles
    """
    # Get all role assignments with principal details expanded
    query_params = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetQueryParameters(
        expand=["principal"],
    )
    request_config = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    response = await client.role_management.directory.role_assignments.get(
        request_configuration=request_config
    )
    assignments = []
    while response:
        assignments.extend(response.value or [])
        if response.odata_next_link:
            response = await client.role_management.directory.role_assignments.with_url(response.odata_next_link).get()
        else:
            break

    findings: list[dict] = []

    for assignment in assignments:
        # Check if this is a privileged role (lowercase for case-insensitive comparison)
        role_id = (assignment.role_definition_id or "").lower()
        if role_id not in PRIVILEGED_ROLES:
            continue

        role_name = PRIVILEGED_ROLES[role_id]
        principal = assignment.principal

        if principal is None:
            continue

        # Check if principal is a service principal
        odata_type = getattr(principal, "odata_type", None)
        if odata_type == "#microsoft.graph.servicePrincipal":
            findings.append({
                "service_principal_id": principal.id,
                "display_name": getattr(principal, "display_name", "Unknown"),
                "role": role_name,
            })

    if not findings:
        return CheckResult(
            check_id="sp-admin-roles",
            status="pass",
            message="No service principals found in privileged admin roles.",
        )

    return CheckResult(
        check_id="sp-admin-roles",
        status="warning",
        message=f"{len(findings)} service principal(s) in privileged admin roles.",
        recommendation="Review if these service principals require privileged access.",
        details={
            "service_principals": findings,
            "details_summary": "\n".join(
                f'- "{sp["display_name"]}" → {sp["role"]}' for sp in findings
            ),
        },
    )
