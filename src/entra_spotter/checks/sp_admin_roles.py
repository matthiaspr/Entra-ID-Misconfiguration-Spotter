"""Check for service principals in privileged admin roles."""

from msgraph import GraphServiceClient
from msgraph.generated.role_management.directory.role_assignments.role_assignments_request_builder import (
    RoleAssignmentsRequestBuilder,
)

from entra_spotter.checks import CheckResult

# Role definition IDs for privileged roles (same as template IDs)
# https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
PRIVILEGED_ROLE_DEFINITIONS = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
}


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
    assignments_response = await client.role_management.directory.role_assignments.get(
        request_configuration=request_config
    )
    assignments = assignments_response.value or []

    findings: list[dict] = []

    for assignment in assignments:
        # Check if this is a privileged role
        if assignment.role_definition_id not in PRIVILEGED_ROLE_DEFINITIONS:
            continue

        role_name = PRIVILEGED_ROLE_DEFINITIONS[assignment.role_definition_id]
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
        details={"service_principals": findings},
    )
