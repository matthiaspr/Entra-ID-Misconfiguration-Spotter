"""Check for service principals with sensitive MS Graph app roles."""

from msgraph import GraphServiceClient
from msgraph.generated.service_principals.service_principals_request_builder import (
    ServicePrincipalsRequestBuilder,
)

from entra_spotter.checks import CheckResult
from entra_spotter.checks._shared import SENSITIVE_APP_ROLES


async def check_sp_graph_roles(client: GraphServiceClient) -> CheckResult:
    """Check for service principals with sensitive MS Graph app roles.

    These roles are dangerous because they allow privilege escalation:
    - RoleManagement.ReadWrite.Directory: Can assign any directory role
    - AppRoleAssignment.ReadWrite.All: Can grant any app role to any SP
    - UserAuthenticationMethod.ReadWrite.All: Can generate TAP to take over any user

    Pass: No service principals have these sensitive roles
    Warning: One or more service principals have sensitive roles
    """
    # Get all service principals with their app role assignments
    query_params = ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetQueryParameters(
        expand=["appRoleAssignments"],
    )
    request_config = ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )

    findings: list[dict] = []

    # Get first page
    response = await client.service_principals.get(request_configuration=request_config)

    # Process all pages
    while response:
        service_principals = response.value or []

        for sp in service_principals:
            assignments = getattr(sp, "app_role_assignments", None) or []

            for assignment in assignments:
                # Check if this is a sensitive Graph API role
                role_id = str(assignment.app_role_id).lower() if assignment.app_role_id else None
                # Compare lowercase to handle UUID case differences
                for sensitive_id, role_name in SENSITIVE_APP_ROLES.items():
                    if role_id == sensitive_id.lower():
                        findings.append({
                            "service_principal_id": sp.id,
                            "display_name": sp.display_name or "Unknown",
                            "app_role": role_name,
                            "app_role_id": role_id,
                        })

        # Get next page if available
        if response.odata_next_link:
            response = await client.service_principals.with_url(response.odata_next_link).get()
        else:
            break

    if not findings:
        return CheckResult(
            check_id="sp-graph-roles",
            status="pass",
            message="No service principals have sensitive MS Graph app roles.",
        )

    return CheckResult(
        check_id="sp-graph-roles",
        status="warning",
        message=f"{len(findings)} service principal(s) with sensitive MS Graph app roles.",
        recommendation="Review if these service principals require these powerful permissions.",
        details={"service_principals": findings},
    )
