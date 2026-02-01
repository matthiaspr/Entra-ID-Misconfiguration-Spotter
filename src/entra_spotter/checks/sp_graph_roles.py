"""Check for service principals with sensitive MS Graph app roles."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult

# Sensitive MS Graph app role IDs
# These roles allow privilege escalation if compromised
SENSITIVE_APP_ROLES = {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
    "06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
    "50483e42-d915-4231-9639-7fdb7fd190e5": "UserAuthenticationMethod.ReadWrite.All",
}

# Microsoft Graph service principal app ID (same across all tenants)
MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"


def check_sp_graph_roles(client: GraphServiceClient) -> CheckResult:
    """Check for service principals with sensitive MS Graph app roles.

    These roles are dangerous because they allow privilege escalation:
    - RoleManagement.ReadWrite.Directory: Can assign any directory role
    - AppRoleAssignment.ReadWrite.All: Can grant any app role to any SP
    - UserAuthenticationMethod.ReadWrite.All: Can generate TAP to take over any user

    Pass: No service principals have these sensitive roles
    Warning: One or more service principals have sensitive roles
    """
    # Get all service principals with their app role assignments
    response = client.service_principals.get(
        request_configuration=lambda config: setattr(
            config.query_parameters, "expand", ["appRoleAssignments"]
        )
    )

    service_principals = response.value or []
    findings: list[dict] = []

    for sp in service_principals:
        # Skip if no app role assignments
        assignments = getattr(sp, "app_role_assignments", None) or []

        for assignment in assignments:
            # Check if this is a sensitive Graph API role
            role_id = str(assignment.app_role_id) if assignment.app_role_id else None
            if role_id in SENSITIVE_APP_ROLES:
                findings.append({
                    "service_principal_id": sp.id,
                    "display_name": sp.display_name or "Unknown",
                    "app_role": SENSITIVE_APP_ROLES[role_id],
                    "app_role_id": role_id,
                })

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
