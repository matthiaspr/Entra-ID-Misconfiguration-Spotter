"""Check for service principals in privileged admin roles."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult
from entra_spotter.graph import run_sync

# Role template IDs for privileged roles
# https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
PRIVILEGED_ROLE_TEMPLATES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
}


def check_sp_admin_roles(client: GraphServiceClient) -> CheckResult:
    """Check for service principals in privileged admin roles.

    Calls GET /directoryRoles and GET /directoryRoles/{id}/members
    to find service principals in privileged roles.

    Pass: No service principals in privileged roles
    Warning: One or more service principals found in privileged roles
    """
    # Get all activated directory roles
    roles_response = run_sync(client.directory_roles.get())
    roles = roles_response.value or []

    findings: list[dict] = []

    for role in roles:
        # Check if this is a privileged role by template ID
        if role.role_template_id not in PRIVILEGED_ROLE_TEMPLATES:
            continue

        role_name = PRIVILEGED_ROLE_TEMPLATES[role.role_template_id]

        # Get members of this role
        members_response = run_sync(
            client.directory_roles.by_directory_role_id(role.id).members.get()
        )
        members = members_response.value or []

        for member in members:
            # Check if member is a service principal (not a user)
            # Service principals have @odata.type = #microsoft.graph.servicePrincipal
            odata_type = getattr(member, "odata_type", None)
            if odata_type == "#microsoft.graph.servicePrincipal":
                findings.append({
                    "service_principal_id": member.id,
                    "display_name": getattr(member, "display_name", "Unknown"),
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
