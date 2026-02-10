"""Check for shadow admins via role-assignable group ownership."""

from msgraph import GraphServiceClient
from msgraph.generated.role_management.directory.role_assignments.role_assignments_request_builder import (
    RoleAssignmentsRequestBuilder,
)
from kiota_abstractions.base_request_configuration import RequestConfiguration

from entra_spotter.checks import CheckResult
from entra_spotter.checks._shared import PRIVILEGED_ROLES


async def check_shadow_admins_group_owners(client: GraphServiceClient) -> CheckResult:
    """Check for users who own groups assigned to privileged roles.

    Identifies users who are owners of security groups assigned to privileged
    Entra ID roles (role-assignable groups). The owner can add themselves to
    the group and inherit the role.

    Warning: One or more users own role-assignable groups with privileged roles
    Pass: No users own role-assignable groups with privileged roles
    """
    partial_errors: list[dict] = []
    # Step 1: Find groups assigned to privileged directory roles
    query_params = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetQueryParameters(
        expand=["principal"],
    )
    request_config = RequestConfiguration(query_parameters=query_params)
    try:
        response = await client.role_management.directory.role_assignments.get(
            request_configuration=request_config
        )
    except Exception as e:
        return CheckResult(
            check_id="shadow-admins-group-owners",
            status="error",
            message=f"Failed to retrieve role assignments: {e}",
        )
    assignments = []
    while response:
        assignments.extend(response.value or [])
        if response.odata_next_link:
            response = await client.role_management.directory.role_assignments.with_url(response.odata_next_link).get()
        else:
            break

    # Collect group IDs that hold privileged roles
    privileged_group_ids: dict[str, list[str]] = {}  # group_id -> [role_names]
    group_names: dict[str, str] = {}
    for assignment in assignments:
        if assignment.role_definition_id not in PRIVILEGED_ROLES:
            continue
        principal = assignment.principal
        if not principal:
            continue
        odata_type = getattr(principal, "odata_type", "")
        if odata_type == "#microsoft.graph.group":
            group_id = principal.id
            role_name = PRIVILEGED_ROLES[assignment.role_definition_id]
            privileged_group_ids.setdefault(group_id, []).append(role_name)
            if group_id and getattr(principal, "display_name", None):
                group_names[group_id] = principal.display_name

    if not privileged_group_ids:
        return CheckResult(
            check_id="shadow-admins-group-owners",
            status="pass",
            message="No groups found assigned to privileged directory roles.",
        )

    # Step 2: For each privileged group, get owners and check for user owners
    findings: list[dict] = []
    for group_id, roles in privileged_group_ids.items():
        try:
            owners_response = await client.groups.by_group_id(group_id).owners.get()
            owners = owners_response.value or []
        except Exception as e:
            partial_errors.append({
                "stage": "group_owners",
                "group_id": group_id,
                "error": str(e),
            })
            continue

        for owner in owners:
            odata_type = getattr(owner, "odata_type", "")
            if odata_type == "#microsoft.graph.user":
                findings.append({
                    "user_id": owner.id,
                    "user_display_name": getattr(owner, "display_name", "Unknown"),
                    "group_id": group_id,
                    "group_display_name": group_names.get(group_id),
                    "roles": roles,
                })

    if not findings:
        if partial_errors:
            return CheckResult(
                check_id="shadow-admins-group-owners",
                status="warning",
                message=(
                    "No shadow admin group owners found, but some ownership lookups failed."
                ),
                recommendation="Review API permissions or transient Graph errors.",
                details={"partial_errors": partial_errors},
            )

        return CheckResult(
            check_id="shadow-admins-group-owners",
            status="pass",
            message="No users own role-assignable groups with privileged roles.",
        )

    details_summary = "\n".join(
        f'- "{admin.get("group_display_name") or admin.get("group_id", "Unknown")}" '
        f'owned by "{admin.get("user_display_name", admin.get("user_id", "Unknown"))}"'
        for admin in findings
    )

    return CheckResult(
        check_id="shadow-admins-group-owners",
        status="warning",
        message=(
            f"{len(findings)} user(s) own role-assignable groups with privileged roles "
            "(shadow admins)."
        ),
        recommendation=(
            "Review group ownership. Owners can add themselves to the group and inherit "
            "its role. Remove unnecessary owners or use PIM for just-in-time access."
        ),
        details={
            "shadow_admins": findings,
            "details_summary": details_summary,
            "partial_errors": partial_errors,
        },
    )
