"""Check for Global Administrator role membership."""

from collections import deque

from msgraph import GraphServiceClient
from msgraph.generated.role_management.directory.role_assignments.role_assignments_request_builder import (
    RoleAssignmentsRequestBuilder,
)
from kiota_abstractions.base_request_configuration import RequestConfiguration

from entra_spotter.checks import CheckResult

# Global Administrator role template ID
GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"

# Limits
MIN_GLOBAL_ADMINS = 2
MAX_GLOBAL_ADMINS = 8


async def check_global_admin_count(client: GraphServiceClient) -> CheckResult:
    """Check Global Administrator role membership count and cloud-only status.

    Fail conditions:
    - Fewer than 2 user accounts
    - More than 8 user accounts
    - Any user account is synced from on-premises AD (not cloud-only)

    Service principals are reported separately and don't count toward the 2-8 limit.
    Groups are recursively expanded to count nested user members.
    """
    # Get role assignments for Global Administrator
    query_params = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetQueryParameters(
        filter=f"roleDefinitionId eq '{GLOBAL_ADMIN_ROLE_ID}'",
        expand=["principal"],
    )
    config = RequestConfiguration(query_parameters=query_params)
    response = await client.role_management.directory.role_assignments.get(config)
    assignments = []
    while response:
        assignments.extend(response.value or [])
        if response.odata_next_link:
            response = await client.role_management.directory.role_assignments.with_url(
                response.odata_next_link
            ).get()
        else:
            break

    # Collect users and service principals
    users: list[dict] = []
    service_principals: list[dict] = []
    processed_user_ids: set[str] = set()
    group_members_cache: dict[str, list[object]] = {}
    group_queue: deque[tuple[str, set[str]]] = deque()

    async def _add_user(user_id: str) -> None:
        """Resolve a user once and append to the users list."""
        if user_id in processed_user_ids:
            return
        processed_user_ids.add(user_id)
        user = await client.users.by_user_id(user_id).get()
        users.append({
            "id": user_id,
            "upn": user.user_principal_name,
            "is_synced": user.on_premises_sync_enabled or False,
        })

    async def _get_group_members(group_id: str) -> list[object]:
        """Retrieve all members for a group, including paginated pages."""
        if group_id in group_members_cache:
            return group_members_cache[group_id]

        members_request = client.groups.by_group_id(group_id).members
        members_response = await members_request.get()
        members: list[object] = []
        while members_response:
            members.extend(members_response.value or [])
            if getattr(members_response, "odata_next_link", None):
                members_response = await members_request.with_url(
                    members_response.odata_next_link
                ).get()
            else:
                break

        group_members_cache[group_id] = members
        return members

    for assignment in assignments:
        principal = assignment.principal
        if not principal:
            continue

        odata_type = getattr(principal, "odata_type", "")

        if odata_type == "#microsoft.graph.user":
            if principal.id:
                await _add_user(principal.id)

        elif odata_type == "#microsoft.graph.servicePrincipal":
            service_principals.append({
                "id": principal.id,
                "display_name": principal.display_name,
            })

        elif odata_type == "#microsoft.graph.group":
            if principal.id:
                group_queue.append((principal.id, {principal.id}))

    # Expand group membership recursively (nested groups), with cycle protection.
    while group_queue:
        group_id, visited_group_ids = group_queue.popleft()
        members = await _get_group_members(group_id)

        for member in members:
            member_id = getattr(member, "id", None)
            if not member_id:
                continue

            member_type = getattr(member, "odata_type", "")
            if member_type == "#microsoft.graph.user":
                await _add_user(member_id)
            elif member_type == "#microsoft.graph.group":
                if member_id in visited_group_ids:
                    continue
                next_visited = set(visited_group_ids)
                next_visited.add(member_id)
                group_queue.append((member_id, next_visited))

    # Check for synced users
    synced_users = [u for u in users if u["is_synced"]]
    cloud_only_users = [u for u in users if not u["is_synced"]]
    user_count = len(users)

    # Build user UPN list for output
    user_upns = [u["upn"] for u in users]
    sp_names = [sp["display_name"] for sp in service_principals]

    # Build details
    details = {
        "user_count": user_count,
        "users": user_upns,
        "service_principal_count": len(service_principals),
        "service_principals": sp_names,
        "synced_user_count": len(synced_users),
        "synced_users": [u["upn"] for u in synced_users],
    }

    # Evaluate fail conditions
    fail_reasons = []

    if user_count < MIN_GLOBAL_ADMINS:
        fail_reasons.append(f"Only {user_count} user(s) (minimum: {MIN_GLOBAL_ADMINS})")

    if user_count > MAX_GLOBAL_ADMINS:
        fail_reasons.append(f"{user_count} user(s) (maximum: {MAX_GLOBAL_ADMINS})")

    if synced_users:
        synced_upns = ", ".join(u["upn"] for u in synced_users)
        fail_reasons.append(f"{len(synced_users)} synced (non-cloud-only) user(s): {synced_upns}")

    # Build member summary for message
    members_summary = _format_members_summary(user_upns, sp_names)

    if fail_reasons:
        return CheckResult(
            check_id="global-admin-count",
            status="fail",
            message=f"Global Administrator role issues: {'; '.join(fail_reasons)}. {members_summary}",
            recommendation="Ensure 2-8 cloud-only user accounts are assigned to Global Administrator.",
            details=details,
        )

    return CheckResult(
        check_id="global-admin-count",
        status="pass",
        message=f"{user_count} cloud-only user(s) in Global Administrator role. {members_summary}",
        details=details,
    )


def _format_members_summary(user_upns: list[str], sp_names: list[str]) -> str:
    """Format a summary of all members for display."""
    parts = []
    if user_upns:
        parts.append(f"Users: {', '.join(user_upns)}")
    if sp_names:
        parts.append(f"Service principals: {', '.join(sp_names)}")
    return " | ".join(parts) if parts else "No members found"
