"""Check that privileged role users have Entra ID P1/P2 licensing."""

from collections import deque

from msgraph import GraphServiceClient
from msgraph.generated.role_management.directory.role_assignments.role_assignments_request_builder import (
    RoleAssignmentsRequestBuilder,
)
from kiota_abstractions.base_request_configuration import RequestConfiguration

from entra_spotter.checks import CheckResult
from entra_spotter.checks._shared import PRIVILEGED_ROLES

PREMIUM_PLAN_NAMES = {"AAD_PREMIUM", "AAD_PREMIUM_P2"}


def _has_premium_entra_plan(user: object) -> bool:
    """Return True when a user has enabled Entra ID P1/P2 service plan."""
    for plan in getattr(user, "assigned_plans", None) or []:
        plan_name = (getattr(plan, "service_plan_name", None) or "").upper()
        capability_status = (getattr(plan, "capability_status", None) or "").lower()
        if plan_name in PREMIUM_PLAN_NAMES and capability_status == "enabled":
            return True
    return False


async def _get_paginated_items(
    first_page_getter,
    next_page_getter,
) -> list[object]:
    """Collect all items from a paginated Graph collection response."""
    items: list[object] = []
    response = await first_page_getter()
    while response:
        items.extend(response.value or [])
        next_link = getattr(response, "odata_next_link", None)
        if not next_link:
            break
        response = await next_page_getter(next_link)
    return items


async def check_privileged_roles_license(client: GraphServiceClient) -> CheckResult:
    """Verify all privileged role user members have Entra ID P1/P2 licensing.

    Scope:
    - Active role assignments only (`/roleManagement/directory/roleAssignments`)
    - Privileged roles defined in `PRIVILEGED_ROLES`
    - User principals only (direct assignment or recursive nested group membership)
    """
    try:
        query_params = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetQueryParameters(
            expand=["principal"],
        )
        request_config = RequestConfiguration(query_parameters=query_params)
        assignments = await _get_paginated_items(
            lambda: client.role_management.directory.role_assignments.get(
                request_configuration=request_config
            ),
            lambda next_link: client.role_management.directory.role_assignments.with_url(
                next_link
            ).get(),
        )
    except Exception as e:
        return CheckResult(
            check_id="privileged-roles-license",
            status="error",
            message=f"Failed to retrieve role assignments: {e}",
        )

    user_context: dict[str, dict[str, set[str]]] = {}
    group_queue: deque[tuple[str, str, str, set[str]]] = deque()
    # (group_id, group_path, role_name, visited_group_ids)
    ignored_principals: list[dict[str, str | None]] = []
    partial_errors: list[dict[str, str]] = []

    def _add_user_context(user_id: str, role_name: str, path: str) -> None:
        context = user_context.setdefault(user_id, {"roles": set(), "paths": set()})
        context["roles"].add(role_name)
        context["paths"].add(path)

    for assignment in assignments:
        role_id = (assignment.role_definition_id or "").lower()
        if role_id not in PRIVILEGED_ROLES:
            continue

        principal = assignment.principal
        if not principal or not getattr(principal, "id", None):
            continue

        role_name = PRIVILEGED_ROLES[role_id]
        principal_type = getattr(principal, "odata_type", "")
        principal_id = principal.id
        principal_name = getattr(principal, "display_name", None)

        if principal_type == "#microsoft.graph.user":
            _add_user_context(principal_id, role_name, f"{role_name} -> {principal_id}")
        elif principal_type == "#microsoft.graph.group":
            root_name = principal_name or principal_id
            group_queue.append(
                (principal_id, f"{role_name} -> {root_name}", role_name, {principal_id})
            )
        else:
            ignored_principals.append(
                {
                    "id": principal_id,
                    "display_name": principal_name,
                    "type": principal_type or "unknown",
                    "role": role_name,
                }
            )

    group_members_cache: dict[str, list[object]] = {}

    async def _get_group_members(group_id: str) -> list[object]:
        if group_id in group_members_cache:
            return group_members_cache[group_id]

        members_request = client.groups.by_group_id(group_id).members
        members = await _get_paginated_items(
            lambda: members_request.get(),
            lambda next_link: members_request.with_url(next_link).get(),
        )
        group_members_cache[group_id] = members
        return members

    # Expand group membership recursively with cycle protection.
    while group_queue:
        group_id, path, role_name, seen_group_ids = group_queue.popleft()

        try:
            members = await _get_group_members(group_id)
        except Exception as e:
            partial_errors.append(
                {
                    "stage": "group_members",
                    "group_id": group_id,
                    "path": path,
                    "error": str(e),
                }
            )
            continue

        for member in members:
            member_id = getattr(member, "id", None)
            if not member_id:
                continue

            member_type = getattr(member, "odata_type", "")
            member_name = getattr(member, "display_name", None) or member_id

            if member_type == "#microsoft.graph.user":
                _add_user_context(member_id, role_name, f"{path} -> {member_name}")
            elif member_type == "#microsoft.graph.group":
                if member_id in seen_group_ids:
                    continue
                next_seen = set(seen_group_ids)
                next_seen.add(member_id)
                group_queue.append(
                    (member_id, f"{path} -> {member_name}", role_name, next_seen)
                )
            else:
                ignored_principals.append(
                    {
                        "id": member_id,
                        "display_name": member_name,
                        "type": member_type or "unknown",
                        "role": role_name,
                    }
                )

    if not user_context:
        return CheckResult(
            check_id="privileged-roles-license",
            status="warning",
            message="No privileged role user members found to evaluate for Entra ID P1/P2 licensing.",
            recommendation="Assign privileged roles directly to licensed users or expand groups to include user members.",
            details={
                "evaluated_user_count": 0,
                "ignored_principals": ignored_principals,
                "partial_errors": partial_errors,
            },
        )

    licensed_users: list[dict] = []
    unlicensed_users: list[dict] = []
    unresolved_users: list[str] = []

    for user_id, context in user_context.items():
        try:
            user = await client.users.by_user_id(user_id).get()
        except Exception as e:
            unresolved_users.append(user_id)
            partial_errors.append(
                {
                    "stage": "user_lookup",
                    "user_id": user_id,
                    "error": str(e),
                }
            )
            continue

        user_info = {
            "id": user_id,
            "upn": getattr(user, "user_principal_name", None),
            "display_name": getattr(user, "display_name", None),
            "roles": sorted(context["roles"]),
            "membership_paths": sorted(context["paths"]),
        }

        if _has_premium_entra_plan(user):
            licensed_users.append(user_info)
        else:
            unlicensed_users.append(user_info)

    details = {
        "evaluated_user_count": len(user_context),
        "licensed_user_count": len(licensed_users),
        "unlicensed_user_count": len(unlicensed_users),
        "unlicensed_users": unlicensed_users,
        "unresolved_user_count": len(unresolved_users),
        "unresolved_user_ids": sorted(unresolved_users),
        "ignored_principals": ignored_principals,
        "partial_errors": partial_errors,
    }

    if unlicensed_users:
        details["details_summary"] = "\n".join(
            f'- "{u.get("upn") or u.get("display_name") or u["id"]}" missing Entra ID P1/P2'
            for u in unlicensed_users
        )
        return CheckResult(
            check_id="privileged-roles-license",
            status="fail",
            message=(
                f"{len(unlicensed_users)} privileged role user(s) do not have "
                "Entra ID P1/P2 licensing."
            ),
            recommendation=(
                "Assign Entra ID P1 or P2 licensing to all users with privileged role access."
            ),
            details=details,
        )

    if partial_errors:
        return CheckResult(
            check_id="privileged-roles-license",
            status="warning",
            message=(
                "All resolved privileged role users have Entra ID P1/P2 licensing, "
                "but some group or user lookups failed."
            ),
            recommendation="Review Graph API errors and rerun the check to confirm full coverage.",
            details=details,
        )

    return CheckResult(
        check_id="privileged-roles-license",
        status="pass",
        message=(
            f"All {len(licensed_users)} privileged role user(s) have Entra ID P1/P2 licensing."
        ),
        details=details,
    )
