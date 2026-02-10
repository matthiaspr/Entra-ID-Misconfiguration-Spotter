"""Check for dynamic groups assigned to privileged roles with mutable rules."""

import re

from msgraph import GraphServiceClient
from msgraph.generated.role_management.directory.role_assignments.role_assignments_request_builder import (
    RoleAssignmentsRequestBuilder,
)

from entra_spotter.checks import CheckResult
from entra_spotter.checks._shared import PRIVILEGED_ROLES

# User attributes that are commonly mutable by helpdesk or HR systems
MUTABLE_ATTRIBUTES = [
    "department",
    "companyName",
    "jobTitle",
    "city",
    "country",
    "state",
    "usageLocation",
    "employeeType",
    "costCenter",
    "division",
    "officeLocation",
    "postalCode",
    "streetAddress",
]

# Pattern to match user.attribute references in dynamic membership rules
_ATTRIBUTE_PATTERN = re.compile(
    r"user\.(" + "|".join(re.escape(a) for a in MUTABLE_ATTRIBUTES) + r")",
    re.IGNORECASE,
)


def _find_mutable_attributes(rule: str) -> list[str]:
    """Extract mutable attributes referenced in a dynamic membership rule."""
    return list({m.group(1).lower() for m in _ATTRIBUTE_PATTERN.finditer(rule)})


async def check_dynamic_group_hijack(client: GraphServiceClient) -> CheckResult:
    """Check for dynamic groups with privileged roles using mutable attributes.

    Scans for dynamic groups assigned to privileged roles and checks whether
    their membership rules rely on mutable user attributes (e.g. department).
    If a helpdesk user can change these attributes, they can force accounts
    into privileged dynamic groups.

    Fail: Dynamic groups with privileged roles use mutable attributes
    Warning: Dynamic groups are assigned to privileged roles (any rule)
    Pass: No dynamic groups assigned to privileged roles
    """
    # Step 1: Find groups assigned to privileged directory roles
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

    # Collect group IDs that hold privileged roles
    privileged_group_ids: dict[str, list[str]] = {}  # group_id -> [role_names]
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

    if not privileged_group_ids:
        return CheckResult(
            check_id="dynamic-group-hijack",
            status="pass",
            message="No groups assigned to privileged directory roles.",
        )

    # Step 2: Fetch each group to check if it's dynamic and inspect its rule
    dynamic_groups_with_mutable: list[dict] = []
    dynamic_groups_without_mutable: list[dict] = []

    for group_id, roles in privileged_group_ids.items():
        try:
            group = await client.groups.by_group_id(group_id).get()
        except Exception:
            continue

        # Check for dynamic membership
        membership_rule = getattr(group, "membership_rule", None)
        group_types = getattr(group, "group_types", None) or []

        if "DynamicMembership" not in group_types or not membership_rule:
            continue

        mutable_attrs = _find_mutable_attributes(membership_rule)
        group_info = {
            "group_id": group_id,
            "display_name": getattr(group, "display_name", "Unknown"),
            "roles": roles,
            "membership_rule": membership_rule,
            "mutable_attributes": mutable_attrs,
        }

        if mutable_attrs:
            dynamic_groups_with_mutable.append(group_info)
        else:
            dynamic_groups_without_mutable.append(group_info)

    if not dynamic_groups_with_mutable and not dynamic_groups_without_mutable:
        return CheckResult(
            check_id="dynamic-group-hijack",
            status="pass",
            message="No dynamic groups are assigned to privileged directory roles.",
        )

    if dynamic_groups_with_mutable:
        return CheckResult(
            check_id="dynamic-group-hijack",
            status="fail",
            message=(
                f"{len(dynamic_groups_with_mutable)} dynamic group(s) with privileged roles "
                "use mutable attributes in their membership rules."
            ),
            recommendation=(
                "Replace mutable attributes with immutable ones (e.g. user.objectId, "
                "user.extensionAttributes) or use static group assignment with access reviews."
            ),
            details={
                "mutable_rule_groups": dynamic_groups_with_mutable,
                "other_dynamic_groups": dynamic_groups_without_mutable,
            },
        )

    return CheckResult(
        check_id="dynamic-group-hijack",
        status="warning",
        message=(
            f"{len(dynamic_groups_without_mutable)} dynamic group(s) are assigned to "
            "privileged roles. No mutable attributes detected, but review rules carefully."
        ),
        recommendation=(
            "Audit dynamic membership rules regularly. Prefer static groups with access "
            "reviews for privileged role assignment."
        ),
        details={
            "mutable_rule_groups": [],
            "other_dynamic_groups": dynamic_groups_without_mutable,
        },
    )
