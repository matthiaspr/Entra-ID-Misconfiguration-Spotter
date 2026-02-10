"""Check for shadow admins via app/service principal ownership."""

from msgraph import GraphServiceClient
from msgraph.generated.role_management.directory.role_assignments.role_assignments_request_builder import (
    RoleAssignmentsRequestBuilder,
)
from msgraph.generated.applications.applications_request_builder import (
    ApplicationsRequestBuilder,
)
from msgraph.generated.service_principals.service_principals_request_builder import (
    ServicePrincipalsRequestBuilder,
)

from entra_spotter.checks import CheckResult
from entra_spotter.checks._shared import PRIVILEGED_ROLES, SENSITIVE_APP_ROLES


async def check_shadow_admins_app_owners(client: GraphServiceClient) -> CheckResult:
    """Check for standard users who own privileged apps/service principals.

    Identifies users who are owners of Service Principals or App Registrations
    that hold privileged directory roles or sensitive Graph permissions.
    An owner can add credentials to the app and wield its permissions.

    Warning: One or more standard users own privileged apps
    Pass: No standard users own privileged apps
    """
    partial_errors: list[dict] = []
    # Step 1: Find service principals with privileged directory roles
    query_params = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetQueryParameters(
        expand=["principal"],
    )
    request_config = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    try:
        response = await client.role_management.directory.role_assignments.get(
            request_configuration=request_config
        )
    except Exception as e:
        return CheckResult(
            check_id="shadow-admins-app-owners",
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
    try:
        sp_response = await client.service_principals.get(request_configuration=sp_config)
    except Exception as e:
        return CheckResult(
            check_id="shadow-admins-app-owners",
            status="error",
            message=f"Failed to retrieve service principals: {e}",
        )

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

    # Step 3: For each privileged SP, get owners from both
    # the service principal and its app registration (if any)
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()  # (user_id, sp_id) for deduplication

    for sp_id, privileges in privileged_sp_ids.items():
        sp_owners: list = []
        app_reg_owners: list = []
        sp_display_name = "Unknown"

        # 3a: Get service principal owners
        try:
            sp_owners_response = await client.service_principals.by_service_principal_id(
                sp_id
            ).owners.get()
            sp_owners = sp_owners_response.value or []
        except Exception as e:
            partial_errors.append({
                "stage": "service_principal_owners",
                "service_principal_id": sp_id,
                "error": str(e),
            })

        # 3b: Get app registration owners (via appId → Application object)
        try:
            sp_detail = await client.service_principals.by_service_principal_id(
                sp_id
            ).get()
            sp_display_name = getattr(sp_detail, "display_name", None) or "Unknown"
            app_id = getattr(sp_detail, "app_id", None)
            if app_id:
                app_query = ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters(
                    filter=f"appId eq '{app_id}'",
                )
                app_config = ApplicationsRequestBuilder.ApplicationsRequestBuilderGetRequestConfiguration(
                    query_parameters=app_query,
                )
                apps_response = await client.applications.get(
                    request_configuration=app_config
                )
                apps = apps_response.value or []
                if apps:
                    app_object_id = apps[0].id
                    app_owners_response = await client.applications.by_application_id(
                        app_object_id
                    ).owners.get()
                    app_reg_owners = app_owners_response.value or []
        except Exception as e:
            partial_errors.append({
                "stage": "app_registration_owners",
                "service_principal_id": sp_id,
                "error": str(e),
            })

        # Track user owner IDs by source for ownership_source tagging
        sp_owner_ids = {
            owner.id for owner in sp_owners
            if getattr(owner, "odata_type", "") == "#microsoft.graph.user"
        }
        app_owner_ids = {
            owner.id for owner in app_reg_owners
            if getattr(owner, "odata_type", "") == "#microsoft.graph.user"
        }

        for owner in sp_owners + app_reg_owners:
            odata_type = getattr(owner, "odata_type", "")
            if odata_type == "#microsoft.graph.user":
                key = (owner.id, sp_id)
                if key in seen:
                    continue
                seen.add(key)
                in_sp = owner.id in sp_owner_ids
                in_app = owner.id in app_owner_ids
                if in_sp and in_app:
                    ownership_source = "both"
                elif in_app:
                    ownership_source = "app_registration"
                else:
                    ownership_source = "service_principal"
                findings.append({
                    "user_id": owner.id,
                    "user_display_name": getattr(owner, "display_name", "Unknown"),
                    "user_principal_name": getattr(owner, "user_principal_name", None),
                    "service_principal_id": sp_id,
                    "service_principal_display_name": sp_display_name,
                    "ownership_source": ownership_source,
                    "privileges": privileges,
                })

    if not findings:
        if partial_errors:
            return CheckResult(
                check_id="shadow-admins-app-owners",
                status="warning",
                message=(
                    "No shadow admin owners found, but some ownership lookups failed."
                ),
                recommendation="Review API permissions or transient Graph errors.",
                details={"partial_errors": partial_errors},
            )

        return CheckResult(
            check_id="shadow-admins-app-owners",
            status="pass",
            message="No standard users own privileged service principals or app registrations.",
        )

    details_summary = "\n".join(
        f'- "{admin.get("service_principal_display_name", admin.get("service_principal_id", "Unknown"))}" '
        f'owned by "{admin.get("user_principal_name") or admin.get("user_display_name", admin.get("user_id", "Unknown"))}"'
        + (f' (via {admin.get("ownership_source", "").replace("_", " ")})' if admin.get("ownership_source") else "")
        for admin in findings
    )

    return CheckResult(
        check_id="shadow-admins-app-owners",
        status="warning",
        message=f"{len(findings)} user(s) are owners of privileged service principals or app registrations (shadow admins).",
        recommendation=(
            "Review app ownership. Owners can add credentials and act as the app. "
            "Remove unnecessary owners or replace with dedicated admin accounts."
        ),
        details={
            "shadow_admins": findings,
            "details_summary": details_summary,
            "partial_errors": partial_errors,
        },
    )
