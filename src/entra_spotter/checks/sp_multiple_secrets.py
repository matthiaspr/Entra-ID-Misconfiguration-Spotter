"""Check for service principals with multiple assigned credentials."""

from msgraph import GraphServiceClient
from msgraph.generated.applications.applications_request_builder import (
    ApplicationsRequestBuilder,
)
from msgraph.generated.service_principals.service_principals_request_builder import (
    ServicePrincipalsRequestBuilder,
)
from kiota_abstractions.base_request_configuration import RequestConfiguration

from entra_spotter.checks import CheckResult


def _format_credential_name(credential: object, fallback_label: str) -> str:
    """Get a stable display name for a credential."""
    display_name = getattr(credential, "display_name", None)
    if isinstance(display_name, str) and display_name.strip():
        return display_name.strip()

    key_id = getattr(credential, "key_id", None)
    if key_id:
        return f"Unnamed {fallback_label} (key_id={key_id})"

    return f"Unnamed {fallback_label}"


def _collect_credential_entries(
    credentials: list[object] | None,
    fallback_label: str,
    credential_type: str,
    source: str,
) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for credential in credentials or []:
        entries.append(
            {
                "name": _format_credential_name(credential, fallback_label),
                "type": credential_type,
                "source": source,
            }
        )
    return entries


async def check_sp_multiple_secrets(client: GraphServiceClient) -> CheckResult:
    """Check for service principals with two or more assigned credentials.

    Counts:
    - Service principal password_credentials (client secrets)
    - Service principal key_credentials (certificates)
    - App registration password_credentials (client secrets)
    - App registration key_credentials (certificates)

    Service principal and app registration credentials are merged by app_id.

    Pass: No service principal has 2+ credentials assigned
    Warning: One or more service principals have 2+ credentials assigned
    """
    sp_query_params = ServicePrincipalsRequestBuilder.ServicePrincipalsRequestBuilderGetQueryParameters(
        select=["id", "displayName", "appId", "passwordCredentials", "keyCredentials"],
    )
    sp_request_config = RequestConfiguration(query_parameters=sp_query_params)

    findings: list[dict] = []
    service_principals: list[object] = []

    sp_response = await client.service_principals.get(request_configuration=sp_request_config)
    while sp_response:
        page_items = getattr(sp_response, "value", None)
        if isinstance(page_items, list):
            service_principals.extend(page_items)

        next_link = getattr(sp_response, "odata_next_link", None)
        if isinstance(next_link, str) and next_link:
            sp_response = await client.service_principals.with_url(next_link).get()
        else:
            break

    app_query_params = ApplicationsRequestBuilder.ApplicationsRequestBuilderGetQueryParameters(
        select=["id", "appId", "displayName", "passwordCredentials", "keyCredentials"],
    )
    app_request_config = RequestConfiguration(query_parameters=app_query_params)

    apps_by_app_id: dict[str, object] = {}
    app_response = await client.applications.get(request_configuration=app_request_config)
    while app_response:
        page_items = getattr(app_response, "value", None)
        if isinstance(page_items, list):
            for app in page_items:
                app_id = getattr(app, "app_id", None)
                if app_id:
                    apps_by_app_id[app_id] = app

        next_link = getattr(app_response, "odata_next_link", None)
        if isinstance(next_link, str) and next_link:
            app_response = await client.applications.with_url(next_link).get()
        else:
            break

    for sp in service_principals:
        secrets: list[dict[str, str]] = []
        sp_secret_entries = _collect_credential_entries(
            credentials=getattr(sp, "password_credentials", None),
            fallback_label="secret",
            credential_type="client_secret",
            source="service_principal",
        )
        sp_key_entries = _collect_credential_entries(
            credentials=getattr(sp, "key_credentials", None),
            fallback_label="key",
            credential_type="certificate",
            source="service_principal",
        )
        secrets.extend(sp_secret_entries)
        secrets.extend(sp_key_entries)

        app = None
        app_id = getattr(sp, "app_id", None)
        if app_id:
            app = apps_by_app_id.get(app_id)

        app_secret_entries: list[dict[str, str]] = []
        app_key_entries: list[dict[str, str]] = []
        if app is not None:
            app_secret_entries = _collect_credential_entries(
                credentials=getattr(app, "password_credentials", None),
                fallback_label="secret",
                credential_type="client_secret",
                source="app_registration",
            )
            app_key_entries = _collect_credential_entries(
                credentials=getattr(app, "key_credentials", None),
                fallback_label="key",
                credential_type="certificate",
                source="app_registration",
            )
            secrets.extend(app_secret_entries)
            secrets.extend(app_key_entries)

        if len(secrets) >= 2:
            findings.append(
                {
                    "service_principal_id": sp.id,
                    "display_name": sp.display_name or "Unknown",
                    "secret_count": len(secrets),
                    "service_principal_secret_count": len(sp_secret_entries) + len(sp_key_entries),
                    "app_registration_secret_count": len(app_secret_entries) + len(app_key_entries),
                    "app_id": app_id,
                    "app_registration_id": getattr(app, "id", None),
                    "app_registration_display_name": getattr(app, "display_name", None),
                    "secrets": secrets,
                }
            )

    if not findings:
        return CheckResult(
            check_id="sp-multiple-secrets",
            status="pass",
            message=(
                "No service principals have 2 or more assigned credentials "
                "(service principal + app registration)."
            ),
        )

    return CheckResult(
        check_id="sp-multiple-secrets",
        status="warning",
        message=(
            f"{len(findings)} service principal(s) have 2 or more assigned credentials "
            "(service principal + app registration)."
        ),
        recommendation=(
            "Review service principals with multiple credentials and remove unnecessary secrets "
            "or certificates."
        ),
        details={
            "service_principals": findings,
            "details_summary": "\n".join(
                f'- "{sp["display_name"]}" → {sp["secret_count"]} secret(s): '
                + ", ".join(
                    f'{secret["name"]} ({secret["type"]}, {secret["source"]})'
                    for secret in sp["secrets"]
                )
                for sp in findings
            ),
        },
    )
