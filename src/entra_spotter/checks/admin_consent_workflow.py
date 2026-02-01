"""Check for admin consent workflow configuration."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult


def check_admin_consent_workflow(client: GraphServiceClient) -> CheckResult:
    """Check if admin consent workflow is enabled with reviewers.

    Calls GET /policies/adminConsentRequestPolicy and checks
    isEnabled and reviewers array.

    Pass: isEnabled=true AND reviewers is non-empty
    Fail: isEnabled=false
    Warning: isEnabled=true but reviewers is empty
    """
    response = client.policies.admin_consent_request_policy.get()

    is_enabled = response.is_enabled
    reviewers = response.reviewers or []

    if not is_enabled:
        return CheckResult(
            check_id="admin-consent-workflow",
            status="fail",
            message="Admin consent workflow is disabled.",
            recommendation="Enable admin consent workflow in Entra ID.",
            details={"is_enabled": is_enabled},
        )

    if not reviewers:
        return CheckResult(
            check_id="admin-consent-workflow",
            status="warning",
            message="Admin consent workflow is enabled but has no reviewers.",
            recommendation="Add reviewers to the admin consent workflow.",
            details={"is_enabled": is_enabled, "reviewer_count": 0},
        )

    return CheckResult(
        check_id="admin-consent-workflow",
        status="pass",
        message=f"Admin consent workflow is enabled with {len(reviewers)} reviewer(s).",
        details={"is_enabled": is_enabled, "reviewer_count": len(reviewers)},
    )
