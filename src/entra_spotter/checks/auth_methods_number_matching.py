"""Check that Microsoft Authenticator enforces number matching."""

from msgraph import GraphServiceClient

from entra_spotter.checks import CheckResult


async def check_auth_methods_number_matching(client: GraphServiceClient) -> CheckResult:
    """Check that number matching is enforced in Microsoft Authenticator.

    Number matching prevents MFA fatigue attacks (bombarding users with
    push notifications until they approve). When enabled, users must enter
    a number displayed on the sign-in screen into the Authenticator app.

    Pass: Number matching is enforced for all users (enabled or Microsoft-managed)
    Fail: Number matching is explicitly disabled
    Warning: Number matching is only enabled for specific groups
    """
    # GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator
    response = await client.policies.authentication_methods_policy.authentication_method_configurations.by_authentication_method_configuration_id(
        "MicrosoftAuthenticator"
    ).get()

    state = getattr(response, "state", None)

    if state == "disabled":
        return CheckResult(
            check_id="auth-methods-number-matching",
            status="warning",
            message="Microsoft Authenticator is disabled for the tenant.",
            recommendation=(
                "If push notifications are not used, this is acceptable. "
                "Otherwise, enable Microsoft Authenticator with number matching."
            ),
            details={"authenticator_state": state},
        )

    # Check feature settings for number matching
    # The numberMatchingRequiredState is in additionalData or feature_settings
    feature_settings = getattr(response, "feature_settings", None)
    if not feature_settings:
        # If no feature settings, number matching is Microsoft-managed (default enabled)
        return CheckResult(
            check_id="auth-methods-number-matching",
            status="pass",
            message=(
                "Microsoft Authenticator number matching is using default settings "
                "(Microsoft-managed, enabled by default)."
            ),
            details={"authenticator_state": state, "number_matching": "default"},
        )

    number_matching = getattr(feature_settings, "number_matching_required_state", None)
    if not number_matching:
        return CheckResult(
            check_id="auth-methods-number-matching",
            status="pass",
            message=(
                "Microsoft Authenticator number matching is using default settings "
                "(Microsoft-managed, enabled by default)."
            ),
            details={"authenticator_state": state, "number_matching": "default"},
        )

    nm_state = getattr(number_matching, "state", None)

    if nm_state == "enabled":
        # Check if it targets all users or specific groups
        include_target = getattr(number_matching, "include_target", None)
        if not include_target:
            return CheckResult(
                check_id="auth-methods-number-matching",
                status="pass",
                message="Number matching is enforced in Microsoft Authenticator.",
                details={"authenticator_state": state, "number_matching": nm_state},
            )

        target_type = getattr(include_target, "target_type", None)
        if target_type == "group":
            return CheckResult(
                check_id="auth-methods-number-matching",
                status="warning",
                message="Number matching is only enabled for specific groups, not all users.",
                recommendation="Enable number matching for all users to prevent MFA fatigue attacks.",
                details={"authenticator_state": state, "number_matching": nm_state, "target_type": target_type},
            )

        return CheckResult(
            check_id="auth-methods-number-matching",
            status="pass",
            message="Number matching is enforced in Microsoft Authenticator.",
            details={"authenticator_state": state, "number_matching": nm_state},
        )

    if nm_state == "disabled":
        return CheckResult(
            check_id="auth-methods-number-matching",
            status="fail",
            message="Number matching is disabled in Microsoft Authenticator.",
            recommendation=(
                "Enable number matching to prevent MFA fatigue attacks. "
                "Users will be required to enter a number shown on the sign-in screen."
            ),
            details={"authenticator_state": state, "number_matching": nm_state},
        )

    # "default" or Microsoft-managed state — number matching is on by default
    return CheckResult(
        check_id="auth-methods-number-matching",
        status="pass",
        message=(
            "Microsoft Authenticator number matching is Microsoft-managed "
            "(enabled by default)."
        ),
        details={"authenticator_state": state, "number_matching": nm_state},
    )
