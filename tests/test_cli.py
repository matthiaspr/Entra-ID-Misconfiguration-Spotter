"""Tests for CLI functionality."""

import json

import pytest
from click.testing import CliRunner

from entra_spotter.cli import (
    main,
    get_config,
    format_text_output,
    format_json_output,
    get_exit_code,
)
from entra_spotter.checks import Check, CheckResult


@pytest.fixture
def runner():
    return CliRunner()


class TestGetConfig:
    """Tests for configuration handling."""

    def test_cli_flags_override_env_vars(self, monkeypatch):
        """CLI flags should take precedence over environment variables."""
        monkeypatch.setenv("AZURE_TENANT_ID", "env-tenant")
        monkeypatch.setenv("AZURE_CLIENT_ID", "env-client")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "env-secret")

        tenant, client, secret = get_config(
            tenant_id="cli-tenant",
            client_id="cli-client",
            client_secret="cli-secret",
        )

        assert tenant == "cli-tenant"
        assert client == "cli-client"
        assert secret == "cli-secret"

    def test_falls_back_to_env_vars(self, monkeypatch):
        """Should use environment variables when CLI flags not provided."""
        monkeypatch.setenv("AZURE_TENANT_ID", "env-tenant")
        monkeypatch.setenv("AZURE_CLIENT_ID", "env-client")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "env-secret")

        tenant, client, secret = get_config(
            tenant_id=None,
            client_id=None,
            client_secret=None,
        )

        assert tenant == "env-tenant"
        assert client == "env-client"
        assert secret == "env-secret"

    def test_raises_when_config_missing(self, monkeypatch):
        """Should raise ClickException when required config is missing."""
        monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
        monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
        monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)

        with pytest.raises(Exception) as exc_info:
            get_config(None, None, None)

        assert "Missing required configuration" in str(exc_info.value)


class TestOutputFormatting:
    """Tests for output formatting."""

    @pytest.fixture
    def sample_results(self):
        """Sample check results for testing."""
        return [
            (
                Check(id="check-1", name="Check One", run=lambda x: None),
                CheckResult(
                    check_id="check-1",
                    status="pass",
                    message="All good.",
                ),
            ),
            (
                Check(id="check-2", name="Check Two", run=lambda x: None),
                CheckResult(
                    check_id="check-2",
                    status="fail",
                    message="Something wrong.",
                    recommendation="Fix it.",
                ),
            ),
            (
                Check(id="check-3", name="Check Three", run=lambda x: None),
                CheckResult(
                    check_id="check-3",
                    status="warning",
                    message="Watch out.",
                    recommendation="Review this.",
                ),
            ),
        ]

    def test_text_output_contains_status_symbols(self, sample_results):
        """Text output should contain status symbols."""
        output = format_text_output(sample_results)

        assert "[PASS]" in output
        assert "[FAIL]" in output
        assert "[WARN]" in output

    def test_text_output_contains_check_names(self, sample_results):
        """Text output should contain check names."""
        output = format_text_output(sample_results)

        assert "Check One" in output
        assert "Check Two" in output
        assert "Check Three" in output

    def test_text_output_contains_summary(self, sample_results):
        """Text output should contain summary."""
        output = format_text_output(sample_results)

        assert "1 failed" in output
        assert "1 warning" in output
        assert "1 passed" in output

    def test_json_output_is_valid_json(self, sample_results):
        """JSON output should be valid JSON."""
        output = format_json_output(sample_results, "test-tenant")
        parsed = json.loads(output)

        assert "version" in parsed
        assert "timestamp" in parsed
        assert "tenant_id" in parsed
        assert "results" in parsed
        assert "summary" in parsed

    def test_json_output_summary_counts(self, sample_results):
        """JSON output should have correct summary counts."""
        output = format_json_output(sample_results, "test-tenant")
        parsed = json.loads(output)

        assert parsed["summary"]["total"] == 3
        assert parsed["summary"]["passed"] == 1
        assert parsed["summary"]["failed"] == 1
        assert parsed["summary"]["warnings"] == 1
        assert parsed["summary"]["errors"] == 0


class TestExitCodes:
    """Tests for exit code determination."""

    def test_exit_0_when_all_pass(self):
        """Should return 0 when all checks pass."""
        results = [
            (None, CheckResult("c1", "pass", "ok")),
            (None, CheckResult("c2", "pass", "ok")),
        ]

        assert get_exit_code(results) == 0

    def test_exit_1_when_fail(self):
        """Should return 1 when any check fails."""
        results = [
            (None, CheckResult("c1", "pass", "ok")),
            (None, CheckResult("c2", "fail", "bad")),
        ]

        assert get_exit_code(results) == 1

    def test_exit_1_when_warning(self):
        """Should return 1 when any check warns."""
        results = [
            (None, CheckResult("c1", "pass", "ok")),
            (None, CheckResult("c2", "warning", "maybe")),
        ]

        assert get_exit_code(results) == 1

    def test_exit_2_when_error(self):
        """Should return 2 when any check errors."""
        results = [
            (None, CheckResult("c1", "pass", "ok")),
            (None, CheckResult("c2", "error", "boom")),
        ]

        assert get_exit_code(results) == 2

    def test_error_takes_precedence_over_fail(self):
        """Error exit code should take precedence over fail."""
        results = [
            (None, CheckResult("c1", "fail", "bad")),
            (None, CheckResult("c2", "error", "boom")),
        ]

        assert get_exit_code(results) == 2


class TestCLI:
    """Tests for CLI commands."""

    def test_list_checks(self, runner):
        """--list-checks should list all available checks."""
        result = runner.invoke(main, ["--list-checks"])

        assert result.exit_code == 0
        assert "user-consent" in result.output
        assert "admin-consent-workflow" in result.output
        assert "sp-admin-roles" in result.output

    def test_version(self, runner):
        """--version should show version."""
        result = runner.invoke(main, ["--version"])

        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_missing_config_shows_error(self, runner, monkeypatch):
        """Should show error when config is missing."""
        monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
        monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
        monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)

        result = runner.invoke(main, [])

        assert result.exit_code != 0
        assert "Missing required configuration" in result.output

    def test_invalid_check_id_shows_error(self, runner, monkeypatch):
        """Should show error for invalid check IDs."""
        monkeypatch.setenv("AZURE_TENANT_ID", "t")
        monkeypatch.setenv("AZURE_CLIENT_ID", "c")
        monkeypatch.setenv("AZURE_CLIENT_SECRET", "s")

        result = runner.invoke(main, ["--check", "nonexistent-check"])

        assert result.exit_code != 0
        assert "Unknown check ID" in result.output
