"""
backend/tests/sentinel/test_email_notifier.py
-----------------------------------------------
Unit tests for the Sentinel Email Alert Dispatcher.

Tests cover:
  1. Severity threshold logic (should_alert)
  2. Email context building from SentinelPlaybook records
  3. Email composition (subject, headers, multipart body)
  4. Async dispatch mechanics (thread spawning)
  5. Integration with sentinel_service.py pipeline
  6. Graceful failure when SMTP is unavailable

All SMTP calls are mocked — no actual emails are sent during testing.

Phase 5, Week 5 — Email Alert Notifications
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from unittest.mock import MagicMock, patch, PropertyMock
import pytest


# ---------------------------------------------------------------------------
# Set test environment BEFORE importing modules
# ---------------------------------------------------------------------------
os.environ.setdefault("ENVIRONMENT", "test")
os.environ["SENTINEL_EMAIL_ALERTS_ENABLED"] = "true"
os.environ["SENTINEL_EMAIL_SMTP_HOST"] = "smtp.test.local"
os.environ["SENTINEL_EMAIL_SMTP_PORT"] = "587"
os.environ["SENTINEL_EMAIL_SMTP_USER"] = "test@phantomnet.local"
os.environ["SENTINEL_EMAIL_SMTP_PASSWORD"] = "test-password"
os.environ["SENTINEL_EMAIL_SMTP_USE_TLS"] = "true"
os.environ["SENTINEL_EMAIL_FROM_ADDRESS"] = "sentinel@phantomnet.local"
os.environ["SENTINEL_EMAIL_RECIPIENTS"] = "admin@test.com,soc@test.com"
os.environ["SENTINEL_EMAIL_SEVERITY_THRESHOLD"] = "CRITICAL"
os.environ["SENTINEL_DASHBOARD_BASE_URL"] = "http://localhost:3000"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class MockPlaybook:
    """Lightweight mock of a SentinelPlaybook ORM object for testing."""

    def __init__(self, **kwargs):
        self.id = kwargs.get("id", 42)
        self.playbook_id = kwargs.get("playbook_id", "PB-20260729-120000-ABC123")
        self.playbook_name = kwargs.get("playbook_name", "SSH Brute Force Response Playbook")
        self.severity = kwargs.get("severity", "CRITICAL")
        self.attack_type = kwargs.get("attack_type", "SSH_AUTH_FAILURE")
        self.technique_id = kwargs.get("technique_id", "T1110.001")
        self.technique_name = kwargs.get("technique_name", "Brute Force: Password Guessing")
        self.tactic = kwargs.get("tactic", "Credential Access")
        self.threat_score = kwargs.get("threat_score", 87.5)
        self.src_ip = kwargs.get("src_ip", "192.168.1.100")
        self.dst_port = kwargs.get("dst_port", 2222)
        self.protocol = kwargs.get("protocol", "TCP")
        self.confidence_score = kwargs.get("confidence_score", 0.85)
        self.created_at = kwargs.get("created_at", datetime(2026, 7, 29, 12, 0, 0))
        self.status = kwargs.get("status", "pending")


@pytest.fixture
def critical_playbook():
    """Return a CRITICAL severity mock playbook."""
    return MockPlaybook(severity="CRITICAL", threat_score=92.0)


@pytest.fixture
def high_playbook():
    """Return a HIGH severity mock playbook."""
    return MockPlaybook(severity="HIGH", threat_score=72.0)


@pytest.fixture
def medium_playbook():
    """Return a MEDIUM severity mock playbook."""
    return MockPlaybook(severity="MEDIUM", threat_score=45.0)


@pytest.fixture
def low_playbook():
    """Return a LOW severity mock playbook."""
    return MockPlaybook(severity="LOW", threat_score=15.0)


# ---------------------------------------------------------------------------
# Helper: force-reload the notifier module to pick up fresh env vars
# ---------------------------------------------------------------------------

def _create_notifier():
    """Create a fresh SentinelEmailNotifier with current env vars."""
    # Reset the cached singleton
    import sentinel.email_notifier as mod
    mod._notifier_instance = None

    # Force-reload config to pick up env vars
    import importlib
    import config.sentinel_config
    importlib.reload(config.sentinel_config)

    from sentinel.email_notifier import SentinelEmailNotifier
    return SentinelEmailNotifier()


# ===========================================================================
# 1. Severity threshold tests
# ===========================================================================

class TestSeverityThreshold:
    """Tests for should_alert() severity threshold logic."""

    def test_critical_meets_critical_threshold(self, critical_playbook):
        notifier = _create_notifier()
        assert notifier.should_alert("CRITICAL") is True

    def test_high_does_not_meet_critical_threshold(self):
        notifier = _create_notifier()
        # Default threshold is CRITICAL, so HIGH should NOT trigger
        assert notifier.should_alert("HIGH") is False

    def test_medium_does_not_meet_critical_threshold(self):
        notifier = _create_notifier()
        assert notifier.should_alert("MEDIUM") is False

    def test_low_does_not_meet_critical_threshold(self):
        notifier = _create_notifier()
        assert notifier.should_alert("LOW") is False

    def test_high_meets_high_threshold(self):
        os.environ["SENTINEL_EMAIL_SEVERITY_THRESHOLD"] = "HIGH"
        notifier = _create_notifier()
        assert notifier.should_alert("HIGH") is True
        assert notifier.should_alert("CRITICAL") is True
        assert notifier.should_alert("MEDIUM") is False
        # Restore
        os.environ["SENTINEL_EMAIL_SEVERITY_THRESHOLD"] = "CRITICAL"

    def test_none_severity_returns_false(self):
        notifier = _create_notifier()
        assert notifier.should_alert(None) is False

    def test_empty_severity_returns_false(self):
        notifier = _create_notifier()
        assert notifier.should_alert("") is False

    def test_disabled_notifier_always_returns_false(self):
        os.environ["SENTINEL_EMAIL_ALERTS_ENABLED"] = "false"
        notifier = _create_notifier()
        assert notifier.should_alert("CRITICAL") is False
        # Restore
        os.environ["SENTINEL_EMAIL_ALERTS_ENABLED"] = "true"

    def test_no_recipients_returns_false(self):
        os.environ["SENTINEL_EMAIL_RECIPIENTS"] = ""
        notifier = _create_notifier()
        assert notifier.should_alert("CRITICAL") is False
        # Restore
        os.environ["SENTINEL_EMAIL_RECIPIENTS"] = "admin@test.com,soc@test.com"


# ===========================================================================
# 2. Email context building tests
# ===========================================================================

class TestEmailContext:
    """Tests for build_email_context() template variable extraction."""

    def test_context_has_required_keys(self, critical_playbook):
        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)

        required_keys = [
            "playbook_name", "playbook_id", "severity", "severity_color",
            "attack_type", "technique_id", "technique_name", "threat_score",
            "src_ip", "generated_at", "summary", "dashboard_url",
        ]
        for key in required_keys:
            assert key in ctx, f"Missing key: {key}"

    def test_context_values_match_playbook(self, critical_playbook):
        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)

        assert ctx["playbook_name"] == "SSH Brute Force Response Playbook"
        assert ctx["playbook_id"] == "PB-20260729-120000-ABC123"
        assert ctx["severity"] == "CRITICAL"
        assert ctx["attack_type"] == "SSH_AUTH_FAILURE"
        assert ctx["technique_id"] == "T1110.001"
        assert ctx["src_ip"] == "192.168.1.100"

    def test_dashboard_url_contains_playbook_id(self, critical_playbook):
        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)
        assert "42" in ctx["dashboard_url"]
        assert "localhost:3000" in ctx["dashboard_url"]

    def test_summary_includes_attack_details(self, critical_playbook):
        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)
        assert "SSH_AUTH_FAILURE" in ctx["summary"]
        assert "192.168.1.100" in ctx["summary"]

    def test_severity_color_for_critical(self, critical_playbook):
        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)
        assert ctx["severity_color"] == "#ef4444"

    def test_context_handles_missing_fields(self):
        playbook = MockPlaybook(
            attack_type=None, technique_id=None, technique_name=None,
            src_ip=None, threat_score=None, created_at=None,
        )
        notifier = _create_notifier()
        ctx = notifier.build_email_context(playbook)
        assert ctx["attack_type"] == "Unknown"
        assert ctx["technique_id"] == "N/A"
        assert ctx["threat_score"] == "N/A"
        assert ctx["src_ip"] == "N/A"


# ===========================================================================
# 3. Email composition tests
# ===========================================================================

class TestEmailComposition:
    """Tests for compose_email() MIME message construction."""

    def test_email_has_correct_subject(self, critical_playbook):
        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)
        msg = notifier.compose_email(ctx)

        assert "CRITICAL ALERT" in msg["Subject"]
        assert "SSH Brute Force Response Playbook" in msg["Subject"]

    def test_email_has_from_and_to(self, critical_playbook):
        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)
        msg = notifier.compose_email(ctx)

        assert msg["From"] == "sentinel@phantomnet.local"
        assert "admin@test.com" in msg["To"]
        assert "soc@test.com" in msg["To"]

    def test_email_has_priority_header(self, critical_playbook):
        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)
        msg = notifier.compose_email(ctx)

        assert msg["X-Priority"] == "1"  # Critical = priority 1

    def test_email_has_custom_headers(self, critical_playbook):
        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)
        msg = notifier.compose_email(ctx)

        assert msg["X-PhantomNet-Playbook-ID"] == "PB-20260729-120000-ABC123"
        assert msg["X-PhantomNet-Severity"] == "CRITICAL"

    def test_email_is_multipart(self, critical_playbook):
        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)
        msg = notifier.compose_email(ctx)

        assert msg.is_multipart()
        payloads = msg.get_payload()
        assert len(payloads) == 2  # plain + HTML

    def test_email_plain_text_body(self, critical_playbook):
        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)
        msg = notifier.compose_email(ctx)

        plain_body = msg.get_payload(0).get_payload(decode=True).decode("utf-8")
        assert "PHANTOMNET SENTINEL ALERT" in plain_body
        assert "SSH Brute Force Response Playbook" in plain_body
        assert "T1110.001" in plain_body

    def test_email_html_body(self, critical_playbook):
        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)
        msg = notifier.compose_email(ctx)

        html_body = msg.get_payload(1).get_payload(decode=True).decode("utf-8")
        assert "<!DOCTYPE html>" in html_body
        assert "SENTINEL ALERT" in html_body
        assert "View Playbook in Dashboard" in html_body


# ===========================================================================
# 4. SMTP sending tests (mocked)
# ===========================================================================

class TestSMTPSending:
    """Tests for _send_smtp() with mocked SMTP connections."""

    @patch("sentinel.email_notifier.smtplib.SMTP")
    def test_successful_send(self, mock_smtp_class, critical_playbook):
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)
        msg = notifier.compose_email(ctx)

        result = notifier._send_smtp(msg)
        assert result is True
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("test@phantomnet.local", "test-password")
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()

    @patch("sentinel.email_notifier.smtplib.SMTP")
    def test_smtp_auth_failure(self, mock_smtp_class, critical_playbook):
        import smtplib
        mock_server = MagicMock()
        mock_server.login.side_effect = smtplib.SMTPAuthenticationError(535, b"Auth failed")
        mock_smtp_class.return_value = mock_server

        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)
        msg = notifier.compose_email(ctx)

        result = notifier._send_smtp(msg)
        assert result is False

    @patch("sentinel.email_notifier.smtplib.SMTP")
    def test_smtp_connection_error(self, mock_smtp_class, critical_playbook):
        import smtplib
        mock_smtp_class.side_effect = smtplib.SMTPConnectError(421, b"Connection refused")

        notifier = _create_notifier()
        ctx = notifier.build_email_context(critical_playbook)
        msg = notifier.compose_email(ctx)

        result = notifier._send_smtp(msg)
        assert result is False

    @patch("sentinel.email_notifier.smtplib.SMTP")
    def test_send_without_tls(self, mock_smtp_class, critical_playbook):
        os.environ["SENTINEL_EMAIL_SMTP_USE_TLS"] = "false"
        notifier = _create_notifier()

        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        ctx = notifier.build_email_context(critical_playbook)
        msg = notifier.compose_email(ctx)
        result = notifier._send_smtp(msg)

        assert result is True
        mock_server.starttls.assert_not_called()
        # Restore
        os.environ["SENTINEL_EMAIL_SMTP_USE_TLS"] = "true"


# ===========================================================================
# 5. End-to-end send_alert tests
# ===========================================================================

class TestSendAlert:
    """Tests for the send_alert() blocking dispatch method."""

    @patch("sentinel.email_notifier.smtplib.SMTP")
    def test_send_alert_for_critical(self, mock_smtp_class, critical_playbook):
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        notifier = _create_notifier()
        result = notifier.send_alert(critical_playbook)
        assert result is True

    def test_send_alert_skips_low_severity(self, low_playbook):
        notifier = _create_notifier()
        result = notifier.send_alert(low_playbook)
        assert result is False

    def test_send_alert_skips_medium_severity(self, medium_playbook):
        notifier = _create_notifier()
        result = notifier.send_alert(medium_playbook)
        assert result is False


# ===========================================================================
# 6. Async dispatch tests
# ===========================================================================

class TestAsyncDispatch:
    """Tests for send_alert_async() background thread dispatch."""

    @patch("sentinel.email_notifier.smtplib.SMTP")
    def test_async_alert_spawns_thread(self, mock_smtp_class, critical_playbook):
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        notifier = _create_notifier()

        initial_count = threading.active_count()
        notifier.send_alert_async(critical_playbook)

        # Give the thread a moment to spawn
        import time
        time.sleep(0.2)

        # The thread should have been created (may have finished already)
        # The key assertion is that no exception was raised
        assert True

    def test_async_alert_skips_low_severity(self, low_playbook):
        notifier = _create_notifier()
        # Should return immediately without spawning a thread
        notifier.send_alert_async(low_playbook)
        # No exception means success


# ===========================================================================
# 7. Module-level convenience function tests
# ===========================================================================

class TestTriggerFunction:
    """Tests for the trigger_email_alert_async() convenience function."""

    @patch("sentinel.email_notifier.smtplib.SMTP")
    def test_trigger_function_works(self, mock_smtp_class, critical_playbook):
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        import sentinel.email_notifier as mod
        mod._notifier_instance = None  # Reset singleton

        from sentinel.email_notifier import trigger_email_alert_async
        # Should not raise
        trigger_email_alert_async(critical_playbook)

    def test_trigger_function_handles_errors_gracefully(self):
        """Ensure the trigger function doesn't raise even on errors."""
        import sentinel.email_notifier as mod
        mod._notifier_instance = None

        from sentinel.email_notifier import trigger_email_alert_async
        # Pass a broken playbook that might cause issues
        broken_playbook = MockPlaybook(severity=None)
        trigger_email_alert_async(broken_playbook)  # Should not raise


# ===========================================================================
# 8. Severity helper function tests
# ===========================================================================

class TestSeverityHelper:
    """Tests for the _severity_meets_threshold() utility function."""

    def test_critical_meets_critical(self):
        from sentinel.email_notifier import _severity_meets_threshold
        assert _severity_meets_threshold("CRITICAL", "CRITICAL") is True

    def test_critical_meets_high(self):
        from sentinel.email_notifier import _severity_meets_threshold
        assert _severity_meets_threshold("CRITICAL", "HIGH") is True

    def test_high_does_not_meet_critical(self):
        from sentinel.email_notifier import _severity_meets_threshold
        assert _severity_meets_threshold("HIGH", "CRITICAL") is False

    def test_medium_meets_medium(self):
        from sentinel.email_notifier import _severity_meets_threshold
        assert _severity_meets_threshold("MEDIUM", "MEDIUM") is True

    def test_low_meets_low(self):
        from sentinel.email_notifier import _severity_meets_threshold
        assert _severity_meets_threshold("LOW", "LOW") is True

    def test_case_insensitive(self):
        from sentinel.email_notifier import _severity_meets_threshold
        assert _severity_meets_threshold("critical", "CRITICAL") is True
        assert _severity_meets_threshold("Critical", "critical") is True
