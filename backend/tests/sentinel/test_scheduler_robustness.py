"""
backend/tests/sentinel/test_scheduler_robustness.py
-----------------------------------------------------
Robustness & edge-case tests for the background playbook scheduler.

Test categories:
  1. Database lock timeout simulation during generation
  2. LLM API failure → graceful degradation to templated playbook
  3. Email alert triggering on critical failures
  4. Concurrent lock contention (overlapping cycles)
  5. Campaign clustering failure recovery

All database and external service calls are mocked.

Phase 5, Week 8 — Scheduler Robustness Testing
"""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock, call
import pytest

# ---------------------------------------------------------------------------
# Set test environment BEFORE importing modules
# ---------------------------------------------------------------------------
os.environ.setdefault("ENVIRONMENT", "test")
os.environ["DATABASE_URL"] = "sqlite:///test.db"
os.environ["SENTINEL_AUTO_GEN_ENABLED"] = "true"
os.environ["SENTINEL_AUTO_GEN_INTERVAL_MINUTES"] = "5"
os.environ["SENTINEL_EMAIL_ALERTS_ENABLED"] = "true"
os.environ["SENTINEL_EMAIL_SMTP_HOST"] = "smtp.test.local"
os.environ["SENTINEL_EMAIL_SMTP_PORT"] = "587"
os.environ["SENTINEL_EMAIL_SMTP_USER"] = "test@phantomnet.local"
os.environ["SENTINEL_EMAIL_SMTP_PASSWORD"] = "test-password"
os.environ["SENTINEL_EMAIL_SMTP_USE_TLS"] = "true"
os.environ["SENTINEL_EMAIL_FROM_ADDRESS"] = "sentinel@phantomnet.local"
os.environ["SENTINEL_EMAIL_RECIPIENTS"] = "admin@test.com,soc@test.com"
os.environ["SENTINEL_EMAIL_SEVERITY_THRESHOLD"] = "HIGH"
os.environ["SENTINEL_DASHBOARD_BASE_URL"] = "http://localhost:3000"


# ---------------------------------------------------------------------------
# Mock campaign data factory
# ---------------------------------------------------------------------------

def _make_campaign(campaign_id="CAMP-TEST-001", ips=None, ports=None):
    """Create a mock campaign clustering result."""
    return {
        "campaign_count": 1,
        "campaigns": [
            {
                "campaign_id": campaign_id,
                "unique_sources": ips or ["10.0.0.1", "10.0.0.2"],
                "target_ports": ports or [2222],
                "protocols": ["TCP"],
                "event_count": 150,
                "start_time": "2026-08-07T00:00:00",
                "end_time": "2026-08-07T06:00:00",
            }
        ],
    }


def _make_multi_campaign(count=3):
    """Create multiple campaigns for batch testing."""
    return {
        "campaign_count": count,
        "campaigns": [
            {
                "campaign_id": f"CAMP-BATCH-{i:03d}",
                "unique_sources": [f"10.0.{i}.1"],
                "target_ports": [2222],
                "protocols": ["TCP"],
                "event_count": 50 + i * 10,
            }
            for i in range(count)
        ],
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fresh_scheduler():
    """Create a fresh SchedulerService with cleared state."""
    from services.scheduler_service import SchedulerService
    svc = SchedulerService()
    svc._sentinel_processed_hashes.clear()
    svc._sentinel_seeded = True  # skip DB seed in tests
    return svc


@pytest.fixture
def mock_db_session():
    """Create a mock SQLAlchemy session."""
    session = MagicMock()
    session.query.return_value.all.return_value = []
    session.query.return_value.filter.return_value.all.return_value = []
    return session


# ===========================================================================
# 1. Database Lock Timeout Simulation
# ===========================================================================

class TestDatabaseLockTimeouts:
    """Simulate database lock timeouts during playbook generation."""

    @patch("services.scheduler_service.SessionLocal")
    @patch("services.scheduler_service.SchedulerService._seed_sentinel_hashes")
    def test_db_lock_timeout_triggers_fallback(
        self, mock_seed, mock_session_local, fresh_scheduler
    ):
        """When generate_playbook raises OperationalError (lock timeout),
        the scheduler should attempt a fallback playbook."""
        from sqlalchemy.exc import OperationalError

        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        # Simulate lock timeout on generate_playbook
        lock_error = OperationalError(
            "database is locked", params=None, orig=Exception("lock timeout")
        )

        with patch(
            "sentinel.sentinel_service.SentinelService.generate_playbook",
            side_effect=lock_error,
        ), patch.object(
            fresh_scheduler, "_generate_fallback_playbook"
        ) as mock_fallback, patch.object(
            fresh_scheduler, "_notify_critical_failure"
        ) as mock_notify, patch(
            "ml_engine.campaign_clustering.campaign_clusterer.identify_campaigns",
            return_value=_make_campaign(),
        ):
            fresh_scheduler._execute_sentinel_cycle()

            # Fallback should have been called
            assert mock_fallback.called, "Fallback playbook was not generated"
            # Email notification should have been triggered
            assert mock_notify.called, "Critical failure notification not sent"

            # Verify the error type was passed correctly
            notify_args = mock_notify.call_args
            assert "OperationalError" in notify_args[0][1]

    @patch("services.scheduler_service.SessionLocal")
    @patch("services.scheduler_service.SchedulerService._seed_sentinel_hashes")
    def test_db_timeout_on_commit_during_generation(
        self, mock_seed, mock_session_local, fresh_scheduler
    ):
        """Simulate commit failure (IntegrityError) during generation."""
        from sqlalchemy.exc import IntegrityError

        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        integrity_error = IntegrityError(
            "UNIQUE constraint failed",
            params=None,
            orig=Exception("duplicate key"),
        )

        with patch(
            "sentinel.sentinel_service.SentinelService.generate_playbook",
            side_effect=integrity_error,
        ), patch.object(
            fresh_scheduler, "_generate_fallback_playbook"
        ) as mock_fallback, patch.object(
            fresh_scheduler, "_notify_critical_failure"
        ), patch(
            "ml_engine.campaign_clustering.campaign_clusterer.identify_campaigns",
            return_value=_make_campaign(),
        ):
            fresh_scheduler._execute_sentinel_cycle()

            assert mock_fallback.called

    @patch("services.scheduler_service.SessionLocal")
    @patch("services.scheduler_service.SchedulerService._seed_sentinel_hashes")
    def test_repeated_lock_timeouts_dont_crash_cycle(
        self, mock_seed, mock_session_local, fresh_scheduler
    ):
        """Multiple campaigns failing with lock timeouts should not abort
        the entire cycle — each campaign is processed independently."""
        from sqlalchemy.exc import OperationalError

        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        lock_error = OperationalError(
            "database is locked", params=None, orig=Exception("lock")
        )

        with patch(
            "sentinel.sentinel_service.SentinelService.generate_playbook",
            side_effect=lock_error,
        ), patch.object(
            fresh_scheduler, "_generate_fallback_playbook"
        ) as mock_fallback, patch.object(
            fresh_scheduler, "_notify_critical_failure"
        ) as mock_notify, patch(
            "ml_engine.campaign_clustering.campaign_clusterer.identify_campaigns",
            return_value=_make_multi_campaign(3),
        ):
            # Should NOT raise — all errors handled gracefully
            fresh_scheduler._execute_sentinel_cycle()

            # All 3 campaigns should trigger fallback
            assert mock_fallback.call_count == 3
            assert mock_notify.call_count == 3


# ===========================================================================
# 2. LLM API Failure → Graceful Degradation
# ===========================================================================

class TestLLMFailureDegradation:
    """Simulate LLM API failures and verify fallback to templated playbook."""

    @patch("services.scheduler_service.SessionLocal")
    @patch("services.scheduler_service.SchedulerService._seed_sentinel_hashes")
    def test_llm_connection_refused_triggers_fallback(
        self, mock_seed, mock_session_local, fresh_scheduler
    ):
        """When LLM service is unreachable, scheduler should still create
        a playbook via the fallback path."""
        import httpx

        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        # Simulate ConnectError from httpx (LLM unreachable)
        llm_error = httpx.ConnectError("Connection refused")

        with patch(
            "sentinel.sentinel_service.SentinelService.generate_playbook",
            side_effect=llm_error,
        ), patch.object(
            fresh_scheduler, "_generate_fallback_playbook"
        ) as mock_fallback, patch.object(
            fresh_scheduler, "_notify_critical_failure"
        ), patch(
            "ml_engine.campaign_clustering.campaign_clusterer.identify_campaigns",
            return_value=_make_campaign(),
        ):
            fresh_scheduler._execute_sentinel_cycle()
            assert mock_fallback.called

    @patch("services.scheduler_service.SessionLocal")
    @patch("services.scheduler_service.SchedulerService._seed_sentinel_hashes")
    def test_llm_timeout_triggers_fallback(
        self, mock_seed, mock_session_local, fresh_scheduler
    ):
        """When LLM times out (60s), scheduler should gracefully degrade."""
        import httpx

        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        timeout_error = httpx.ReadTimeout("Read timed out after 60s")

        with patch(
            "sentinel.sentinel_service.SentinelService.generate_playbook",
            side_effect=timeout_error,
        ), patch.object(
            fresh_scheduler, "_generate_fallback_playbook"
        ) as mock_fallback, patch.object(
            fresh_scheduler, "_notify_critical_failure"
        ), patch(
            "ml_engine.campaign_clustering.campaign_clusterer.identify_campaigns",
            return_value=_make_campaign(),
        ):
            fresh_scheduler._execute_sentinel_cycle()
            assert mock_fallback.called

    def test_fallback_playbook_content_is_valid(self, fresh_scheduler, mock_db_session):
        """The fallback playbook should contain campaign context and actions."""
        from sentinel.models import SentinelPlaybook

        campaign_data = {
            "source_ips": ["192.168.1.50", "192.168.1.51"],
            "target_ports": [2222],
            "protocols": ["TCP"],
            "event_count": 200,
        }
        error = RuntimeError("LLM service unavailable")

        with patch.object(mock_db_session, "add") as mock_add, \
             patch.object(mock_db_session, "commit"):
            fresh_scheduler._generate_fallback_playbook(
                mock_db_session, campaign_data, "CAMP-FB-001", error
            )

            # Verify a SentinelPlaybook was added
            assert mock_add.called
            record = mock_add.call_args[0][0]
            assert isinstance(record, SentinelPlaybook)
            assert "FALLBACK" in record.attack_type
            assert record.severity == "HIGH"
            assert "192.168.1.50" in record.playbook_content
            assert "Block source IPs" in record.playbook_content
            assert "RuntimeError" in record.playbook_content
            assert record.src_ip == "192.168.1.50"
            assert record.template_name == "fallback"

    def test_fallback_playbook_handles_empty_campaign_data(
        self, fresh_scheduler, mock_db_session
    ):
        """Fallback should gracefully handle empty campaign data."""
        campaign_data = {
            "source_ips": [],
            "target_ports": [],
            "protocols": ["TCP"],
            "event_count": 0,
        }
        error = Exception("Pipeline crashed")

        with patch.object(mock_db_session, "add") as mock_add, \
             patch.object(mock_db_session, "commit"):
            fresh_scheduler._generate_fallback_playbook(
                mock_db_session, campaign_data, "CAMP-EMPTY", error
            )

            record = mock_add.call_args[0][0]
            assert record.src_ip == "unknown"
            assert record.dst_port is None


# ===========================================================================
# 3. Email Alert Triggering on Critical Failures
# ===========================================================================

class TestCriticalFailureEmailAlerts:
    """Verify email alerts fire properly on critical scheduler failures."""

    @patch("sentinel.email_notifier.SentinelEmailNotifier.compose_email")
    @patch("sentinel.email_notifier.smtplib.SMTP")
    def test_critical_failure_sends_email(
        self, mock_smtp_class, mock_compose, fresh_scheduler
    ):
        """A generation failure should trigger an email alert."""
        mock_compose.return_value = MagicMock()
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        import sentinel.email_notifier as notifier_mod
        notifier_mod._notifier_instance = None
        import importlib
        import config.sentinel_config
        importlib.reload(config.sentinel_config)

        fresh_scheduler._notify_critical_failure(
            campaign_id="CAMP-ALERT-001",
            error_type="OperationalError",
            error_message="database is locked",
        )

        assert mock_compose.called
        context = mock_compose.call_args[0][0]
        assert "SCHEDULER FAILURE" in context["playbook_name"]
        assert "CAMP-ALERT-001" in context["playbook_name"]

    @patch("sentinel.email_notifier.SentinelEmailNotifier.compose_email")
    @patch("sentinel.email_notifier.smtplib.SMTP")
    def test_email_contains_error_details(
        self, mock_smtp_class, mock_compose, fresh_scheduler
    ):
        """The alert email should contain the error type and message."""
        mock_compose.return_value = MagicMock()
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        import sentinel.email_notifier as notifier_mod
        notifier_mod._notifier_instance = None
        import importlib
        import config.sentinel_config
        importlib.reload(config.sentinel_config)

        fresh_scheduler._notify_critical_failure(
            campaign_id="CAMP-ERR-002",
            error_type="TimeoutError",
            error_message="LLM inference timed out after 60 seconds",
        )

        context = mock_compose.call_args[0][0]
        assert "TimeoutError" in context["summary"]
        assert "LLM inference timed out" in context["summary"]

    def test_email_disabled_does_not_send(self, fresh_scheduler):
        """When email alerts are disabled, no SMTP call is made."""
        os.environ["SENTINEL_EMAIL_ALERTS_ENABLED"] = "false"

        import sentinel.email_notifier as notifier_mod
        notifier_mod._notifier_instance = None
        import importlib
        import config.sentinel_config
        importlib.reload(config.sentinel_config)

        with patch("sentinel.email_notifier.smtplib.SMTP") as mock_smtp:
            fresh_scheduler._notify_critical_failure(
                "CAMP-SKIP", "RuntimeError", "test"
            )
            assert not mock_smtp.called

        # Restore
        os.environ["SENTINEL_EMAIL_ALERTS_ENABLED"] = "true"

    @patch("sentinel.email_notifier.smtplib.SMTP")
    def test_email_failure_does_not_crash_scheduler(
        self, mock_smtp_class, fresh_scheduler
    ):
        """If the email itself fails to send, the scheduler should not crash."""
        import smtplib
        mock_smtp_class.side_effect = smtplib.SMTPConnectError(
            421, b"Service unavailable"
        )

        import sentinel.email_notifier as notifier_mod
        notifier_mod._notifier_instance = None
        import importlib
        import config.sentinel_config
        importlib.reload(config.sentinel_config)

        # Should not raise
        fresh_scheduler._notify_critical_failure(
            "CAMP-NOCRASH", "RuntimeError", "test error"
        )

    @patch("services.scheduler_service.SessionLocal")
    @patch("services.scheduler_service.SchedulerService._seed_sentinel_hashes")
    @patch("sentinel.email_notifier.smtplib.SMTP")
    def test_full_cycle_with_failure_sends_email_alert(
        self, mock_smtp_class, mock_seed, mock_session_local, fresh_scheduler
    ):
        """End-to-end: a failed generation cycle triggers an email alert."""
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        import sentinel.email_notifier as notifier_mod
        notifier_mod._notifier_instance = None
        import importlib
        import config.sentinel_config
        importlib.reload(config.sentinel_config)

        with patch(
            "sentinel.sentinel_service.SentinelService.generate_playbook",
            side_effect=RuntimeError("Pipeline explosion"),
        ), patch.object(
            fresh_scheduler, "_generate_fallback_playbook"
        ), patch(
            "ml_engine.campaign_clustering.campaign_clusterer.identify_campaigns",
            return_value=_make_campaign("CAMP-E2E-001"),
        ):
            fresh_scheduler._execute_sentinel_cycle()

            assert mock_server.sendmail.called


# ===========================================================================
# 4. Concurrent Lock Contention
# ===========================================================================

class TestConcurrentLockContention:
    """Test the threading.Lock preventing overlapping scheduler cycles."""

    def test_concurrent_cycles_are_blocked(self, fresh_scheduler):
        """If one cycle is running, a second invocation should skip."""
        results = {"blocked": False, "ran": False}

        # Manually acquire the lock to simulate a running cycle
        fresh_scheduler._sentinel_lock.acquire()

        def try_cycle():
            # This should be blocked (non-blocking acquire fails)
            acquired = fresh_scheduler._sentinel_lock.acquire(blocking=False)
            if not acquired:
                results["blocked"] = True
            else:
                results["ran"] = True
                fresh_scheduler._sentinel_lock.release()

        thread = threading.Thread(target=try_cycle)
        thread.start()
        thread.join(timeout=2)

        fresh_scheduler._sentinel_lock.release()

        assert results["blocked"] is True
        assert results["ran"] is False

    def test_run_sentinel_auto_gen_skips_when_locked(self, fresh_scheduler):
        """_run_sentinel_auto_gen_cycle should skip if lock is held."""
        fresh_scheduler._sentinel_lock.acquire()

        with patch.object(
            fresh_scheduler, "_execute_sentinel_cycle"
        ) as mock_exec:
            fresh_scheduler._run_sentinel_auto_gen_cycle()
            assert not mock_exec.called, "Cycle should have been skipped"

        fresh_scheduler._sentinel_lock.release()

    def test_lock_released_after_exception(self, fresh_scheduler):
        """The lock must be released even if the cycle raises."""
        with patch.object(
            fresh_scheduler, "_execute_sentinel_cycle",
            side_effect=RuntimeError("Unhandled"),
        ):
            fresh_scheduler._run_sentinel_auto_gen_cycle()

        # Lock should be released
        assert not fresh_scheduler._sentinel_lock.locked()


# ===========================================================================
# 5. Campaign Clustering Failure Recovery
# ===========================================================================

class TestClusteringFailureRecovery:
    """Test scheduler behavior when campaign clustering itself fails."""

    @patch("services.scheduler_service.SessionLocal")
    @patch("services.scheduler_service.SchedulerService._seed_sentinel_hashes")
    def test_clustering_exception_does_not_crash(
        self, mock_seed, mock_session_local, fresh_scheduler
    ):
        """If identify_campaigns raises, the cycle should log and return."""
        with patch(
            "ml_engine.campaign_clustering.campaign_clusterer.identify_campaigns",
            side_effect=ConnectionError("ML engine unavailable"),
        ):
            # Should not raise
            fresh_scheduler._execute_sentinel_cycle()

    @patch("services.scheduler_service.SessionLocal")
    @patch("services.scheduler_service.SchedulerService._seed_sentinel_hashes")
    def test_empty_clustering_result(
        self, mock_seed, mock_session_local, fresh_scheduler
    ):
        """When clustering returns no campaigns, no playbooks should be generated."""
        with patch(
            "ml_engine.campaign_clustering.campaign_clusterer.identify_campaigns",
            return_value={"campaign_count": 0, "campaigns": []},
        ), patch(
            "sentinel.sentinel_service.SentinelService.generate_playbook"
        ) as mock_gen:
            fresh_scheduler._execute_sentinel_cycle()
            assert not mock_gen.called

    @patch("services.scheduler_service.SessionLocal")
    @patch("services.scheduler_service.SchedulerService._seed_sentinel_hashes")
    def test_none_clustering_result(
        self, mock_seed, mock_session_local, fresh_scheduler
    ):
        """When clustering returns None, cycle should handle gracefully."""
        with patch(
            "ml_engine.campaign_clustering.campaign_clusterer.identify_campaigns",
            return_value=None,
        ), patch(
            "sentinel.sentinel_service.SentinelService.generate_playbook"
        ) as mock_gen:
            fresh_scheduler._execute_sentinel_cycle()
            assert not mock_gen.called


# ===========================================================================
# 6. Deduplication Under Failure
# ===========================================================================

class TestDeduplicationUnderFailure:
    """Ensure dedup hashes are NOT added when both primary + fallback fail."""

    @patch("services.scheduler_service.SessionLocal")
    @patch("services.scheduler_service.SchedulerService._seed_sentinel_hashes")
    def test_hash_not_added_when_both_paths_fail(
        self, mock_seed, mock_session_local, fresh_scheduler
    ):
        """If both generate_playbook AND fallback fail, the campaign should
        remain unprocessed so it can be retried next cycle."""
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        with patch(
            "sentinel.sentinel_service.SentinelService.generate_playbook",
            side_effect=RuntimeError("Primary failed"),
        ), patch.object(
            fresh_scheduler, "_generate_fallback_playbook",
            side_effect=RuntimeError("Fallback also failed"),
        ), patch.object(
            fresh_scheduler, "_notify_critical_failure"
        ), patch(
            "ml_engine.campaign_clustering.campaign_clusterer.identify_campaigns",
            return_value=_make_campaign("CAMP-RETRY-001"),
        ):
            fresh_scheduler._execute_sentinel_cycle()

            # Hash should NOT be in the set (both paths failed)
            assert len(fresh_scheduler._sentinel_processed_hashes) == 0

    @patch("services.scheduler_service.SessionLocal")
    @patch("services.scheduler_service.SchedulerService._seed_sentinel_hashes")
    def test_hash_added_when_fallback_succeeds(
        self, mock_seed, mock_session_local, fresh_scheduler
    ):
        """If primary fails but fallback succeeds, the campaign hash should
        be added to prevent re-processing."""
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        with patch(
            "sentinel.sentinel_service.SentinelService.generate_playbook",
            side_effect=RuntimeError("Primary failed"),
        ), patch.object(
            fresh_scheduler, "_generate_fallback_playbook"
        ) as mock_fallback, patch.object(
            fresh_scheduler, "_notify_critical_failure"
        ), patch(
            "ml_engine.campaign_clustering.campaign_clusterer.identify_campaigns",
            return_value=_make_campaign("CAMP-FB-OK"),
        ):
            fresh_scheduler._execute_sentinel_cycle()

            assert mock_fallback.called
            assert len(fresh_scheduler._sentinel_processed_hashes) == 1


# ===========================================================================
# 7. Mixed Success/Failure Batch Processing
# ===========================================================================

class TestMixedBatchProcessing:
    """Test that partial failures in a batch don't affect successful campaigns."""

    @patch("services.scheduler_service.SessionLocal")
    @patch("services.scheduler_service.SchedulerService._seed_sentinel_hashes")
    def test_mixed_batch_continues_after_failure(
        self, mock_seed, mock_session_local, fresh_scheduler
    ):
        """In a batch of 3 campaigns, if campaign 2 fails, campaigns 1 and 3
        should still be processed successfully."""
        mock_db = MagicMock()
        mock_session_local.return_value = mock_db

        call_count = {"n": 0}

        def selective_failure(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise RuntimeError("Campaign 2 pipeline crashed")
            return MagicMock()

        with patch(
            "sentinel.sentinel_service.SentinelService.generate_playbook",
            side_effect=selective_failure,
        ), patch.object(
            fresh_scheduler, "_generate_fallback_playbook"
        ), patch.object(
            fresh_scheduler, "_notify_critical_failure"
        ), patch(
            "ml_engine.campaign_clustering.campaign_clusterer.identify_campaigns",
            return_value=_make_multi_campaign(3),
        ):
            fresh_scheduler._execute_sentinel_cycle()

            # All 3 should be tracked (2 success + 1 fallback)
            assert len(fresh_scheduler._sentinel_processed_hashes) == 3
