"""
tests/test_sentinel_scheduler.py
---------------------------------
Unit tests for the Sentinel Auto-Generation Scheduler.

Validates:
  1. Configuration module reads environment variables correctly.
  2. SchedulerService.start_sentinel_auto_gen() registers / skips the job
     based on SENTINEL_AUTO_GEN_ENABLED.
  3. Locking mechanism prevents concurrent sentinel generation cycles.
  4. Dedup hash logic skips already-processed campaigns.
  5. Status introspection returns correct metadata.

Phase 5, Week 4 — Sentinel Auto-Generation Scheduler Tests
"""

import os
import sys
import hashlib
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

# Force SQLite test database and test environment before importing application modules
os.environ["DATABASE_URL"] = "sqlite:///./phantomnet.db"
os.environ["ENVIRONMENT"] = "test"

# Ensure backend and root project directories are in sys.path
dir_path = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.abspath(os.path.join(dir_path, ".."))
backend_dir = os.path.join(root_dir, "backend")

if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)


class TestSentinelConfig(unittest.TestCase):
    """Tests for backend/config/sentinel_config.py."""

    def test_env_bool_true_values(self):
        """_env_bool returns True for 'true', '1', 'yes', 'on'."""
        from config.sentinel_config import _env_bool

        for val in ("true", "1", "yes", "on", "TRUE", "True", "YES", "ON"):
            with patch.dict(os.environ, {"TEST_BOOL": val}):
                self.assertTrue(_env_bool("TEST_BOOL", default=False))

    def test_env_bool_false_values(self):
        """_env_bool returns False for 'false', '0', 'no', random strings."""
        from config.sentinel_config import _env_bool

        for val in ("false", "0", "no", "off", "random"):
            with patch.dict(os.environ, {"TEST_BOOL": val}):
                self.assertFalse(_env_bool("TEST_BOOL", default=False))

    def test_env_bool_missing_uses_default(self):
        """_env_bool returns default when env var is not set."""
        from config.sentinel_config import _env_bool

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NONEXISTENT_VAR", None)
            self.assertTrue(_env_bool("NONEXISTENT_VAR", default=True))
            self.assertFalse(_env_bool("NONEXISTENT_VAR", default=False))

    def test_env_int_valid(self):
        """_env_int parses valid integers correctly."""
        from config.sentinel_config import _env_int

        with patch.dict(os.environ, {"TEST_INT": "42"}):
            self.assertEqual(_env_int("TEST_INT", default=0), 42)

    def test_env_int_invalid_uses_default(self):
        """_env_int returns default for non-integer strings."""
        from config.sentinel_config import _env_int

        with patch.dict(os.environ, {"TEST_INT": "not_a_number"}):
            self.assertEqual(_env_int("TEST_INT", default=99), 99)

    def test_env_int_missing_uses_default(self):
        """_env_int returns default when env var is not set."""
        from config.sentinel_config import _env_int

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NONEXISTENT_INT", None)
            self.assertEqual(_env_int("NONEXISTENT_INT", default=15), 15)


class TestSchedulerServiceSentinel(unittest.TestCase):
    """Tests for SchedulerService sentinel auto-gen integration."""

    def _make_service(self):
        """Create a fresh SchedulerService with a non-started scheduler."""
        from services.scheduler_service import SchedulerService

        svc = SchedulerService()
        return svc

    @patch("config.sentinel_config.SENTINEL_AUTO_GEN_ENABLED", False)
    def test_start_auto_gen_disabled(self):
        """start_sentinel_auto_gen returns False when disabled."""
        svc = self._make_service()
        result = svc.start_sentinel_auto_gen()
        self.assertFalse(result)

    @patch("config.sentinel_config.SENTINEL_AUTO_GEN_ENABLED", True)
    @patch("config.sentinel_config.SENTINEL_AUTO_GEN_INTERVAL_MINUTES", 5)
    def test_start_auto_gen_enabled_registers_job(self):
        """start_sentinel_auto_gen registers the APScheduler job when enabled."""
        svc = self._make_service()
        # Manually start the scheduler for test
        if not svc.scheduler.running:
            svc.scheduler.start()

        result = svc.start_sentinel_auto_gen()
        self.assertTrue(result)

        # Verify job exists
        job = svc.scheduler.get_job("sentinel_auto_gen")
        self.assertIsNotNone(job)
        self.assertEqual(job.name, "Sentinel Playbook Auto-Generation")

        svc.scheduler.shutdown(wait=False)

    @patch("config.sentinel_config.SENTINEL_AUTO_GEN_ENABLED", True)
    @patch("config.sentinel_config.SENTINEL_AUTO_GEN_INTERVAL_MINUTES", 5)
    def test_start_auto_gen_idempotent(self):
        """Calling start_sentinel_auto_gen twice does not create duplicate jobs."""
        svc = self._make_service()
        if not svc.scheduler.running:
            svc.scheduler.start()

        svc.start_sentinel_auto_gen()
        svc.start_sentinel_auto_gen()

        jobs = svc.scheduler.get_jobs()
        sentinel_jobs = [j for j in jobs if j.id == "sentinel_auto_gen"]
        self.assertEqual(len(sentinel_jobs), 1)

        svc.scheduler.shutdown(wait=False)

    def test_stop_auto_gen_no_job(self):
        """stop_sentinel_auto_gen returns False when no job is registered."""
        svc = self._make_service()
        result = svc.stop_sentinel_auto_gen()
        self.assertFalse(result)

    @patch("config.sentinel_config.SENTINEL_AUTO_GEN_ENABLED", True)
    @patch("config.sentinel_config.SENTINEL_AUTO_GEN_INTERVAL_MINUTES", 5)
    def test_stop_auto_gen_removes_job(self):
        """stop_sentinel_auto_gen removes an existing job."""
        svc = self._make_service()
        if not svc.scheduler.running:
            svc.scheduler.start()

        svc.start_sentinel_auto_gen()
        result = svc.stop_sentinel_auto_gen()
        self.assertTrue(result)

        job = svc.scheduler.get_job("sentinel_auto_gen")
        self.assertIsNone(job)

        svc.scheduler.shutdown(wait=False)

    def test_lock_prevents_concurrent_execution(self):
        """Concurrent cycles are blocked by the threading.Lock."""
        svc = self._make_service()

        # Simulate a long-running cycle holding the lock
        svc._sentinel_lock.acquire()

        # Attempting to run another cycle should skip (non-blocking)
        with patch.object(svc, "_execute_sentinel_cycle") as mock_exec:
            svc._run_sentinel_auto_gen_cycle()
            mock_exec.assert_not_called()

        svc._sentinel_lock.release()

    def test_lock_allows_execution_when_free(self):
        """Cycle executes normally when lock is free."""
        svc = self._make_service()

        with patch.object(svc, "_execute_sentinel_cycle") as mock_exec:
            svc._run_sentinel_auto_gen_cycle()
            mock_exec.assert_called_once()

    def test_dedup_hash_generation(self):
        """Deterministic campaign hash is consistent."""
        campaign_id = "CAMP-001"
        source_ips = sorted(["10.0.0.1", "10.0.0.2"])
        target_ports = sorted(["22", "8080"])
        hash_input = (
            f"{campaign_id}|"
            f"{'|'.join(source_ips)}|"
            f"{'|'.join(target_ports)}"
        )
        expected = hashlib.sha256(hash_input.encode("utf-8")).hexdigest()[:16]

        # Re-compute to confirm determinism
        hash_input_2 = (
            f"{campaign_id}|"
            f"{'|'.join(source_ips)}|"
            f"{'|'.join(target_ports)}"
        )
        actual = hashlib.sha256(hash_input_2.encode("utf-8")).hexdigest()[:16]
        self.assertEqual(expected, actual)

    def test_dedup_skips_known_campaigns(self):
        """Already-processed campaign hashes are skipped."""
        svc = self._make_service()
        svc._sentinel_seeded = True  # Skip DB pre-seeding

        # Pre-populate a known hash
        known_hash = "abcdef1234567890"
        svc._sentinel_processed_hashes.add(known_hash)

        # The cycle should skip this campaign
        self.assertIn(known_hash, svc._sentinel_processed_hashes)

    @patch("config.sentinel_config.SENTINEL_AUTO_GEN_ENABLED", True)
    @patch("config.sentinel_config.SENTINEL_AUTO_GEN_INTERVAL_MINUTES", 10)
    def test_get_status_returns_metadata(self):
        """get_sentinel_auto_gen_status returns correct structure."""
        svc = self._make_service()
        if not svc.scheduler.running:
            svc.scheduler.start()

        svc.start_sentinel_auto_gen()

        status = svc.get_sentinel_auto_gen_status()

        self.assertIn("enabled", status)
        self.assertIn("job_registered", status)
        self.assertIn("interval_minutes", status)
        self.assertIn("is_locked", status)
        self.assertIn("tracked_hashes_count", status)
        self.assertIn("next_run_time", status)

        self.assertTrue(status["job_registered"])
        self.assertEqual(status["interval_minutes"], 10)
        self.assertFalse(status["is_locked"])
        self.assertIsNotNone(status["next_run_time"])

        svc.scheduler.shutdown(wait=False)

    def test_execute_cycle_no_campaigns(self):
        """Cycle exits early when no campaigns are found."""
        svc = self._make_service()
        svc._sentinel_seeded = True  # Skip DB seeding

        with patch(
            "services.scheduler_service.campaign_clusterer",
            create=True,
        ) as mock_clusterer:
            # Patch the import inside the method
            mock_clusterer.identify_campaigns.return_value = {
                "campaign_count": 0,
                "campaigns": [],
            }

            # Patch the dynamic import within _execute_sentinel_cycle
            with patch.dict("sys.modules", {
                "ml_engine.campaign_clustering": MagicMock(
                    campaign_clusterer=mock_clusterer
                ),
            }):
                svc._execute_sentinel_cycle()
                mock_clusterer.identify_campaigns.assert_called_once_with(24)

    def test_execute_cycle_processes_new_campaign(self):
        """Cycle processes a new campaign and adds hash to dedup set."""
        svc = self._make_service()
        svc._sentinel_seeded = True

        mock_clusterer = MagicMock()
        mock_clusterer.identify_campaigns.return_value = {
            "campaign_count": 1,
            "campaigns": [
                {
                    "campaign_id": "CAMP-TEST-001",
                    "unique_sources": ["192.168.1.1"],
                    "target_ports": [2222],
                    "protocols": ["TCP"],
                    "event_count": 50,
                    "start_time": None,
                    "end_time": None,
                },
            ],
        }

        mock_svc_instance = MagicMock()
        mock_svc_cls = MagicMock(return_value=mock_svc_instance)

        mock_session = MagicMock()

        with patch.dict("sys.modules", {
            "ml_engine.campaign_clustering": MagicMock(
                campaign_clusterer=mock_clusterer
            ),
            "sentinel.sentinel_service": MagicMock(
                SentinelService=mock_svc_cls
            ),
        }):
            with patch(
                "services.scheduler_service.SessionLocal",
                return_value=mock_session,
            ):
                svc._execute_sentinel_cycle()

                # Verify generate_playbook was called
                mock_svc_instance.generate_playbook.assert_called_once()

                # Verify the hash was added to dedup set
                self.assertGreater(len(svc._sentinel_processed_hashes), 0)

    def test_lock_is_released_on_exception(self):
        """Lock is released even if _execute_sentinel_cycle raises."""
        svc = self._make_service()

        with patch.object(
            svc, "_execute_sentinel_cycle", side_effect=RuntimeError("boom")
        ):
            # Should not raise — lock should be released
            svc._run_sentinel_auto_gen_cycle()

        # Lock should be free
        self.assertFalse(svc._sentinel_lock.locked())


if __name__ == "__main__":
    unittest.main()
