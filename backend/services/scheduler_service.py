"""
backend/services/scheduler_service.py
--------------------------------------
PhantomNet — Background Task Scheduler Service

Manages two categories of scheduled work:

  1. **Report Generation Jobs** (existing) — APScheduler cron-based jobs
     that generate and deliver periodic reports.

  2. **Sentinel Auto-Generation Job** (new) — An interval-based APScheduler
     job that periodically triggers the Sentinel pipeline to scan for new
     campaign clusters and auto-generate playbooks.

Concurrency Safety
------------------
The sentinel auto-generation job uses a ``threading.Lock`` to guarantee
that only one generation cycle can execute at a time.  If a previous
cycle is still running when the next trigger fires, the new invocation
exits immediately (non-blocking ``acquire(blocking=False)``).

Configuration
-------------
  SENTINEL_AUTO_GEN_ENABLED          : Enable the periodic job (default: False).
  SENTINEL_AUTO_GEN_INTERVAL_MINUTES : Interval in minutes (default: 30).

Phase 5, Week 4 — Sentinel Auto-Generation Scheduler
"""

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session
from database.database import SessionLocal
from database.models import ScheduledReport
from services.report_service import ReportService
from datetime import datetime, timedelta
import hashlib
import json
import logging
import os
import threading
from typing import Set

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SchedulerService:
    """Central scheduler for all PhantomNet background tasks.

    Attributes
    ----------
    scheduler : BackgroundScheduler
        The APScheduler instance that manages all registered jobs.
    _sentinel_lock : threading.Lock
        Mutex ensuring at most one sentinel auto-generation cycle runs
        concurrently.  Uses non-blocking acquisition so overlapping
        triggers are skipped rather than queued.
    _sentinel_processed_hashes : set[str]
        In-memory set of deterministic campaign hashes that have already
        been processed.  Pre-seeded from the database on first run to
        survive process restarts.
    _sentinel_seeded : bool
        Whether the in-memory dedup set has been pre-seeded from the DB.
    """

    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self._sentinel_lock = threading.Lock()
        self._sentinel_processed_hashes: Set[str] = set()
        self._sentinel_seeded = False

        if os.getenv("ENVIRONMENT") not in ("test", "ci"):
            self.scheduler.start()

    # ------------------------------------------------------------------
    # Report scheduling (existing functionality)
    # ------------------------------------------------------------------
    def load_schedules(self):
        db = SessionLocal()
        try:
            reports = (
                db.query(ScheduledReport)
                .filter(ScheduledReport.is_active == True)
                .all()
            )
            for report in reports:
                self.add_report_job(report)
        finally:
            db.close()

    def add_report_job(self, report):
        trigger = self._get_trigger(
            report.frequency, report.schedule_time, report.day_of_week
        )
        self.scheduler.add_job(
            self.run_scheduled_report,
            trigger=trigger,
            args=[report.id],
            id=f"report_{report.id}",
            replace_existing=True,
        )
        logger.info(
            f"Added job for report {report.id} ({report.name}) at {report.schedule_time}"
        )

    def _get_trigger(self, frequency, schedule_time, day_of_week=None):
        hour, minute = map(int, schedule_time.split(":"))
        if frequency == "Daily":
            return CronTrigger(hour=hour, minute=minute)
        elif frequency == "Weekly":
            return CronTrigger(
                day_of_week=day_of_week or "mon", hour=hour, minute=minute
            )
        elif frequency == "Monthly":
            return CronTrigger(day=1, hour=hour, minute=minute)
        return CronTrigger(hour=hour, minute=minute)

    def run_scheduled_report(self, report_id):
        db = SessionLocal()
        try:
            report = (
                db.query(ScheduledReport)
                .filter(ScheduledReport.id == report_id)
                .first()
            )
            if not report:
                return

            logger.info(f"Running scheduled report: {report.name}")
            service = ReportService(db)
            filters = (
                json.loads(report.filters.replace("'", '"'))
                if isinstance(report.filters, str)
                else report.filters
            )
            data = service.get_report_data(report.template_type, filters)

            # Here we would generate the actual file (PDF/Excel) and email it.
            # For now, we simulation the "sent" status.
            logger.info(f"Simulating report delivery to: {report.recipients}")

            report.last_run = datetime.utcnow()
            # Update next_run if needed (APScheduler handles the next run, but we can store it for UI)
            db.commit()
        except Exception as e:
            logger.error(f"Error running scheduled report {report_id}: {e}")
        finally:
            db.close()

    # ==================================================================
    # Sentinel Auto-Generation Scheduler
    # ==================================================================

    def start_sentinel_auto_gen(self) -> bool:
        """Register the periodic sentinel playbook auto-generation job.

        Reads ``SENTINEL_AUTO_GEN_ENABLED`` and
        ``SENTINEL_AUTO_GEN_INTERVAL_MINUTES`` from environment (via
        ``config.sentinel_config``) to decide whether and how often
        to run.

        Returns
        -------
        bool
            True if the job was registered, False if auto-gen is disabled
            or the scheduler is not running.
        """
        from config.sentinel_config import (
            SENTINEL_AUTO_GEN_ENABLED,
            SENTINEL_AUTO_GEN_INTERVAL_MINUTES,
        )

        if not SENTINEL_AUTO_GEN_ENABLED:
            logger.info(
                "[Sentinel AutoGen] Disabled (SENTINEL_AUTO_GEN_ENABLED=false)"
            )
            return False

        # Prevent duplicate registration
        existing = self.scheduler.get_job("sentinel_auto_gen")
        if existing is not None:
            logger.info(
                "[Sentinel AutoGen] Job already registered — skipping re-registration"
            )
            return True

        trigger = IntervalTrigger(minutes=SENTINEL_AUTO_GEN_INTERVAL_MINUTES)

        self.scheduler.add_job(
            self._run_sentinel_auto_gen_cycle,
            trigger=trigger,
            id="sentinel_auto_gen",
            name="Sentinel Playbook Auto-Generation",
            replace_existing=True,
            max_instances=1,  # APScheduler-level guard
        )

        logger.info(
            "[Sentinel AutoGen] Registered — interval=%d min",
            SENTINEL_AUTO_GEN_INTERVAL_MINUTES,
        )
        return True

    def stop_sentinel_auto_gen(self) -> bool:
        """Remove the sentinel auto-generation job if it exists.

        Returns
        -------
        bool
            True if the job was removed, False if it was not registered.
        """
        existing = self.scheduler.get_job("sentinel_auto_gen")
        if existing is None:
            return False
        self.scheduler.remove_job("sentinel_auto_gen")
        logger.info("[Sentinel AutoGen] Job removed")
        return True

    # ------------------------------------------------------------------
    # Pre-seed dedup hashes from DB (survives process restarts)
    # ------------------------------------------------------------------
    def _seed_sentinel_hashes(self) -> None:
        """Pre-populate the in-memory dedup set from existing SentinelPlaybook rows.

        This is called once on the first auto-gen cycle to ensure that
        playbooks generated before a process restart are not re-generated.
        """
        if self._sentinel_seeded:
            return

        from sentinel.models import SentinelPlaybook

        db = SessionLocal()
        try:
            existing = (
                db.query(
                    SentinelPlaybook.src_ip,
                    SentinelPlaybook.playbook_id,
                )
                .all()
            )
            for row in existing:
                self._sentinel_processed_hashes.add(row.playbook_id)

            self._sentinel_seeded = True
            logger.info(
                "[Sentinel AutoGen] Pre-seeded %d existing playbook IDs for dedup",
                len(self._sentinel_processed_hashes),
            )
        except Exception as exc:
            logger.warning(
                "[Sentinel AutoGen] DB pre-seed failed (non-fatal): %s", exc
            )
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Core auto-generation cycle (lock-protected)
    # ------------------------------------------------------------------
    def _run_sentinel_auto_gen_cycle(self) -> None:
        """Execute one sentinel auto-generation cycle.

        Acquires ``_sentinel_lock`` in non-blocking mode:
        - If the lock is free → runs the full cycle.
        - If the lock is held → skips this invocation (prevents pile-up).

        The cycle:
        1. Pre-seed dedup hashes from DB (first run only).
        2. Run campaign clustering (identify_campaigns).
        3. For each new campaign, build a deterministic hash and check dedup.
        4. Feed new campaigns into SentinelService.generate_playbook().
        """
        acquired = self._sentinel_lock.acquire(blocking=False)
        if not acquired:
            logger.warning(
                "[Sentinel AutoGen] Skipping cycle — previous cycle still running "
                "(lock held)"
            )
            return

        try:
            self._execute_sentinel_cycle()
        except Exception as exc:
            logger.error(
                "[Sentinel AutoGen] Unhandled error in cycle: %s", exc,
                exc_info=True,
            )
        finally:
            self._sentinel_lock.release()

    def _execute_sentinel_cycle(self) -> None:
        """Internal: the actual sentinel pipeline cycle (runs under lock)."""
        from ml_engine.campaign_clustering import campaign_clusterer
        from sentinel.sentinel_service import SentinelService

        logger.info("=" * 60)
        logger.info("[Sentinel AutoGen] Cycle starting")

        # Step 0: Pre-seed dedup set on first run
        self._seed_sentinel_hashes()

        # Step 1: Run campaign clustering
        try:
            result = campaign_clusterer.identify_campaigns(24)
        except Exception as exc:
            logger.error(
                "[Sentinel AutoGen] Campaign clustering failed: %s", exc
            )
            return

        if not result or result.get("campaign_count", 0) == 0:
            logger.info("[Sentinel AutoGen] No campaigns detected — sleeping")
            return

        campaigns = result.get("campaigns", [])
        total_found = len(campaigns)
        new_count = 0
        skipped_count = 0
        error_count = 0

        logger.info(
            "[Sentinel AutoGen] %d campaign(s) found from clustering",
            total_found,
        )

        # Step 2: Process each campaign
        db = SessionLocal()
        try:
            svc = SentinelService(db)

            for campaign in campaigns:
                campaign_id = campaign.get("campaign_id", "")
                if not campaign_id:
                    logger.warning(
                        "[Sentinel AutoGen] Skipping campaign with empty campaign_id"
                    )
                    skipped_count += 1
                    continue

                # Build deterministic dedup hash
                source_ips = sorted(campaign.get("unique_sources", []))
                target_ports = sorted(
                    str(p) for p in campaign.get("target_ports", [])
                )
                hash_input = (
                    f"{campaign_id}|"
                    f"{'|'.join(source_ips)}|"
                    f"{'|'.join(target_ports)}"
                )
                campaign_hash = hashlib.sha256(
                    hash_input.encode("utf-8")
                ).hexdigest()[:16]

                # Dedup check
                if campaign_hash in self._sentinel_processed_hashes:
                    logger.debug(
                        "[Sentinel AutoGen] SKIP campaign %s (hash=%s, already processed)",
                        campaign_id,
                        campaign_hash,
                    )
                    skipped_count += 1
                    continue

                # Map campaign fields → SentinelService format
                campaign_data = {
                    "source_ips": campaign.get("unique_sources", []),
                    "target_ports": campaign.get("target_ports", []),
                    "protocols": campaign.get("protocols", ["TCP"]),
                    "event_count": campaign.get("event_count", 0),
                    "campaign_id": campaign_id,
                    "time_range": {
                        "start": campaign.get("start_time"),
                        "end": campaign.get("end_time"),
                    }
                    if campaign.get("start_time")
                    else None,
                }

                try:
                    svc.generate_playbook(campaign_data)
                    self._sentinel_processed_hashes.add(campaign_hash)
                    new_count += 1
                    logger.info(
                        "[Sentinel AutoGen] GENERATED playbook for campaign %s "
                        "(hash=%s, ips=%d, ports=%s, events=%d)",
                        campaign_id,
                        campaign_hash,
                        len(campaign_data["source_ips"]),
                        campaign_data["target_ports"],
                        campaign_data["event_count"],
                    )
                except Exception as gen_exc:
                    error_count += 1
                    logger.error(
                        "[Sentinel AutoGen] FAILED to generate playbook for "
                        "campaign %s: %s",
                        campaign_id,
                        gen_exc,
                    )
        finally:
            db.close()

        # Cycle summary
        logger.info(
            "[Sentinel AutoGen] SUMMARY: found=%d, new=%d, skipped=%d, "
            "errors=%d, total_tracked=%d",
            total_found,
            new_count,
            skipped_count,
            error_count,
            len(self._sentinel_processed_hashes),
        )
        logger.info("=" * 60)

    # ------------------------------------------------------------------
    # Introspection helpers (for API / health checks)
    # ------------------------------------------------------------------
    def get_sentinel_auto_gen_status(self) -> dict:
        """Return the current status of the sentinel auto-gen job.

        Returns
        -------
        dict
            Keys: enabled, job_registered, interval_minutes, is_locked,
            tracked_hashes_count, next_run_time.
        """
        from config.sentinel_config import (
            SENTINEL_AUTO_GEN_ENABLED,
            SENTINEL_AUTO_GEN_INTERVAL_MINUTES,
        )

        job = self.scheduler.get_job("sentinel_auto_gen")

        return {
            "enabled": SENTINEL_AUTO_GEN_ENABLED,
            "job_registered": job is not None,
            "interval_minutes": SENTINEL_AUTO_GEN_INTERVAL_MINUTES,
            "is_locked": self._sentinel_lock.locked(),
            "tracked_hashes_count": len(self._sentinel_processed_hashes),
            "next_run_time": (
                job.next_run_time.isoformat() if job and job.next_run_time else None
            ),
        }


scheduler_service = SchedulerService()
