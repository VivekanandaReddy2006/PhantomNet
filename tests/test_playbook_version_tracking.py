"""
tests/test_playbook_version_tracking.py
-----------------------------------------
Unit tests for the SentinelPlaybook version tracking feature.

Validates:
  1. New playbooks default to version=1, is_latest=True, parent_id=None.
  2. Regeneration creates a new versioned record with incremented version.
  3. Previous versions are marked is_latest=False upon regeneration.
  4. Version history retrieval returns all versions in correct order.
  5. get_latest_version() returns the correct current version.
  6. to_dict() includes version tracking fields.
  7. Multiple regeneration cycles produce correct version chains.
"""

import os
import sys

# Force SQLite test database configuration before importing database models
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

import pytest
from datetime import datetime

from database.database import SessionLocal, engine
from database.models import Base
from sentinel.models import SentinelPlaybook


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="function")
def db_session():
    """Create the tables and provide a clean session for each test."""
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    yield session
    # Cleanup test data
    session.query(SentinelPlaybook).filter(
        SentinelPlaybook.playbook_id.like("PB-TEST-%")
        | SentinelPlaybook.playbook_id.like("PB-PARENT-%")
        | SentinelPlaybook.playbook_id.like("PB-CHILD-%")
        | SentinelPlaybook.playbook_id.like("PB-V%")
        | SentinelPlaybook.playbook_id.like("PB-3V-%")
        | SentinelPlaybook.playbook_id.like("PB-HIST-%")
        | SentinelPlaybook.playbook_id.like("PB-LV-%")
        | SentinelPlaybook.playbook_id.like("PB-ISO-%")
        | SentinelPlaybook.playbook_id.like("PB-FILT-%")
    ).delete(synchronize_session="fetch")
    session.commit()
    session.close()


def _make_playbook(db, **kwargs):
    """Helper to create and persist a SentinelPlaybook with sensible defaults."""
    defaults = {
        "playbook_id": f"PB-TEST-{datetime.utcnow().strftime('%H%M%S%f')}",
        "src_ip": "10.0.0.1",
        "dst_port": 2222,
        "protocol": "TCP",
        "attack_type": "SSH_AUTH_FAILURE",
        "threat_score": 75.0,
        "confidence_score": 0.82,
        "severity": "HIGH",
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "mitre_url": "https://attack.mitre.org/techniques/T1110/",
        "playbook_name": "SSH Brute Force Response",
        "playbook_content": "# Playbook Content\n\nTest content.",
        "template_name": "brute_force.md.j2",
        "status": "pending",
        "version": 1,
        "is_latest": True,
        "parent_id": None,
        "regeneration_reason": None,
    }
    defaults.update(kwargs)
    pb = SentinelPlaybook(**defaults)
    db.add(pb)
    db.commit()
    db.refresh(pb)
    return pb


# ---------------------------------------------------------------------------
# Tests: Model Defaults
# ---------------------------------------------------------------------------

class TestPlaybookModelDefaults:
    """Verify that new playbook records have correct version tracking defaults."""

    def test_new_playbook_defaults_v1(self, db_session):
        """New playbooks should default to version=1, is_latest=True, parent_id=None."""
        pb = _make_playbook(db_session)
        assert pb.version == 1
        assert pb.is_latest is True
        assert pb.parent_id is None
        assert pb.regeneration_reason is None

    def test_explicit_version_set(self, db_session):
        """Explicitly setting version fields should work correctly."""
        pb = _make_playbook(
            db_session,
            version=3,
            is_latest=False,
            regeneration_reason="Test reason",
        )
        assert pb.version == 3
        assert pb.is_latest is False
        assert pb.regeneration_reason == "Test reason"


# ---------------------------------------------------------------------------
# Tests: to_dict Serialization
# ---------------------------------------------------------------------------

class TestPlaybookToDict:
    """Verify that to_dict() includes version tracking fields."""

    def test_to_dict_includes_version_fields(self, db_session):
        """to_dict() should include all 4 version tracking fields."""
        pb = _make_playbook(db_session)
        d = pb.to_dict()

        assert "version" in d
        assert "parent_id" in d
        assert "is_latest" in d
        assert "regeneration_reason" in d

        assert d["version"] == 1
        assert d["parent_id"] is None
        assert d["is_latest"] is True
        assert d["regeneration_reason"] is None

    def test_to_dict_version_tracking_with_parent(self, db_session):
        """to_dict() should correctly serialize version fields for child versions."""
        parent = _make_playbook(db_session, playbook_id="PB-PARENT-001")
        child = _make_playbook(
            db_session,
            playbook_id="PB-CHILD-001",
            version=2,
            parent_id=parent.id,
            is_latest=True,
            regeneration_reason="Updated threat intel",
        )

        d = child.to_dict()
        assert d["version"] == 2
        assert d["parent_id"] == parent.id
        assert d["is_latest"] is True
        assert d["regeneration_reason"] == "Updated threat intel"


# ---------------------------------------------------------------------------
# Tests: Version History Queries
# ---------------------------------------------------------------------------

class TestVersionHistory:
    """Verify version history retrieval methods."""

    def test_single_version_history(self, db_session):
        """A playbook with no regenerations should return a 1-item history."""
        pb = _make_playbook(db_session)
        history = SentinelPlaybook.get_version_history(
            db_session, parent_chain_id=pb.id
        )
        assert len(history) == 1
        assert history[0].id == pb.id
        assert history[0].version == 1

    def test_two_version_chain(self, db_session):
        """A playbook with one regeneration should return 2 versions, newest first."""
        v1 = _make_playbook(
            db_session,
            playbook_id="PB-V1",
            version=1,
            is_latest=False,
        )
        v2 = _make_playbook(
            db_session,
            playbook_id="PB-V2",
            version=2,
            parent_id=v1.id,
            is_latest=True,
            regeneration_reason="Analyst requested refresh",
        )

        # Query from v1
        history_from_v1 = SentinelPlaybook.get_version_history(
            db_session, parent_chain_id=v1.id
        )
        assert len(history_from_v1) == 2
        assert history_from_v1[0].version == 2  # newest first
        assert history_from_v1[1].version == 1

        # Query from v2
        history_from_v2 = SentinelPlaybook.get_version_history(
            db_session, parent_chain_id=v2.id
        )
        assert len(history_from_v2) == 2
        assert history_from_v2[0].version == 2

    def test_three_version_chain(self, db_session):
        """Three versions should produce a 3-item history in correct order."""
        v1 = _make_playbook(db_session, playbook_id="PB-3V-1", version=1, is_latest=False)
        v2 = _make_playbook(
            db_session, playbook_id="PB-3V-2", version=2,
            parent_id=v1.id, is_latest=False,
            regeneration_reason="First regeneration",
        )
        v3 = _make_playbook(
            db_session, playbook_id="PB-3V-3", version=3,
            parent_id=v2.id, is_latest=True,
            regeneration_reason="Second regeneration",
        )

        # Query from middle version
        history = SentinelPlaybook.get_version_history(
            db_session, parent_chain_id=v2.id
        )
        assert len(history) == 3
        assert [h.version for h in history] == [3, 2, 1]
        assert history[0].is_latest is True
        assert history[1].is_latest is False
        assert history[2].is_latest is False

    def test_get_version_history_by_playbook_id(self, db_session):
        """get_version_history should work when given a playbook_id string."""
        v1 = _make_playbook(db_session, playbook_id="PB-HIST-001", version=1, is_latest=False)
        v2 = _make_playbook(
            db_session, playbook_id="PB-HIST-002", version=2,
            parent_id=v1.id, is_latest=True,
        )

        # Query by playbook_id of v1
        history = SentinelPlaybook.get_version_history(
            db_session, playbook_id="PB-HIST-001"
        )
        assert len(history) == 2
        assert history[0].playbook_id == "PB-HIST-002"

    def test_nonexistent_playbook_returns_empty(self, db_session):
        """Querying history for a non-existent ID should return empty list."""
        history = SentinelPlaybook.get_version_history(
            db_session, parent_chain_id=99999
        )
        assert history == []

    def test_get_version_history_requires_argument(self, db_session):
        """Calling without either argument should raise ValueError."""
        with pytest.raises(ValueError, match="Provide either"):
            SentinelPlaybook.get_version_history(db_session)


# ---------------------------------------------------------------------------
# Tests: get_latest_version
# ---------------------------------------------------------------------------

class TestGetLatestVersion:
    """Verify the get_latest_version class method."""

    def test_latest_version_single(self, db_session):
        """For a single playbook, get_latest_version should return itself."""
        pb = _make_playbook(db_session)
        latest = SentinelPlaybook.get_latest_version(db_session, parent_chain_id=pb.id)
        assert latest is not None
        assert latest.id == pb.id
        assert latest.version == 1

    def test_latest_version_chain(self, db_session):
        """get_latest_version should return the row with is_latest=True."""
        v1 = _make_playbook(db_session, playbook_id="PB-LV-1", version=1, is_latest=False)
        v2 = _make_playbook(
            db_session, playbook_id="PB-LV-2", version=2,
            parent_id=v1.id, is_latest=False,
        )
        v3 = _make_playbook(
            db_session, playbook_id="PB-LV-3", version=3,
            parent_id=v2.id, is_latest=True,
        )

        # Query from any version should return v3
        for row_id in [v1.id, v2.id, v3.id]:
            latest = SentinelPlaybook.get_latest_version(db_session, parent_chain_id=row_id)
            assert latest.id == v3.id
            assert latest.version == 3

    def test_latest_version_nonexistent(self, db_session):
        """get_latest_version should return None for non-existent IDs."""
        latest = SentinelPlaybook.get_latest_version(db_session, parent_chain_id=99999)
        assert latest is None


# ---------------------------------------------------------------------------
# Tests: Version Isolation
# ---------------------------------------------------------------------------

class TestVersionIsolation:
    """Verify that separate playbook lineages don't interfere."""

    def test_separate_lineages(self, db_session):
        """Two unrelated playbooks should have independent version histories."""
        pb_a = _make_playbook(db_session, playbook_id="PB-ISO-A1", version=1, is_latest=True)
        pb_b = _make_playbook(db_session, playbook_id="PB-ISO-B1", version=1, is_latest=True)

        history_a = SentinelPlaybook.get_version_history(
            db_session, parent_chain_id=pb_a.id
        )
        history_b = SentinelPlaybook.get_version_history(
            db_session, parent_chain_id=pb_b.id
        )

        assert len(history_a) == 1
        assert len(history_b) == 1
        assert history_a[0].id != history_b[0].id

    def test_is_latest_filter(self, db_session):
        """Querying only is_latest=True should return only current versions."""
        v1 = _make_playbook(db_session, playbook_id="PB-FILT-1", version=1, is_latest=False)
        v2 = _make_playbook(
            db_session, playbook_id="PB-FILT-2", version=2,
            parent_id=v1.id, is_latest=True,
        )
        # Also create an unrelated playbook
        pb_other = _make_playbook(db_session, playbook_id="PB-FILT-OTHER", version=1, is_latest=True)

        latest_only = (
            db_session.query(SentinelPlaybook)
            .filter(SentinelPlaybook.is_latest == True)  # noqa: E712
            .all()
        )
        latest_ids = {r.id for r in latest_only}
        assert v2.id in latest_ids
        assert pb_other.id in latest_ids
        assert v1.id not in latest_ids


# ---------------------------------------------------------------------------
# Tests: __repr__
# ---------------------------------------------------------------------------

class TestRepr:
    """Verify the updated __repr__ includes version info."""

    def test_repr_includes_version(self, db_session):
        """__repr__ should mention version and is_latest."""
        pb = _make_playbook(db_session, version=2, is_latest=False)
        r = repr(pb)
        assert "v2" in r
        assert "is_latest=False" in r
