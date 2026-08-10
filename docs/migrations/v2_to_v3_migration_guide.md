# PhantomNet V2.0 to V3.0 Database Migration Guide

**Document Version:** 1.0  
**Target Release:** PhantomNet V3.0.0-rc1  
**Applicable Engines:** SQLite (3.24+), PostgreSQL (12+)  

---

## 1. Overview

PhantomNet V3.0 introduces new database columns across `sentinel_playbooks`, `packet_logs`, and `system_config` tables to support:
- Local LLM playbook narrative summaries (`llm_narrative`)
- Playbook version tracking & revision history (`version`, `parent_id`, `is_latest`, `regeneration_reason`)
- Enhanced threat scoring & signature storage (`detected_signatures`, `anomaly_score`, `threat_level`)
- Global LLM feature toggle configuration (`sentinel_llm_enabled`)

All schema changes are **backward compatible** and introduce columns with reasonable default values or `NULL` constraints.

---

## 2. Upgrade Approaches

### Option A: Automatic Application (Recommended)

PhantomNet V3.0 includes an in-app schema inspector (`backend/database/database.py:upgrade_db_schema()`) that automatically checks for missing columns and applies non-destructive `ALTER TABLE` statements upon application startup.

To use automatic migration:
1. Stop the PhantomNet backend application.
2. Backup your existing database (see [Section 5](#5-backup--rollback-procedures)).
3. Start the V3.0 application:
   ```bash
   python backend/main.py
   ```
4. Verify startup logs for migration confirmation messages:
   ```text
   INFO: Database connection established.
   INFO: ✅ Database schema migration: added llm_narrative to sentinel_playbooks
   INFO: ✅ Database schema migration: added sentinel_llm_enabled to system_config
   ```

---

### Option B: Manual SQL Execution

For production environments managed via CI/CD, migration pipelines, or external DBAs, manual SQL migration scripts are located in `backend/database/migrations/`.

#### Step 1: Migration SQL Scripts

1. **Add detected_signatures to packet_logs:**
   `backend/database/migrations/add_detected_signatures.sql`
   ```sql
   ALTER TABLE packet_logs ADD COLUMN detected_signatures VARCHAR;
   ```

2. **Add threat scores & anomaly score to packet_logs:**
   `backend/database/migrations/add_threat_scores.sql`
   ```sql
   ALTER TABLE packet_logs ADD COLUMN threat_level VARCHAR(16);
   ALTER TABLE packet_logs ADD COLUMN anomaly_score FLOAT;
   CREATE INDEX IF NOT EXISTS ix_packet_logs_threat_level ON packet_logs (threat_level);
   ```

3. **Add llm_narrative to sentinel_playbooks:**
   `backend/database/migrations/add_llm_narrative.sql`
   ```sql
   ALTER TABLE sentinel_playbooks ADD COLUMN llm_narrative TEXT;
   ```

4. **Add Version Tracking to sentinel_playbooks:**
   `backend/database/migrations/add_playbook_version_tracking.sql`
   ```sql
   ALTER TABLE sentinel_playbooks ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
   ALTER TABLE sentinel_playbooks ADD COLUMN parent_id INTEGER DEFAULT NULL REFERENCES sentinel_playbooks(id) ON DELETE SET NULL;
   ALTER TABLE sentinel_playbooks ADD COLUMN is_latest BOOLEAN NOT NULL DEFAULT 1;
   ALTER TABLE sentinel_playbooks ADD COLUMN regeneration_reason VARCHAR(512) DEFAULT NULL;

   CREATE INDEX IF NOT EXISTS ix_sentinel_playbooks_parent_id ON sentinel_playbooks(parent_id);
   CREATE INDEX IF NOT EXISTS ix_sentinel_playbooks_is_latest ON sentinel_playbooks(is_latest);

   -- Backfill existing playbooks as version 1 & latest
   UPDATE sentinel_playbooks
   SET version = 1, is_latest = 1, parent_id = NULL
   WHERE version IS NULL OR version = 0;
   ```

5. **Add sentinel_llm_enabled to system_config:**
   `backend/database/migrations/add_sentinel_llm_enabled.sql`
   ```sql
   ALTER TABLE system_config ADD COLUMN sentinel_llm_enabled BOOLEAN DEFAULT 0;
   ```

---

## 3. SQLite Concurrency (WAL Mode)

PhantomNet V3.0 enables **Write-Ahead Logging (WAL)** mode for SQLite connections (`backend/database/models.py:set_sqlite_pragma`) to prevent database locking (`SQLITE_BUSY`) errors during concurrent playbook writes and TAXII read requests.

No manual file changes are required. The WAL mode configuration executes automatically on connection initialization:
```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
```

---

## 4. Post-Migration Verification

After applying migrations, execute the following SQL queries to verify schema integrity:

```sql
-- 1. Check sentinel_playbooks version columns
SELECT id, playbook_id, version, is_latest, parent_id, llm_narrative
FROM sentinel_playbooks
LIMIT 5;

-- 2. Verify packet_logs threat scores & signatures
SELECT id, src_ip, dst_port, threat_level, anomaly_score, detected_signatures
FROM packet_logs
LIMIT 5;

-- 3. Verify system_config LLM toggle
SELECT key, value, sentinel_llm_enabled
FROM system_config;
```

---

## 5. Backup & Rollback Procedures

### Backup (Pre-Migration)
Before applying migrations, create a complete database snapshot:
- **SQLite:**
  ```bash
  cp backend/phantomnet.db backend/phantomnet.db.v2.bak
  ```
- **PostgreSQL:**
  ```bash
  pg_dump -U phantomnet_user -d phantomnet_db -F c -b -v -f phantomnet_v2_backup.dump
  ```

### Rollback (If Required)
To revert to V2.0 schema state:
- **SQLite:** Stop the application and restore the backup file:
  ```bash
  cp backend/phantomnet.db.v2.bak backend/phantomnet.db
  ```
- **PostgreSQL:**
  ```sql
  ALTER TABLE sentinel_playbooks DROP COLUMN IF EXISTS llm_narrative;
  ALTER TABLE sentinel_playbooks DROP COLUMN IF EXISTS version;
  ALTER TABLE sentinel_playbooks DROP COLUMN IF EXISTS parent_id;
  ALTER TABLE sentinel_playbooks DROP COLUMN IF EXISTS is_latest;
  ALTER TABLE sentinel_playbooks DROP COLUMN IF EXISTS regeneration_reason;
  ALTER TABLE packet_logs DROP COLUMN IF EXISTS detected_signatures;
  ALTER TABLE packet_logs DROP COLUMN IF EXISTS threat_level;
  ALTER TABLE packet_logs DROP COLUMN IF EXISTS anomaly_score;
  ALTER TABLE system_config DROP COLUMN IF EXISTS sentinel_llm_enabled;
  ```
