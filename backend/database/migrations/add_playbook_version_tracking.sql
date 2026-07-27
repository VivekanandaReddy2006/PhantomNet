-- Migration: Add Version Tracking to sentinel_playbooks
-- Date: 2026-07-27
-- Description: Adds version tracking columns (version, parent_id, is_latest,
--              regeneration_reason) to the sentinel_playbooks table to support
--              full revision history for regenerated playbooks.
--
-- Backward compatible: All new columns have defaults, so existing rows
-- will automatically get version=1, parent_id=NULL, is_latest=1 (true).

-- 1. Add version column (integer, default 1, not null)
ALTER TABLE sentinel_playbooks
ADD COLUMN version INTEGER NOT NULL DEFAULT 1;

-- 2. Add parent_id column (self-referencing FK to previous version)
ALTER TABLE sentinel_playbooks
ADD COLUMN parent_id INTEGER DEFAULT NULL
REFERENCES sentinel_playbooks(id) ON DELETE SET NULL;

-- 3. Add is_latest column (boolean flag for current version)
ALTER TABLE sentinel_playbooks
ADD COLUMN is_latest BOOLEAN NOT NULL DEFAULT 1;

-- 4. Add regeneration_reason column (audit trail text)
ALTER TABLE sentinel_playbooks
ADD COLUMN regeneration_reason VARCHAR(512) DEFAULT NULL;

-- 5. Create indexes for efficient queries
CREATE INDEX IF NOT EXISTS ix_sentinel_playbooks_parent_id
ON sentinel_playbooks(parent_id);

CREATE INDEX IF NOT EXISTS ix_sentinel_playbooks_is_latest
ON sentinel_playbooks(is_latest);

-- 6. Backfill existing rows: all current playbooks are v1 and latest
UPDATE sentinel_playbooks
SET version = 1, is_latest = 1, parent_id = NULL
WHERE version IS NULL OR version = 0;
