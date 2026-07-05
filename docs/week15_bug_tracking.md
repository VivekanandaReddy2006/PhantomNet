# PhantomNet Week 15 Bug Tracking & Kickoff Document

This document compiles, categorizes, and logs all bugs identified during the Week 15 testing phase. These issues are prioritized for triage and resolution during the Week 16 kickoff.

---

## 🏷️ Bug Priority Categories

- **P0 (Blocks Demo / Operation)**: Critical system blockers requiring immediate hotfix or early sprint attention.
- **P1 (Wrong Output / Logic Error)**: Functionality works, but outputs incorrect metrics, fails on specific OS/environments, or results in data inconsistency.
- **P2 (Cosmetic / Performance)**: UI lag, minor layout defects, or slow response times under normal load.

---

## 🐛 Week 15 Bug Log

### 1. SQLite Database Concurrency Lock (P0)
- **Priority:** P0 (Blocks Demo)
- **Status:** Escalated
- **Description:** SQLite locks the entire database file during write transactions. Under load (e.g. background campaign scanning running concurrently with active honeypot logs insertion or API status updates), concurrent tasks crash with `sqlite3.OperationalError: database is locked`.
- **Reproduction Steps:**
  1. Start the backend server (`uvicorn`) with background generation loops active.
  2. Simulate high traffic by executing the integration test suite or running concurrent HTTP/SSH attack simulators.
  3. Attempt to save or approve a playbook on the dashboard.
- **Expected Behavior:** Database updates queue and resolve gracefully without throwing write errors.
- **Actual Behavior:** Processes raise `sqlite3.OperationalError: database is locked` and fail to persist log entries.
- **Week 16 Action:** Migrate the development/test databases from SQLite to PostgreSQL or enable WAL (Write-Ahead Logging) mode on SQLite connection initialization.

---

### 2. Timezone Mismatch in ML Campaign Clustering (P1)
- **Priority:** P1 (Wrong Output)
- **Status:** Resolved in `campaign_clustering.py` (needs monitoring)
- **Description:** The campaign clustering service calculated timezone-naive local cutoffs (`datetime.now()`), whereas the default timestamp of the `PacketLog` model uses timezone-naive UTC (`datetime.utcnow()`). In timezones outside UTC, the clustering engine fails to detect any recent logs since the cutoff is hours ahead of the logs.
- **Reproduction Steps:**
  1. Set system timezone to any non-UTC zone (e.g. UTC+5:30).
  2. Insert packet logs using standard UTC timestamps.
  3. Execute `CampaignClusterer.identify_campaigns(hours_back=1)`.
- **Expected Behavior:** Returns all logs inserted within the last hour.
- **Actual Behavior:** Returns 0 logs due to the timezone offset.
- **Week 16 Action:** Audit all timestamp generation/comparisons across `backend/` and enforce a unified timezone approach (either standard UTC or zone-aware datetime objects).

---

### 3. Windows Terminal Console Emoji Crash (P1)
- **Priority:** P1 (Wrong Output)
- **Status:** Patched in `backend/main.py`
- **Description:** Standard Windows console hosts (cmd/powershell) raise encoding exceptions when executing Python scripts that output Unicode emoji characters to stdout.
- **Reproduction Steps:**
  1. Open a standard Windows Command Prompt (without UTF-8 encoding enabled).
  2. Run `uvicorn main:app` where status messages contain emojis.
- **Expected Behavior:** Text prints normally to the console.
- **Actual Behavior:** Raises `UnicodeEncodeError: 'charmap' codec can't encode characters` and exits.
- **Week 16 Action:** Establish a logging middleware wrapper that strips emoji characters if console stream encoding does not support them, or configure system-wide `PYTHONIOENCODING=utf-8` policies.

---

### 4. Playbook Detail Modal Layout Lag (P2)
- **Priority:** P2 (Cosmetic / Performance)
- **Status:** Logged
- **Description:** When viewing detailed playbooks on the Sentinel Dashboard, the large Markdown payload in the tabs renders slowly, creating a visible layout shift/freeze.
- **Reproduction Steps:**
  1. Navigate to the Sentinel Dashboard.
  2. Click on a playbook card to open the detail view modal.
  3. Select the "Playbook" content tab.
- **Expected Behavior:** Modal opens instantly with smooth tab transitions.
- **Actual Behavior:** The UI freezes for 200ms–400ms while parser compiles the Jinja2-rendered Markdown content.
- **Week 16 Action:** Implement react-markdown component lazy loading, or pre-render Markdown to HTML on the backend.

---

## 📅 Summary List for Week 16 Kickoff

| Bug ID | Title | Priority | Block W16 Work? | Owner |
|--------|-------|----------|-----------------|-------|
| **BUG-001** | SQLite Database Concurrency Lock | **P0** | **Yes** (Blocks Load Testing) | Backend/DevOps |
| **BUG-002** | Timezone Mismatch in ML Clustering | **P1** | No | ML Engineer |
| **BUG-003** | Windows Console Emoji Crash | **P1** | No | Dev Lead |
| **BUG-004** | Playbook Detail Modal Layout Lag | **P2** | No | Frontend |
