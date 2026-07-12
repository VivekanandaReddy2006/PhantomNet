# Month 4 Retrospective & Month 5 Planning

## 1. Executive Summary

Month 4 (Weeks 13–16) was highly successful, focusing on the delivery of the **Core Sentinel Layer**. The team implemented threat detection signature parsing, MITRE ATT&CK mapping, Snort/Sigma rule generation, Jinja2-based playbook generation, and an interactive React dashboard. The month concluded with a major stabilization and hardening phase, addressing key database concurrency, timezone, and terminal encoding issues discovered during E2E testing.

---

## 2. Velocity & Completion Assessment

### What Went Well (On Time / Easier than Expected)
* **Core Sentinel Pipeline**: The entire pipeline from traffic detection to playbook persistence and approval works end-to-end.
* **Rule Generation Engines**: Automated generation of Snort and Sigma rules was completed successfully and verified against schemas.
* **Testing Coverage**: Over 120 tests were added in Week 16 alone to verify template rendering across 5 templates and 7 sections. E2E pipeline verification was highly automated, passing 103 tests in the SQLi test suite and 62 in the SSH suite.
* **STIX 2.1 Bundling**: Mapping detection indicators into structured STIX 2.1 intelligence bundles was easier than anticipated due to the robust `stix2` library integration.

### What Slipped / Required Buffer Time
* **Hardening and Bug Fixes**: Although the features themselves were implemented on time, E2E scale and concurrency testing in Week 15 revealed critical bugs (SQLite locks and timezone misalignments) that consumed most of the Week 16 buffer days. 
* **Dev Environment Inconsistencies**: Path bootstrapping and module shadowing issues in the ML directory required late-sprint hotfixes in Week 16.

---

## 3. Technical Debt & Learnings from Month 4

Before initiating Month 5 features, we must account for the following technical debt identified during Month 4:

1. **SQLite Database Concurrency**:
   * *Issue*: SQLite locks the database during write transactions, causing concurrent tasks to crash with `sqlite3.OperationalError: database is locked`.
   * *Resolution*: Solved in Week 16 by enabling SQLite WAL (Write-Ahead Logging) mode and increasing timeouts.
   * *Impact on Month 5*: The LLM generation tasks in Month 5 are long-running network requests (averaging 5–15 seconds). If a request runs synchronously or blocks a thread during a write connection, it could trigger locking issues. All LLM API calls must be strictly asynchronous (`httpx.AsyncClient`) and run in background tasks.

2. **Timezone Inconsistencies**:
   * *Issue*: DBSCAN clustering calculated naive local cutoffs, whereas logs used UTC, resulting in empty clusters outside UTC system zones.
   * *Resolution*: Patched in Week 16 by standardizing on naive UTC.
   * *Impact on Month 5*: We must ensure that any LLM prompt context involving timestamps explicitly formats them as UTC to prevent analytical errors.

3. **Windows Terminal Emoji Crash**:
   * *Issue*: Terminal stdout encoding issues crashed the server when printing status emojis.
   * *Resolution*: Enforced `PYTHONIOENCODING=utf-8` in the environment.

4. **Frontend Render Lag**:
   * *Issue*: Large Jinja2 playbooks caused 200ms–400ms UI freezes when opening details.
   * *Resolution*: Optimized in React but must watch performance as we inject longer AI narratives in Month 5.

---

## 4. LLM Integration Feasibility Audit

### Environment Audit Results
* **Ollama Installation**: **NOT INSTALLED** on the development environment (command `ollama` is not recognized).
* **Mistral 7B Availability**: **NOT DOWNLOADED** (no Ollama instance is active to pull the model).
* **Hardware & Memory Considerations**: Running a 7B parameter model locally requires at least 8GB of free VRAM (GPU) or 16GB of system RAM (CPU) for acceptable performance. Some developer machines may experience high latency (>30 seconds per summary).

### Feasibility Strategy & Mitigations
1. **Developer Environment Bootstrap**: Day 21 must explicitly focus on setting up Ollama on at least one developer host, pulling the `mistral` model, and running baseline speed checks.
2. **Graceful Fallback Mode**: The backend must run fine even if `SENTINEL_LLM_ENABLED=false` or if the Ollama endpoint is offline/unreachable. If offline, the playbook generator will cleanly fallback to template-only markdown generation without crashing.
3. **Optional Lightweight Model Support**: If Mistral 7B is too heavy, we should support pulling smaller models (e.g., `llama3:8b`, `phi3:3.8b`, or `gemma:2b`) via configuration.
4. **Mock LLM Service for Testing**: Implement a mock LLM client in `tests/conftest.py` so that automated tests and developers without local Ollama setups can run the suite instantly.

---

## 5. Adjusted Month 5 Priorities & Scope

We will keep the overall month goals intact but adjust the timelines and task focus for Week 17 to accommodate Ollama bootstrap tasks and concurrency safeguards:

1. **Prioritize Local Setup & Verification**: Day 21 will include local setup, hardware benchmarking, and fallback testing.
2. **Async LLM Ingestion**: Ensure the LLM generation and database update do not block SQLite transactions. We will run the LLM narrative generation asynchronously using FastAPI's background tasks or an async worker.
3. **AI Narrative UI Polish**: Styling must differentiate the AI narrative clearly from human-curated templates, providing clear warnings that the summary is AI-generated (cybersecurity audit compliance).

---

## 6. Preliminary Week 17 (Month 5, Week 1) Plan

### Daily Tasks and Allocations

#### Day 21 (Monday) — Environment Setup & LLM Service Scaffold
* **S (Sriram)**: Design LLM integration architecture, draft the Ollama API communication spec (POST `/api/generate`), and configure the database migration to support `llm_narrative` in `sentinel_playbooks`.
* **V (Vivek)**: Install Ollama, pull `mistral` model, benchmark model loading/generation times, and document local setup instructions.
* **K (Vikranth)**: Create `backend/sentinel/llm_service.py` scaffold with `LLMService` class containing `generate_narrative(context_data) -> str` and toggle `SENTINEL_LLM_ENABLED`.
* **M (Manideep)**: Add an AI connection status indicator badge to the Sentinel Dashboard header showing "AI: Online/Offline" depending on the health API.

#### Day 22 (Tuesday) — API Endpoints & Prompt Templating
* **S (Sriram)**: Create `GET /api/sentinel/llm/status` endpoint to return Ollama server health, enabled/disabled state, and configured model name.
* **V (Vivek)**: Verify Ollama installation across the remaining developer setups and configure fallback models (e.g., `gemma:2b` or `phi3`) for lower-memory hosts.
* **K (Vikranth)**: Build the LLM Prompt Template. Create system instructions, zero-shot/few-shot examples, and format inputs (cluster metadata, IOCs, MITRE ATT&CK codes, and mitigation steps).
* **M (Manideep)**: Create the "AI Summary" section in `PlaybookViewer` with show/hide toggles and distinct styling.

#### Day 23 (Wednesday) — Client Implementation & Toggle API
* **S (Sriram)**: Update the `SystemConfig` API to allow enabling/disabling LLM enrichment dynamically from the admin panel.
* **V (Vivek)**: Evaluate output quality of generated summaries for the SSH brute force campaign and refine prompt instructions.
* **K (Vikranth)**: Implement the HTTP client in `llm_service.py` to talk to Ollama (`http://localhost:11434/api/generate`) using `httpx.AsyncClient` with a 60-second timeout.
* **M (Manideep)**: Apply premium styling (cyberpunk border, glow effects, and "AI-Enhanced Summary" badge) to differentiate AI text from template markdown.

#### Day 24 (Thursday) — Orchestrator Integration & Graceful Degradation
* **S (Sriram)**: Integrate `llm_service` into the `sentinel_service` orchestrator. When a playbook is generated, if LLM is enabled, run the LLM request asynchronously and save to `llm_narrative`.
* **V (Vivek)**: Perform prompt quality testing for SQLi and Port Scan scenarios. Highlight any hallucinations or formatting discrepancies.
* **K (Vikranth)**: Implement the robust fallback engine: if Ollama is unreachable, times out, or throws an error, log the warning, return a blank narrative, and proceed with template generation without breaking the pipeline.
* **M (Manideep)**: Add a "Regenerate AI Summary" button to the `PlaybookViewer` (visible to admins/analysts) to re-trigger the asynchronous generation endpoint.

#### Day 25 (Friday) — Testing, Fine-Tuning & Verification
* **S (Sriram)**: Write integration tests in `tests/test_llm_service.py` covering fallback modes, toggle operations, timeout scenarios, and mock client configurations.
* **V (Vivek)**: Fine-tune prompt system instructions based on week-long feedback to ensure strict Markdown output and consistent terminology.
* **K (Vikranth)**: Add generation latency and response time logging to the `llm_service` performance tracking backend.
* **M (Manideep)**: Run full E2E pipeline verification (simulation -> detection -> clustering -> playbook creation -> AI summary rendering).
