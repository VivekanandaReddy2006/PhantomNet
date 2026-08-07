# Sentinel V3 Workflow Demo Script - PhantomNet

**Target Audience:** SOC Analysts, Security Engineers, Academic Evaluators  
**Goal:** Showcase Sentinel V3 end-to-end automated threat mitigation, playbook review, analyst approval, and threat intelligence export.  
**Resolution:** 1080p Full HD (1920x1080)  
**Target Duration:** ~3 Minutes  

---

## Storyboard & Timeline Breakdown

| Timestamp | Sentinel V3 Phase | Dashboard View | Actions & System Event | Subtitle / Audio Narration |
| :--- | :--- | :--- | :--- | :--- |
| **0:00 - 0:30** | **Phase 1: Attack Vector Simulation** | Threat Hunting / Topology View | Ingestion of high-frequency SSH Brute Force attempt (`T1110.001`) from malicious IP `192.168.1.105`. | *"Phase 1: Attack Vector Simulation. PhantomNet sensors capture a high-volume SSH password guessing attack against internal servers."* |
| **0:30 - 1:00** | **Phase 2: AI Detection & MITRE Mapping** | Sentinel Dashboard Overview & Stats Panel | ML Anomaly Engine flags threat with 95/100 severity score. Interactive MITRE ATT&CK Matrix highlights `Credential Access -> Password Guessing`. | *"Phase 2: Automated Detection. The ML detection engine flags the anomaly with a threat score of 95, dynamically mapping it to MITRE ATT&CK Tactic Credential Access."* |
| **1:00 - 1:45** | **Phase 3: Playbook & Rule Generation** | Playbook Viewer (`pb-101`) | Sentinel V3 auto-generates response playbook `SSH Brute Force Mitigation`. Renders Snort alert rule, Sigma YAML rule, and LLM narrative summary. | *"Phase 3: Playbook & Rule Generation. Sentinel V3 synthesizes Snort and Sigma detection signatures alongside an LLM explainability report."* |
| **1:45 - 2:30** | **Phase 4: SOC Analyst Review & Approval** | Playbook Detail & Approval Modal | Analyst inspects mitigation steps (`Block source IP`, `Disable password auth`). Analyst signs with `analyst_admin` and approves. Status transitions from `Pending` to `Approved`. | *"Phase 4: Analyst Review & Approval. The SOC analyst reviews generated rules and submits digital approval, locking the mitigation workflow."* |
| **2:30 - 3:00** | **Phase 5: Interoperability & STIX Export** | Export Menu & Download Bar | Analyst exports executive PDF Incident Report and STIX 2.1 JSON Threat Intelligence bundle for TAXII sharing. | *"Phase 5: Intelligence Export. The finalized playbook is exported as an executive PDF report and standardized STIX 2.1 bundle."* |

---

## Technical Recording Setup
1. **Frontend Dashboard:** React / Vite server running on `http://localhost:5173/sentinel` (or `http://127.0.0.1:5173/sentinel`).
2. **Backend API:** FastAPI application running on `http://127.0.0.1:8000`.
3. **Viewport Size:** `1920x1080` (1080p Full HD).
4. **Theme:** Modern Dark Cyber-Security Aesthetic.
5. **Output Artifacts:** `demos/sentinel_v3_demo.mp4`, `demos/sentinel_v3_demo.webp`.
