# Aero_EWS 2.0

**Hybrid Multi-Agent Competitive Intelligence & Early Warning System for the Aerospace Industry**

Aero_EWS 2.0 is a local, request-driven Python research system accompanying the master's thesis *"Využití metod Competitive Intelligence s prvky automatizovaného monitorování v leteckém průmyslu"* at the Faculty of Informatics and Statistics, Prague University of Economics and Business (VŠE).

The system combines **KIT-to-KIQ analytical planning**, **adaptive agentic OSINT acquisition** (`agentic_exa` over Exa Search API + governed regulatory and corporate connectors), **two-stage relevance filtering (FR03)**, **structured multi-agent analysis**, **deterministic 5-factor I&W risk scoring**, **evidence provenance validation (Harness)**, **catalog & runtime KIQ evaluation**, and **Human-in-the-Loop (HITL)** decision governance.

---

## Architecture Overview (5 Agent Roles + Deterministic Safeguards)

`KIT → [1. Planner] → [2. Acquisition Agent (Exa + 6 Governed Tools)] → FR03 Filter → [3. Risk Analyst] → [4. QA Auditor] → [5. Editor] → Deterministic 5-Factor Scoring → Deterministic Harness & KIQ Evaluation → SQLite & Pending Report → HITL Gate → Published Dashboard & Archive`

*(Note: `architecture.puml` presents a simplified 4-stage logical view combining Planning and Acquisition; in `ews_pipeline.py`, Planner and Acquisition execute as two distinct agent invocations.)*

### Five Specialized Agent Roles (`agents.py`, `tasks.py`, `ews_collection.py`)
1. **KIQ Planner Agent (`create_planner_agent`):** Deconstructs the user's Key Intelligence Topic (KIT) into a structured `KIQPlan` with atomic information requirements, target entities, specificity level, and source priorities, guarded by deterministic scope constraints (`plan_constraints.py`).
2. **Acquisition Agent (`create_planning_and_acquisition_agent`, `aero_ews/collection/agent_tools.py`):** Autonomously selects and executes searches within a shared `AcquisitionBudget` (default: max 10 tool calls, max 4 Exa calls, 180 s budget) across six governed CrewAI tools:
   - `ExaSemanticSearchTool` (Exa Search API)
   - `OfficialRegulatorsSearchTool` (FAA / Federal Register, EASA, NTSB)
   - `CorporateFilingsSearchTool` (SEC EDGAR, ESEF/XBRL, OEM PR)
   - `MediaAndSocialSearchTool` (NewsAPI, Bluesky, YouTube)
   - `AirshowNewsroomsSearchTool` (major airshow newsrooms)
   - `InspectCollectionCoverageTool` (coverage inspection before stopping)
3. **Aviation Risk Analyst Agent (`create_risk_analyst_agent`):** Processes FR03-accepted document batches using a claim-first workflow with error recovery, separating confirmed facts from analytical interpretations and hypothetical scenarios, citing exact `DOC_ID`s, and rating five structured I&W factors (`F1–F5`).
4. **Quality Assurance Agent (`create_quality_assurance_agent`):** Independently reviews analyst outputs for citation grounding, aircraft/engine variant scope, SCM tier classification, causal rigor, and `F1–F5` factor justifications.
5. **EWS Editor Agent (`create_editor_agent`, `ews_editor_formatter.py`):** Synthesizes an executive narrative and action plan (`EditorialOutput`) without mutating underlying `ThreatAssessment` truth records or scores.

### Deterministic Non-Agentic Safeguards
- **FR03 Two-Stage Filtering (`ews_filtering.py`):** Stage 1 applies deterministic identity, variant-scope, date, and content-quality rules without LLM calls; Stage 2 performs batched LLM semantic verification (up to 5 candidates per batch) with deterministic post-checks and full audit logging (`semantic_filter_audit.json`, `document_filter_log`).
- **Deterministic 5-Factor I&W Scoring (`aero_ews/intelligence/scoring.py`):** Computes a reproducible weighted threat score (`1–10`) from five `1–5` factors with full `scoring_audit` traceability:
  - **F1 Impact Severity** (`w = 0.30`)
  - **F2 Supplier Criticality** (`w = 0.20`)
  - **F3 Substitutability Difficulty** (`w = 0.15`)
  - **F4 Propagation Scope** (`w = 0.15`)
  - **F5 Temporal Urgency** (`w = 0.20`)
  - Formula: $W = \sum_{i=1}^{5} w_i F_i$, $S = \operatorname{clamp}(\lfloor 2W + 0.5 \rfloor, 1, 10)$ (`1–4` Monitored, `5–7` Elevated, `8–10` High Potential Impact).
- **Deterministic Harness & KIQ Engine (`ews_validation.py`, `ews_kiq.py`, `ews_reporting.py`):** Strictly separates *Potential Severity* (`1–10`) from *Evidence Validation* (`SUPPORTED` / `PARTIALLY_SUPPORTED` / `UNSUPPORTED` / `UNVERIFIED_COMMUNITY`) and *Confidence*. Verifies `DOC_ID`s, URLs, verbatim quotes, causal claims, independent corroboration, and entity identity. Confirmed critical escalation (`is_confirmed_critical()`) requires all deterministic gates simultaneously. Runtime KIQ evaluation classifies each question as `ANSWERED`, `PARTIALLY_ANSWERED`, `UNANSWERED`, or `NOT_SEARCHED`.
- **HITL Governance & Verified Alerts (`ews_api.py`, `ews_alerts.py`):** Completed runs default to `WAITING_FOR_HITL` (`pending_dashboard_data.json`) and require authenticated analyst approval (`POST /approve-ews` with `X-Review-Key`) before publication (`dashboard_data.json`, `historical_threats_archive.csv`). Optional SMTP alerts (`send_verified_critical_alerts`) fire only after `APPROVED_BY_HITL_AND_QA` and are deduplicated via `ews_alert_state.json`.
- **Connector Safety & Compliance Guards (`tools.py`, `ews_governance.py`):** Implements SSRF/private-IP blocking, rate limiting, `robots.txt` and HTML TDM opt-out checks, PII redaction, prompt-injection sanitization, and SHA-256 document fingerprinting.

---

## Project Structure

| Module / Directory | Responsibility |
|---|---|
| `main.py`, `ews_api.py`, `ews_models.py`, `ews_state.py` | Local FastAPI server (`127.0.0.1:8000`), strict request validation (`collection_mode="agentic_exa"`, QA & Harness enforced), single-run locking, HITL & audit endpoints |
| `ews_pipeline.py`, `agents.py`, `tasks.py`, `ews_agent_support.py` | End-to-end orchestration, 5 agent factories, multi-provider LLM configuration, batch recovery, and Pydantic contracts |
| `ews_collection.py`, `tools.py`, `ews_sources_extra.py` | Agentic OSINT collection loop and governed connectors (Exa, FAA, EASA, NTSB, SEC EDGAR, ESEF/XBRL, OEM PR, NewsAPI, Airshows, Bluesky, YouTube) |
| `aero_ews/collection/` | `agent_tools.py` (6 CrewAI tools + `AcquisitionBudget`), `exa_connector.py`, `registry.py`, `financial_registry.py`, `queries.py`, `query_expansion.py` |
| `aero_ews/domain/` | `identity.py`, `identity_patterns.py`, `evidence_text.py` (entity/model identity resolution & quote verification) |
| `aero_ews/intelligence/` | `scoring.py` (deterministic `F1–F5` engine), `plan_constraints.py`, `query_repair.py` |
| `aero_ews/persistence/schema.py`, `ews_database.py` | SQLite persistence (`ews_intelligence.db`), migrations, event chronology (`event_history`), and replay dataset storage |
| `ews_filtering.py`, `ews_validation.py`, `ews_kiq.py`, `ews_evidence_contract.py`, `ews_query_constraints.py` | FR03 two-stage filter, deterministic Harness, FAA evidence contracts, and catalog/runtime KIQ engine |
| `ews_reporting.py`, `ews_editor_formatter.py`, `ews_targeted.py`, `ews_alerts.py`, `ews_governance.py`, `ews_evaluation.py` | Evidence-locked reporting, `EditorialOutput` parsing, non-mutating Targeted KIQ Scan proposals (`PENDING_QA`), SMTP alerts, AI governance record, and evaluation helpers |
| `index.html`, `static/dashboard.js`, `static/dashboard.css` | Executive & Analyst dashboard with `F1–F5` breakdown, Source Audit, Acquisition Trace, Full Report, and persistent Agent Feedback |
| `run_final_thesis_suite.py`, `ews_final_regression.py` | Thesis evaluation suite (Chapter 8: contracts, 25 queries across 5 scenarios, 3× stability replay, exports) and offline regression tests |
| `architecture.puml` | PlantUML architecture diagram served at `/api/architecture.puml` |

---

## Getting Started

```powershell
# 1. Create and activate virtual environment (Windows)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment variables (.env)
Copy-Item .env.example .env
# Edit .env with your LLM provider key (e.g., OPENROUTER_API_KEY; supports OpenRouter, OpenAI,
# Gemini, Anthropic, Cohere, Groq, Ollama), EXA_API_KEY, EWS_CONTACT_EMAIL, and EWS_REVIEW_KEY

# 4. Start local FastAPI server & dashboard ([http://127.0.0.1:8000](http://127.0.0.1:8000))
python main.py