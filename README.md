# Aero_EWS 2.0

**Multi-Agent Competitive Intelligence Early Warning System for the Aerospace Industry**

Aero_EWS 2.0 is a Python-based research application that monitors publicly available aerospace information, identifies potential risks and emerging signals, and presents structured intelligence findings in an interactive dashboard. It combines Open-Source Intelligence (OSINT), AI-assisted analysis, and evidence-based validation to support Competitive Intelligence (CI) activities.

This project accompanies the master's thesis *Využití metod Competitive Intelligence s prvky automatizovaného monitorování v leteckém průmyslu* at the Prague University of Economics and Business (VŠE).

## Features

- **OSINT monitoring:** Collects information from aviation news, regulatory sources (FAA/EASA), NTSB investigations, manufacturer announcements, and selected online platforms.
- **Intelligence-driven search:** Translates Key Intelligence Topics (KITs) into Key Intelligence Questions (KIQs) and targeted collection queries.
- **Relevance filtering:** Uses deterministic checks and LLM-assisted semantic filtering (FR03) to reduce irrelevant results.
- **Multi-agent analysis:** Coordinates specialized agents for planning, risk analysis, quality assurance, editorial synthesis, and scoring.
- **Evidence validation:** Checks source traceability, technical applicability, uncertainty, and the support available for reported claims.
- **Dashboard and history:** Presents threats, priorities, recommended actions, and historical results through a web interface.
- **Human oversight:** Supports Human-in-the-Loop (HITL) review before final approval.

## How It Works

1. **Define an intelligence requirement:** The user enters a KIT, time range, and monitoring sources.
2. **Plan and collect:** The system develops KIQs and retrieves relevant OSINT documents.
3. **Filter and analyze:** FR03 selects candidate documents for multi-agent risk assessment.
4. **Validate and score:** QA and deterministic safeguards assess evidence quality and alert eligibility.
5. **Review and report:** The system prepares an intelligence report for human review and dashboard visualization.

`KIT → KIQ → OSINT → FR03 → Analyst → QA → Editor → Scoring → Validation → HITL`

## Architecture

The application uses **Python, FastAPI, CrewAI, Pydantic, SQLite, and HTML/CSS/JavaScript**. Analytical stages are orchestrated sequentially, with persistent records and structured JSON outputs.

| Component | Responsibility |
|---|---|
| `main.py`, `ews_api.py` | Local server and REST API |
| `ews_pipeline.py`, `agents.py`, `tasks.py` | Workflow orchestration and AI agents |
| `ews_collection.py`, `tools*.py` | OSINT collection and external connectors |
| `ews_filtering.py`, `ews_validation.py` | Relevance filtering and evidence safeguards |
| `ews_reporting.py`, `ews_database.py` | Reports, persistence, and historical analysis |
| `index.html` | Interactive monitoring dashboard |

## Getting Started

**Prerequisites:** Python and compatible project dependencies; API credentials for the selected LLM provider and external data sources.

```powershell
# Create and activate a virtual environment (Windows)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies if requirements.txt is included
pip install -r requirements.txt
```

Configure the relevant keys in a local `.env` file (for example, `OPENROUTER_API_KEY`, `NEWS_API_KEY`, and optional source-specific credentials). Do not commit credentials to the repository.

Start the application:

```powershell
python main.py
```

Open the dashboard at **http://127.0.0.1:8000**.

## Outputs and Testing

The system stores intelligence reports in JSON, operational and historical information in SQLite, and selected exports in CSV. Relevant artifacts include `dashboard_data.json`, `ews_intelligence.db`, and `historical_threats_archive.csv`.

Offline regression testing can be run with:

```powershell
python ews_final_regression.py --smoke-import
```

## Limitations

Aero_EWS 2.0 is a **local academic prototype**, not a production monitoring or aviation safety system. Source availability, API limits, semantic filtering, and LLM behavior can affect coverage and accuracy. Automated findings, risk scores, and recommendations must be independently verified by a human analyst before consequential use. The system does not certify regulatory compliance or guarantee the detection of every relevant event.
