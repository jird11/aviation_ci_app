# 8.3 Functional and API Contract Testing — Aero_EWS 2.0

| Test ID | Area | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| T01 | Offline smoke-import & contracts | Zero exit code with no import or schema errors | rc=0; ============================================================================== | **PASS** |
| T02 | Dashboard & UML availability | HTTP 200 for / and /api/architecture.puml | GET /=200, GET /api/architecture.puml=200 | **PASS** |
| T03 | KIQ catalog & connector status | HTTP 200 with active KIQ catalog and connector status | /api/kiq-catalog=200 (KIQ=6), /api/source-status=200 | **PASS** |
| T04 | Input validation — blank KIT | Rejected with HTTP 422 | HTTP 422 | **PASS** |
| T05 | Input validation — inverted dates | Rejected with HTTP 422 | HTTP 422 | **PASS** |
| T06 | Input validation — unknown platform | Rejected with HTTP 422 | HTTP 422 | **PASS** |
| T07 | HITL authorization — unauthorized approval | Fail-closed rejection (HTTP 401/403/422/503) | HTTP 403 | **PASS** |
| T08 | Runtime diagnostics & FR03 audit | HTTP 200 for /logs and /api/filter-audit | /logs=200 (state=IDLE), /api/filter-audit=200 | **PASS** |
