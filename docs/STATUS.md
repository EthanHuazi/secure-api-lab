# Acceptance and Evidence Checklist

Updated: 2026-10-19, after the CVE experiment was executed in the local Docker lab. Not a final grade claim.

| Rubric | Max | Actual status |
|---|---:|---|
| API functionality | 2 | Locally verified: 40 pytest tests and 6 curl scenarios, re-run and still passing |
| SQL injection prevention | 0.5 | Parameterized queries and attack-input rejection verified |
| XSS prevention | 0.5 | Stored payload output encoding and response headers verified; no browser screenshot |
| JWT + password hashing | 1 | Signature/time/issuer/audience checks, protected endpoints and database hash checks verified |
| CI with security scanners | 2 | Workflow prepared; local Bandit 0 findings and pip-audit clean. **Dependency-Check blocked: no NVD API key.** Remote pipeline not yet run |
| CVE reproduction | 2 | **Executed.** 2.4.49 disclosed `/etc/passwd` (200, 926 bytes) for both the CVE-2021-41773 and CVE-2021-42013 payloads. Containers torn down |
| Root cause analysis | 1 | Source-backed explanation written and reconciled with the observed `AH10244` rejection |
| Fix and verification | 1 | **Executed.** 2.4.69 returns `400 Bad Request` with no disclosure for both payloads, and serves the normal page (`200 OK`) |

## Genuine screenshots still needed

Use terminal output or actual GitHub Actions pages. No screenshots have been fabricated. Save screenshots under `evidence/screenshots/` and reference them with relative Markdown paths after creation.

1. `python -m json.tool evidence/curl.json`: successful/failed login, JWT denial and data access, SQLi rejection (JWT already redacted).
2. `python -m pytest -v tests/test_api.py -k 'stored_xss or hash'`: actual security tests.
3. `python -m json.tool evidence/bandit.json`: local Bandit findings; also capture the remote report after CI.
4. Dependency-Check HTML report after a real successful scan; pip-audit is supplementary only.
5. GitHub Actions successful run, its URL and downloaded scanner artifacts.
6. Docker `compose ps`, actual Apache version and architecture — captured as transcripts (`vuln-ps.txt`, `vuln-version.txt`, `vuln-arch.txt`, `fixed-*` in `evidence/run-20261019T063701Z/`); a screenshot still needs re-running and capturing.
7. Vulnerable container normal page and traversal HTTP response — captured as `vuln-normal.txt` / `vuln-traversal.txt` / `vuln-42013.txt`.
8. Fixed container same traversal response and normal page regression result — captured as `fixed-normal.txt` / `fixed-traversal.txt` / `fixed-42013.txt`.

Transcripts are evidence but not screenshots. For items 6-8 the containers have been torn down, so reproducing a screenshot means re-running the same commands; the exact sequence is in `cve/CVE-2021-41773/RESULTS.md`.

Do not display `.env`, real passwords, GitHub tokens or bearer tokens in screenshots. A transcript is evidence but not a screenshot. Add screenshot links only after the files exist.

## Required user actions

- **Request a free NVD API key** at https://nvd.nist.gov/developers/request-an-api-key and supply it as `NVD_API_KEY`. Without it OWASP Dependency-Check aborts with `Invalid API Key` / `No documents exist`, so the mandated SCA report cannot be produced. This is the single remaining blocker for the CI rubric item.
- Capture genuine screenshots (list above) from your own terminal and the GitHub Actions page, saving them under `evidence/screenshots/`.
- Provide Variant Number, Student Name (Surname and Name), and HDU Number before a formal report cover is generated. Student ID belongs in the submitted report; do not automatically place it in the public repository.
- Authorize public repository publication and specify the GitHub account/repository (or provide an existing empty repository URL). The repository has local commits but no remote; nothing has been uploaded. Never paste an access token into chat; authenticate locally or via the connector's authorization UI.

## Remaining execution order

1. ~~Check `docker --version`, `docker compose version`, `docker info`.~~ Done: 29.8.2 / v5.6.0 / `linux aarch64`.
2. ~~Pull/build the prepared ARM64 images and run CVE before/after and regression checks.~~ Done and torn down; see `cve/CVE-2021-41773/RESULTS.md`.
3. Obtain an NVD API key, then execute and inspect Dependency-Check; resolve real tool/data problems without masking failure.
4. Collect genuine screenshots and update all pending statements with actual observations.
5. Review files for secrets, then publish only after authorization and run GitHub Actions.
6. Produce and visually inspect the final English PDF report with supplied cover details.
7. Recheck every rubric item and record actual public repository and successful pipeline URLs.

## Submission status

Public repository URL: not available.
Last successful pipeline URL: not available.
Final PDF: not generated; identity details and experiment evidence are pending.
