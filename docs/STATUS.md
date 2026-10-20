# Acceptance and Evidence Checklist

Updated: 2026-10-20, after the case study was switched to CVE-2023-51449. Not a final grade claim.

| Rubric | Max | Actual status |
|---|---:|---|
| API functionality | 2 | Locally verified: 40 pytest tests and 6 curl scenarios, re-run and still passing |
| SQL injection prevention | 0.5 | Parameterized queries and attack-input rejection verified |
| XSS prevention | 0.5 | Stored payload output encoding and response headers verified; no browser screenshot |
| JWT + password hashing | 1 | Signature/time/issuer/audience checks, protected endpoints and database hash checks verified |
| CI with security scanners | 2 | Workflow runs on the remote repository; `tests-and-sast` green (pytest, curl, Bandit 0 findings, pip-audit clean). **Dependency-Check red: no NVD API key.** No fully green run yet |
| CVE reproduction | 2 | **Executed, CVE-2023-51449.** Gradio 4.10.0 returned 200 and the 97-byte canary (plus `/etc/passwd`, 839 bytes) through a `/file` traversal. Containers torn down |
| Root cause analysis | 1 | Source-backed: `abspath()` leaves `..` unresolved and `is_in_or_equal()` used a prefix test. Confirmed against the installed 4.10.0 and 4.11.0 code |
| Fix and verification | 1 | **Executed.** Gradio 4.11.0 returns 403 `File not allowed` with no content for the same payload, and still serves the app normally |

## Genuine screenshots still needed

Use terminal output or actual GitHub Actions pages. No screenshots have been fabricated. Save screenshots under `evidence/screenshots/` and reference them with relative Markdown paths after creation.

1. `python -m json.tool evidence/curl.json`: successful/failed login, JWT denial and data access, SQLi rejection (JWT already redacted).
2. `python -m pytest -v tests/test_api.py -k 'stored_xss or hash'`: actual security tests.
3. `python -m json.tool evidence/bandit.json`: local Bandit findings; also capture the remote report after CI.
4. Dependency-Check HTML report after a real successful scan; pip-audit is supplementary only.
5. GitHub Actions successful run, its URL and downloaded scanner artifacts.
6. `docker ps` and `docker port cve51449-vuln-gradio-1` showing `127.0.0.1:7860->7860/tcp`, plus `docker exec ... uname -m` and `gradio.__version__` — captured as transcripts (`vulnerable-container.txt`, `fixed-container.txt`); a screenshot still needs capturing.
7. Vulnerable 4.10.0: `GET /` page and the traversal response returning the canary — transcript in `vulnerability-before.txt`.
8. Fixed 4.11.0: the same traversal returning 403, and `GET /` still 200 — transcript in `vulnerability-after.txt` / `normal-after.txt`.

Transcripts are evidence but not screenshots. Both stacks are down, so reproducing a screenshot means re-running the same commands; the exact sequence is in `cve/CVE-2023-51449/RESULTS.md` section 4.

Do not display `.env`, real passwords, GitHub tokens or bearer tokens in screenshots. Add screenshot links only after the files exist.

## Required user actions

- **Request a free NVD API key** at https://nvd.nist.gov/developers/request-an-api-key and add it as the repository secret `NVD_API_KEY` (Settings → Secrets and variables → Actions → New repository secret). The workflow reads it via `env: NVD_API_KEY`. Without it OWASP Dependency-Check aborts with `Invalid API Key` / `No documents exist`, which is why the workflow is red. After adding it, re-run the failed job to obtain a fully green run.
- Capture genuine screenshots (list above) from your own terminal and the Actions page, saving them under `evidence/screenshots/`.
- ~~Provide Variant Number, Student Name and HDU Number.~~ Supplied: Variant Number not assigned; Hua Yichen; HDU 23320129. These are in the report's title page. The HDU number is deliberately **not** placed in the public README, and the generated PDF and its generator are git-ignored for the same reason.
- ~~Authorize public repository publication.~~ Done: published to https://github.com/EthanHuazi/secure-api-lab on 2026-10-19. The published branch is clean; local agent notes were removed from history during setup and contained no credentials or student identifiers.

## Remaining execution order

1. ~~Check Docker and run the CVE experiment.~~ Done twice: CVE-2021-41773 (2026-10-19) and the current case study CVE-2023-51449 (2026-10-20).
2. Obtain an NVD API key, then execute and inspect Dependency-Check; resolve real tool/data problems without masking failure.
3. Collect genuine screenshots and update all pending statements with actual observations.
4. Review files for secrets, then commit and push the CVE swap (push requires explicit authorization).
5. Produce and visually inspect the final English PDF report with the new CVE case study.
6. Recheck every rubric item and record the actual public repository and successful pipeline URLs.

## Submission status

Public repository URL: **https://github.com/EthanHuazi/secure-api-lab** (published 2026-10-19, branch `main`).

Pipeline runs (all triggered automatically by push; the repository is published):

| Run | Result |
|---|---|
| [#1](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39214061398) | **Overall: failure.** `tests-and-sast` **passed** (24s, artifact `api-test-and-sast-reports`); `dependency-check` **failed** (11s) — no NVD API key |
| [#6](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39215404092) (last run before the CVE swap) | Same split: `tests-and-sast` **passed** (23s, artifact produced); `dependency-check` **failed** (14s) — no NVD API key |

Runs #2-#5 are intermediate documentation pushes with the same outcome. In every run so far the `tests-and-sast` job has been green and the `dependency-check` job has been red, for the single documented reason above.

Last **fully successful** pipeline URL: **not available yet.** The `tests-and-sast` job succeeds, which already satisfies "at least one SAST/SCA tool running", but the workflow is red while Dependency-Check cannot obtain NVD data. Adding the `NVD_API_KEY` secret and re-running should make the whole workflow green.

Final PDF: regenerated locally from `scripts/build_report.py` with CVE-2023-51449 as the case study. The PDF and the generator are **git-ignored on purpose** because they carry the HDU number. Screenshot slots remain marked `[SCREENSHOT PENDING]` and have not been fabricated; after capturing them into `evidence/screenshots/`, rebuild with `.venv/bin/python scripts/build_report.py`.
