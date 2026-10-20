# Acceptance and Evidence Checklist

Updated: 2026-10-20, after the case study was switched to CVE-2023-51449 and the CI pipeline reached a fully green run. Not a final grade claim.

| Rubric | Max | Actual status |
|---|---:|---|
| API functionality | 2 | Locally verified: 40 pytest tests and 6 curl scenarios, re-run and still passing |
| SQL injection prevention | 0.5 | Parameterized queries and attack-input rejection verified |
| XSS prevention | 0.5 | Stored payload output encoding and response headers verified; no browser screenshot |
| JWT + password hashing | 1 | Signature/time/issuer/audience checks, protected endpoints and database hash checks verified |
| CI with security scanners | 2 | Workflow runs on the remote repository and **run [#14](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39376435859) is fully green**: `tests-and-sast` 22s (pytest, curl, Bandit, pip-audit) and `dependency-check` 1h 32m, both `success`, with the `owasp-dependency-check-reports` (52 KB) and `api-test-and-sast-reports` (1.82 KB) artifacts produced. No `continue-on-error`, no threshold change |
| CVE reproduction | 2 | **Executed, CVE-2023-51449.** Gradio 4.10.0 returned 200 and the 97-byte canary (plus `/etc/passwd`, 839 bytes) through a `/file` traversal. Containers torn down |
| Root cause analysis | 1 | Source-backed: `abspath()` leaves `..` unresolved and `is_in_or_equal()` used a prefix test. Confirmed against the installed 4.10.0 and 4.11.0 code |
| Fix and verification | 1 | **Executed.** Gradio 4.11.0 returns 403 `File not allowed` with no content for the same payload, and still serves the app normally |

## Genuine screenshots still needed

Use terminal output or actual GitHub Actions pages. No screenshots have been fabricated. Save screenshots under `evidence/screenshots/` and reference them with relative Markdown paths after creation.

1. `python -m json.tool evidence/curl.json`: successful/failed login, JWT denial and data access, SQLi rejection (JWT already redacted).
2. `python -m pytest -v tests/test_api.py -k 'stored_xss or hash'`: actual security tests.
3. `python -m json.tool evidence/bandit.json`: local Bandit findings; also capture the remote Bandit section of the `api-test-and-sast-reports` artifact.
4. The Dependency-Check HTML report. It now exists: download `owasp-dependency-check-reports` (52 KB) from run [#14](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39376435859) and screenshot the summary page. Artifact download requires an authenticated session, so the file itself has not been placed in the repository; pip-audit remains supplementary only.
5. GitHub Actions successful run, its URL and downloaded scanner artifacts.
6. `docker ps` and `docker port cve51449-vuln-gradio-1` showing `127.0.0.1:7860->7860/tcp`, plus `docker exec ... uname -m` and `gradio.__version__` — captured as transcripts (`vulnerable-container.txt`, `fixed-container.txt`); a screenshot still needs capturing.
7. Vulnerable 4.10.0: `GET /` page and the traversal response returning the canary — transcript in `vulnerability-before.txt`.
8. Fixed 4.11.0: the same traversal returning 403, and `GET /` still 200 — transcript in `vulnerability-after.txt` / `normal-after.txt`.

Transcripts are evidence but not screenshots. Both stacks are down, so reproducing a screenshot means re-running the same commands; the exact sequence is in `cve/CVE-2023-51449/RESULTS.md` section 4.

Do not display `.env`, real passwords, GitHub tokens or bearer tokens in screenshots. Add screenshot links only after the files exist.

## Required user actions

- ~~Request a free NVD API key and add it as the repository secret `NVD_API_KEY`.~~ Done. The workflow passes it to the tool with `--nvdApiKey "$NVD_API_KEY"` (Dependency-Check does not read the environment variable) and the NVD database is now cached between runs, so later scans only fetch increments.
- Capture genuine screenshots (list above) from your own terminal and the Actions page, saving them under `evidence/screenshots/`.
- ~~Provide Variant Number, Student Name and HDU Number.~~ Supplied: Variant Number not assigned; Hua Yichen; HDU 23320129. These are in the report's title page. The HDU number is deliberately **not** placed in the public README, and the generated PDF and its generator are git-ignored for the same reason.
- ~~Authorize public repository publication.~~ Done: published to https://github.com/EthanHuazi/secure-api-lab on 2026-10-19. The published branch is clean; local agent notes were removed from history during setup and contained no credentials or student identifiers.

## Remaining execution order

1. ~~Check Docker and run the CVE experiment.~~ Done twice: CVE-2021-41773 (2026-10-19) and the current case study CVE-2023-51449 (2026-10-20).
2. ~~Obtain an NVD API key, then execute and inspect Dependency-Check.~~ Done: run #14 completed the scan and passed the `--failOnCVSS 7` gate. The remaining sub-task is to download the HTML artifact and screenshot it.
3. Collect genuine screenshots and update all pending statements with actual observations. **Still open — the only substantive gap left.**
4. ~~Review files for secrets, then commit and push the CVE swap.~~ Done: the CVE swap and the CI fixes are on `main` (head `99e16e3`), pushed with explicit authorization.
5. Produce and visually inspect the final English PDF report with the new CVE case study. Rebuilt after the CI result was recorded; the eight `[SCREENSHOT PENDING]` slots remain until step 3 is done.
6. ~~Recheck every rubric item and record the actual public repository and successful pipeline URLs.~~ Done: repository and run #14 URLs are recorded above.

## Submission status

Public repository URL: **https://github.com/EthanHuazi/secure-api-lab** (published 2026-10-19, branch `main`).

Pipeline runs (all triggered automatically by push; the repository is published):

| Run | Result |
|---|---|
| [#1](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39214061398) | **Overall: failure.** `tests-and-sast` **passed** (24s, artifact `api-test-and-sast-reports`); `dependency-check` **failed** (11s) — `--out` pointed at a directory that did not exist, so the scanner never started |
| [#6](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39215404092) (last run before the CVE swap) | Same split: `tests-and-sast` **passed** (23s, artifact produced); `dependency-check` **failed** (14s) — same cause |
| #7–#13 | Diagnosis chain, one defect per commit: `290660d` the key existed only as an environment variable and had to be passed with `--nvdApiKey`; `e672651` re-emitted the tool's own error as a `::error::` annotation; `4c69878` created the `--out` directory; `bc437c7` added a scoped suppression and streamed the log. Run `39363679093` was the first run in which the scan actually completed — it exited **15**, meaning the `--failOnCVSS 7` gate tripped on a CPE mismatch against PyJWT. #13 was cancelled while the NVD database was being downloaded a second time |
| [#14](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39376435859) | **Overall: success — first fully green run.** `tests-and-sast` **22s**; `dependency-check` **1h 32m**; total 1h 32m 22s. Two artifacts: `api-test-and-sast-reports` 1.82 KB and `owasp-dependency-check-reports` 52 KB. Annotations: 3 warnings + 2 notices, all deprecation notices (Node.js 20, `setup-java` v4, the `ubuntu-latest` migration) and **no errors** |

Last **fully successful** pipeline URL: **https://github.com/EthanHuazi/secure-api-lab/actions/runs/39376435859** (commit `99e16e3`, Success, 1h 32m 22s, both jobs green).

The one finding that ever tripped the CVSS gate is documented rather than muted: `dependency-check-suppressions.xml` suppresses **CVE-2025-45770 against `pkg:pypi/pyjwt@2.15.1` only**, because the advisory's own report names `lcobucci/jwt` (PHP) and the CPE match to `jwt_project:jwt` is a product mismatch. The scope is an exact package URL and one CVE with an expiry date, so any other finding still fails the build. The detailed inventory inside the 52 KB report has not been transcribed here, because artifact download needs an authenticated session; downloading and screenshotting it is the open action above.

Final PDF: regenerated locally from `scripts/build_report.py` with CVE-2023-51449 as the case study. The PDF and the generator are **git-ignored on purpose** because they carry the HDU number. Screenshot slots remain marked `[SCREENSHOT PENDING]` and have not been fabricated; after capturing them into `evidence/screenshots/`, rebuild with `.venv/bin/python scripts/build_report.py`.
