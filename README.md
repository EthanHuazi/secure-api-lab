# Work 1: Secure REST API and Real CVE Analysis

## Project Overview

A Python 3.12 / Flask / SQLite teaching project implementing Work 1 of the HDU Information Security manual (pages 1-5). The manual requires three endpoints, SQLi/XSS controls, JWT and password hashing, automated SAST/SCA, and a real Vulhub CVE reproduction followed by remediation and regression tests.

**Status: Part A and Part B are executed and verified. The case study is CVE-2023-51449 (Gradio), reproduced and remediated in the local Docker lab with saved evidence. The CI pipeline is fully green on run #14, including OWASP Dependency-Check. Still outstanding: genuine screenshots, and the final PDF built after they are captured. No marks are self-awarded.**

The earlier CVE-2021-41773 (Apache) experiment is retained in [cve/CVE-2021-41773](cve/CVE-2021-41773/) as a completed historical run. It is not mixed into the results below.

## Development Environment

Verified on 2026-10-20: macOS 26.5.2 on arm64, Python 3.12.15 at `/opt/homebrew/bin/python3.12`, pip 26.2.1, Git 2.50.1, Homebrew 7.0.9, VS Code installed. A project-specific `.venv` is used; system Python was not changed. Docker Desktop 29.8.2 with Docker Compose v5.6.0 is running and produces `linux/aarch64` containers; both CVE experiments were executed against it. Repository: **https://github.com/EthanHuazi/secure-api-lab** (published 2026-10-19). No Java runtime is installed on the workstation, so OWASP Dependency-Check runs on the GitHub Actions runner instead of locally; that job completed successfully in run [#14](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39376435859) (see SCA Results).

## Installation

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python scripts/bootstrap.py
```

Bootstrap generates a random JWT secret and random lab password in ignored `.env` (mode 0600), and initializes a local SQLite account. Running it again preserves the existing account. Never publish `.env`, real credentials, databases or active tokens. Runtime dependencies and their transitive dependencies are pinned in `requirements.txt`; development tools are in `requirements-dev.txt`.

To create another lab account interactively:

```sh
sh scripts/init_db.sh
```

The initializer prompts for username and hidden password with confirmation. Existing usernames are unchanged. Passwords must be 12-72 UTF-8 bytes. The database schema is `users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash BLOB NOT NULL)`.

## How to Run

```sh
.venv/bin/python -m flask --app secure_api run --host 127.0.0.1 --port 5000
```

Flask CLI loads the local `.env` through python-dotenv. Open `.env` privately to obtain generated lab credentials; never include its contents in screenshots. This is a local laboratory server. Deployment would additionally require TLS, production serving, request throttling, secret lifecycle controls and an operational monitoring plan. No deployment is claimed here.

## API Documentation

| Method | Path | Input | Success | Errors |
|---|---|---|---|---|
| POST | `/auth/login` | JSON `login` and `password` (`username` alias supported) | 200, access_token/token_type/expires_in | 400 invalid fields, 401 credentials, 413 oversized body, 415 media type |
| GET | `/api/data` | Authorization: Bearer TOKEN | 200, data array | 401 absent/invalid/expired token |
| GET | `/api/profile` | Authorization: Bearer TOKEN | 200, user id and escaped username | 401 absent/invalid/expired token |

Malformed and nonexistent routes use JSON HTTP error responses. Conflicting `login` and `username` values are rejected. The profile is an allowlist and never returns password hashes or signing secrets.

## Authentication / JWT Authentication

Successful login produces an HS256 JWT with `sub`, `iat`, `nbf`, `exp`, `iss` and `aud`; lifetime is 900 seconds. The shared decorator restricts algorithms to HS256, requires these claims, validates signature, issuer, audience and times, and verifies that the referenced database user still exists. Rejection is HTTP 401 with a Bearer authentication challenge. `JWT_SECRET` must be at least 32 bytes; bootstrap generates it with Python's cryptographic random generator. Tokens are signed, not encrypted. There is no refresh token or per-token revocation implementation in this small lab.

## Security Measures / SQL Injection Prevention

SQL injection occurs when an input value changes the structure of a database command. Every input-bearing query uses SQLite `?` placeholders and a separate tuple of values. Values are bound as data, not parsed as SQL syntax. Both login and user-ID lookup use parameters, as do insertion and duplicate-user checks. Tests submit quote/comment/OR payloads and confirm HTTP 401; a username containing punctuation can still be safely stored and retrieved. No intentionally injectable endpoint is retained.

## XSS Prevention

The manual explicitly asks for escaping returned user data. The only returned user-controlled field is `username`; it is encoded using MarkupSafe `escape()` before JSON serialization. `<`, `>`, quotes and ampersands become HTML entities. The API contract intentionally returns this escaped representation. Tokens contain only a database identifier and server-generated claims, not arbitrary user strings.

JSON is served with `application/json`, `X-Content-Type-Options: nosniff`, a restrictive CSP and no-store caching. There is no HTML UI or client-side HTML insertion. Consumers must use a text sink such as `textContent`; they must not decode entities and insert the result with `innerHTML`. HTML escaping is not a universal defense for JavaScript, URLs or CSS contexts. A future HTML page must use context-appropriate escaping and safe templates. Tests persist an actual `<img ... onerror=...>` payload, authenticate that user and assert encoded output and safe response headers. This verifies the API's output contract; no browser execution screenshot is claimed.

## Password Hashing

bcrypt with cost 12 stores salted hashes only. Unknown users undergo a dummy bcrypt verification to reduce account timing differences, and login errors do not distinguish unknown usernames from wrong passwords. Inputs above 72 UTF-8 bytes are rejected rather than truncated. The password-hash test checks the database value and verifies it with bcrypt.

## API Testing

```sh
.venv/bin/python -m pytest -v --junitxml=evidence/pytest.xml
.venv/bin/python scripts/curl_smoke.py
.venv/bin/python -m pip check
```

Actual local result: **40 pytest tests passed**. Six real curl HTTP checks passed using an ephemeral loopback server. The script initializes its own isolated database, passes secrets through stdin, masks the returned JWT in the evidence, and shuts down the server. Records: [pytest transcript](evidence/pytest.txt), [JUnit](evidence/pytest.xml), [curl responses](evidence/curl.json). These are actual outputs, not screenshots. Test fixture passwords are synthetic, isolated test data.

Re-verified on 2026-10-20 during the CVE case-study swap: **40 pytest tests passed**. This environment's sandbox denies `mkdir` under the system temp directory, so pytest needs `--basetemp=.pytest-tmp`; no test file was modified. Record: [regression-test.txt](evidence/cve-2023-51449/regression-test.txt).

## CI/CD Pipeline

[Workflow](.github/workflows/ci.yml) triggers on push and pull_request. One job installs Python dependencies, executes pytest and curl, runs Bandit and supplementary pip-audit. Another installs Java 21 and OWASP Dependency-Check 13.0.0, downloads exact Python dependency distributions, enables experimental Python analyzers and generates HTML/JSON reports. High/critical CVSS findings (>=7) fail Dependency-Check; Bandit and pip-audit also fail on findings. Report upload uses `always()` so failed scans can be investigated. No blanket suppression or continue-on-error is used.

**Actual remote result.** The workflow ran automatically after publishing:

| Run | Result |
|---|---|
| [#1](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39214061398) | Overall **failure**. `tests-and-sast` **passed** in 24s and produced the `api-test-and-sast-reports` artifact; `dependency-check` **failed** in 11s |
| [#6](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39215404092) | Current `main` before the CVE swap: `tests-and-sast` passed (23s), `dependency-check` failed (14s) |
| #7-#13 | Diagnosis chain, one concrete defect per commit (below). Run `39363679093` was the first in which the scan actually completed, and it exited **15** |
| [#14](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39376435859) | **Overall success - first fully green run.** `tests-and-sast` **22s**, `dependency-check` **1h 32m** (total 1h 32m 22s). Artifacts: `api-test-and-sast-reports` 1.82 KB and `owasp-dependency-check-reports` 52 KB. Annotations are 3 warnings and 2 notices, all deprecation notices, with no errors |

The red runs were workflow defects, and each was fixed in the workflow rather than hidden:

1. `--out .ci-reports/dependency-check` pointed at a directory Dependency-Check does not create, so the tool aborted with `Invalid 'out' argument ... path does not exist` before any scan. Fixed by creating the directory first (`4c69878`).
2. `NVD_API_KEY` was only a job environment variable, which Dependency-Check does not read. It is now passed explicitly as `--nvdApiKey "$NVD_API_KEY"` (`290660d`).
3. The tool's own message was only visible in job logs, which require authentication to read. The step now re-emits it with `::error::` so it appears as a public annotation (`e672651`).
4. Exit code 15 on run `39363679093` was the intended `--failOnCVSS 7` gate firing on one finding: CVE-2025-45770, matched to `pkg:pypi/pyjwt@2.15.1`. The advisory describes `lcobucci/jwt` for PHP, so this is a CPE product mismatch. [dependency-check-suppressions.xml](dependency-check-suppressions.xml) suppresses that exact package URL and that one CVE until 2027-01-20 with the reasoning recorded in the file; the gate, its threshold and all other rules are unchanged (`bc437c7`).
5. `actions/cache` only saves on success, so a failed run discarded the 410k-record NVD database and every retry re-downloaded it from zero. The workflow now uses `actions/cache/restore` plus `actions/cache/save` with `if: always()`, and the job timeout was raised from 60 to 300 minutes (`99e16e3`).

No `continue-on-error`, blanket suppression or lowered threshold is used anywhere in the workflow.

Dependency-Check's Python support is experimental and CPE matching can be incomplete or imprecise. pip-audit supplements ecosystem-specific coverage, but does not replace the manual's mandated scanner. OSS Index is disabled because it requires separate account credentials; the NVD-backed Dependency-Check scan remains enabled. A cold NVD download is slow even with a key, which is why the database is cached; remote execution must confirm database update, nonempty dependency inventory and actual results, and service failures are not clean scans.

## SAST Results

Local Bandit 1.9.4 scanned `secure_api/`: **0 findings**; [JSON report](evidence/bandit.json). Re-run on 2026-10-19 with the same result: [JSON](evidence/run-20261019T063701Z/bandit.json), [output](evidence/run-20261019T063701Z/bandit.txt). Tests contain intentional malicious strings and assertions and are outside this application-source scan scope. The first scan flagged B106 on the protocol constant `Bearer`, not a password. The public authentication scheme was named `AUTH_SCHEME` and used in the response dictionary, then rescanned with all rules still enabled. The original report is preserved in `evidence/bandit-initial.json`. This is a static analysis result, not a general proof of security.

## SCA Results

Local pip-audit on `requirements.txt`: **no known vulnerabilities found** across **10 dependencies**; [JSON report](evidence/run-20261019T063701Z/pip-audit.json) and [output](evidence/run-20261019T063701Z/pip-audit.txt). pip-audit was run with `--cache-dir` inside the project because this workstation's tooling sandbox denied creating `~/Library/Caches/pip-audit`.

OWASP Dependency-Check is executed in CI because no Java runtime is installed locally. In run [#14](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39376435859) the job completed and produced the `owasp-dependency-check-reports` artifact (52 KB, HTML and JSON) with `--failOnCVSS 7` satisfied, so no dependency at or above that threshold remains after the scoped suppression described below. The report file itself is not committed: downloading an Actions artifact requires an authenticated session, so the finding inventory lives in that artifact and its screenshot is still on the capture list.

One finding ever reached the gate. Run `39363679093` exited 15 on **CVE-2025-45770**, matched to `pkg:pypi/pyjwt@2.15.1`; the advisory's own report describes `lcobucci/jwt` for PHP, so the CPE match against `jwt_project:jwt` is a product mismatch rather than a real defect in this project. The suppression in [dependency-check-suppressions.xml](dependency-check-suppressions.xml) names that exact package URL and that one CVE, expires 2027-01-20, and records the reasoning; the gate, the threshold and every other rule are untouched.

The earlier local attempt is kept as a record of why the key was needed. Run from the official `owasp/dependency-check` container against this project, it aborted before analysis:

```
[ERROR] Error updating the NVD Data
Caused by: NvdApiException: Invalid API Key, length of 0 too short to provided a masked partial key
[ERROR] Unable to continue dependency-check analysis.
[ERROR] No documents exist
```

NVD's CVE API requires an API key; without one Dependency-Check has no vulnerability data and aborts. Full output: [dependency-check.txt](evidence/run-20261019T063701Z/dependency-check.txt). That blocker is resolved by the repository secret plus the explicit `--nvdApiKey` pass-through, and the analysis now runs in CI. pip-audit is a supplementary ecosystem-specific check and does not replace the manual's mandated scanner.

## CVE Identification

| Field | Value |
|---|---|
| CVE | **CVE-2023-51449** |
| Affected software | Gradio (PyPI package `gradio`), a Python library for ML web UIs |
| Affected versions | `< 4.11.0` |
| Patched version | `4.11.0` |
| Severity | High, CVSS 3.1 base **8.6** (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L`) |
| Advisory | GHSA-6qm2-wpxq-7qh2 |
| Fix reference | gradio-app/gradio PR #6833 |
| Vulhub scenario | `gradio/CVE-2023-51449` |

Version fields were read from the vendor advisory, not assumed. The Vulhub README says "In Gradio versions 4.11 and below", which conflicts with the advisory's `patched: 4.11.0`; the advisory was treated as authoritative and the question was settled by running both versions. 4.11.0 blocks the request and 4.10.0 does not, so the README wording is imprecise.

## Vulnerability Description

Gradio serves uploaded and generated files through a `/file=<path>` route. The route is supposed to accept only files the application produced or the user uploaded, plus anything under explicitly configured `allowed_paths`. In 4.10.0 the containment check could be bypassed with dot segments, so an unauthenticated client who knew a path could read arbitrary files on the host running the app. Gradio's own advisory notes this matters when the app is publicly reachable (`share=True` or a hosted Space) and that the request must be sent programmatically, for example with `curl --path-as-is`, because a browser normalises the URL first.

## Root Cause Analysis

`/file` calls `utils.abspath()` and then asks `utils.is_in_or_equal(abs_path, app.uploaded_file_dir)` whether the path was uploaded. `abspath()` returns an already-absolute path **unchanged** — its docstring says it does not resolve symlinks, and it does not normalise dot segments either:

```python
def abspath(path):
    path = Path(path)
    if path.is_absolute():
        return path    # /tmp/gradio/<hash>/../../../srv/private/canary.txt
```

`is_in_or_equal()` then calls `Path.relative_to()` on that un-normalised path. Relative to `/tmp/gradio` the result is `<hash>/../../../srv/private/canary.txt`. The 4.10.0 test was a prefix test:

```python
if str(path_1.relative_to(path_2)).startswith(".."):
    return False
```

The relative string begins with the hash directory, not with `..`, so the predicate returns True. The path is classified as an uploaded file, no 403 is raised, and `FileResponse` opens it; the kernel then resolves the `..` segments and returns `/srv/private/canary.txt`. The defect is a check that inspects only the start of a string instead of asking whether the path, once normalised, is still inside the intended directory.

The fix in 4.11.0 changes that one comparison:

```python
if ".." in str(path_1.relative_to(path_2)):
    return False
```

Because `abspath()` leaves the segments in place, a `..` anywhere in the relative path now fails the check and the route returns 403 before touching the filesystem. The diff of the two installed `gradio/utils.py` files is exactly this line plus an unrelated cache-folder helper; `gradio/routes.py` differs only in that helper's call site and queue-status handling ([fix-diff.txt](evidence/cve-2023-51449/fix-diff.txt)).

Observed behaviour matches this reading: on 4.10.0 the traversal returns 200 while a nonexistent target returns 404 (the containment check passed, only the filesystem objected); on 4.11.0 both return 403 (the containment check now rejects first).

## Vulnerable Environment

The upstream scenario uses the prebuilt image `vulhub/gradio:4.10.0`. `docker inspect` reports `Architecture=amd64`, and the image has a single-platform manifest, so on Apple silicon it would require emulation. The Vulhub repository ships no Dockerfile and no `app.py`; both exist only inside the image. The build recipe was recovered from the image history, `app.py` was extracted with `docker cp` (no amd64 binary executed), and both versions were rebuilt **natively for arm64** from [one Dockerfile](cve/CVE-2023-51449/Dockerfile) whose only variable is `GRADIO_VERSION`:

- base `python:3.9-slim`, Python 3.9.25 inside both images
- `gradio==4.10.0` / `gradio==4.11.0`, `fastapi==0.112.4`, `pydantic==2.8.2`
- `huggingface_hub==0.20.3` pinned for reproducibility: an unpinned install now pulls hub 1.x, which removed `HfFolder` and makes `gradio/oauth.py` fail at import, so the container exits before serving. The pin restores the dependency set contemporary with the CVE and does not touch `/file` logic.
- `app.py` is byte-identical to the upstream image's file: a `gr.Interface` with one text input and one text output, launched on `0.0.0.0:7860`.

Both stacks publish on loopback only (`127.0.0.1:7860` and `127.0.0.1:7861`), mount nothing from the host, and do not use `internal: true` — that flag silently prevents Docker from publishing ports and had broken the earlier Apache lab. Port publication was verified with `docker ps` and `docker port`, not inferred from the Compose file.

The proof target is a synthetic canary created inside the image outside the Gradio temp directory: `/srv/private/canary.txt`, containing `CANARY-CVE-2023-51449-7f3a9c1d`. No real file, credential or user data exists in the container.

## Reproduction Procedure

1. `docker compose -p cve51449-vuln -f compose.vulnerable.yml up -d --no-build`, then confirm `127.0.0.1:7860->7860/tcp`.
2. Record `uname -m` (`aarch64`), `gradio.__version__` (4.10.0) and `GET /config` (`"version":"4.10.0"`).
3. `POST /upload` a harmless 28-byte file; the response returns `/tmp/gradio/<hash>/cve-probe.txt`.
4. Baseline `GET /file=<that path>` returns 200 with the exact uploaded bytes.
5. Traversal: `GET /file=/tmp/gradio/<hash>/../../../../../../srv/private/canary.txt`, sent with `curl --path-as-is` or on a raw socket so the client cannot normalise the `..`.
6. Repeat identically against 4.11.0 on port 7861.

Two client-side traps were eliminated before the result was accepted, because each produces a convincing false negative:

- `requests`/`urllib3` rewrite dot segments, so the traversal arrived as `/srv/private/canary.txt` and returned 404. The probe therefore writes the request line on a raw socket; the shell evidence uses `curl --path-as-is`.
- A traversal cannot start at a regular file (`probe.txt/..` fails with ENOTDIR), so the payload starts at the upload **directory**, matching Vulhub's `.../<hash>/../../..` shape. The first such attempt returned `404 File not found`, which already showed the 403 had been skipped.

The host exports `HTTP_PROXY`, so every request bypasses it (`--noproxy '*'`, `trust_env = False`); otherwise loopback traffic is answered by the proxy with misleading status codes.

## Evidence

| | Vulnerable 4.10.0 | Fixed 4.11.0 |
|---|---|---|
| `GET /` | 200 | 200 |
| `GET /config` version | 4.10.0 | 4.11.0 |
| Upload + legitimate `GET /file` | 200, 28 bytes, body matches | 200, 28 bytes, body matches |
| Traversal to canary | **200, 97 bytes, `CANARY-CVE-2023-51449-7f3a9c1d` returned** | **403 `File not allowed`, no content** |
| Traversal to `/etc/passwd` (secondary) | **200, 839 bytes, disclosed** | **403 `File not allowed`, no content** |
| Nonexistent traversal target | 404 | 403 |
| `POST /run/predict` | `{"data":["Hello World!"]}` | `{"data":["Hello World!"]}` |

The canary is the primary proof because it contains no real data; `/etc/passwd` inside the throwaway container is recorded only as secondary confirmation that arbitrary paths, not just one file, were readable. The control request rules out a blanket 200 response. Raw files: [normal-before.txt](evidence/cve-2023-51449/normal-before.txt), [vulnerability-before.txt](evidence/cve-2023-51449/vulnerability-before.txt), [normal-after.txt](evidence/cve-2023-51449/normal-after.txt), [vulnerability-after.txt](evidence/cve-2023-51449/vulnerability-after.txt), [container state](evidence/cve-2023-51449/vulnerable-container.txt), [fixed container](evidence/cve-2023-51449/fixed-container.txt), [environment](evidence/cve-2023-51449/environment.txt), and the machine-readable probes [probe-vulnerable.json](evidence/cve-2023-51449/probe-vulnerable.json) / [probe-fixed.json](evidence/cve-2023-51449/probe-fixed.json). Summary: [RESULTS.md](cve/CVE-2023-51449/RESULTS.md).

## Remediation

The remediation is the vendor fix: upgrade Gradio from 4.10.0 to 4.11.0, the version the advisory names as patched, while keeping the application code, base image, dependency pins and Compose structure identical. No configuration workaround such as tightening `allowed_paths` was used, because that would test a mitigation rather than the fix. The only difference between the two images is the `GRADIO_VERSION` build argument, so the version is the only variable.

## Verification

Against `gradio 4.11.0` on `127.0.0.1:7861`, the identical request now returns:

```
HTTP/1.1 403 Forbidden
{"detail":"File not allowed: /tmp/gradio/<hash>/../../../../../../srv/private/canary.txt."}
```

The response body is checked, not only the status: the canary marker is absent, and the `/etc/passwd` attempt is likewise refused with no content. The nonexistent-target case also returns 403 rather than 404, showing the rejection now happens at the containment check before any filesystem access — the expected shape of this particular fix.

## Regression Testing

- Fixed app: `GET /` returns 200 with the Gradio page, `GET /config` reports 4.11.0, `POST /upload` and the legitimate `GET /file` still return 200 with matching bytes, and `POST /run/predict` still returns `{"data":["Hello World!"]}`. The legitimate read also succeeds *after* the blocked traversal, so the service is not wedged.
- API: 40 pytest tests pass on 2026-10-20 locally, and the same suite plus the curl checks and Bandit pass in CI (`tests-and-sast`, 22s in run #14). Six curl HTTP checks pass from the earlier run.
- Both Compose projects were brought down; `docker ps -a` is empty. Images are kept for review and no global prune was used.

## Conclusion

CVE-2023-51449 was reproduced on Gradio 4.10.0 in an authorized, loopback-only, ARM64-native lab, with a canary file as the proof target rather than real data. The root cause was confirmed in the shipped source: `abspath()` leaves dot segments unresolved and `is_in_or_equal()` tested only the start of the relative path, so a traversal path was classified as an uploaded file. Gradio 4.11.0's one-line change to a substring test rejects the same request with 403, and normal operation is unaffected. The CI pipeline is fully green on run #14, including the mandated Dependency-Check scan. Remaining items are evidence capture, not unfinished engineering: genuine screenshots, and the PDF rebuilt once they exist. No marks are self-awarded.

## Appendix: earlier CVE-2021-41773 experiment

The Apache HTTP Server path-traversal experiment was executed on 2026-10-19 and is retained unchanged for reference: [results](cve/CVE-2021-41773/RESULTS.md), [plan](cve/CVE-2021-41773/PLAN.md), [raw evidence](evidence/run-20261019T063701Z/), [original compose files](evidence/run-20261019T063701Z/compose-original/). It is no longer the case study in this report and its numbers are not mixed with the Gradio results.

## References

- Course manual: Work 1, pages 1-5 (provided locally).
- [GHSA-6qm2-wpxq-7qh2 advisory](https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2)
- [gradio-app/gradio PR #6833](https://github.com/gradio-app/gradio/pull/6833)
- [NVD CVE-2023-51449](https://nvd.nist.gov/vuln/detail/CVE-2023-51449)
- [Vulhub gradio/CVE-2023-51449](https://github.com/vulhub/vulhub/tree/master/gradio/CVE-2023-51449)
- [Dependency-Check Python analyzer](https://dependency-check.github.io/DependencyCheck/analyzers/python.html)
- [Dependency-Check CLI](https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html)
