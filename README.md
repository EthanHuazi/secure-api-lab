# Work 1: Secure REST API and Real CVE Analysis

## Project Overview

A Python 3.12 / Flask / SQLite teaching project implementing Work 1 of the HDU Information Security manual (pages 1-5). The manual requires three endpoints, SQLi/XSS controls, JWT and password hashing, automated SAST/SCA, and a real Vulhub CVE reproduction followed by remediation and regression tests.

**Status: Part A is verified locally and the CVE experiment has now been executed and remediated in the local Docker lab. Still outstanding: an NVD API key for OWASP Dependency-Check, remote GitHub Actions execution, and genuine screenshots. This is not a completed 10/10 submission.**

## Development Environment

Verified on 2026-10-19: macOS arm64, Python 3.12.15 at `/opt/homebrew/bin/python3.12`, pip 26.2.1, Git 2.50.1, Homebrew 7.0.9, VS Code installed. A project-specific `.venv` is used; system Python was not changed. Docker Desktop 29.8.2 with Docker Compose v5.6.0 is running and produces `linux/arm64` containers; the CVE experiment below was executed against it. Repository: **https://github.com/EthanHuazi/secure-api-lab** (published 2026-10-19). No Java runtime is installed, so Dependency-Check was run from its official container instead; that scan is currently blocked by the missing NVD API key (see SCA Results). GitHub Actions has now executed on the remote repository (see CI/CD Pipeline).

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

Re-verified on 2026-10-19 during the regression pass: **40 pytest tests passed** (JUnit regenerated in place) and **6/6 real curl HTTP checks passed** ([transcript](evidence/run-20261019T063701Z/curl-smoke.txt)).

## CI/CD Pipeline

[Workflow](.github/workflows/ci.yml) triggers on push and pull_request. One job installs Python dependencies, executes pytest and curl, runs Bandit and supplementary pip-audit. Another installs Java 21 and OWASP Dependency-Check 13.0.0, downloads exact Python dependency distributions, enables experimental Python analyzers and generates HTML/JSON reports. High/critical CVSS findings (>=7) fail Dependency-Check; Bandit and pip-audit also fail on findings. Report upload uses `always()` so failed scans can be investigated. No blanket suppression or continue-on-error is used.

**Actual remote result.** The workflow ran automatically after publishing:

| Run | Result |
|---|---|
| [#1](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39214061398) | Overall **failure**. `tests-and-sast` **passed** in 24s and produced the `api-test-and-sast-reports` artifact; `dependency-check` **failed** in 11s |
| [#2](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39214172287) | Triggered after wiring the `NVD_API_KEY` secret; expected to fail on `dependency-check` until the secret is populated |

The `dependency-check` failure is the NVD API-key blocker described under SCA Results, surfaced remotely exactly as it was locally; it is not a code defect and has not been suppressed. The `NVD_API_KEY` repository secret was wired into the workflow so that adding the key is the only remaining step. There is no fully green workflow run yet.

Dependency-Check's Python support is experimental and CPE matching can be incomplete or imprecise. pip-audit supplements ecosystem-specific coverage, but does not replace the manual's mandated scanner. OSS Index is disabled because it requires separate account credentials; the NVD-backed Dependency-Check scan remains enabled. NVD initial download without an API key may be slow or rate-limited. Remote execution must confirm database update, nonempty dependency inventory and actual results; service failures are not clean scans.

## SAST Results

Local Bandit 1.9.4 scanned `secure_api/`: **0 findings**; [JSON report](evidence/bandit.json). Re-run on 2026-10-19 with the same result: [JSON](evidence/run-20261019T063701Z/bandit.json), [output](evidence/run-20261019T063701Z/bandit.txt). Tests contain intentional malicious strings and assertions and are outside this application-source scan scope. The first scan flagged B106 on the protocol constant `Bearer`, not a password. The public authentication scheme was named `AUTH_SCHEME` and used in the response dictionary, then rescanned with all rules still enabled. The original report is preserved in `evidence/bandit-initial.json`. This is a static analysis result, not a general proof of security.

## SCA Results

Local pip-audit on `requirements.txt`: **no known vulnerabilities found** across **10 dependencies**; [JSON report](evidence/run-20261019T063701Z/pip-audit.json) and [output](evidence/run-20261019T063701Z/pip-audit.txt). pip-audit was run with `--cache-dir` inside the project because this workstation's tooling sandbox denied creating `~/Library/Caches/pip-audit`.

OWASP Dependency-Check **has not produced a report yet**. No Java runtime is installed locally, so it was executed from the official `owasp/dependency-check` container against this project. The run failed before analysis:

```
[ERROR] Error updating the NVD Data
Caused by: NvdApiException: Invalid API Key, length of 0 too short to provided a masked partial key
[ERROR] Unable to continue dependency-check analysis.
[ERROR] No documents exist
```

NVD's CVE API now requires an API key; without one Dependency-Check has no vulnerability data and aborts. This is a missing-credential blocker, not a suppressed failure. Full output: [dependency-check.txt](evidence/run-20261019T063701Z/dependency-check.txt). Resolution requires a free NVD API key from https://nvd.nist.gov/developers/request-an-api-key passed as `--nvdApiKey` or `NVD_API_KEY` (CI already has `--disableOssIndex` to avoid the second credentialed feed). pip-audit is a supplementary ecosystem-specific check and does not replace the manual's mandated scanner.

## Selected CVE / Vulnerability Description / Root Cause Analysis

CVE-2021-41773 affects Apache HTTP Server 2.4.49. Incorrect normalization of encoded dot segments permits traversal outside an aliased directory under permissive access configuration. This can expose container files, and CGI configurations can permit code execution. This experiment tested file-disclosure only. See [preparation and analysis](cve/CVE-2021-41773/PLAN.md) and the [executed results](cve/CVE-2021-41773/RESULTS.md).

**Root cause.** 2.4.49 changed URL path normalization so that an encoded dot segment such as `.%2e` is decoded *after* the traversal check rather than before it. The server therefore accepts a URI that still contains a dot segment and resolves it to a path outside the `/icons/` alias. The permissive `<Directory /> Require all granted</Directory>` configuration in the lab image then authorizes reading that resolved path. It is the combination of a canonicalization defect and a permissive filesystem authorization: neither alone would expose the file. 2.4.51 corrected the normalization order; the fixed container's `AH10244` error confirms the newer code rejects the malformed path outright.

## Vulnerability Reproduction

The official Vulhub repository has been cloned separately and the selected upstream configuration is preserved. Docker Hub metadata confirms an ARM64 variant of the equivalent official `httpd:2.4.49` base; the Vulhub prebuilt image is amd64-only, so both images were built locally from the official bases using the preserved vulnerable configuration.

**Executed on 2026-10-19 against the local Docker Desktop lab.** Full results, raw outputs and the configuration defect that was found and fixed are in [CVE-2021-41773/RESULTS.md](cve/CVE-2021-41773/RESULTS.md); raw files are in [evidence/run-20261019T063701Z](evidence/run-20261019T063701Z/).

Before the fix — `Apache/2.4.49 (Unix)`, `aarch64`, bound to `127.0.0.1:8080`:

| Request | Result |
|---|---|
| `GET /` | `200 OK`, `It works!` |
| `GET /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd` | **`200 OK`, 926 bytes — container `/etc/passwd` disclosed** |
| `GET /icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd` | **`200 OK`, 926 bytes — disclosed (CVE-2021-42013 variant)** |

Only file disclosure was tested. No command execution was attempted, no host filesystem was mounted, and every target was `127.0.0.1`.

## Remediation / Verification After Fix / Regression Testing

The applied remediation upgrades the Apache base from 2.4.49 to 2.4.69 while preserving the test configuration byte-for-byte, so the version change is the only variable. See [diff](cve/CVE-2021-41773/remediation.diff) and the vulnerable/fixed Dockerfiles and Compose files. Apache documents that 2.4.50's initial fix was incomplete and the follow-up bypass (CVE-2021-42013) was fixed in 2.4.51; 2.4.69 is later than both.

After the fix — `Apache/2.4.69 (Unix)`, `aarch64`, bound to `127.0.0.1:8081`:

| Request | Result |
|---|---|
| `GET /` | `200 OK`, `It works!` — **regression check passed, service still works** |
| `GET /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd` | **`400 Bad Request`, no file content** |
| `GET /icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd` | **`400 Bad Request`, no file content** |

The fixed server logs `AH10244: invalid URI path` for both payloads, showing the request is rejected during path validation before any filesystem mapping. That is a genuine rejection of a live server, not a refused connection. Both Compose projects were brought down afterwards and `docker ps -a` is empty.

A configuration defect was also found and corrected: both Compose files declared `networks: lab: internal: true`, and Docker does not publish host ports for services on an internal network. The containers therefore started with no host binding and every earlier HTTP probe failed with "connection refused" — which had correctly been recorded as inconclusive rather than as a failed exploit. Removing `internal: true` restored `127.0.0.1:8080->80` and `127.0.0.1:8081->80`; loopback-only binding preserves the intended isolation. Originals are kept in `evidence/run-20261019T063701Z/compose-original/`. A second, environment-specific note: this shell exports `http_proxy`, so all HTTP evidence was collected with `curl --noproxy '*'` to stop the proxy answering `502 Bad Gateway` for loopback requests.

Screenshots of the above still have to be captured by the student from their own terminal; transcripts alone are evidence but not screenshots.

## Conclusion

Local API functionality and focused security tests are verified, and the CVE-2021-41773 reproduction, root-cause analysis, remediation and regression checks are now executed with saved evidence. Full Work 1 completion still requires an NVD API key to produce a Dependency-Check report, remote GitHub Actions execution, genuine screenshots, and final student details. See [acceptance and screenshots](docs/STATUS.md) and [control questions](docs/CONTROL_QUESTIONS.md). No marks are self-awarded.

## References

- Course manual: Work 1, pages 1-5 (provided locally).
- [Vulhub](https://github.com/vulhub/vulhub/tree/master/httpd/CVE-2021-41773)
- [Apache advisories](https://httpd.apache.org/security/vulnerabilities_24.html)
- [NVD CVE record](https://nvd.nist.gov/vuln/detail/CVE-2021-41773)
- [Dependency-Check Python analyzer](https://dependency-check.github.io/DependencyCheck/analyzers/python.html)
- [Dependency-Check CLI](https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html)
