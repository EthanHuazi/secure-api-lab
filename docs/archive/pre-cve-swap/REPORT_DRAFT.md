# Work 1: Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis

## Title page

| Field | Value |
|---|---|
| Laboratory work | Work 1 — Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis |
| Variant Number | Not assigned |
| Surname and Name | Hua Yichen |
| HDU number | 23320129 |
| Public repository | https://github.com/EthanHuazi/secure-api-lab |
| Selected vulnerability | CVE-2021-41773 (Apache HTTP Server 2.4.49) |

**Status of this draft:** the API, the security controls and the CVE experiment are executed and verified. The Dependency-Check report is pending an NVD API key, so the `dependency-check` CI job is currently red; the `tests-and-sast` job (pytest, curl, Bandit, pip-audit) passes. Genuine screenshots have not been captured yet.

## 1. Introduction

This laboratory combines secure backend development with vulnerability analysis and remediation. The implementation follows Work 1 on pages 1-5 of the course manual.

## 2. Objectives

Implement three authenticated REST API operations, prevent SQL injection and unsafe user-data rendering, hash passwords, automate static and dependency analysis, reproduce an authorized local CVE, explain its cause, and verify both remediation and continued normal operation.

## 3. Development Environment

The inspected workstation runs macOS on arm64. Python 3.12.15 is installed at `/opt/homebrew/bin/python3.12`. The application uses a separate virtual environment, Git 2.50.1, Flask, SQLite, bcrypt and PyJWT. Docker Desktop 29.8.2 with Docker Compose v5.6.0 provides `linux/arm64` containers, which is what the CVE experiment was executed against. No Java runtime is installed, so OWASP Dependency-Check was run from its official container; that scan is blocked pending an NVD API key.

## 4. REST API Design

`POST /auth/login` accepts a login and password and returns a short-lived JWT. `GET /api/data` returns example application data. `GET /api/profile` returns the authenticated user's identifier and escaped username. Both GET endpoints require a verified bearer token. Sensitive fields are excluded from the response schema.

## 5. Implementation

An application factory initializes configuration, response protections and routes. SQLite connections are scoped to the Flask context and closed at teardown. An idempotent CLI command creates the users table and a bcrypt-hashed lab account. Bootstrap generates local secrets in an ignored file without publishing them. Runtime dependencies are pinned.

## 6. Security Controls

All SQL values are bound through parameters. Returned usernames are escaped with MarkupSafe to satisfy the manual's API output requirement, and JSON uses the correct content type with nosniff and a restrictive CSP. No HTML rendering client is present. HS256 JWT verification requires subject, time, issuer and audience claims. bcrypt cost 12 and random salts protect stored passwords. Input checks reject oversized requests and passwords beyond bcrypt's byte limit. Secrets and databases are excluded from Git.

## 7. Security Testing

The actual local pytest run passed 40 tests. Coverage includes accepted and rejected logins, both protected endpoints, missing/invalid/expired/wrong-signature tokens, malformed input, injection attempts, stored XSS output, hash storage and repeat initialization. Six real curl requests against a loopback server verified the main HTTP behavior. Evidence is in `evidence/pytest.txt`, `evidence/pytest.xml` and `evidence/curl.json`. Tokens were redacted from the saved curl report. No screenshot is claimed.

## 8. CI/CD Pipeline

The workflow is prepared for pushes and pull requests. It runs tests, curl, Bandit, supplementary pip-audit and OWASP Dependency-Check with report artifacts. Locally, Bandit reported zero findings (re-confirmed on 2026-10-19) and pip-audit reported no known vulnerabilities across 10 dependencies. Dependency-Check has not produced a report: it was executed from the official container and aborted because the NVD CVE API requires an API key (`Invalid API Key` / `No documents exist`). Remote GitHub Actions is still unverified, and the public repository and successful pipeline URLs remain pending publication authorization and actual execution.

## 9. CVE Background

CVE-2021-41773 affects Apache HTTP Server 2.4.49. The official Vulhub scenario is `httpd/CVE-2021-41773`. The test will exercise file disclosure only, on a loopback-bound isolated container. Upstream configuration is preserved alongside an ARM64 adaptation based on the equivalent official image.

## 10. Vulnerability Reproduction

**Executed on 2026-10-19** against locally built `linux/arm64` containers bound to loopback only. Two containers were used, built from identical configuration so that only the Apache version differs.

Before the fix, `Apache/2.4.49 (Unix)` on `127.0.0.1:8080`:

| Request | Result |
|---|---|
| `GET /` | `200 OK`, `It works!` |
| `GET /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd` | `200 OK`, 926 bytes — container `/etc/passwd` disclosed |
| `GET /icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd` | `200 OK`, 926 bytes — disclosed (CVE-2021-42013 variant) |

curl's `--path-as-is` preserved the encoded dot segments. The disclosed content was independently confirmed inside the container. Only file disclosure was tested; no command execution was attempted and no host filesystem was mounted.

One configuration defect had to be corrected first. Both Compose files declared `networks: lab: internal: true`, and Docker does not publish host ports for services attached to an internal network, so the containers came up with no host binding and every HTTP probe failed with "connection refused". An earlier attempt recorded that as inconclusive rather than as a failed exploit. Removing `internal: true` restored `127.0.0.1:8080->80` and `127.0.0.1:8081->80`; loopback-only binding keeps the intended isolation. Separately, this shell exports `http_proxy`, so all probes used `curl --noproxy '*'` to stop the proxy returning `502 Bad Gateway` for loopback requests.

Raw evidence: `evidence/run-20261019T063701Z/`; summary: `cve/CVE-2021-41773/RESULTS.md`.

## 11. Root Cause Analysis

The path-normalization change permits encoded dot segments to escape an alias directory. Permissive filesystem authorization allows access to the resulting target. The problem combines faulty canonicalization with an exploitable access configuration. CGI may increase impact to execution, but this experiment does not need that behavior.

The runtime observations confirm this reading. In 2.4.49 the encoded segment is decoded after the traversal check, so the URI still resolves outside `/icons/` and is then authorized by `Require all granted`; the request returns `200` with file content. In 2.4.69 the same URI is rejected with `AH10244: invalid URI path` during path validation, before any filesystem mapping — the server refuses to build the path at all rather than reaching an authorization decision about a resolved file. The defect is therefore in canonicalization, and hardening the directory configuration alone would leave the malformed path accepted.

## 12. Remediation

The Dockerfile change upgrades Apache 2.4.49 to 2.4.69 while preserving the comparison configuration, so the version change is the only variable. Apache's advisory records that 2.4.50 was an incomplete fix and the related bypass was fixed in 2.4.51; 2.4.69 is later than both. The diff is saved with the CVE files.

**Verified.** Against `Apache/2.4.69 (Unix)` on `127.0.0.1:8081`, the identical traversal requests now return `400 Bad Request` with a generic error page and no file content, for both the CVE-2021-41773 and CVE-2021-42013 payloads. The error log records `AH10244: invalid URI path` for each. This is a live server rejecting the request, not a refused connection or a crashed service, so it is a genuine result rather than an inconclusive one. Both containers were brought down afterwards.

## 13. Verification

Pending. Execute the same traversal against the fixed container, record status and body, and confirm that unauthorized file content is absent. A refused connection or crashed service must be classified as inconclusive rather than fixed.

## 14. Regression Testing

API regression tests pass: 40 pytest tests and 6 real curl HTTP checks were re-run on 2026-10-19 and still pass.

CVE-service regression also passes. After the fix, `GET /` on `127.0.0.1:8081` returns `200 OK` with the default page containing `It works!`, so the upgrade did not break normal operation. Apache version (`2.4.69`), container architecture (`aarch64`), service health and access/error logs were all recorded, and both containers were then stopped and removed.

## 15. Conclusion

The local API and focused security controls are implemented and tested. CVE-2021-41773 was reproduced in an authorized loopback-only container, its root cause was confirmed against runtime behaviour, and the version upgrade to 2.4.69 was verified to stop both the original payload and the CVE-2021-42013 bypass while leaving normal service working. The experiment still cannot be submitted as complete: the mandated Dependency-Check report needs an NVD API key, remote CI has not run, genuine screenshots have not been captured, and the final cover details are outstanding.

## 16. References

- HDU Information Security Laboratory Manual, Work 1, pages 1-5.
- https://github.com/vulhub/vulhub/tree/master/httpd/CVE-2021-41773
- https://httpd.apache.org/security/vulnerabilities_24.html
- https://nvd.nist.gov/vuln/detail/CVE-2021-41773
- https://dependency-check.github.io/DependencyCheck/analyzers/python.html
- https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html
