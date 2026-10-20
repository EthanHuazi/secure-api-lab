# Work 1: Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis

## Title page

| Field | Value |
|---|---|
| Laboratory work | Work 1 — Secure REST API Development with CI/CD and Real CVE Vulnerability Analysis |
| Variant Number | Not assigned |
| Surname and Name | Hua Yichen |
| HDU number | 23320129 |
| Public repository | https://github.com/EthanHuazi/secure-api-lab |
| Selected vulnerability | CVE-2023-51449 (Gradio, `/file` path traversal) |

**Status of this draft:** the API, the security controls and the CVE experiment are executed and verified. The Dependency-Check report is pending an NVD API key, so the `dependency-check` CI job is currently red while `tests-and-sast` passes. Genuine screenshots have not been captured yet. The earlier CVE-2021-41773 experiment is kept in the repository as a historical run and is not part of the findings below.

# Part A — Secure REST API

## 1. Introduction

This laboratory combines secure backend development with vulnerability analysis and remediation. The implementation follows Work 1 on pages 1-5 of the course manual.

## 2. Objectives

Implement three authenticated REST API operations, prevent SQL injection and unsafe user-data rendering, hash passwords, automate static and dependency analysis, reproduce an authorized local CVE, explain its cause, and verify both remediation and continued normal operation.

## 3. Development Environment

The workstation runs macOS 26.5.2 on arm64. Python 3.12.15 is installed at `/opt/homebrew/bin/python3.12`. The application uses a separate virtual environment, Git 2.50.1, Flask, SQLite, bcrypt and PyJWT. Docker Desktop 29.8.2 with Docker Compose v5.6.0 provides `linux/arm64` containers, which is what the CVE experiment ran against. No Java runtime is installed, so OWASP Dependency-Check was run from its official container; that scan is blocked pending an NVD API key.

## 4. REST API Design

`POST /auth/login` accepts a login and password and returns a short-lived JWT. `GET /api/data` returns example application data. `GET /api/profile` returns the authenticated user's identifier and escaped username. Both GET endpoints require a verified bearer token. Sensitive fields are excluded from the response schema.

## 5. Implementation

An application factory initializes configuration, response protections and routes. SQLite connections are scoped to the Flask context and closed at teardown. An idempotent CLI command creates the users table and a bcrypt-hashed lab account. Bootstrap generates local secrets in an ignored file without publishing them. Runtime dependencies are pinned.

## 6. Security Controls

All SQL values are bound through parameters. Returned usernames are escaped with MarkupSafe to satisfy the manual's API output requirement, and JSON uses the correct content type with nosniff and a restrictive CSP. No HTML rendering client is present. HS256 JWT verification requires subject, time, issuer and audience claims. bcrypt cost 12 and random salts protect stored passwords. Input checks reject oversized requests and passwords beyond bcrypt's byte limit. Secrets and databases are excluded from Git.

## 7. Security Testing

The actual local pytest run passed 40 tests. Coverage includes accepted and rejected logins, both protected endpoints, missing/invalid/expired/wrong-signature tokens, malformed input, injection attempts, stored XSS output, hash storage and repeat initialization. Six real curl requests against a loopback server verified the main HTTP behavior. Evidence is in `evidence/pytest.txt`, `evidence/pytest.xml` and `evidence/curl.json`. Tokens were redacted from the saved curl report. No screenshot is claimed.

## 8. CI/CD Pipeline

The workflow is prepared for pushes and pull requests. It runs tests, curl, Bandit, supplementary pip-audit and OWASP Dependency-Check with report artifacts. Locally, Bandit reported zero findings and pip-audit reported no known vulnerabilities across 10 dependencies. Dependency-Check has not produced a report: run from the official container, it aborted because the NVD CVE API requires an API key (`Invalid API Key` / `No documents exist`). The repository is published and Actions executes on every push; the `tests-and-sast` job is green in every run, the `dependency-check` job is red for that single documented reason. There is no fully green run yet, and the failure has not been suppressed with `continue-on-error`.

# Part B — CVE Case Study: CVE-2023-51449

## 9. CVE Identification

| Field | Value |
|---|---|
| CVE | CVE-2023-51449 |
| Advisory | GHSA-6qm2-wpxq-7qh2, published 2023-12-20 |
| Package | `gradio` (PyPI) |
| Affected versions | `< 4.11.0` |
| Patched versions | `4.11.0` |
| Severity | High; CVSS 3.1 base 8.6 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L`) |
| Fix reference | gradio-app/gradio PR #6833, "Prevent file traversals" |
| Experiment versions | 4.10.0 (vulnerable) and 4.11.0 (fixed) |

The version fields were read from the vendor advisory rather than assumed. One documentation conflict had to be resolved: the Vulhub scenario README states "In Gradio versions 4.11 and below", which would imply 4.11.0 is still vulnerable. The advisory is authoritative and declares 4.11.0 patched. Rather than choose between the two on paper, both versions were run; 4.11.0 blocks the request and 4.10.0 does not, so the README wording is imprecise.

## 10. Affected Software

Gradio is a Python library for building web interfaces for machine-learning models. An application is usually created with `gr.Interface` or `gr.Blocks` and served by Gradio's own FastAPI/uvicorn stack. Every Gradio app exposes internal routes that the front end uses, including `/upload` for receiving files and `/file=<path>` for serving them back. Those routes exist even when the demo itself has no file component: the lab application is a single text box, and `/upload` and `/file` are still reachable. Unicode characters in the path are irrelevant here; the affected surface is the file-serving route.

## 11. Vulnerability Description

`/file` is meant to serve only files the app created, files the user uploaded, and anything under explicitly configured `allowed_paths`. In 4.10.0 that containment decision could be bypassed with `..` segments. An unauthenticated client who knew a path could therefore read arbitrary files readable by the process, for example `/etc/passwd` or application configuration containing secrets.

The vendor advisory notes two preconditions: the app must be reachable by the attacker (public sharing or a hosted Space), and the request must be issued programmatically, because browsers normalise dot segments in a URL before sending it. curl's `--path-as-is` sends the raw path. The advisory also reports an SSRF aspect of the same route; this experiment tests file disclosure only and claims nothing about SSRF.

## 12. Root Cause

The route calls `utils.abspath()` and then `utils.is_in_or_equal(abs_path, app.uploaded_file_dir)` to decide whether the requested file was uploaded. The first function is the key: for an already-absolute path it returns the path **unchanged**, so dot segments survive.

```python
def abspath(path):
    path = Path(path)
    if path.is_absolute():
        return path   # /tmp/gradio/<hash>/../../../srv/private/canary.txt
```

`is_in_or_equal()` then computes `Path.relative_to()` on that un-normalised path. Relative to `/tmp/gradio` the result is `<hash>/../../../srv/private/canary.txt`. In 4.10.0 the traversal test inspected only the beginning of that string:

```python
if str(path_1.relative_to(path_2)).startswith(".."):
    return False
```

Because the string starts with the hash directory, the test returns False and the function reports the path as being inside the upload directory. No 403 is raised, and `FileResponse` opens the path; the kernel resolves the dot segments and returns the file outside the intended root. The defect is a containment check that examines a prefix of an un-normalised path instead of asking whether the normalised path is still inside the intended directory.

4.11.0 replaces the prefix test with a substring test:

```python
if ".." in str(path_1.relative_to(path_2)):
    return False
```

Since `abspath()` leaves the segments in place, a `..` anywhere in the relative path now fails the check and the route returns 403 before touching the filesystem. Diffing the libraries installed in the two lab images confirms that this single line is the security-relevant change: `gradio/utils.py` differs only here plus an unrelated cache-folder helper, and `gradio/routes.py` differs only in that helper's call site and queue-status handling.

The runtime behaviour matches this reading. On 4.10.0 the traversal returns 200 while a nonexistent target returns 404: the containment check passed and only the filesystem objected. On 4.11.0 both return 403: the containment check now rejects first.

## 13. Vulnerable Environment

The official Vulhub scenario is `gradio/CVE-2023-51449`, which runs the prebuilt image `vulhub/gradio:4.10.0`. On this Apple-silicon host that image cannot run natively: `docker inspect` reports `Architecture=amd64` and the manifest is single-platform.

Vulhub's repository contains only a README, a Compose file and two screenshots - no Dockerfile and no `app.py`. Both exist only inside the published image, so the recipe was recovered from the image history and `app.py` was extracted with `docker cp` (`docker create` plus `docker cp`, which does not execute the amd64 binary). The application file is byte-identical to upstream: a `gr.Interface` with one text input and one text output.

Both versions were rebuilt natively for arm64 from a single Dockerfile that reproduces the upstream build:

- base `python:3.9-slim` (Python 3.9.25 inside both images)
- `gradio==4.10.0` or `gradio==4.11.0`, with `fastapi==0.112.4` and `pydantic==2.8.2` as upstream pinned them
- `huggingface_hub==0.20.3` pinned for reproducibility only: an unpinned install today pulls hub 1.x, which removed `HfFolder`, so `gradio/oauth.py` fails at import and the container exits before serving. This restores the dependency set contemporary with the CVE and does not touch `/file` logic.
- `CMD python app.py`, `EXPOSE 7860`

The only build argument that differs between the two images is `GRADIO_VERSION`, so the library version is the only variable in the comparison. Both stacks publish on loopback only (`127.0.0.1:7860` and `127.0.0.1:7861`), mount nothing from the host and do not use `internal: true`, because that flag silently prevents Docker from publishing ports. Port publication was asserted with `docker ps` and `docker port`, not inferred from the Compose file.

The proof target is synthetic. A canary file is created inside the image outside the Gradio temp directory:

```
/srv/private/canary.txt -> CANARY-CVE-2023-51449-7f3a9c1d
```

No real file, credential or user data exists in the container, so a successful read proves the boundary escape without exposing anything.

## 14. Reproduction Procedure

1. Start the vulnerable stack (`docker compose -p cve51449-vuln -f compose.vulnerable.yml up -d --no-build`) and confirm `127.0.0.1:7860->7860/tcp`.
2. Record `uname -m` (`aarch64`), `gradio.__version__` (4.10.0) and `GET /config` (`"version":"4.10.0"`).
3. `POST /upload` a harmless 28-byte file; the response returns `/tmp/gradio/<hash>/cve-probe.txt`.
4. Baseline: `GET /file=<that path>` returns 200 with the exact uploaded bytes.
5. Traversal: `GET /file=/tmp/gradio/<hash>/../../../../../../srv/private/canary.txt`, sent with `curl --path-as-is`.
6. Repeat identically against 4.11.0 on port 7861.

Two client-side traps had to be removed before a result could be accepted, because each produces a convincing false negative:

- `requests`/`urllib3` rewrite dot segments in the request path, so the first attempt reached the server as `/srv/private/canary.txt` and returned 404. The traversal is therefore issued on a raw socket, and the shell evidence uses `curl --path-as-is`.
- A traversal cannot start at a regular file: `probe.txt/..` fails with ENOTDIR, so the path is reported as not found. The payload starts at the upload **directory**, matching Vulhub's `.../<hash>/../../..` shape.

The host also exports `HTTP_PROXY`, so every request bypasses it (`--noproxy '*'`, `trust_env = False`); otherwise loopback traffic is answered by the proxy with misleading status codes.

## 15. Evidence

All results below were produced on 2026-10-20 in the local lab, from the same payloads, with only the Gradio version and host port differing.

| Observation | 4.10.0 (vulnerable) | 4.11.0 (fixed) |
|---|---|---|
| `GET /` | 200 | 200 |
| `GET /config` reported version | 4.10.0 | 4.11.0 |
| Upload + legitimate `GET /file` | 200, 28 bytes, body matches | 200, 28 bytes, body matches |
| Traversal to `/srv/private/canary.txt` | **200, 97 bytes, marker disclosed** | **403 `File not allowed`, no content** |
| Traversal to `/etc/passwd` (secondary) | **200, 839 bytes, disclosed** | **403 `File not allowed`, no content** |
| Traversal to a nonexistent path (control) | 404 | 403 |
| `POST /run/predict` | `{"data":["Hello World!"]}` | `{"data":["Hello World!"]}` |

The canary is the primary proof because it contains no real data. `/etc/passwd` is recorded only as secondary confirmation that arbitrary paths, not one specific file, were readable. The control request rules out a blanket 200 response. The differing status for a nonexistent target is a fingerprint of the change: 4.10.0 passes the containment check and then fails on existence, 4.11.0 fails the containment check first.

Raw files are stored in `evidence/cve-2023-51449/`: `environment.txt`, `vulnerable-container.txt`, `fixed-container.txt`, `normal-before.txt`, `vulnerability-before.txt`, `normal-after.txt`, `vulnerability-after.txt`, `docker-logs-before.txt`, `docker-logs-after.txt`, `fix-diff.txt`, `regression-test.txt`, and the machine-readable `probe-vulnerable.json` / `probe-fixed.json`. A narrative summary is in `cve/CVE-2023-51449/RESULTS.md`.

`[SCREENSHOT PENDING]` screenshots of the terminal and the Actions page are listed in `docs/STATUS.md`; they must be captured by the student and have not been fabricated.

## 16. Remediation

The remediation is the vendor fix: upgrade Gradio from 4.10.0 to 4.11.0, the version the advisory names as patched. The application code, base image, dependency pins and Compose structure are unchanged, and the two stacks never run at the same time, so the version is the only difference. No configuration workaround such as tightening `allowed_paths` was used, because that would test a mitigation rather than the fix.

## 17. Verification

Against Gradio 4.11.0 on `127.0.0.1:7861`, the identical request returns:

```
HTTP/1.1 403 Forbidden
{"detail":"File not allowed: /tmp/gradio/<hash>/../../../../../../srv/private/canary.txt."}
```

The body is inspected, not only the status: the canary marker is absent and the `/etc/passwd` attempt is refused as well. The nonexistent-target case returns 403 instead of 404, showing the rejection now happens at the containment check before any filesystem access, which is the expected shape of this particular fix.

## 18. Regression Testing

The fixed application still works: `GET /` returns 200 with the Gradio page, `GET /config` reports 4.11.0, `POST /upload` and the legitimate `GET /file` still return 200 with matching bytes, and `POST /run/predict` still returns `{"data":["Hello World!"]}`. The legitimate read also succeeds after the blocked traversal, so the service is not left in a broken state.

The API suite is unaffected: 40 pytest tests pass on 2026-10-20, and the six curl HTTP checks from the earlier run still pass. In this environment pytest needs `--basetemp=.pytest-tmp` because the platform sandbox denies `mkdir` under the system temp directory; no test file was modified for that.

Both Compose projects were brought down afterwards and `docker ps -a` is empty. Images are kept for review; no global prune was used.

## 19. Conclusion

CVE-2023-51449 was reproduced on Gradio 4.10.0 in an authorized, loopback-only, ARM64-native lab, using a synthetic canary instead of real data. The root cause was confirmed in the shipped source: `abspath()` leaves dot segments unresolved and `is_in_or_equal()` tested only the start of the relative path, so a traversal path was classified as an uploaded file and served. Gradio 4.11.0's one-line change to a substring test rejects the same request with 403, and normal operation is unaffected.

Outstanding items are unchanged and unrelated to the case study: an NVD API key is needed for the mandated Dependency-Check report, genuine screenshots must be captured, and the CI workflow remains red solely because of that missing key.

## 20. References

- HDU Information Security Laboratory Manual, Work 1, pages 1-5.
- GHSA-6qm2-wpxq-7qh2: https://github.com/gradio-app/gradio/security/advisories/GHSA-6qm2-wpxq-7qh2
- gradio-app/gradio PR #6833: https://github.com/gradio-app/gradio/pull/6833
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2023-51449
- Vulhub: https://github.com/vulhub/vulhub/tree/master/gradio/CVE-2023-51449
- Dependency-Check CLI: https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html
