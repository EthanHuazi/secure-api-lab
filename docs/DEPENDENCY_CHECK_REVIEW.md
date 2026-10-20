# Dependency-Check finding review

Reviewed: 2026-10-20. Local configuration change; remote validation pending.

## Observed failure

[Run #12](https://github.com/EthanHuazi/secure-api-lab/actions/runs/39363679093)
completed analysis and generated HTML/JSON reports. It failed with exit code 15
because PyJWT 2.15.1 was associated with CVE-2025-45770 (CVSS 7.0).
The tests-and-sast job passed. This run was not blocked by a missing NVD key.

## Product identity review

The log identifies `pkg:pypi/pyjwt@2.15.1`, but also assigns the generic
`jwt_project:jwt` CPE. The [original CVE report](https://gist.github.com/ZupeiNie/cd88c827eef11a1618f8baacccd240fb)
references `lcobucci/jwt`, a PHP library, and versions through 5.4.3.
That is a different project from Python's `jpadilla/pyjwt`.
The [NVD record](https://nvd.nist.gov/vuln/detail/CVE-2025-45770) is disputed;
disputed status by itself does not justify suppressing a vulnerability.
The linked upstream advisory is currently unavailable (404); the product
identity is recorded in the original reporter's reference.

## Scoped correction

`dependency-check-suppressions.xml` excludes only CVE-2025-45770 for the exact
PURL `pkg:pypi/pyjwt@2.15.1`, expiring on 2027-01-20 UTC. Other CVEs, packages
and versions remain subject to the unchanged CVSS >= 7 failure threshold.
pip-audit remains enabled as an independent Python ecosystem check.

The workflow streams output through tee and saves dc.log alongside HTML/JSON
reports. It preserves the scanner exit code and fails if log writing fails.
Report/log upload still runs after a failed scan. The prior NVD key-shape
heuristic was removed: the scanner validates the actual key, while the workflow
checks only that it is present without displaying its value.

## Remaining verification

After an authorized push, inspect the new Actions run and downloaded report.
Confirm the exact finding is suppressed, the dependency inventory is nonempty,
other findings are reviewed and both jobs pass. No successful remote run is
claimed by this local change. Initial NVD downloads may still take time.
