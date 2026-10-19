"""Run real curl requests against an ephemeral loopback HTTP server."""
import json
import os
import secrets
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from secure_api import create_app
from werkzeug.serving import make_server


def main():
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    password = secrets.token_urlsafe(24)
    app = create_app({'JWT_SECRET': secrets.token_urlsafe(48),
                      'DATABASE': str(Path('instance') / f'curl-{run_id}.sqlite3')})
    result = app.test_cli_runner().invoke(args=['init-db', '--username', 'curl-student', '--password', password])
    if result.exit_code:
        raise RuntimeError(result.output)
    server = make_server('127.0.0.1', 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    records = []

    def call(label, path, expected, body=None, token=None):
        config = f'url = "http://127.0.0.1:{server.server_port}{path}"\n'
        if token:
            config += f'header = "Authorization: Bearer {token}"\n'
        args = ['curl', '--silent', '--show-error', '--max-time', '10', '--config', '-', '--write-out', '\n%{http_code}']
        if body is not None:
            config += 'header = "Content-Type: application/json"\n'
            config += 'data = ' + json.dumps(json.dumps(body)) + '\n'
        process = subprocess.run(args, input=config, text=True, capture_output=True, check=True)
        raw, status = process.stdout.rsplit('\n', 1)
        data = json.loads(raw)
        safe = dict(data)
        if 'access_token' in safe:
            safe['access_token'] = '[REDACTED: actual signed token received]'
        records.append({'case': label, 'method': 'POST' if body is not None else 'GET',
                        'path': path, 'status': int(status), 'response': safe})
        assert int(status) == expected, records[-1]
        return data

    try:
        signed = call('Successful login', '/auth/login', 200, {'login': 'curl-student', 'password': password})['access_token']
        call('Failed login', '/auth/login', 401, {'login': 'curl-student', 'password': 'wrong'})
        call('No JWT', '/api/data', 401)
        call('Valid JWT data', '/api/data', 200, token=signed)
        call('Valid JWT profile', '/api/profile', 200, token=signed)
        call('SQL injection rejected', '/auth/login', 401, {'login': "' OR 1=1 --", 'password': 'wrong'})
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        output = Path(os.environ.get('EVIDENCE_DIR', 'evidence'))
        output.mkdir(parents=True, exist_ok=True)
        (output / 'curl.json').write_text(json.dumps({'run_at_utc': run_id, 'cases': records}, indent=2)+'\n')
    print(f'{len(records)} real curl checks passed; tokens and passwords excluded from evidence.')


if __name__ == '__main__':
    main()
