"""Create ignored local credentials and an idempotent demonstration account."""
import os
import secrets
import sys
from pathlib import Path

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from secure_api import create_app


def main():
    os.chdir(ROOT)
    path = ROOT / '.env'
    values = dotenv_values(path) if path.exists() else {}
    additions = {}
    if not values.get('JWT_SECRET'):
        additions['JWT_SECRET'] = secrets.token_urlsafe(48)
    if not values.get('LAB_USERNAME'):
        additions['LAB_USERNAME'] = 'lab-student'
    if not values.get('LAB_PASSWORD'):
        additions['LAB_PASSWORD'] = secrets.token_urlsafe(24)
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        for name, value in additions.items():
            stream.write(f'{name}={value}\n')
    os.chmod(path, 0o600)
    values.update(additions)
    app = create_app({'JWT_SECRET': values['JWT_SECRET']})
    result = app.test_cli_runner().invoke(args=['init-db', '--username', values['LAB_USERNAME'], '--password', values['LAB_PASSWORD']])
    if result.exit_code:
        raise RuntimeError(result.output)
    print(result.output.strip())
    print('Credentials are in the ignored .env file; keep this file private.')


if __name__ == '__main__':
    main()
