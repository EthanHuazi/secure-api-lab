import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
import pytest
from secure_api import create_app


@pytest.fixture(scope='module')
def app(tmp_path_factory):
    app = create_app({'TESTING': True, 'JWT_SECRET': secrets.token_urlsafe(48),
                      'DATABASE': str(tmp_path_factory.mktemp('db') / 'test.sqlite3')})
    result = app.test_cli_runner().invoke(args=['init-db', '--username', 'student', '--password', 'Lab-password-123!'])
    assert result.exit_code == 0, result.output
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def token(app, **changes):
    now = datetime.now(timezone.utc)
    payload = {'sub': '1', 'iat': now, 'nbf': now, 'exp': now + timedelta(minutes=5),
               'iss': 'secure-api-lab', 'aud': 'secure-api-lab-client'}
    payload.update(changes)
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')


def headers(value):
    return {'Authorization': 'Bearer ' + value}


@pytest.mark.parametrize('field', ['login', 'username'])
def test_login(client, field):
    r = client.post('/auth/login', json={field: 'student', 'password': 'Lab-password-123!'})
    assert r.status_code == 200
    assert r.json['token_type'] == 'Bearer'
    for endpoint in ['/api/data', '/api/profile']:
        assert client.get(endpoint, headers=headers(r.json['access_token'])).status_code == 200


@pytest.mark.parametrize('login,password', [('missing', 'wrong'), ('student', 'wrong'), ("' OR 1=1 --", 'x'), ('student\' --', 'x'), ('student" OR "1"="1', 'x')])
def test_failed_login(client, login, password):
    r = client.post('/auth/login', json={'login': login, 'password': password})
    assert r.status_code == 401
    assert r.json == {'error': 'Invalid or missing credentials'}


@pytest.mark.parametrize('body', [{}, {'login': 'student'}, [], None, {'login': 12, 'password': 'x'}, {'login': 'student', 'password': 'a'*73}, {'login': 'student', 'password': '中'*25}, {'login': 'a', 'username': 'b', 'password': 'x'}])
def test_invalid_input(client, body):
    import json
    assert client.post('/auth/login', data=json.dumps(body), content_type='application/json').status_code == 400


def test_content_type_and_size(client):
    assert client.post('/auth/login', data='login=student').status_code == 415
    assert client.post('/auth/login', data='{', content_type='application/json').status_code == 400
    assert client.post('/auth/login', data='x'*20000, content_type='application/json').status_code == 413


@pytest.mark.parametrize('endpoint', ['/api/data', '/api/profile'])
@pytest.mark.parametrize('kind', ['none', 'invalid', 'expired', 'signature', 'algorithm', 'missing-exp', 'audience', 'future', 'deleted-user', 'bad-sub'])
def test_reject_tokens(app, client, endpoint, kind):
    now = datetime.now(timezone.utc)
    values = {
        'none': '', 'invalid': 'broken', 'expired': token(app, exp=now-timedelta(seconds=1)),
        'signature': jwt.encode(jwt.decode(token(app), app.config['JWT_SECRET'], algorithms=['HS256'], audience='secure-api-lab-client'), secrets.token_urlsafe(48), algorithm='HS256'),
        'algorithm': jwt.encode({'sub': '1'}, '', algorithm='none'),
        'missing-exp': jwt.encode({'sub': '1'}, app.config['JWT_SECRET'], algorithm='HS256'),
        'audience': token(app, aud='other'), 'future': token(app, nbf=now+timedelta(hours=1)),
        'deleted-user': token(app, sub='999'), 'bad-sub': token(app, sub='9'*500),
    }
    r = client.get(endpoint, headers=headers(values[kind]))
    assert r.status_code == 401
    assert r.headers['WWW-Authenticate'] == 'Bearer'


def test_profile_allowlist_and_headers(app, client):
    r = client.get('/api/profile', headers=headers(token(app)))
    assert set(r.json['user']) == {'id', 'username'}
    assert r.mimetype == 'application/json'
    assert r.headers['X-Content-Type-Options'] == 'nosniff'
    assert r.headers['Cache-Control'] == 'no-store'
    assert "default-src 'none'" in r.headers['Content-Security-Policy']


def test_stored_xss_and_parameterized_insert(app, client):
    payload = '<img src=x onerror=alert(1)>\'"&'
    result = app.test_cli_runner().invoke(args=['init-db', '--username', payload, '--password', 'Lab-password-123!'])
    assert result.exit_code == 0
    r = client.post('/auth/login', json={'login': payload, 'password': 'Lab-password-123!'})
    assert r.status_code == 200
    profile = client.get('/api/profile', headers=headers(r.json['access_token']))
    assert '<img' not in profile.json['user']['username']
    assert '&lt;img' in profile.json['user']['username']
    assert '&#39;' in profile.json['user']['username']
    assert profile.mimetype == 'application/json'


def test_hash_and_idempotence(app):
    with sqlite3.connect(app.config['DATABASE']) as db:
        before = db.execute('SELECT password_hash FROM users WHERE username = ?', ('student',)).fetchone()[0]
    assert before != b'Lab-password-123!'
    assert bcrypt.checkpw(b'Lab-password-123!', before)
    result = app.test_cli_runner().invoke(args=['init-db', '--username', 'student', '--password', 'Different-password!'])
    assert result.exit_code == 0
    with sqlite3.connect(app.config['DATABASE']) as db:
        after = db.execute('SELECT password_hash FROM users WHERE username = ?', ('student',)).fetchone()[0]
    assert before == after


def test_missing_secret_fails_closed(monkeypatch):
    monkeypatch.delenv('JWT_SECRET', raising=False)
    with pytest.raises(RuntimeError):
        create_app()
