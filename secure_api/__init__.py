"""Secure REST API teaching application."""
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import bcrypt
import click
import jwt
from flask import Flask, g, jsonify, request
from markupsafe import escape
from werkzeug.exceptions import HTTPException

# Public HTTP authentication scheme, not a secret credential.
AUTH_SCHEME = "Bearer"


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(g.app_database)
        g.db.row_factory = sqlite3.Row
    return g.db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        JWT_SECRET=os.environ.get('JWT_SECRET', ''),
        DATABASE=os.environ.get('DATABASE_PATH', str(Path(app.instance_path) / 'lab.sqlite3')),
        JWT_TTL_SECONDS=900,
        MAX_CONTENT_LENGTH=16384,
    )
    if test_config:
        app.config.update(test_config)
    if len(app.config['JWT_SECRET'].encode()) < 32:
        raise RuntimeError('JWT_SECRET must contain at least 32 bytes; generate a random secret.')
    Path(app.config['DATABASE']).parent.mkdir(parents=True, exist_ok=True)
    # Equal-cost password verification for unknown accounts reduces timing disclosure.
    dummy_hash = bcrypt.hashpw(secrets.token_bytes(32), bcrypt.gensalt(rounds=12))

    @app.before_request
    def configure_database():
        g.app_database = app.config['DATABASE']

    @app.teardown_appcontext
    def close_database(error=None):
        db = g.pop('db', None)
        if db is not None:
            db.close()

    @app.after_request
    def security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Frame-Options'] = 'DENY'
        return response

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.name), error.code

    def unauthorized():
        return jsonify(error='Invalid or missing credentials'), 401, {'WWW-Authenticate': 'Bearer'}

    def authenticated(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            parts = request.headers.get('Authorization', '').split()
            if len(parts) != 2 or parts[0].lower() != 'bearer':
                return unauthorized()
            try:
                claims = jwt.decode(
                    parts[1], app.config['JWT_SECRET'], algorithms=['HS256'],
                    issuer='secure-api-lab', audience='secure-api-lab-client',
                    options={'require': ['sub', 'iat', 'nbf', 'exp', 'iss', 'aud']},
                )
                subject = claims['sub']
                if not isinstance(subject, str) or not subject.isascii() or not subject.isdecimal() or len(subject) > 18:
                    return unauthorized()
                user = get_db().execute('SELECT id, username FROM users WHERE id = ?', (int(subject),)).fetchone()
                if user is None:
                    return unauthorized()
                g.user = user
            except jwt.InvalidTokenError:
                return unauthorized()
            return view(*args, **kwargs)
        return wrapper

    @app.post('/auth/login')
    def login():
        if not request.is_json:
            return jsonify(error='Expected application/json'), 415
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify(error='Expected a JSON object'), 400
        # The manual calls this field login; username is an explicit alias.
        username = data.get('login', data.get('username'))
        password = data.get('password')
        if ('login' in data and 'username' in data and data['login'] != data['username']):
            return jsonify(error='Conflicting login and username'), 400
        if not isinstance(username, str) or not 1 <= len(username) <= 128:
            return jsonify(error='Invalid login'), 400
        if not isinstance(password, str) or not 1 <= len(password.encode()) <= 72:
            return jsonify(error='Password must contain 1 to 72 UTF-8 bytes'), 400
        user = get_db().execute('SELECT id, password_hash FROM users WHERE username = ?', (username,)).fetchone()
        password_hash = user['password_hash'] if user else dummy_hash
        valid = bcrypt.checkpw(password.encode(), password_hash)
        if not user or not valid:
            return unauthorized()
        now = datetime.now(timezone.utc)
        token = jwt.encode({'sub': str(user['id']), 'iat': now, 'nbf': now,
                            'exp': now + timedelta(seconds=app.config['JWT_TTL_SECONDS']),
                            'iss': 'secure-api-lab', 'aud': 'secure-api-lab-client'},
                           app.config['JWT_SECRET'], algorithm='HS256')
        return jsonify({'access_token': token, 'token_type': AUTH_SCHEME,
                        'expires_in': app.config['JWT_TTL_SECONDS']})

    @app.get('/api/data')
    @authenticated
    def data():
        return jsonify(data=[{'id': 1, 'title': 'Information Security Lab'}])

    @app.get('/api/profile')
    @authenticated
    def profile():
        # Explicit HTML entity encoding meets the manual's API-output requirement.
        # Consumers must still use textContent, never innerHTML or entity decoding.
        return jsonify(user={'id': g.user['id'], 'username': str(escape(g.user['username']))})

    @app.cli.command('init-db')
    @click.option('--username', prompt=True)
    @click.password_option(confirmation_prompt=True)
    def init_db(username, password):
        """Create a lab user without resetting existing users."""
        if not 1 <= len(username) <= 128 or not 12 <= len(password.encode()) <= 72:
            raise click.ClickException('Username: 1-128 characters; password: 12-72 UTF-8 bytes.')
        g.app_database = app.config['DATABASE']
        db = get_db()
        db.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash BLOB NOT NULL)')
        if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            click.echo('User already exists; unchanged.')
            return
        db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                   (username, bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))))
        db.commit()
        os.chmod(app.config['DATABASE'], 0o600)
        click.echo('Lab user created.')

    return app
