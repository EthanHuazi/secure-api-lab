#!/bin/sh
set -eu
exec .venv/bin/python -m flask --app secure_api init-db "$@"
