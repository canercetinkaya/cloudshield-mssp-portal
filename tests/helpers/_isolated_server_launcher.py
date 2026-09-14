#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CloudShield MSSP Platform - Stage 1A Test-Only Isolated Server Launcher
========================================================================

This is a TEST-ONLY helper. It is NOT production code and is never imported by
the application. It launches the UNMODIFIED `Portal/api/server.py` against an
isolated temporary SQLite database so that automated tests never touch the
development/production database.

Mechanism (no production file is modified):
  * `database.db` resolves its SQLite path from the module-level `DB_PATH` at
    call time (`get_db()` -> `path = db_path or DB_PATH`, and `init_db()` ->
    `get_db(db_path)`).
  * This launcher rebinds `database.db.DB_PATH` to the temp path supplied via
    the `CS_TEST_DB_PATH` environment variable BEFORE importing the server.
  * Consequently every `get_db()` / `init_db()` call made by the unmodified
    server (and by `rbac_engine`) resolves to the temp database.

Pilot local authentication is NEVER enabled here: the launcher does not set
`CLOUDSHIELD_ALLOW_LOCAL_AUTH`. Server startup behavior is unchanged - this
script simply calls the server's own `run(port)` entry point.

Usage (internal, from tests only):
    CS_TEST_DB_PATH=<tmp.sqlite> python tests/helpers/_isolated_server_launcher.py <port>
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.abspath(os.path.join(_HERE, "..", ".."))
if _ROOT_DIR not in sys.path:
    sys.path.insert(0, _ROOT_DIR)

# 1. Rebind the database path to the isolated temp DB BEFORE importing the server.
import database.db as _dbmod  # noqa: E402

_tmp_db_path = os.environ.get("CS_TEST_DB_PATH", "").strip()
if not _tmp_db_path:
    sys.stderr.write("[launcher] CS_TEST_DB_PATH is required.\n")
    sys.exit(2)
_dbmod.DB_PATH = _tmp_db_path

# 2. Start the UNMODIFIED server. `server.run()` itself calls `init_db()`,
#    which now targets the isolated temp database via the rebinding above.
from Portal.api import server as _server  # noqa: E402

_port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("CS_TEST_PORT", "8080"))
_server.run(_port)
