"""Owner-only (0700/0600) local SQLite persistence for MCP App intents & dry-run receipts."""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys
from contextlib import closing
from pathlib import Path
from typing import Any

from .errors import AppError
from .validation import canonical_json

APPLICATION_ID = 0x43424D41  # CBMA: Coinbase MCP App receipts.
CREATE_INTENTS = (
    "CREATE TABLE mcp_intents ("
    "intent_id TEXT PRIMARY KEY, "
    "client_order_id TEXT NOT NULL UNIQUE, "
    "account_alias TEXT NOT NULL, "
    "kind TEXT NOT NULL, "
    "state TEXT NOT NULL, "
    "intent_sha256 TEXT NOT NULL, "
    "active_nonce TEXT, "
    "consumed_nonce TEXT, "
    "created_at TEXT NOT NULL, "
    "updated_at TEXT NOT NULL, "
    "expires_at TEXT NOT NULL, "
    "payload TEXT NOT NULL, "
    "receipt TEXT)"
)
EXPECTED_SCHEMA = [
    ("index", "sqlite_autoindex_mcp_intents_1", "mcp_intents", None),
    ("index", "sqlite_autoindex_mcp_intents_2", "mcp_intents", None),
    ("table", "mcp_intents", "mcp_intents", CREATE_INTENTS),
]
FINAL_STATES = frozenset({"DRY_RUN_APPROVED", "DRY_RUN_CANCEL_APPROVED", "REJECTED"})


def default_data_dir() -> Path:
    env_dir = os.environ.get("COINBASE_MCP_DATA_DIR")
    if env_dir and env_dir.strip():
        return Path(env_dir).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "coinbase-mcp-app"
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "coinbase-mcp-app"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "coinbase-mcp-app"


def _unavailable(message: str = "Private receipt storage is unavailable.") -> AppError:
    return AppError("STORAGE_UNAVAILABLE", message, "Check the configured --data-dir and permissions (0700 dir, 0600 file).", 4)


class ReceiptStore:
    def __init__(self, data_dir: Path) -> None:
        self.directory = Path(data_dir).expanduser()
        self.path = self.directory / "receipts.sqlite3"

    @staticmethod
    def _check_perms(path: Path, *, directory: bool) -> None:
        info = path.lstat()
        ok_type = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not ok_type:
            raise _unavailable("Receipt storage must use a real directory and regular file, not symlinks.")
        if os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise _unavailable("Receipt storage must be owner-only (directory 0700, database 0600).")

    def _connect(self, *, write: bool) -> sqlite3.Connection | None:
        if not self.directory.exists():
            if not write:
                return None
            self.directory.parent.mkdir(parents=True, exist_ok=True)
            os.mkdir(self.directory, 0o700)
        self._check_perms(self.directory, directory=True)

        if not self.path.exists():
            if not write:
                return None
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.close(fd)
        self._check_perms(self.path, directory=False)

        conn = sqlite3.connect(self.path, isolation_level=None, timeout=5.0)
        try:
            identity = conn.execute("PRAGMA application_id").fetchone()[0]
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            schema = conn.execute("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name").fetchall()
            empty = identity == 0 and version == 0 and not schema
            if empty:
                if not write:
                    conn.close()
                    return None
                conn.execute("PRAGMA journal_mode=DELETE")
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(CREATE_INTENTS)
                conn.execute(f"PRAGMA application_id={APPLICATION_ID}")
                conn.execute("PRAGMA user_version=1")
                conn.execute("COMMIT")
            elif identity != APPLICATION_ID or version != 1 or schema != EXPECTED_SCHEMA:
                raise _unavailable("Existing database is not a valid coinbase-mcp-app receipt store.")
            return conn
        except Exception:
            conn.close()
            raise

    @staticmethod
    def _row(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "intent_id": row[0],
            "client_order_id": row[1],
            "account_alias": row[2],
            "kind": row[3],
            "state": row[4],
            "intent_sha256": row[5],
            "active_nonce": row[6],
            "consumed_nonce": row[7],
            "created_at": row[8],
            "updated_at": row[9],
            "expires_at": row[10],
            "payload": json.loads(row[11]),
            "receipt": json.loads(row[12]) if row[12] else None,
        }

    def save_preview(self, *, intent_id: str, client_order_id: str, account_alias: str, kind: str,
                     intent_sha256: str, active_nonce: str, created_at: str, expires_at: str, payload: dict[str, Any]) -> None:
        conn = self._connect(write=True)
        assert conn is not None
        with closing(conn):
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO mcp_intents VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (intent_id, client_order_id, account_alias, kind, "PREVIEWED", intent_sha256,
                     active_nonce, None, created_at, created_at, expires_at, canonical_json(payload), None),
                )
                conn.execute("COMMIT")
            except sqlite3.IntegrityError:
                conn.execute("ROLLBACK")
                raise AppError("INTENT_CONFLICT", "Duplicate intent_id or client_order_id.", "Request a fresh preview.") from None
            except sqlite3.Error:
                conn.execute("ROLLBACK")
                raise _unavailable() from None

    def refresh_preview(self, *, intent_id: str, expected_nonce: str, new_nonce: str, new_intent_sha256: str,
                        updated_at: str, expires_at: str, payload: dict[str, Any]) -> dict[str, Any]:
        conn = self._connect(write=True)
        assert conn is not None
        with closing(conn):
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT * FROM mcp_intents WHERE intent_id=?", (intent_id,)).fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    raise AppError("INTENT_NOT_FOUND", "Unknown preview intent.", "Request a fresh preview.", 3)
                rec = self._row(row)
                if rec["state"] in FINAL_STATES:
                    conn.execute("ROLLBACK")
                    raise AppError("INTENT_ALREADY_FINALIZED", f"Intent already finalized ({rec['state']}).", "Request a new preview.", 4)
                if rec["active_nonce"] != expected_nonce:
                    conn.execute("ROLLBACK")
                    raise AppError("CONFIRMATION_TOKEN_STALE", "Confirmation token was superseded by a newer refresh.", "Use the latest quote card.", 4)
                conn.execute(
                    "UPDATE mcp_intents SET intent_sha256=?, active_nonce=?, updated_at=?, expires_at=?, payload=? WHERE intent_id=?",
                    (new_intent_sha256, new_nonce, updated_at, expires_at, canonical_json(payload), intent_id),
                )
                conn.execute("COMMIT")
                rec.update(intent_sha256=new_intent_sha256, active_nonce=new_nonce, updated_at=updated_at, expires_at=expires_at, payload=payload)
                return rec
            except AppError:
                raise
            except sqlite3.Error:
                conn.execute("ROLLBACK")
                raise _unavailable() from None

    def finalize_once(self, *, intent_id: str, expected_nonce: str, expected_sha256: str,
                      new_state: str, updated_at: str, receipt: dict[str, Any], check_status: bool = False) -> tuple[dict[str, Any], bool]:
        conn = self._connect(write=True)
        assert conn is not None
        with closing(conn):
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT * FROM mcp_intents WHERE intent_id=?", (intent_id,)).fetchone()
                if row is None:
                    conn.execute("ROLLBACK")
                    raise AppError("INTENT_NOT_FOUND", "Unknown preview intent.", "Request a fresh preview.", 3)
                rec = self._row(row)
                if rec["state"] in FINAL_STATES:
                    conn.execute("ROLLBACK")
                    if check_status and rec["consumed_nonce"] == expected_nonce:
                        return rec, True
                    raise AppError("CONFIRMATION_TOKEN_REPLAYED", f"Token already used (state={rec['state']}).", "Use check_status=true or request a new preview.", 4)
                if check_status:
                    conn.execute("ROLLBACK")
                    return rec, False
                if rec["active_nonce"] != expected_nonce or rec["intent_sha256"] != expected_sha256:
                    conn.execute("ROLLBACK")
                    raise AppError("CONFIRMATION_TOKEN_MISMATCH", "Confirmation token does not match the active intent.", "Refresh or request a new preview.", 4)
                conn.execute(
                    "UPDATE mcp_intents SET state=?, active_nonce=NULL, consumed_nonce=?, updated_at=?, receipt=? WHERE intent_id=?",
                    (new_state, expected_nonce, updated_at, canonical_json(receipt), intent_id),
                )
                conn.execute("COMMIT")
                rec.update(state=new_state, active_nonce=None, consumed_nonce=expected_nonce, updated_at=updated_at, receipt=receipt)
                return rec, False
            except AppError:
                raise
            except sqlite3.Error:
                conn.execute("ROLLBACK")
                raise _unavailable() from None

    def get_by_intent_id(self, intent_id: str) -> dict[str, Any] | None:
        conn = self._connect(write=False)
        if conn is None:
            return None
        with closing(conn):
            row = conn.execute("SELECT * FROM mcp_intents WHERE intent_id=?", (intent_id,)).fetchone()
            return self._row(row) if row else None

    def get_by_client_order_id(self, client_order_id: str) -> dict[str, Any] | None:
        conn = self._connect(write=False)
        if conn is None:
            return None
        with closing(conn):
            row = conn.execute("SELECT * FROM mcp_intents WHERE client_order_id=?", (client_order_id,)).fetchone()
            return self._row(row) if row else None

    def list_recent(self, account_alias: str | None = None, *, limit: int = 8) -> list[dict[str, Any]]:
        conn = self._connect(write=False)
        if conn is None:
            return []
        with closing(conn):
            if account_alias:
                rows = conn.execute("SELECT * FROM mcp_intents WHERE account_alias=? ORDER BY updated_at DESC, intent_id DESC LIMIT ?", (account_alias, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM mcp_intents ORDER BY updated_at DESC, intent_id DESC LIMIT ?", (limit,)).fetchall()
            return [self._row(r) for r in rows]
