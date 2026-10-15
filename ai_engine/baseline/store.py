import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

DEFAULT_BASELINE_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "baseline.db"


class BaselineStore:
    def __init__(self, db_path: Optional[str] = None, min_age_seconds: int = 86400):
        if db_path is None:
            self.db_path = os.environ.get("AI_ENGINE_BASELINE_DB", str(DEFAULT_BASELINE_DB_PATH))
        else:
            self.db_path = db_path

        self.min_age_seconds = min_age_seconds
        self._lock = threading.Lock()

        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS known_pairs (
                        username TEXT,
                        source_ip TEXT,
                        first_seen TEXT,
                        last_seen TEXT,
                        success_count INTEGER,
                        PRIMARY KEY (username, source_ip)
                    )
                    """
                )

    def record_success(
        self, username: Optional[str], source_ip: str, ts: Union[datetime, str]
    ) -> None:
        if not username:
            return
        clean_user = username.strip().lower()
        clean_ip = source_ip.strip()

        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                ts_str = dt.astimezone(timezone.utc).isoformat()
            except Exception:
                ts_str = ts
        elif isinstance(ts, datetime):
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            ts_str = ts.astimezone(timezone.utc).isoformat()
        else:
            ts_str = str(ts)

        with self._lock:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO known_pairs (username, source_ip, first_seen, last_seen, success_count)
                    VALUES (?, ?, ?, ?, 1)
                    ON CONFLICT(username, source_ip) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        success_count = known_pairs.success_count + 1
                    """,
                    (clean_user, clean_ip, ts_str, ts_str),
                )

    def is_known_pair(
        self, username: Optional[str], source_ip: str, now: Optional[datetime] = None
    ) -> bool:
        if not username:
            return False
        clean_user = username.strip().lower()
        clean_ip = source_ip.strip()

        with self._lock:
            cursor = self._conn.execute(
                "SELECT first_seen FROM known_pairs WHERE username = ? AND source_ip = ?",
                (clean_user, clean_ip),
            )
            row = cursor.fetchone()

        if row is None:
            return False

        first_seen_str = row[0]
        try:
            first_seen_dt = datetime.fromisoformat(first_seen_str.replace("Z", "+00:00"))
            if first_seen_dt.tzinfo is None:
                first_seen_dt = first_seen_dt.replace(tzinfo=timezone.utc)
            else:
                first_seen_dt = first_seen_dt.astimezone(timezone.utc)
        except Exception:
            return False

        if now is None:
            now = datetime.now(timezone.utc)
        elif now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        else:
            now = now.astimezone(timezone.utc)

        age_seconds = (now - first_seen_dt).total_seconds()
        return age_seconds >= self.min_age_seconds

    def close(self) -> None:
        with self._lock:
            self._conn.close()
