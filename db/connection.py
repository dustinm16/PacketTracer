"""Database connection management with WAL mode for concurrent access."""

import sqlite3
import threading
from typing import Optional
from contextlib import contextmanager
from pathlib import Path

from .schema import init_schema


class ConnectionPool:
    """Thread-safe SQLite connection pool with WAL mode.

    WAL (Write-Ahead Logging) mode allows:
    - Multiple concurrent readers
    - One writer that doesn't block readers
    - Readers see consistent snapshots
    """

    def __init__(
        self,
        db_path: str = "packettracer.db",
        read_pool_size: int = 4,
        wal_mode: bool = True
    ):
        self.db_path = Path(db_path).expanduser()
        self.read_pool_size = read_pool_size
        self.wal_mode = wal_mode

        # Single write connection (SQLite allows only one writer)
        self._write_conn: Optional[sqlite3.Connection] = None
        self._write_lock = threading.Lock()

        # Read connection pool (WAL allows concurrent reads)
        self._read_connections: list[sqlite3.Connection] = []
        self._read_lock = threading.Lock()
        self._read_semaphore = threading.Semaphore(read_pool_size)

        self._initialized = False

    def initialize(self) -> None:
        """Initialize the connection pool and schema."""
        if self._initialized:
            return

        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Create write connection and configure WAL
        self._write_conn = self._create_connection()
        if self.wal_mode:
            self._write_conn.execute("PRAGMA journal_mode=WAL")
            self._write_conn.execute("PRAGMA synchronous=NORMAL")
            self._write_conn.execute("PRAGMA wal_autocheckpoint=1000")
            self._write_conn.execute("PRAGMA busy_timeout=5000")
            # Enable foreign keys
            self._write_conn.execute("PRAGMA foreign_keys=ON")

        # Initialize schema using write connection
        init_schema(self._write_conn)

        # Initialize read connections
        for _ in range(self.read_pool_size):
            conn = self._create_connection()
            if self.wal_mode:
                conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._read_connections.append(conn)

        self._initialized = True

    def _create_connection(self) -> sqlite3.Connection:
        """Create a new database connection."""
        conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,  # We manage thread safety ourselves
            isolation_level=None,  # Autocommit mode for reads
        )
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def write_connection(self):
        """Get the write connection with exclusive lock.

        Usage:
            with pool.write_connection() as conn:
                conn.execute("INSERT ...")
        """
        with self._write_lock:
            if self._write_conn is None:
                raise RuntimeError("Connection pool not initialized")
            yield self._write_conn

    @contextmanager
    def read_connection(self):
        """Get a read connection from the pool.

        Usage:
            with pool.read_connection() as conn:
                cursor = conn.execute("SELECT ...")
        """
        self._read_semaphore.acquire()
        try:
            with self._read_lock:
                if not self._read_connections:
                    raise RuntimeError("No read connections available")
                conn = self._read_connections.pop()
            try:
                yield conn
            finally:
                with self._read_lock:
                    self._read_connections.append(conn)
        finally:
            self._read_semaphore.release()

    def execute_read(self, query: str, params: tuple = ()) -> list[sqlite3.Row]:
        """Execute a read query and return all results."""
        with self.read_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.fetchall()

    def execute_read_one(self, query: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        """Execute a read query and return first result."""
        with self.read_connection() as conn:
            cursor = conn.execute(query, params)
            return cursor.fetchone()

    def close(self) -> None:
        """Close all connections."""
        if self._write_conn:
            # Checkpoint WAL before closing
            if self.wal_mode:
                try:
                    self._write_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass
            self._write_conn.close()
            self._write_conn = None

        with self._read_lock:
            for conn in self._read_connections:
                conn.close()
            self._read_connections.clear()

        self._initialized = False

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False
