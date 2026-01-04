"""Tests for db/connection.py module."""

import os
import sqlite3
import tempfile
import threading
import pytest
from pathlib import Path

from db.connection import ConnectionPool


class TestConnectionPool:
    """Tests for ConnectionPool class."""

    def test_creation(self, temp_db_path):
        """Test connection pool creation."""
        pool = ConnectionPool(db_path=temp_db_path, read_pool_size=2)
        assert pool.db_path == Path(temp_db_path).expanduser()
        assert pool.read_pool_size == 2
        assert pool.is_initialized is False
        pool.close()

    def test_initialize(self, temp_db_path):
        """Test pool initialization."""
        pool = ConnectionPool(db_path=temp_db_path)
        pool.initialize()

        assert pool.is_initialized is True
        assert pool._write_conn is not None

        pool.close()

    def test_initialize_creates_directory(self):
        """Test that initialize creates parent directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nested_path = os.path.join(tmpdir, "nested", "dir", "test.db")
            pool = ConnectionPool(db_path=nested_path)
            pool.initialize()

            assert os.path.exists(os.path.dirname(nested_path))

            pool.close()

    def test_wal_mode_enabled(self, temp_db_path):
        """Test that WAL mode is enabled."""
        pool = ConnectionPool(db_path=temp_db_path, wal_mode=True)
        pool.initialize()

        with pool.write_connection() as conn:
            cursor = conn.execute("PRAGMA journal_mode")
            mode = cursor.fetchone()[0]
            assert mode.lower() == "wal"

        pool.close()

    def test_write_connection_context_manager(self, connection_pool):
        """Test write connection context manager."""
        with connection_pool.write_connection() as conn:
            assert conn is not None
            conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY)")
            conn.execute("INSERT INTO test VALUES (1)")

        # Verify data was written
        with connection_pool.read_connection() as conn:
            cursor = conn.execute("SELECT * FROM test")
            rows = cursor.fetchall()
            assert len(rows) == 1

    def test_write_connection_not_initialized(self, temp_db_path):
        """Test write connection raises when not initialized."""
        pool = ConnectionPool(db_path=temp_db_path)

        with pytest.raises(RuntimeError, match="not initialized"):
            with pool.write_connection() as conn:
                pass

    def test_read_connection_context_manager(self, connection_pool):
        """Test read connection context manager."""
        # First write some data
        with connection_pool.write_connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY)")
            conn.execute("INSERT INTO test VALUES (1)")

        # Then read it
        with connection_pool.read_connection() as conn:
            cursor = conn.execute("SELECT * FROM test")
            rows = cursor.fetchall()
            assert len(rows) == 1

    def test_read_connection_pool_size(self, temp_db_path):
        """Test read connection pool returns connections."""
        pool = ConnectionPool(db_path=temp_db_path, read_pool_size=3)
        pool.initialize()

        # Should be able to get 3 connections
        connections = []
        for _ in range(3):
            pool._read_semaphore.acquire()
            with pool._read_lock:
                conn = pool._read_connections.pop()
                connections.append(conn)

        assert len(connections) == 3

        # Return them
        for conn in connections:
            with pool._read_lock:
                pool._read_connections.append(conn)
            pool._read_semaphore.release()

        pool.close()

    def test_execute_read(self, connection_pool):
        """Test execute_read helper method."""
        with connection_pool.write_connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER, name TEXT)")
            conn.execute("INSERT INTO test VALUES (1, 'test')")

        rows = connection_pool.execute_read("SELECT * FROM test WHERE id = ?", (1,))

        assert len(rows) == 1
        assert rows[0]["id"] == 1
        assert rows[0]["name"] == "test"

    def test_execute_read_one(self, connection_pool):
        """Test execute_read_one helper method."""
        with connection_pool.write_connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER, name TEXT)")
            conn.execute("INSERT INTO test VALUES (1, 'test')")

        row = connection_pool.execute_read_one("SELECT * FROM test WHERE id = ?", (1,))

        assert row is not None
        assert row["id"] == 1
        assert row["name"] == "test"

    def test_execute_read_one_missing(self, connection_pool):
        """Test execute_read_one returns None for missing row."""
        with connection_pool.write_connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER)")

        row = connection_pool.execute_read_one("SELECT * FROM test WHERE id = ?", (999,))
        assert row is None

    def test_row_factory(self, connection_pool):
        """Test that row factory returns dict-like rows."""
        with connection_pool.write_connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER, name TEXT)")
            conn.execute("INSERT INTO test VALUES (1, 'test')")

        rows = connection_pool.execute_read("SELECT * FROM test")

        # Should be able to access by column name
        assert rows[0]["id"] == 1
        assert rows[0]["name"] == "test"

    def test_close(self, temp_db_path):
        """Test close method."""
        pool = ConnectionPool(db_path=temp_db_path, read_pool_size=2)
        pool.initialize()

        assert pool.is_initialized is True

        pool.close()

        assert pool.is_initialized is False
        assert pool._write_conn is None
        assert len(pool._read_connections) == 0

    def test_context_manager(self, temp_db_path):
        """Test context manager usage."""
        with ConnectionPool(db_path=temp_db_path) as pool:
            assert pool.is_initialized is True

            with pool.write_connection() as conn:
                conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER)")

        # After exiting, should be closed
        assert pool.is_initialized is False

    def test_concurrent_reads(self, connection_pool):
        """Test concurrent read operations."""
        # Write test data
        with connection_pool.write_connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER)")
            for i in range(100):
                conn.execute("INSERT INTO test VALUES (?)", (i,))

        results = []
        errors = []

        def reader():
            try:
                rows = connection_pool.execute_read("SELECT COUNT(*) as c FROM test")
                results.append(rows[0]["c"])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=reader) for _ in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert all(r == 100 for r in results)

    def test_write_while_reading(self, connection_pool):
        """Test that writes don't block reads (WAL mode)."""
        # Write initial data
        with connection_pool.write_connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER)")
            conn.execute("INSERT INTO test VALUES (1)")

        read_count = [0]
        errors = []

        def reader():
            try:
                for _ in range(10):
                    rows = connection_pool.execute_read("SELECT * FROM test")
                    read_count[0] += len(rows)
            except Exception as e:
                errors.append(e)

        def writer():
            try:
                with connection_pool.write_connection() as conn:
                    for i in range(10):
                        conn.execute("INSERT INTO test VALUES (?)", (i + 100,))
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=reader),
            threading.Thread(target=writer),
            threading.Thread(target=reader),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert read_count[0] > 0

    def test_foreign_keys_enabled(self, connection_pool):
        """Test that foreign keys are enabled."""
        with connection_pool.write_connection() as conn:
            cursor = conn.execute("PRAGMA foreign_keys")
            fk_enabled = cursor.fetchone()[0]
            assert fk_enabled == 1

    def test_double_initialize(self, temp_db_path):
        """Test that double initialization is safe."""
        pool = ConnectionPool(db_path=temp_db_path)
        pool.initialize()
        pool.initialize()  # Should not raise

        assert pool.is_initialized is True

        pool.close()

    def test_wal_checkpoint_on_close(self, temp_db_path):
        """Test that WAL is checkpointed on close."""
        pool = ConnectionPool(db_path=temp_db_path, wal_mode=True)
        pool.initialize()

        # Write some data
        with pool.write_connection() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS test (id INTEGER)")
            conn.execute("INSERT INTO test VALUES (1)")

        pool.close()

        # WAL file should be small or gone after checkpoint
        wal_path = Path(temp_db_path).with_suffix(".db-wal")
        if wal_path.exists():
            # If it exists, it should be small
            assert wal_path.stat().st_size < 10000
