"""Database module for persistent storage with SQLite WAL mode.

This module provides:
- Connection pool with WAL mode for concurrent reads during writes
- Background writer for non-blocking batch inserts
- Repository classes for data access
- Schema management and migrations

Usage:
    from db import ConnectionPool, DatabaseWriter
    from db.repositories import FlowRepository, SessionRepository

    pool = ConnectionPool("~/.packettracer/data.db")
    pool.initialize()

    writer = DatabaseWriter(pool)
    writer.start()

    flow_repo = FlowRepository(pool, writer)
"""

from .connection import ConnectionPool
from .writer import DatabaseWriter, WriteOp, WriteRequest
from .schema import init_schema, cleanup_expired_cache, SCHEMA_VERSION

__all__ = [
    "ConnectionPool",
    "DatabaseWriter",
    "WriteOp",
    "WriteRequest",
    "init_schema",
    "cleanup_expired_cache",
    "SCHEMA_VERSION",
]
