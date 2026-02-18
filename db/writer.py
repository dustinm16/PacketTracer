"""Background write queue for non-blocking packet processing."""

import threading
import time
from queue import Queue, Empty
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING
from enum import Enum, auto

if TYPE_CHECKING:
    from .connection import ConnectionPool


class WriteOp(Enum):
    """Types of write operations."""
    INSERT_FLOW = auto()
    UPDATE_FLOW = auto()
    UPSERT_FLOW = auto()
    UPDATE_FLOW_GEO = auto()
    UPDATE_FLOW_DNS = auto()
    UPDATE_FLOW_CLASSIFICATION = auto()
    UPSERT_PORT_STATS = auto()
    UPSERT_GEO_CACHE = auto()
    UPSERT_DNS_CACHE = auto()
    UPDATE_SESSION_STATS = auto()
    INSERT_SCAN_ACTIVITY = auto()
    UPDATE_SCAN_ACTIVITY = auto()
    INSERT_TRACEROUTE = auto()
    UPDATE_TRACEROUTE = auto()
    UPSERT_HOP = auto()
    INSERT_LATENCY_SAMPLE = auto()
    UPSERT_PATH_SUMMARY = auto()
    INSERT_DNS_QUERY = auto()
    UPSERT_DNS_STATS = auto()
    # Relay agent operations
    UPDATE_AGENT_STATUS = auto()
    UPDATE_AGENT_HEARTBEAT = auto()
    INSERT_RELAY_EVENT = auto()
    INSERT_RELAY_METRICS = auto()


@dataclass
class WriteRequest:
    """A write operation to be processed."""
    op: WriteOp
    data: dict
    timestamp: float = field(default_factory=time.time)


class DatabaseWriter:
    """Background thread for batched database writes.

    Collects write operations and flushes them in batches for efficiency.
    This prevents the packet capture thread from blocking on database writes.
    """

    def __init__(
        self,
        pool: "ConnectionPool",
        batch_size: int = 100,
        flush_interval: float = 0.1,
    ):
        self.pool = pool
        self.batch_size = batch_size
        self.flush_interval = flush_interval

        self._queue: Queue[WriteRequest] = Queue()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Statistics
        self.writes_queued = 0
        self.writes_completed = 0
        self.batches_flushed = 0
        self.errors = 0

    def start(self) -> None:
        """Start the background writer thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._writer_loop, daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the writer thread and flush remaining writes."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None

    def queue_write(self, op: WriteOp, data: dict) -> None:
        """Queue a write operation."""
        self._queue.put(WriteRequest(op=op, data=data))
        self.writes_queued += 1

    def flush(self) -> None:
        """Force flush all pending writes (blocking)."""
        batch = []
        while True:
            try:
                request = self._queue.get_nowait()
                batch.append(request)
            except Empty:
                break
        if batch:
            self._flush_batch(batch)

    def _writer_loop(self) -> None:
        """Main writer loop - batches writes for efficiency."""
        last_flush = time.time()
        batch: list[WriteRequest] = []

        while not self._stop_event.is_set():
            try:
                # Collect writes with short timeout
                request = self._queue.get(timeout=0.01)
                batch.append(request)

                now = time.time()
                should_flush = (
                    len(batch) >= self.batch_size or
                    (now - last_flush) >= self.flush_interval
                )

                if should_flush:
                    self._flush_batch(batch)
                    batch = []
                    last_flush = now

            except Empty:
                # Check if we should flush on timeout
                if batch and (time.time() - last_flush) >= self.flush_interval:
                    self._flush_batch(batch)
                    batch = []
                    last_flush = time.time()

        # Flush remaining on shutdown
        if batch:
            self._flush_batch(batch)

    def _flush_batch(self, batch: list[WriteRequest]) -> None:
        """Process a batch of write operations."""
        if not batch:
            return

        try:
            with self.pool.write_connection() as conn:
                conn.execute("BEGIN TRANSACTION")
                try:
                    self._execute_batch(conn, batch)
                    conn.execute("COMMIT")
                    self.writes_completed += len(batch)
                    self.batches_flushed += 1
                except Exception:
                    conn.execute("ROLLBACK")
                    raise
        except Exception as e:
            self.errors += 1
            # Log but don't crash - packet capture should continue
            from utils.logger import logger
            logger.error(f"Database write error: {e}")

    def _execute_batch(self, conn, batch: list[WriteRequest]) -> None:
        """Execute a batch of write operations."""
        # Group by operation type for efficient batching
        flow_inserts = []
        flow_updates = []
        flow_upserts = []
        flow_geo_updates = []
        flow_dns_updates = []
        flow_classification_updates = []
        port_upserts = []
        geo_upserts = []
        dns_upserts = []
        session_updates = []
        scan_inserts = []
        scan_updates = []
        traceroute_inserts = []
        traceroute_updates = []
        hop_upserts = []
        latency_samples = []
        path_summary_upserts = []
        dns_query_inserts = []
        dns_stats_upserts = []
        # Relay agent operations
        agent_status_updates = []
        agent_heartbeat_updates = []
        relay_event_inserts = []
        relay_metrics_inserts = []

        for req in batch:
            if req.op == WriteOp.INSERT_FLOW:
                flow_inserts.append(req.data)
            elif req.op == WriteOp.UPDATE_FLOW:
                flow_updates.append(req.data)
            elif req.op == WriteOp.UPSERT_FLOW:
                flow_upserts.append(req.data)
            elif req.op == WriteOp.UPDATE_FLOW_GEO:
                flow_geo_updates.append(req.data)
            elif req.op == WriteOp.UPDATE_FLOW_DNS:
                flow_dns_updates.append(req.data)
            elif req.op == WriteOp.UPDATE_FLOW_CLASSIFICATION:
                flow_classification_updates.append(req.data)
            elif req.op == WriteOp.UPSERT_PORT_STATS:
                port_upserts.append(req.data)
            elif req.op == WriteOp.UPSERT_GEO_CACHE:
                geo_upserts.append(req.data)
            elif req.op == WriteOp.UPSERT_DNS_CACHE:
                dns_upserts.append(req.data)
            elif req.op == WriteOp.UPDATE_SESSION_STATS:
                session_updates.append(req.data)
            elif req.op == WriteOp.INSERT_SCAN_ACTIVITY:
                scan_inserts.append(req.data)
            elif req.op == WriteOp.UPDATE_SCAN_ACTIVITY:
                scan_updates.append(req.data)
            elif req.op == WriteOp.INSERT_TRACEROUTE:
                traceroute_inserts.append(req.data)
            elif req.op == WriteOp.UPDATE_TRACEROUTE:
                traceroute_updates.append(req.data)
            elif req.op == WriteOp.UPSERT_HOP:
                hop_upserts.append(req.data)
            elif req.op == WriteOp.INSERT_LATENCY_SAMPLE:
                latency_samples.append(req.data)
            elif req.op == WriteOp.UPSERT_PATH_SUMMARY:
                path_summary_upserts.append(req.data)
            elif req.op == WriteOp.INSERT_DNS_QUERY:
                dns_query_inserts.append(req.data)
            elif req.op == WriteOp.UPSERT_DNS_STATS:
                dns_stats_upserts.append(req.data)
            elif req.op == WriteOp.UPDATE_AGENT_STATUS:
                agent_status_updates.append(req.data)
            elif req.op == WriteOp.UPDATE_AGENT_HEARTBEAT:
                agent_heartbeat_updates.append(req.data)
            elif req.op == WriteOp.INSERT_RELAY_EVENT:
                relay_event_inserts.append(req.data)
            elif req.op == WriteOp.INSERT_RELAY_METRICS:
                relay_metrics_inserts.append(req.data)

        # Execute each group
        if flow_inserts:
            self._batch_insert_flows(conn, flow_inserts)
        if flow_updates:
            self._batch_update_flows(conn, flow_updates)
        if flow_upserts:
            self._batch_upsert_flows(conn, flow_upserts)
        if flow_geo_updates:
            self._batch_update_flow_geo(conn, flow_geo_updates)
        if flow_dns_updates:
            self._batch_update_flow_dns(conn, flow_dns_updates)
        if flow_classification_updates:
            self._batch_update_flow_classification(conn, flow_classification_updates)
        if port_upserts:
            self._batch_upsert_ports(conn, port_upserts)
        if geo_upserts:
            self._batch_upsert_geo(conn, geo_upserts)
        if dns_upserts:
            self._batch_upsert_dns(conn, dns_upserts)
        if session_updates:
            self._batch_update_sessions(conn, session_updates)
        if traceroute_inserts:
            self._batch_insert_traceroutes(conn, traceroute_inserts)
        if traceroute_updates:
            self._batch_update_traceroutes(conn, traceroute_updates)
        if hop_upserts:
            self._batch_upsert_hops(conn, hop_upserts)
        if latency_samples:
            self._batch_insert_latency_samples(conn, latency_samples)
        if path_summary_upserts:
            self._batch_upsert_path_summaries(conn, path_summary_upserts)
        if dns_query_inserts:
            self._batch_insert_dns_queries(conn, dns_query_inserts)
        if dns_stats_upserts:
            self._batch_upsert_dns_stats(conn, dns_stats_upserts)
        if agent_status_updates:
            self._batch_update_agent_status(conn, agent_status_updates)
        if agent_heartbeat_updates:
            self._batch_update_agent_heartbeat(conn, agent_heartbeat_updates)
        if relay_event_inserts:
            self._batch_insert_relay_events(conn, relay_event_inserts)
        if relay_metrics_inserts:
            self._batch_insert_relay_metrics(conn, relay_metrics_inserts)

    def _batch_insert_flows(self, conn, flows: list[dict]) -> None:
        """Batch insert new flows."""
        conn.executemany("""
            INSERT OR IGNORE INTO flows (
                session_id, flow_key, src_ip, dst_ip, src_port, dst_port,
                protocol, protocol_name, packets_sent, packets_recv,
                bytes_sent, bytes_recv, first_seen, last_seen, min_ttl, max_ttl
            ) VALUES (
                :session_id, :flow_key, :src_ip, :dst_ip, :src_port, :dst_port,
                :protocol, :protocol_name, :packets_sent, :packets_recv,
                :bytes_sent, :bytes_recv, :first_seen, :last_seen, :min_ttl, :max_ttl
            )
        """, flows)

    def _batch_update_flows(self, conn, updates: list[dict]) -> None:
        """Batch update existing flows with incremental changes."""
        conn.executemany("""
            UPDATE flows SET
                packets_sent = packets_sent + :packets_sent,
                packets_recv = packets_recv + :packets_recv,
                bytes_sent = bytes_sent + :bytes_sent,
                bytes_recv = bytes_recv + :bytes_recv,
                last_seen = :last_seen,
                min_ttl = MIN(min_ttl, :min_ttl),
                max_ttl = MAX(max_ttl, :max_ttl)
            WHERE session_id = :session_id AND flow_key = :flow_key
        """, updates)

    def _batch_upsert_flows(self, conn, flows: list[dict]) -> None:
        """Batch upsert flows (insert or update)."""
        conn.executemany("""
            INSERT INTO flows (
                session_id, flow_key, src_ip, dst_ip, src_port, dst_port,
                protocol, protocol_name, packets_sent, packets_recv,
                bytes_sent, bytes_recv, first_seen, last_seen, min_ttl, max_ttl
            ) VALUES (
                :session_id, :flow_key, :src_ip, :dst_ip, :src_port, :dst_port,
                :protocol, :protocol_name, :packets_sent, :packets_recv,
                :bytes_sent, :bytes_recv, :first_seen, :last_seen, :min_ttl, :max_ttl
            )
            ON CONFLICT(session_id, flow_key) DO UPDATE SET
                packets_sent = packets_sent + excluded.packets_sent,
                packets_recv = packets_recv + excluded.packets_recv,
                bytes_sent = bytes_sent + excluded.bytes_sent,
                bytes_recv = bytes_recv + excluded.bytes_recv,
                last_seen = excluded.last_seen,
                min_ttl = MIN(min_ttl, excluded.min_ttl),
                max_ttl = MAX(max_ttl, excluded.max_ttl)
        """, flows)

    def _batch_update_flow_geo(self, conn, updates: list[dict]) -> None:
        """Update geo data for flows."""
        conn.executemany("""
            UPDATE flows SET
                dst_country = COALESCE(:dst_country, dst_country),
                dst_country_code = COALESCE(:dst_country_code, dst_country_code),
                dst_city = COALESCE(:dst_city, dst_city),
                dst_isp = COALESCE(:dst_isp, dst_isp),
                dst_as_name = COALESCE(:dst_as_name, dst_as_name),
                src_country = COALESCE(:src_country, src_country),
                src_country_code = COALESCE(:src_country_code, src_country_code),
                src_city = COALESCE(:src_city, src_city),
                src_isp = COALESCE(:src_isp, src_isp),
                src_as_name = COALESCE(:src_as_name, src_as_name)
            WHERE session_id = :session_id AND flow_key = :flow_key
        """, updates)

    def _batch_update_flow_dns(self, conn, updates: list[dict]) -> None:
        """Update DNS data for flows."""
        conn.executemany("""
            UPDATE flows SET
                dst_hostname = COALESCE(:dst_hostname, dst_hostname),
                dst_domain = COALESCE(:dst_domain, dst_domain),
                dst_fqdn = COALESCE(:dst_fqdn, dst_fqdn),
                src_hostname = COALESCE(:src_hostname, src_hostname),
                src_domain = COALESCE(:src_domain, src_domain),
                src_fqdn = COALESCE(:src_fqdn, src_fqdn)
            WHERE session_id = :session_id AND flow_key = :flow_key
        """, updates)

    def _batch_update_flow_classification(self, conn, updates: list[dict]) -> None:
        """Update classification data for flows."""
        conn.executemany("""
            UPDATE flows SET
                category = :category,
                subcategory = :subcategory,
                service = :service,
                is_encrypted = :is_encrypted,
                classification_confidence = :confidence
            WHERE session_id = :session_id AND flow_key = :flow_key
        """, updates)

    def _batch_upsert_ports(self, conn, ports: list[dict]) -> None:
        """Batch upsert port statistics."""
        conn.executemany("""
            INSERT INTO port_stats (
                session_id, port, protocol, packets_in, packets_out,
                bytes_in, bytes_out, hit_count, unique_sources,
                unique_destinations, first_seen, last_seen
            ) VALUES (
                :session_id, :port, :protocol, :packets_in, :packets_out,
                :bytes_in, :bytes_out, :hit_count, :unique_sources,
                :unique_destinations, :first_seen, :last_seen
            )
            ON CONFLICT(session_id, port, protocol) DO UPDATE SET
                packets_in = packets_in + excluded.packets_in,
                packets_out = packets_out + excluded.packets_out,
                bytes_in = bytes_in + excluded.bytes_in,
                bytes_out = bytes_out + excluded.bytes_out,
                hit_count = excluded.hit_count,
                unique_sources = excluded.unique_sources,
                unique_destinations = excluded.unique_destinations,
                last_seen = excluded.last_seen
        """, ports)

    def _batch_upsert_geo(self, conn, geos: list[dict]) -> None:
        """Batch upsert geo cache entries."""
        conn.executemany("""
            INSERT INTO geo_cache (
                ip, country, country_code, region, city, zip_code,
                latitude, longitude, timezone, isp, org,
                as_number, as_name, is_private, query_success,
                cached_at, expires_at
            ) VALUES (
                :ip, :country, :country_code, :region, :city, :zip_code,
                :latitude, :longitude, :timezone, :isp, :org,
                :as_number, :as_name, :is_private, :query_success,
                :cached_at, :expires_at
            )
            ON CONFLICT(ip) DO UPDATE SET
                country = excluded.country,
                country_code = excluded.country_code,
                region = excluded.region,
                city = excluded.city,
                zip_code = excluded.zip_code,
                latitude = excluded.latitude,
                longitude = excluded.longitude,
                timezone = excluded.timezone,
                isp = excluded.isp,
                org = excluded.org,
                as_number = excluded.as_number,
                as_name = excluded.as_name,
                is_private = excluded.is_private,
                query_success = excluded.query_success,
                cached_at = excluded.cached_at,
                expires_at = excluded.expires_at
        """, geos)

    def _batch_upsert_dns(self, conn, dns_entries: list[dict]) -> None:
        """Batch upsert DNS cache entries."""
        conn.executemany("""
            INSERT INTO dns_cache (
                ip, hostname, domain, fqdn, resolved, cached_at, expires_at
            ) VALUES (
                :ip, :hostname, :domain, :fqdn, :resolved, :cached_at, :expires_at
            )
            ON CONFLICT(ip) DO UPDATE SET
                hostname = excluded.hostname,
                domain = excluded.domain,
                fqdn = excluded.fqdn,
                resolved = excluded.resolved,
                cached_at = excluded.cached_at,
                expires_at = excluded.expires_at
        """, dns_entries)

    def _batch_update_sessions(self, conn, updates: list[dict]) -> None:
        """Update session statistics."""
        for update in updates:
            conn.execute("""
                UPDATE sessions SET
                    total_packets = total_packets + :packets,
                    total_bytes = total_bytes + :bytes
                WHERE id = :session_id
            """, update)

    def _batch_insert_traceroutes(self, conn, traceroutes: list[dict]) -> None:
        """Batch insert traceroute sessions."""
        conn.executemany("""
            INSERT INTO traceroutes (
                session_id, target_ip, target_hostname, started_at,
                completed_at, total_hops, reached_target
            ) VALUES (
                :session_id, :target_ip, :target_hostname, :started_at,
                :completed_at, :total_hops, :reached_target
            )
        """, traceroutes)

    def _batch_update_traceroutes(self, conn, updates: list[dict]) -> None:
        """Update traceroute sessions."""
        conn.executemany("""
            UPDATE traceroutes SET
                completed_at = :completed_at,
                total_hops = :total_hops,
                reached_target = :reached_target
            WHERE id = :traceroute_id
        """, updates)

    def _batch_upsert_hops(self, conn, hops: list[dict]) -> None:
        """Batch upsert hop nodes with latency data."""
        conn.executemany("""
            INSERT INTO hops (
                traceroute_id, hop_number, ip, hostname, domain,
                rtt_min, rtt_max, rtt_avg, rtt_samples,
                probes_sent, probes_received, loss_percent,
                country, country_code, city, isp, as_name, as_number,
                latitude, longitude, is_timeout, is_target, measured_at
            ) VALUES (
                :traceroute_id, :hop_number, :ip, :hostname, :domain,
                :rtt_min, :rtt_max, :rtt_avg, :rtt_samples,
                :probes_sent, :probes_received, :loss_percent,
                :country, :country_code, :city, :isp, :as_name, :as_number,
                :latitude, :longitude, :is_timeout, :is_target, :measured_at
            )
            ON CONFLICT(traceroute_id, hop_number) DO UPDATE SET
                ip = COALESCE(excluded.ip, ip),
                hostname = COALESCE(excluded.hostname, hostname),
                domain = COALESCE(excluded.domain, domain),
                rtt_min = CASE
                    WHEN excluded.rtt_min IS NOT NULL AND (rtt_min IS NULL OR excluded.rtt_min < rtt_min)
                    THEN excluded.rtt_min ELSE rtt_min END,
                rtt_max = CASE
                    WHEN excluded.rtt_max IS NOT NULL AND (rtt_max IS NULL OR excluded.rtt_max > rtt_max)
                    THEN excluded.rtt_max ELSE rtt_max END,
                rtt_avg = excluded.rtt_avg,
                rtt_samples = rtt_samples + excluded.rtt_samples,
                probes_sent = probes_sent + excluded.probes_sent,
                probes_received = probes_received + excluded.probes_received,
                loss_percent = excluded.loss_percent,
                country = COALESCE(excluded.country, country),
                country_code = COALESCE(excluded.country_code, country_code),
                city = COALESCE(excluded.city, city),
                isp = COALESCE(excluded.isp, isp),
                as_name = COALESCE(excluded.as_name, as_name),
                as_number = COALESCE(excluded.as_number, as_number),
                latitude = COALESCE(excluded.latitude, latitude),
                longitude = COALESCE(excluded.longitude, longitude),
                is_timeout = excluded.is_timeout,
                is_target = excluded.is_target,
                measured_at = excluded.measured_at
        """, hops)

    def _batch_insert_latency_samples(self, conn, samples: list[dict]) -> None:
        """Batch insert latency sample measurements."""
        conn.executemany("""
            INSERT INTO latency_samples (
                hop_id, rtt, probe_number, measured_at
            ) VALUES (
                :hop_id, :rtt, :probe_number, :measured_at
            )
        """, samples)

    def _batch_upsert_path_summaries(self, conn, summaries: list[dict]) -> None:
        """Batch upsert path summaries."""
        conn.executemany("""
            INSERT INTO path_summary (
                session_id, src_ip, dst_ip, hop_count,
                avg_latency, total_latency, path_hash,
                first_seen, last_seen, sample_count
            ) VALUES (
                :session_id, :src_ip, :dst_ip, :hop_count,
                :avg_latency, :total_latency, :path_hash,
                :first_seen, :last_seen, :sample_count
            )
            ON CONFLICT(session_id, src_ip, dst_ip) DO UPDATE SET
                hop_count = excluded.hop_count,
                avg_latency = (avg_latency * sample_count + excluded.avg_latency) / (sample_count + 1),
                total_latency = excluded.total_latency,
                path_hash = excluded.path_hash,
                last_seen = excluded.last_seen,
                sample_count = sample_count + 1
        """, summaries)

    def _batch_insert_dns_queries(self, conn, queries: list[dict]) -> None:
        """Batch insert DNS queries."""
        conn.executemany("""
            INSERT INTO dns_queries (
                session_id, timestamp, transaction_id, src_ip, dst_ip,
                query_name, query_type, query_type_name, is_response,
                response_code, response_code_name, answer_count,
                answers, is_nxdomain, is_error
            ) VALUES (
                :session_id, :timestamp, :transaction_id, :src_ip, :dst_ip,
                :query_name, :query_type, :query_type_name, :is_response,
                :response_code, :response_code_name, :answer_count,
                :answers, :is_nxdomain, :is_error
            )
        """, queries)

    def _batch_upsert_dns_stats(self, conn, stats: list[dict]) -> None:
        """Batch upsert DNS statistics per domain."""
        conn.executemany("""
            INSERT INTO dns_stats (
                session_id, query_name, query_count, response_count,
                nxdomain_count, error_count, first_seen, last_seen,
                unique_query_types, resolved_ips
            ) VALUES (
                :session_id, :query_name,
                CASE WHEN :is_response = 0 THEN 1 ELSE 0 END,
                CASE WHEN :is_response = 1 THEN 1 ELSE 0 END,
                CASE WHEN :is_nxdomain THEN 1 ELSE 0 END,
                CASE WHEN :is_error THEN 1 ELSE 0 END,
                :timestamp, :timestamp,
                :query_type_name,
                :resolved_ips
            )
            ON CONFLICT(session_id, query_name) DO UPDATE SET
                query_count = query_count + CASE WHEN :is_response = 0 THEN 1 ELSE 0 END,
                response_count = response_count + CASE WHEN :is_response = 1 THEN 1 ELSE 0 END,
                nxdomain_count = nxdomain_count + CASE WHEN :is_nxdomain THEN 1 ELSE 0 END,
                error_count = error_count + CASE WHEN :is_error THEN 1 ELSE 0 END,
                last_seen = :timestamp,
                unique_query_types = CASE
                    WHEN unique_query_types NOT LIKE '%' || :query_type_name || '%'
                    THEN unique_query_types || ',' || :query_type_name
                    ELSE unique_query_types
                END,
                resolved_ips = CASE
                    WHEN :resolved_ips IS NOT NULL AND resolved_ips NOT LIKE '%' || :resolved_ips || '%'
                    THEN COALESCE(resolved_ips || ',' || :resolved_ips, :resolved_ips)
                    ELSE resolved_ips
                END
        """, stats)

    def _batch_update_agent_status(self, conn, updates: list[dict]) -> None:
        """Update agent status."""
        for update in updates:
            system_info = update.get("system_info")
            ip_address = update.get("ip_address")
            if system_info:
                conn.execute("""
                    UPDATE relay_agents
                    SET status = ?, last_seen = ?,
                        hostname = COALESCE(?, hostname),
                        ip_address = COALESCE(?, ip_address),
                        os_type = COALESCE(?, os_type),
                        os_version = COALESCE(?, os_version),
                        python_version = COALESCE(?, python_version),
                        agent_version = COALESCE(?, agent_version)
                    WHERE agent_id = ?
                """, (
                    update["status"],
                    update["last_seen"],
                    system_info.get("hostname"),
                    ip_address,
                    system_info.get("os_type"),
                    system_info.get("os_version"),
                    system_info.get("python_version"),
                    system_info.get("agent_version"),
                    update["agent_id"],
                ))
            else:
                conn.execute("""
                    UPDATE relay_agents
                    SET status = ?, last_seen = ?,
                        ip_address = COALESCE(?, ip_address)
                    WHERE agent_id = ?
                """, (
                    update["status"],
                    update["last_seen"],
                    ip_address,
                    update["agent_id"],
                ))

    def _batch_update_agent_heartbeat(self, conn, updates: list[dict]) -> None:
        """Update agent heartbeat timestamps."""
        for update in updates:
            conn.execute("""
                UPDATE relay_agents
                SET last_seen = ?, last_heartbeat = ?, status = 'active',
                    ip_address = COALESCE(?, ip_address)
                WHERE agent_id = ?
            """, (
                update["last_seen"],
                update["last_seen"],
                update.get("ip_address"),
                update["agent_id"],
            ))

    def _batch_insert_relay_events(self, conn, events: list[dict]) -> None:
        """Batch insert relay agent events."""
        conn.executemany("""
            INSERT INTO relay_events (agent_id, event_type, timestamp, event_data, ip_address)
            VALUES (:agent_id, :event_type, :timestamp, :event_data, :ip_address)
        """, events)

    def _batch_insert_relay_metrics(self, conn, metrics: list[dict]) -> None:
        """Batch insert relay agent metrics."""
        conn.executemany("""
            INSERT INTO relay_metrics (agent_id, timestamp, metric_type, metric_data)
            VALUES (:agent_id, :timestamp, :metric_type, :metric_data)
        """, metrics)

    @property
    def pending_count(self) -> int:
        """Number of pending write operations."""
        return self._queue.qsize()

    @property
    def stats(self) -> dict:
        """Get writer statistics."""
        return {
            "queued": self.writes_queued,
            "completed": self.writes_completed,
            "pending": self.pending_count,
            "batches": self.batches_flushed,
            "errors": self.errors,
        }
