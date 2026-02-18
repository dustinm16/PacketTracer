"""CSV exporter for PacketTracer data."""

import csv
import logging
from datetime import datetime
from typing import List, Optional, TYPE_CHECKING

from .base import Exporter, ExportOptions

if TYPE_CHECKING:
    from tracking.flow import Flow
    from db.repositories.dns_query_repo import DNSQueryRecord
    from tracking.ports import PortStats

logger = logging.getLogger(__name__)


class CSVExporter(Exporter):
    """Export data to CSV format."""

    def __init__(self, options: Optional[ExportOptions] = None):
        super().__init__(options)

    def get_extension(self) -> str:
        return "csv"

    def export_flows(self, flows: List["Flow"], path: str) -> bool:
        """Export flows to CSV file."""
        flows = self._limit_records(flows)

        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # Write header
                headers = [
                    "src_ip", "dst_ip", "src_port", "dst_port",
                    "protocol", "protocol_name",
                    "packets_sent", "packets_recv", "total_packets",
                    "bytes_sent", "bytes_recv", "total_bytes",
                    "first_seen", "last_seen", "duration_seconds",
                    "min_ttl", "max_ttl", "estimated_hops"
                ]

                if self.options.include_geo:
                    headers.extend([
                        "src_country", "src_city", "src_isp",
                        "dst_country", "dst_city", "dst_isp"
                    ])

                writer.writerow(headers)

                # Write data
                for flow in flows:
                    row = [
                        flow.src_ip,
                        flow.dst_ip,
                        flow.src_port,
                        flow.dst_port,
                        flow.protocol,
                        flow.protocol_name,
                        flow.packets_sent,
                        flow.packets_recv,
                        flow.total_packets,
                        flow.bytes_sent,
                        flow.bytes_recv,
                        flow.total_bytes,
                        self._format_timestamp(flow.first_seen),
                        self._format_timestamp(flow.last_seen),
                        round(flow.duration, 3),
                        flow.min_ttl,
                        flow.max_ttl,
                        flow.estimated_hops or ""
                    ]

                    if self.options.include_geo:
                        src_geo = flow.src_geo or {}
                        dst_geo = flow.dst_geo or {}
                        row.extend([
                            src_geo.get("country", "") if isinstance(src_geo, dict) else getattr(src_geo, "country", ""),
                            src_geo.get("city", "") if isinstance(src_geo, dict) else getattr(src_geo, "city", ""),
                            src_geo.get("isp", "") if isinstance(src_geo, dict) else getattr(src_geo, "isp", ""),
                            dst_geo.get("country", "") if isinstance(dst_geo, dict) else getattr(dst_geo, "country", ""),
                            dst_geo.get("city", "") if isinstance(dst_geo, dict) else getattr(dst_geo, "city", ""),
                            dst_geo.get("isp", "") if isinstance(dst_geo, dict) else getattr(dst_geo, "isp", ""),
                        ])

                    writer.writerow(row)

            logger.info(f"Exported {len(flows)} flows to {path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export flows to CSV: {e}")
            return False

    def export_dns(self, records: List["DNSQueryRecord"], path: str) -> bool:
        """Export DNS records to CSV file."""
        records = self._limit_records(records)

        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # Write header
                headers = [
                    "timestamp", "transaction_id",
                    "src_ip", "dst_ip",
                    "query_name", "query_type", "query_type_name",
                    "is_response", "response_code", "response_code_name",
                    "answer_count", "latency_ms",
                    "is_nxdomain", "is_error"
                ]
                writer.writerow(headers)

                # Write data
                for record in records:
                    row = [
                        self._format_timestamp(record.timestamp),
                        record.transaction_id,
                        record.src_ip,
                        record.dst_ip,
                        record.query_name,
                        record.query_type,
                        record.query_type_name,
                        record.is_response,
                        record.response_code or "",
                        record.response_code_name or "",
                        record.answer_count,
                        round(record.latency_ms, 2) if record.latency_ms else "",
                        record.is_nxdomain,
                        record.is_error
                    ]
                    writer.writerow(row)

            logger.info(f"Exported {len(records)} DNS records to {path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export DNS to CSV: {e}")
            return False

    def export_ports(self, stats: List["PortStats"], path: str) -> bool:
        """Export port statistics to CSV file."""
        stats = self._limit_records(stats)

        try:
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # Write header
                headers = [
                    "port", "protocol",
                    "bytes_in", "bytes_out", "total_bytes",
                    "packets_in", "packets_out", "total_packets",
                    "hit_count", "unique_sources", "unique_destinations",
                    "packets_per_second", "first_seen", "last_seen"
                ]
                writer.writerow(headers)

                # Write data
                for stat in stats:
                    row = [
                        stat.port,
                        stat.protocol,
                        stat.bytes_in,
                        stat.bytes_out,
                        stat.total_bytes,
                        stat.packets_in,
                        stat.packets_out,
                        stat.total_packets,
                        stat.hit_count,
                        stat.unique_sources,
                        stat.unique_destinations,
                        round(stat.packets_per_second, 2),
                        self._format_timestamp(stat.first_seen) if hasattr(stat, 'first_seen') else "",
                        self._format_timestamp(stat.last_seen) if hasattr(stat, 'last_seen') else ""
                    ]
                    writer.writerow(row)

            logger.info(f"Exported {len(stats)} port stats to {path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export ports to CSV: {e}")
            return False

    def _format_timestamp(self, ts: float) -> str:
        """Format timestamp for CSV output."""
        if not ts:
            return ""
        if self.options.include_timestamps:
            return datetime.fromtimestamp(ts).isoformat()
        return str(ts)
