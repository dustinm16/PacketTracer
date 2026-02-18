"""JSON exporter for PacketTracer data."""

import json
import logging
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any, List, Optional, TYPE_CHECKING

from .base import Exporter, ExportOptions

if TYPE_CHECKING:
    from tracking.flow import Flow
    from db.repositories.dns_query_repo import DNSQueryRecord
    from tracking.ports import PortStats

logger = logging.getLogger(__name__)


class JSONExporter(Exporter):
    """Export data to JSON format."""

    def __init__(self, options: Optional[ExportOptions] = None):
        super().__init__(options)

    def get_extension(self) -> str:
        return "json"

    def export_flows(self, flows: List["Flow"], path: str) -> bool:
        """Export flows to JSON file."""
        flows = self._limit_records(flows)

        try:
            data = {
                "export_type": "flows",
                "export_time": datetime.now().isoformat(),
                "count": len(flows),
                "flows": [self._flow_to_dict(flow) for flow in flows]
            }

            self._write_json(data, path)
            logger.info(f"Exported {len(flows)} flows to {path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export flows to JSON: {e}")
            return False

    def export_dns(self, records: List["DNSQueryRecord"], path: str) -> bool:
        """Export DNS records to JSON file."""
        records = self._limit_records(records)

        try:
            data = {
                "export_type": "dns_queries",
                "export_time": datetime.now().isoformat(),
                "count": len(records),
                "queries": [self._dns_to_dict(record) for record in records]
            }

            self._write_json(data, path)
            logger.info(f"Exported {len(records)} DNS records to {path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export DNS to JSON: {e}")
            return False

    def export_ports(self, stats: List["PortStats"], path: str) -> bool:
        """Export port statistics to JSON file."""
        stats = self._limit_records(stats)

        try:
            data = {
                "export_type": "port_statistics",
                "export_time": datetime.now().isoformat(),
                "count": len(stats),
                "ports": [self._port_stats_to_dict(stat) for stat in stats]
            }

            self._write_json(data, path)
            logger.info(f"Exported {len(stats)} port stats to {path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export ports to JSON: {e}")
            return False

    def _write_json(self, data: dict, path: str) -> None:
        """Write data to JSON file."""
        with open(path, 'w', encoding='utf-8') as f:
            if self.options.pretty_print:
                json.dump(data, f, indent=2, default=self._json_default)
            else:
                json.dump(data, f, default=self._json_default)

    def _json_default(self, obj: Any) -> Any:
        """Default JSON serializer for unsupported types."""
        if is_dataclass(obj) and not isinstance(obj, type):
            return asdict(obj)
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        if isinstance(obj, set):
            return list(obj)
        if isinstance(obj, bytes):
            return obj.hex()
        return str(obj)

    def _flow_to_dict(self, flow: "Flow") -> dict:
        """Convert Flow to dictionary."""
        data = {
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "protocol_name": flow.protocol_name,
            "statistics": {
                "packets_sent": flow.packets_sent,
                "packets_recv": flow.packets_recv,
                "total_packets": flow.total_packets,
                "bytes_sent": flow.bytes_sent,
                "bytes_recv": flow.bytes_recv,
                "total_bytes": flow.total_bytes,
            },
            "timing": {
                "first_seen": flow.first_seen,
                "last_seen": flow.last_seen,
                "duration_seconds": round(flow.duration, 3),
            },
            "ttl": {
                "min": flow.min_ttl,
                "max": flow.max_ttl,
                "estimated_hops": flow.estimated_hops,
            }
        }

        if self.options.include_timestamps:
            data["timing"]["first_seen_iso"] = datetime.fromtimestamp(flow.first_seen).isoformat()
            data["timing"]["last_seen_iso"] = datetime.fromtimestamp(flow.last_seen).isoformat()

        if self.options.include_geo:
            if flow.src_geo:
                data["src_geo"] = self._geo_to_dict(flow.src_geo)
            if flow.dst_geo:
                data["dst_geo"] = self._geo_to_dict(flow.dst_geo)

        return data

    def _geo_to_dict(self, geo: Any) -> dict:
        """Convert GeoInfo to dictionary."""
        if isinstance(geo, dict):
            return geo
        if hasattr(geo, '__dict__'):
            return {
                "country": getattr(geo, "country", ""),
                "country_code": getattr(geo, "country_code", ""),
                "city": getattr(geo, "city", ""),
                "region": getattr(geo, "region", ""),
                "isp": getattr(geo, "isp", ""),
                "org": getattr(geo, "org", ""),
                "as_number": getattr(geo, "as_number", ""),
                "as_name": getattr(geo, "as_name", ""),
                "latitude": getattr(geo, "latitude", 0.0),
                "longitude": getattr(geo, "longitude", 0.0),
            }
        return {}

    def _dns_to_dict(self, record: "DNSQueryRecord") -> dict:
        """Convert DNSQueryRecord to dictionary."""
        data = {
            "transaction_id": record.transaction_id,
            "src_ip": record.src_ip,
            "dst_ip": record.dst_ip,
            "query_name": record.query_name,
            "query_type": record.query_type,
            "query_type_name": record.query_type_name,
            "is_response": record.is_response,
            "response_code": record.response_code,
            "response_code_name": record.response_code_name,
            "answer_count": record.answer_count,
            "answers": record.answers if record.answers else [],
            "latency_ms": round(record.latency_ms, 2) if record.latency_ms else None,
            "is_nxdomain": record.is_nxdomain,
            "is_error": record.is_error,
            "timestamp": record.timestamp,
        }

        if self.options.include_timestamps:
            data["timestamp_iso"] = datetime.fromtimestamp(record.timestamp).isoformat()

        return data

    def _port_stats_to_dict(self, stat: "PortStats") -> dict:
        """Convert PortStats to dictionary."""
        data = {
            "port": stat.port,
            "protocol": stat.protocol,
            "traffic": {
                "bytes_in": stat.bytes_in,
                "bytes_out": stat.bytes_out,
                "total_bytes": stat.total_bytes,
                "packets_in": stat.packets_in,
                "packets_out": stat.packets_out,
                "total_packets": stat.total_packets,
            },
            "connections": {
                "hit_count": stat.hit_count,
                "unique_sources": stat.unique_sources,
                "unique_destinations": stat.unique_destinations,
            },
            "rate": {
                "packets_per_second": round(stat.packets_per_second, 2),
            }
        }

        if hasattr(stat, 'first_seen') and stat.first_seen:
            data["timing"] = {
                "first_seen": stat.first_seen,
                "last_seen": stat.last_seen,
            }
            if self.options.include_timestamps:
                data["timing"]["first_seen_iso"] = datetime.fromtimestamp(stat.first_seen).isoformat()
                data["timing"]["last_seen_iso"] = datetime.fromtimestamp(stat.last_seen).isoformat()

        return data


def export_session_summary(
    session_id: int,
    flows: List["Flow"],
    dns_records: List["DNSQueryRecord"],
    port_stats: List["PortStats"],
    path: str,
    pretty: bool = True
) -> bool:
    """Export a complete session summary to JSON.

    Args:
        session_id: Session ID
        flows: List of flows
        dns_records: List of DNS records
        port_stats: List of port statistics
        path: Output file path
        pretty: Whether to pretty-print JSON

    Returns:
        True if export succeeded
    """
    try:
        exporter = JSONExporter(ExportOptions(pretty_print=pretty))

        # Calculate summary statistics
        total_bytes = sum(f.total_bytes for f in flows)
        total_packets = sum(f.total_packets for f in flows)
        unique_ips = set()
        for f in flows:
            unique_ips.add(f.src_ip)
            unique_ips.add(f.dst_ip)

        data = {
            "session_id": session_id,
            "export_time": datetime.now().isoformat(),
            "summary": {
                "total_flows": len(flows),
                "total_dns_queries": len(dns_records),
                "total_ports": len(port_stats),
                "total_bytes": total_bytes,
                "total_packets": total_packets,
                "unique_ips": len(unique_ips),
            },
            "flows": [exporter._flow_to_dict(f) for f in flows],
            "dns_queries": [exporter._dns_to_dict(r) for r in dns_records],
            "port_statistics": [exporter._port_stats_to_dict(s) for s in port_stats],
        }

        exporter._write_json(data, path)
        logger.info(f"Exported session {session_id} summary to {path}")
        return True

    except Exception as e:
        logger.error(f"Failed to export session summary: {e}")
        return False
