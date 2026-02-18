"""Base exporter class and interfaces."""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from tracking.flow import Flow
    from db.repositories.dns_query_repo import DNSQueryRecord
    from tracking.ports import PortStats

logger = logging.getLogger(__name__)


class ExportFormat(Enum):
    """Supported export formats."""
    CSV = auto()
    JSON = auto()


@dataclass
class ExportOptions:
    """Options for data export."""
    include_geo: bool = True
    include_dns: bool = True
    include_ports: bool = True
    include_timestamps: bool = True
    pretty_print: bool = False
    max_records: Optional[int] = None


class Exporter(ABC):
    """Abstract base class for data exporters."""

    def __init__(self, options: Optional[ExportOptions] = None):
        self.options = options or ExportOptions()

    @abstractmethod
    def export_flows(self, flows: List["Flow"], path: str) -> bool:
        """Export flow data to a file.

        Args:
            flows: List of Flow objects to export
            path: Output file path

        Returns:
            True if export succeeded
        """
        pass

    @abstractmethod
    def export_dns(self, records: List["DNSQueryRecord"], path: str) -> bool:
        """Export DNS query records to a file.

        Args:
            records: List of DNSQueryRecord objects to export
            path: Output file path

        Returns:
            True if export succeeded
        """
        pass

    @abstractmethod
    def export_ports(self, stats: List["PortStats"], path: str) -> bool:
        """Export port statistics to a file.

        Args:
            stats: List of PortStats objects to export
            path: Output file path

        Returns:
            True if export succeeded
        """
        pass

    def export_all(
        self,
        flows: List["Flow"],
        dns_records: List["DNSQueryRecord"],
        port_stats: List["PortStats"],
        output_dir: str,
        prefix: str = "export"
    ) -> bool:
        """Export all data types to separate files.

        Args:
            flows: List of flows to export
            dns_records: List of DNS records to export
            port_stats: List of port stats to export
            output_dir: Output directory path
            prefix: Filename prefix

        Returns:
            True if all exports succeeded
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        success = True
        ext = self.get_extension()

        if flows:
            flow_path = output_path / f"{prefix}_flows.{ext}"
            if not self.export_flows(flows, str(flow_path)):
                success = False
                logger.error(f"Failed to export flows to {flow_path}")

        if dns_records and self.options.include_dns:
            dns_path = output_path / f"{prefix}_dns.{ext}"
            if not self.export_dns(dns_records, str(dns_path)):
                success = False
                logger.error(f"Failed to export DNS to {dns_path}")

        if port_stats and self.options.include_ports:
            ports_path = output_path / f"{prefix}_ports.{ext}"
            if not self.export_ports(port_stats, str(ports_path)):
                success = False
                logger.error(f"Failed to export ports to {ports_path}")

        return success

    @abstractmethod
    def get_extension(self) -> str:
        """Get the file extension for this export format."""
        pass

    def _limit_records(self, records: list) -> list:
        """Apply max_records limit if set."""
        if self.options.max_records and len(records) > self.options.max_records:
            return records[:self.options.max_records]
        return records
