"""Device repository for device tracking and classification."""

import time
import json
from typing import Optional, List, TYPE_CHECKING
from dataclasses import dataclass

if TYPE_CHECKING:
    from ..connection import ConnectionPool
    from ..writer import DatabaseWriter


@dataclass
class DeviceRecord:
    """Device information record."""
    id: int
    ip: str
    mac: Optional[str]
    device_type: str
    device_role: Optional[str]
    hostname: Optional[str]
    domain: Optional[str]
    manufacturer: Optional[str]
    device_name: Optional[str]
    is_local: bool
    is_gateway: bool
    subnet: Optional[str]
    vlan: Optional[int]
    ttl_signature: Optional[int]
    os_guess: Optional[str]
    notes: Optional[str]
    tags: List[str]
    first_seen: float
    last_seen: float
    last_updated: float

    @property
    def display_name(self) -> str:
        """Get best display name for this device."""
        if self.device_name:
            return self.device_name
        if self.hostname:
            return self.hostname.split('.')[0]
        return self.ip


@dataclass
class NodeOwnershipRecord:
    """Node ownership information."""
    id: int
    ip: str
    owner: Optional[str]
    operator: Optional[str]
    contact: Optional[str]
    asn: Optional[str]
    as_name: Optional[str]
    org: Optional[str]
    isp: Optional[str]
    network_cidr: Optional[str]
    management_url: Optional[str]
    management_protocol: Optional[str]
    is_managed: bool
    notes: Optional[str]
    tags: List[str]
    first_seen: float
    last_updated: float


class DeviceRepository:
    """Repository for device tracking and classification."""

    def __init__(self, pool: "ConnectionPool", writer: "DatabaseWriter"):
        self.pool = pool
        self.writer = writer

    def upsert_device(
        self,
        ip: str,
        mac: Optional[str] = None,
        device_type: str = "unknown",
        device_role: Optional[str] = None,
        hostname: Optional[str] = None,
        domain: Optional[str] = None,
        manufacturer: Optional[str] = None,
        device_name: Optional[str] = None,
        is_local: bool = False,
        is_gateway: bool = False,
        subnet: Optional[str] = None,
        vlan: Optional[int] = None,
        ttl_signature: Optional[int] = None,
        os_guess: Optional[str] = None,
        notes: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> None:
        """Insert or update a device."""
        now = time.time()
        tags_json = json.dumps(tags) if tags else None

        with self.pool.write_connection() as conn:
            conn.execute("""
                INSERT INTO devices (
                    ip, mac, device_type, device_role, hostname, domain,
                    manufacturer, device_name, is_local, is_gateway,
                    subnet, vlan, ttl_signature, os_guess, notes, tags,
                    first_seen, last_seen, last_updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac = COALESCE(excluded.mac, mac),
                    device_type = CASE WHEN excluded.device_type != 'unknown'
                        THEN excluded.device_type ELSE device_type END,
                    device_role = COALESCE(excluded.device_role, device_role),
                    hostname = COALESCE(excluded.hostname, hostname),
                    domain = COALESCE(excluded.domain, domain),
                    manufacturer = COALESCE(excluded.manufacturer, manufacturer),
                    device_name = COALESCE(excluded.device_name, device_name),
                    is_local = excluded.is_local OR is_local,
                    is_gateway = excluded.is_gateway OR is_gateway,
                    subnet = COALESCE(excluded.subnet, subnet),
                    vlan = COALESCE(excluded.vlan, vlan),
                    ttl_signature = COALESCE(excluded.ttl_signature, ttl_signature),
                    os_guess = COALESCE(excluded.os_guess, os_guess),
                    notes = COALESCE(excluded.notes, notes),
                    tags = COALESCE(excluded.tags, tags),
                    last_seen = excluded.last_seen,
                    last_updated = excluded.last_updated
            """, [
                ip, mac, device_type, device_role, hostname, domain,
                manufacturer, device_name, 1 if is_local else 0,
                1 if is_gateway else 0, subnet, vlan, ttl_signature,
                os_guess, notes, tags_json, now, now, now
            ])
            conn.commit()

    def get_device(self, ip: str) -> Optional[DeviceRecord]:
        """Get device by IP."""
        row = self.pool.execute_read_one(
            "SELECT * FROM devices WHERE ip = ?",
            (ip,)
        )
        if row:
            return self._row_to_device(row)
        return None

    def get_devices(
        self,
        device_type: Optional[str] = None,
        device_role: Optional[str] = None,
        is_local: Optional[bool] = None,
        limit: int = 100
    ) -> List[DeviceRecord]:
        """Get devices with optional filtering."""
        where = []
        params = []

        if device_type:
            where.append("device_type = ?")
            params.append(device_type)
        if device_role:
            where.append("device_role = ?")
            params.append(device_role)
        if is_local is not None:
            where.append("is_local = ?")
            params.append(1 if is_local else 0)

        where_clause = " AND ".join(where) if where else "1=1"
        params.append(limit)

        rows = self.pool.execute_read(f"""
            SELECT * FROM devices
            WHERE {where_clause}
            ORDER BY last_seen DESC
            LIMIT ?
        """, tuple(params))

        return [self._row_to_device(row) for row in rows]

    def get_routers(self) -> List[DeviceRecord]:
        """Get all router devices."""
        return self.get_devices(device_type="router")

    def get_gateways(self) -> List[DeviceRecord]:
        """Get all gateway devices."""
        rows = self.pool.execute_read(
            "SELECT * FROM devices WHERE is_gateway = 1"
        )
        return [self._row_to_device(row) for row in rows]

    def set_device_type(self, ip: str, device_type: str) -> None:
        """Update device type classification."""
        with self.pool.write_connection() as conn:
            conn.execute("""
                UPDATE devices SET device_type = ?, last_updated = ?
                WHERE ip = ?
            """, [device_type, time.time(), ip])
            conn.commit()

    def set_device_role(self, ip: str, device_role: str) -> None:
        """Update device role."""
        with self.pool.write_connection() as conn:
            conn.execute("""
                UPDATE devices SET device_role = ?, last_updated = ?
                WHERE ip = ?
            """, [device_role, time.time(), ip])
            conn.commit()

    def set_device_name(self, ip: str, name: str) -> None:
        """Set user-assigned device name."""
        with self.pool.write_connection() as conn:
            conn.execute("""
                UPDATE devices SET device_name = ?, last_updated = ?
                WHERE ip = ?
            """, [name, time.time(), ip])
            conn.commit()

    # Node ownership methods

    def upsert_ownership(
        self,
        ip: str,
        owner: Optional[str] = None,
        operator: Optional[str] = None,
        asn: Optional[str] = None,
        as_name: Optional[str] = None,
        org: Optional[str] = None,
        isp: Optional[str] = None,
        network_cidr: Optional[str] = None,
        is_managed: bool = False,
    ) -> None:
        """Insert or update node ownership."""
        now = time.time()
        with self.pool.write_connection() as conn:
            conn.execute("""
                INSERT INTO node_ownership (
                    ip, owner, operator, asn, as_name, org, isp,
                    network_cidr, is_managed, first_seen, last_updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    owner = COALESCE(excluded.owner, owner),
                    operator = COALESCE(excluded.operator, operator),
                    asn = COALESCE(excluded.asn, asn),
                    as_name = COALESCE(excluded.as_name, as_name),
                    org = COALESCE(excluded.org, org),
                    isp = COALESCE(excluded.isp, isp),
                    network_cidr = COALESCE(excluded.network_cidr, network_cidr),
                    is_managed = excluded.is_managed OR is_managed,
                    last_updated = excluded.last_updated
            """, [
                ip, owner, operator, asn, as_name, org, isp,
                network_cidr, 1 if is_managed else 0, now, now
            ])
            conn.commit()

    def get_ownership(self, ip: str) -> Optional[NodeOwnershipRecord]:
        """Get ownership info for an IP."""
        row = self.pool.execute_read_one(
            "SELECT * FROM node_ownership WHERE ip = ?",
            (ip,)
        )
        if row:
            return self._row_to_ownership(row)
        return None

    def _row_to_device(self, row) -> DeviceRecord:
        tags = []
        if row["tags"]:
            try:
                tags = json.loads(row["tags"])
            except json.JSONDecodeError:
                pass

        return DeviceRecord(
            id=row["id"],
            ip=row["ip"],
            mac=row["mac"],
            device_type=row["device_type"],
            device_role=row["device_role"],
            hostname=row["hostname"],
            domain=row["domain"],
            manufacturer=row["manufacturer"],
            device_name=row["device_name"],
            is_local=bool(row["is_local"]),
            is_gateway=bool(row["is_gateway"]),
            subnet=row["subnet"],
            vlan=row["vlan"],
            ttl_signature=row["ttl_signature"],
            os_guess=row["os_guess"],
            notes=row["notes"],
            tags=tags,
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            last_updated=row["last_updated"],
        )

    def _row_to_ownership(self, row) -> NodeOwnershipRecord:
        tags = []
        if row["tags"]:
            try:
                tags = json.loads(row["tags"])
            except json.JSONDecodeError:
                pass

        return NodeOwnershipRecord(
            id=row["id"],
            ip=row["ip"],
            owner=row["owner"],
            operator=row["operator"],
            contact=row["contact"],
            asn=row["asn"],
            as_name=row["as_name"],
            org=row["org"],
            isp=row["isp"],
            network_cidr=row["network_cidr"],
            management_url=row["management_url"],
            management_protocol=row["management_protocol"],
            is_managed=bool(row["is_managed"]),
            notes=row["notes"],
            tags=tags,
            first_seen=row["first_seen"],
            last_updated=row["last_updated"],
        )
