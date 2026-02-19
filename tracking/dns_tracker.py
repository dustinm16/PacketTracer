"""DNS query and response tracking."""

import math
import threading
import time
from collections import defaultdict
from typing import Dict, Optional, List, Set, TYPE_CHECKING
from dataclasses import dataclass, field

from capture.parser import ParsedPacket, DNSInfo

if TYPE_CHECKING:
    from db.repositories.dns_query_repo import DNSQueryRepository


@dataclass
class PendingDNSQuery:
    """A DNS query waiting for a response."""
    timestamp: float
    src_ip: str
    dst_ip: str
    query_name: str
    query_type: int
    query_type_name: str


@dataclass
class DNSTunnelIndicator:
    """Indicators that a domain may be used for DNS tunneling."""
    domain: str
    score: float = 0.0          # 0.0–1.0
    reasons: List[str] = field(default_factory=list)
    query_count: int = 0
    avg_label_length: float = 0.0
    max_label_length: int = 0
    subdomain_count: int = 0
    txt_query_count: int = 0

    @property
    def is_suspicious(self) -> bool:
        return self.score >= 0.5


class DNSTracker:
    """Tracks DNS queries and responses, matching them for latency calculation.

    Records DNS traffic to the database and maintains statistics about
    DNS activity including query types, response codes, and latency.
    """

    def __init__(
        self,
        dns_query_repo: "DNSQueryRepository",
        session_id: int,
        query_timeout: float = 5.0,
    ):
        self.dns_query_repo = dns_query_repo
        self.session_id = session_id
        self.query_timeout = query_timeout
        self._lock = threading.Lock()

        # Pending queries waiting for response, keyed by transaction_id
        self._pending_queries: Dict[int, PendingDNSQuery] = {}

        # Statistics
        self._total_queries = 0
        self._total_responses = 0
        self._nxdomain_count = 0
        self._error_count = 0

        # DNS tunneling detection state (per base domain)
        self._domain_subdomains: Dict[str, Set[str]] = defaultdict(set)
        self._domain_query_count: Dict[str, int] = defaultdict(int)
        self._domain_txt_count: Dict[str, int] = defaultdict(int)
        self._domain_label_lengths: Dict[str, List[int]] = defaultdict(list)

        # Set session on repo
        self.dns_query_repo.set_session(session_id)

    def process_packet(self, packet: ParsedPacket) -> None:
        """Process a packet and extract DNS information if present."""
        if packet.dns is None:
            return

        dns_info = packet.dns

        with self._lock:
            if dns_info.is_query:
                self._process_query(packet, dns_info)
            else:
                self._process_response(packet, dns_info)

    def _process_query(self, packet: ParsedPacket, dns_info: DNSInfo) -> None:
        """Process a DNS query packet."""
        self._total_queries += 1

        for query in dns_info.queries:
            # Record the query
            self.dns_query_repo.record_query(
                timestamp=packet.timestamp,
                transaction_id=dns_info.transaction_id,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                query_name=query.name,
                query_type=query.qtype,
                query_type_name=query.qtype_name,
                is_response=False,
            )

            # Track tunneling indicators
            self._track_tunnel_indicators(query.name, query.qtype)

            # Store pending query for latency matching
            self._pending_queries[dns_info.transaction_id] = PendingDNSQuery(
                timestamp=packet.timestamp,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                query_name=query.name,
                query_type=query.qtype,
                query_type_name=query.qtype_name,
            )

    def _process_response(self, packet: ParsedPacket, dns_info: DNSInfo) -> None:
        """Process a DNS response packet."""
        self._total_responses += 1

        # Track response code stats
        if dns_info.rcode == 3:  # NXDOMAIN
            self._nxdomain_count += 1
        elif dns_info.rcode != 0:
            self._error_count += 1

        # Match with pending query for latency
        latency_ms = None
        pending = self._pending_queries.pop(dns_info.transaction_id, None)
        if pending:
            latency_ms = (packet.timestamp - pending.timestamp) * 1000

        # Convert answers to dict format for storage
        answers = []
        for answer in dns_info.answers:
            answers.append({
                "name": answer.name,
                "rtype": answer.rtype,
                "rtype_name": answer.rtype_name,
                "rdata": answer.rdata,
                "ttl": answer.ttl,
            })

        # Get query name from response queries or pending
        query_name = ""
        query_type = 0
        query_type_name = ""
        if dns_info.queries:
            query_name = dns_info.queries[0].name
            query_type = dns_info.queries[0].qtype
            query_type_name = dns_info.queries[0].qtype_name
        elif pending:
            query_name = pending.query_name
            query_type = pending.query_type
            query_type_name = pending.query_type_name

        # Record the response
        if query_name:
            self.dns_query_repo.record_query(
                timestamp=packet.timestamp,
                transaction_id=dns_info.transaction_id,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                query_name=query_name,
                query_type=query_type,
                query_type_name=query_type_name,
                is_response=True,
                response_code=dns_info.rcode,
                response_code_name=dns_info.rcode_name,
                answers=answers if answers else None,
                latency_ms=latency_ms,
            )

        # Cleanup old pending queries
        self._cleanup_pending()

    def _cleanup_pending(self) -> None:
        """Remove timed-out pending queries."""
        now = time.time()
        expired = [
            txid for txid, q in self._pending_queries.items()
            if now - q.timestamp > self.query_timeout
        ]
        for txid in expired:
            del self._pending_queries[txid]

    def get_recent_queries(self, limit: int = 50) -> List:
        """Get most recent DNS queries."""
        return self.dns_query_repo.get_recent_queries(limit=limit)

    def get_queries(
        self,
        limit: int = 100,
        query_name: Optional[str] = None,
        query_type: Optional[str] = None,
        only_responses: bool = False,
        only_nxdomain: bool = False,
    ) -> List:
        """Get DNS queries with optional filters."""
        return self.dns_query_repo.get_queries(
            limit=limit,
            query_name=query_name,
            query_type=query_type,
            only_responses=only_responses,
            only_nxdomain=only_nxdomain,
        )

    def get_stats(self, limit: int = 50, order_by: str = "query_count") -> List:
        """Get DNS statistics per domain."""
        return self.dns_query_repo.get_stats(limit=limit, order_by=order_by)

    def get_top_queried_domains(self, limit: int = 20) -> List[dict]:
        """Get top queried domains with counts."""
        return self.dns_query_repo.get_top_queried_domains(limit=limit)

    def get_nxdomain_domains(self, limit: int = 50) -> List[dict]:
        """Get domains with NXDOMAIN responses (potential DGA)."""
        return self.dns_query_repo.get_nxdomain_domains(limit=limit)

    def get_query_type_breakdown(self) -> List[dict]:
        """Get breakdown of DNS query types."""
        return self.dns_query_repo.get_query_type_breakdown()

    def get_dns_servers(self) -> List[dict]:
        """Get DNS servers used."""
        return self.dns_query_repo.get_dns_servers()

    @property
    def total_queries(self) -> int:
        """Total DNS queries seen."""
        return self._total_queries

    @property
    def total_responses(self) -> int:
        """Total DNS responses seen."""
        return self._total_responses

    @property
    def nxdomain_count(self) -> int:
        """Number of NXDOMAIN responses."""
        return self._nxdomain_count

    @property
    def error_count(self) -> int:
        """Number of error responses."""
        return self._error_count

    @property
    def pending_queries(self) -> int:
        """Number of pending queries awaiting response."""
        return len(self._pending_queries)

    def get_summary_stats(self) -> dict:
        """Get summary DNS statistics."""
        return {
            "total_queries": self._total_queries,
            "total_responses": self._total_responses,
            "nxdomain_count": self._nxdomain_count,
            "error_count": self._error_count,
            "pending_queries": len(self._pending_queries),
        }

    # ------------------------------------------------------------------
    # DNS tunneling detection
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_base_domain(name: str) -> str:
        """Extract base domain (last two labels) from FQDN.

        'abc123.data.evil.com' -> 'evil.com'
        """
        parts = name.rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return name

    def _track_tunnel_indicators(self, query_name: str, query_type: int) -> None:
        """Accumulate per-domain statistics used for tunneling detection."""
        base = self._extract_base_domain(query_name)
        self._domain_query_count[base] += 1

        # Track unique subdomains (the full name minus the base)
        self._domain_subdomains[base].add(query_name)

        # Track label lengths (excluding the base domain labels)
        labels = query_name.rstrip(".").split(".")
        if len(labels) > 2:
            subdomain_labels = labels[:-2]
            for label in subdomain_labels:
                self._domain_label_lengths[base].append(len(label))
                # Cap stored lengths to prevent unbounded growth
                if len(self._domain_label_lengths[base]) > 500:
                    self._domain_label_lengths[base] = self._domain_label_lengths[base][-300:]

        # Track TXT queries (commonly used in DNS tunneling)
        if query_type == 16:  # TXT
            self._domain_txt_count[base] += 1

    def check_tunnel_indicators(self, min_queries: int = 10) -> List[DNSTunnelIndicator]:
        """Evaluate all tracked domains for DNS tunneling indicators.

        Tunneling signals:
          1. High number of unique subdomains per base domain
          2. Long subdomain labels (data encoded in labels)
          3. High query volume to a single base domain
          4. High proportion of TXT queries
        """
        results = []

        with self._lock:
            domains = list(self._domain_query_count.keys())

        for domain in domains:
            count = self._domain_query_count.get(domain, 0)
            if count < min_queries:
                continue

            indicator = self._evaluate_domain(domain)
            if indicator and indicator.score > 0.2:
                results.append(indicator)

        results.sort(key=lambda i: i.score, reverse=True)
        return results

    def _evaluate_domain(self, domain: str) -> Optional[DNSTunnelIndicator]:
        """Score a single domain for tunneling likelihood."""
        count = self._domain_query_count.get(domain, 0)
        subdomains = self._domain_subdomains.get(domain, set())
        txt_count = self._domain_txt_count.get(domain, 0)
        label_lengths = self._domain_label_lengths.get(domain, [])

        indicator = DNSTunnelIndicator(
            domain=domain,
            query_count=count,
            subdomain_count=len(subdomains),
            txt_query_count=txt_count,
        )

        score = 0.0

        # Signal 1: Many unique subdomains (data encoded as subdomains)
        if len(subdomains) > 50:
            score += 0.35
            indicator.reasons.append(f"{len(subdomains)} unique subdomains")
        elif len(subdomains) > 20:
            score += 0.15
            indicator.reasons.append(f"{len(subdomains)} unique subdomains")

        # Signal 2: Long labels (encoded data)
        if label_lengths:
            avg_len = sum(label_lengths) / len(label_lengths)
            max_len = max(label_lengths)
            indicator.avg_label_length = avg_len
            indicator.max_label_length = max_len

            if avg_len > 30:
                score += 0.3
                indicator.reasons.append(f"avg label length {avg_len:.0f} chars")
            elif avg_len > 15:
                score += 0.15
                indicator.reasons.append(f"avg label length {avg_len:.0f} chars")

            if max_len > 50:
                score += 0.1
                indicator.reasons.append(f"max label {max_len} chars")

        # Signal 3: High proportion of TXT queries
        if count > 0 and txt_count > 0:
            txt_ratio = txt_count / count
            if txt_ratio > 0.5:
                score += 0.2
                indicator.reasons.append(f"{txt_ratio:.0%} TXT queries")
            elif txt_ratio > 0.2:
                score += 0.1
                indicator.reasons.append(f"{txt_ratio:.0%} TXT queries")

        # Signal 4: Very high query rate to a single domain
        if count > 200:
            score += 0.1
            indicator.reasons.append(f"{count} queries")

        indicator.score = min(1.0, score)
        return indicator
