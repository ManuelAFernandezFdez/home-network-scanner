"""Shared data structures for scanning and report generation."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class LocalNetwork:
    interface: str
    address: str
    network: str


@dataclass(frozen=True)
class ScanOptions:
    network: str
    interface: str
    detect_services: bool = False
    detect_os: bool = False
    resolve_hostnames: bool = False
    ports: tuple[int, ...] = (22, 53, 80, 443, 445, 554, 631, 3389, 8080, 8443, 9100)
    timeout_seconds: int = 300


@dataclass
class Service:
    port: int
    protocol: str
    name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""


@dataclass
class Device:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    device_type: str = "Unknown"
    device_type_confidence: str = "unknown"
    os_family: str = ""
    os_product: str = ""
    os_version: str = ""
    os_confidence: str = "unknown"
    discovery_method: str = "Nmap host discovery"
    evidence: list[str] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)


@dataclass
class ScanResult:
    network: str
    interface: str
    started_at: datetime
    finished_at: datetime
    options: ScanOptions
    devices: list[Device]
    nmap_version: str = "Unknown"
    warnings: list[str] = field(default_factory=list)
    partial: bool = False