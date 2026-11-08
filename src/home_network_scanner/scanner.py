"""Bounded Nmap process execution and device-result normalization."""

import ipaddress
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Callable

import nmap

from .models import Device, LocalNetwork, ScanOptions, ScanResult, Service
from .network import validate_target

MAX_XML_BYTES = 20 * 1024 * 1024
MAX_PORTS = 100


class ScanCancelled(Exception):
    """Raised when a user cancels an active scan."""


class ScanError(RuntimeError):
    """Raised when a scan cannot safely complete."""


def build_nmap_command(executable: str, options: ScanOptions, target: ipaddress.IPv4Network) -> list[str]:
    if not 5 <= options.timeout_seconds <= 3600:
        raise ValueError("Timeout must be between 5 and 3,600 seconds.")
    if options.detect_services or options.detect_os:
        if not options.ports or len(options.ports) > MAX_PORTS:
            raise ValueError(f"Select between 1 and {MAX_PORTS} ports for detailed detection.")
        if any(not isinstance(port, int) or not 1 <= port <= 65535 for port in options.ports):
            raise ValueError("Ports must be integers between 1 and 65,535.")
    if len(set(options.ports)) != len(options.ports):
        raise ValueError("Port list must not contain duplicates.")

    command = [
        executable,
        "-oX",
        "-",
        "--reason",
        "--max-retries",
        "1",
        "--host-timeout",
        "60s",
        "-T2",
    ]
    command.append("-R" if options.resolve_hostnames else "-n")

    if options.detect_services:
        command.extend(("-sV", "--version-light"))
    if options.detect_os:
        command.append("-O")
    if options.detect_services or options.detect_os:
        command.extend(("-p", ",".join(str(port) for port in options.ports)))
    else:
        command.append("-sn")

    command.append(str(target))
    return command


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()


def _run_process(
    command: list[str],
    timeout_seconds: int,
    cancel_event: threading.Event,
    progress: Callable[[str], None] | None = None,
) -> tuple[str, str, int]:
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C",
        "LC_ALL": "C",
    }
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            env=environment,
        )
    except OSError as error:
        raise ScanError(f"Could not start Nmap: {error}") from error

    started = time.monotonic()
    next_update = started
    while True:
        if cancel_event.is_set():
            _terminate_process(process)
            raise ScanCancelled("Scan cancelled.")
        elapsed = time.monotonic() - started
        if elapsed >= timeout_seconds:
            _terminate_process(process)
            raise ScanError(f"Scan exceeded the {timeout_seconds}-second time limit.")
        try:
            stdout, stderr = process.communicate(timeout=min(0.25, timeout_seconds - elapsed))
            break
        except subprocess.TimeoutExpired:
            if progress is not None and time.monotonic() >= next_update:
                progress(f"Scanning... {int(elapsed)} seconds elapsed")
                next_update = time.monotonic() + 5

    if len(stdout.encode("utf-8", errors="replace")) > MAX_XML_BYTES:
        raise ScanError("Nmap output exceeded the 20 MiB safety limit.")
    return stdout, stderr, process.returncode


def _confidence(accuracy: object) -> str:
    try:
        value = int(str(accuracy))
    except (TypeError, ValueError):
        return "unknown"
    if value >= 95:
        return "high"
    if value >= 80:
        return "medium"
    return "low"


def _classify_device(device: Device) -> None:
    hostname = device.hostname.lower()
    vendor = device.vendor.lower()
    ports = {service.port for service in device.services}
    services = " ".join(service.name.lower() for service in device.services)

    if ports.intersection({515, 631, 9100}) or any(
        brand in vendor for brand in ("brother", "canon", "epson", "hewlett", "lexmark")
    ):
        device.device_type = "Printer"
        device.device_type_confidence = "high" if ports.intersection({515, 631, 9100}) else "medium"
        device.evidence.append("Printer service port or manufacturer vendor string")
    elif any(token in hostname for token in ("router", "gateway", "access-point", "accesspoint")):
        device.device_type = "Network equipment"
        device.device_type_confidence = "medium"
        device.evidence.append("Hostname contains a network-equipment label")
    elif ports.intersection({554, 1883, 8008, 8009, 8883}) or "rtsp" in services:
        device.device_type = "Media/IoT"
        device.device_type_confidence = "medium"
        device.evidence.append("Media or IoT service port")
    elif ports.intersection({22, 445, 3389}) or device.os_family:
        device.device_type = "Computer"
        device.device_type_confidence = "low" if not device.os_family else device.os_confidence
        device.evidence.append("Computer-related service or OS fingerprint")
    elif ports.intersection({53, 80, 443}) and any(
        token in hostname for token in ("router", "gateway", "nas", "synology", "qnap")
    ):
        device.device_type = "Network equipment"
        device.device_type_confidence = "low"
        device.evidence.append("Hostname and common management service ports")


def parse_nmap_xml(xml_output: str) -> tuple[list[Device], str]:
    """Parse Nmap XML through python-nmap and normalize observed host data."""
    try:
        parser = nmap.PortScanner()
        parsed = parser.analyse_nmap_xml_scan(xml_output)
    except Exception as error:
        raise ScanError(f"Could not parse Nmap XML: {error}") from error

    if not isinstance(parsed, dict):
        raise ScanError("Nmap returned an unexpected XML data structure.")
    host_records = parsed.get("scan", {})
    if not isinstance(host_records, dict):
        raise ScanError("Nmap XML did not contain a valid host list.")

    devices: list[Device] = []
    for ip, record in host_records.items():
        if not isinstance(record, dict):
            continue
        addresses = record.get("addresses", {})
        mac = str(addresses.get("mac", "")) if isinstance(addresses, dict) else ""
        vendor_table = record.get("vendor", {})
        vendor = str(vendor_table.get(mac, "")) if mac and isinstance(vendor_table, dict) else ""
        hostnames = record.get("hostnames", [])
        hostname = ""
        if isinstance(hostnames, list) and hostnames:
            hostname = str(hostnames[0].get("name", ""))

        device = Device(ip=str(ip), hostname=hostname, mac=mac, vendor=vendor)
        for protocol in ("tcp", "udp"):
            ports = record.get(protocol, {})
            if not isinstance(ports, dict):
                continue
            for port_text, port_data in ports.items():
                if not isinstance(port_data, dict) or port_data.get("state") != "open":
                    continue
                service = port_data.get("name", "")
                device.services.append(
                    Service(
                        port=int(port_text),
                        protocol=protocol,
                        name=str(service or ""),
                        product=str(port_data.get("product", "") or ""),
                        version=str(port_data.get("version", "") or ""),
                        extra_info=str(port_data.get("extrainfo", "") or ""),
                    )
                )
                if service:
                    device.evidence.append(f"Observed {protocol}/{port_text} service: {service}")

        os_matches = record.get("osmatch", [])
        if isinstance(os_matches, list) and os_matches:
            match = max(os_matches, key=lambda item: int(item.get("accuracy", 0) or 0))
            device.os_product = str(match.get("name", ""))
            device.os_confidence = _confidence(match.get("accuracy"))
            classes = match.get("osclass", [])
            if isinstance(classes, list) and classes:
                os_class = classes[0]
                device.os_family = str(os_class.get("osfamily", ""))
                device.os_version = str(os_class.get("osgen", ""))
            if device.os_product:
                device.evidence.append(f"Nmap OS guess ({match.get('accuracy', 'unknown')}%): {device.os_product}")

        _classify_device(device)
        devices.append(device)

    nmap_data = parsed.get("nmap", {})
    version = "Unknown"
    if isinstance(nmap_data, dict) and nmap_data.get("version"):
        version = str(nmap_data["version"])
    return sorted(devices, key=lambda item: ipaddress.ip_address(item.ip)), version


def scan_network(
    options: ScanOptions,
    cancel_event: threading.Event | None = None,
    progress: Callable[[str], None] | None = None,
    local_networks: list[LocalNetwork] | None = None,
) -> ScanResult:
    """Run one bounded Nmap scan against a validated local IPv4 subnet."""
    cancel_event = cancel_event or threading.Event()
    target = validate_target(options.network, options.interface, local_networks)
    executable = shutil.which("nmap")
    if executable is None:
        raise ScanError("Nmap is not installed or is not available on PATH.")

    command = build_nmap_command(executable, options, target)
    started_at = datetime.now(timezone.utc)
    if progress is not None:
        progress(f"Starting Nmap host discovery for {target}")
    xml_output, stderr, return_code = _run_process(
        command,
        options.timeout_seconds,
        cancel_event,
        progress,
    )
    if return_code != 0 and not xml_output.strip():
        detail = " ".join(stderr.split())[:500]
        raise ScanError(f"Nmap exited with status {return_code}. {detail}".strip())
    devices, nmap_version = parse_nmap_xml(xml_output)
    warnings: list[str] = []
    if stderr.strip():
        warnings.append("Nmap reported: " + " ".join(stderr.split())[:500])
    if return_code != 0:
        warnings.append(f"Nmap exited with status {return_code}; results may be incomplete.")
    if options.detect_os and any("requires root" in warning.lower() for warning in warnings):
        warnings.append("OS detection may require privileges; the application will not request elevation.")

    return ScanResult(
        network=str(target),
        interface=options.interface,
        started_at=started_at,
        finished_at=datetime.now(timezone.utc),
        options=options,
        devices=devices,
        nmap_version=nmap_version,
        warnings=warnings,
        partial=return_code != 0,
    )