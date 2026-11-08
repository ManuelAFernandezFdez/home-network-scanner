"""Excel and Mermaid Markdown report generation."""

import os
import re
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.utils import get_column_letter

from .models import Device, ScanResult


def _safe_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _markdown_text(value: object) -> str:
    text = "" if value is None else str(value)
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    return re.sub(r"\s+", " ", text).strip().replace("|", "\\|")


def _mermaid_label(value: object) -> str:
    text = "" if value is None else str(value)
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    text = text.replace('"', "'").replace("[", "(").replace("]", " )")
    text = text.replace("<", "")
    return re.sub(r"\s+", " ", text).strip()


def _device_label(device: Device) -> str:
    parts = [device.ip]
    if device.hostname:
        parts.append(device.hostname)
    if device.device_type != "Unknown":
        parts.append(device.device_type)
    return " | ".join(parts)


def render_markdown(result: ScanResult) -> str:
    lines = [
        "# Home Network Inventory",
        "",
        f"- **Network:** `{result.network}`",
        f"- **Interface:** `{_markdown_text(result.interface)}`",
        f"- **Scan started:** {result.started_at.isoformat()}",
        f"- **Scan finished:** {result.finished_at.isoformat()}",
        f"- **Nmap version:** {_markdown_text(result.nmap_version)}",
        f"- **Detection options:** services={'on' if result.options.detect_services else 'off'}, "
        f"OS={'on' if result.options.detect_os else 'off'}, "
        f"hostname resolution={'on' if result.options.resolve_hostnames else 'off'}",
        f"- **Status:** {'partial' if result.partial else 'complete'}",
        "",
        "## Network Map",
        "",
        "```mermaid",
        "flowchart TD",
        f'    lan["Subnet {_mermaid_label(result.network)}"]',
    ]
    if result.devices:
        for index, device in enumerate(result.devices, start=1):
            lines.append(f'    device_{index}["{_mermaid_label(_device_label(device))}"]')
            lines.append(f"    lan --- device_{index}")
    else:
        lines.append('    none["No responsive devices found"]')
        lines.append("    lan --- none")
    lines.extend(
        [
            "```",
            "",
            "## Devices",
            "",
            "| IP | Hostname | MAC | Vendor | Type | OS guess | Confidence | Open services |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for device in result.devices:
        os_guess = " ".join(value for value in (device.os_family, device.os_product, device.os_version) if value)
        services = ", ".join(f"{item.protocol}/{item.port} {item.name}".strip() for item in device.services)
        lines.append(
            "| "
            + " | ".join(
                _markdown_text(value)
                for value in (
                    device.ip,
                    device.hostname,
                    device.mac,
                    device.vendor,
                    device.device_type,
                    os_guess or "Unknown",
                    f"device: {device.device_type_confidence}; OS: {device.os_confidence}",
                    services,
                )
            )
            + " |"
        )
    if not result.devices:
        lines.append("| No responsive devices | | | | | | | |")

    lines.extend(
        [
            "",
            "## Method and Limitations",
            "",
            "The diagram connects discovered hosts to the scanned subnet only; it does not claim physical topology. "
            "Device type and operating-system details are estimates based on network-visible evidence. "
            "Firewalls, sleeping devices, and network isolation may hide hosts. No credentials were used.",
        ]
    )
    if result.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {_markdown_text(warning)}" for warning in result.warnings)
    return "\n".join(lines) + "\n"


def _style_sheet(sheet) -> None:
    sheet.freeze_panes = "A2"
    if sheet.max_row >= 1:
        sheet.auto_filter.ref = sheet.dimensions
    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="245A4A")
    for column in sheet.columns:
        width = max((len(str(cell.value or "")) for cell in column), default=10)
        sheet.column_dimensions[get_column_letter(column[0].column)].width = min(max(width + 2, 12), 60)


def _write_workbook(result: ScanResult, path: Path) -> None:
    workbook = Workbook()
    devices_sheet = workbook.active
    devices_sheet.title = "Devices"
    devices_sheet.append(
        [
            "IP",
            "Hostname",
            "MAC",
            "Vendor",
            "Device Type",
            "Device Type Confidence",
            "OS Family",
            "OS Product Guess",
            "OS Version Guess",
            "OS Confidence",
            "Evidence",
            "Discovery Method",
            "Scan Timestamp",
        ]
    )
    for device in result.devices:
        devices_sheet.append(
            [
                _safe_cell(device.ip),
                _safe_cell(device.hostname),
                _safe_cell(device.mac),
                _safe_cell(device.vendor),
                _safe_cell(device.device_type),
                _safe_cell(device.device_type_confidence),
                _safe_cell(device.os_family),
                _safe_cell(device.os_product),
                _safe_cell(device.os_version),
                _safe_cell(device.os_confidence),
                _safe_cell("; ".join(device.evidence)),
                _safe_cell(device.discovery_method),
                _safe_cell(result.started_at.isoformat()),
            ]
        )

    services_sheet = workbook.create_sheet("Services")
    services_sheet.append(["IP", "Hostname", "Protocol", "Port", "Service", "Product", "Version", "Extra Info"])
    for device in result.devices:
        for service in device.services:
            services_sheet.append(
                [
                    _safe_cell(device.ip),
                    _safe_cell(device.hostname),
                    _safe_cell(service.protocol),
                    service.port,
                    _safe_cell(service.name),
                    _safe_cell(service.product),
                    _safe_cell(service.version),
                    _safe_cell(service.extra_info),
                ]
            )

    summary = workbook.create_sheet("Scan Summary")
    summary.append(["Field", "Value"])
    details = [
        ("Target CIDR", result.network),
        ("Interface", result.interface),
        ("Start time", result.started_at.isoformat()),
        ("End time", result.finished_at.isoformat()),
        ("Nmap version", result.nmap_version),
        ("Service detection", result.options.detect_services),
        ("OS detection", result.options.detect_os),
        ("Hostname resolution", result.options.resolve_hostnames),
        ("Device count", len(result.devices)),
        ("Status", "partial" if result.partial else "complete"),
        ("Warnings", "; ".join(result.warnings)),
    ]
    for label, value in details:
        summary.append([_safe_cell(label), _safe_cell(value)])

    for sheet in workbook.worksheets:
        _style_sheet(sheet)
    workbook.save(path)


def _reserve_paths(output_dir: Path, prefix: str, timestamp: str) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_prefix = re.sub(r"[^A-Za-z0-9._-]+", "-", prefix).strip(".-_")
    if not safe_prefix:
        raise ValueError("Filename prefix must contain letters or numbers.")
    for suffix in range(1000):
        collision = f"-{suffix}" if suffix else ""
        stem = f"{safe_prefix}{collision}"
        workbook_path = output_dir / f"{stem}-inventory-{timestamp}.xlsx"
        markdown_path = output_dir / f"{stem}-map-{timestamp}.md"
        reserved: list[Path] = []
        try:
            for path in (workbook_path, markdown_path):
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(descriptor)
                reserved.append(path)
            return workbook_path, markdown_path
        except FileExistsError:
            for path in reserved:
                path.unlink(missing_ok=True)
    raise FileExistsError("Could not find an unused report filename.")


def write_reports(result: ScanResult, output_dir: str | Path, prefix: str = "network") -> tuple[Path, Path]:
    """Write non-overwriting Excel and Markdown reports and return their paths."""
    timestamp = result.started_at.strftime("%Y%m%d-%H%M%S")
    workbook_path, markdown_path = _reserve_paths(Path(output_dir), prefix, timestamp)
    try:
        _write_workbook(result, workbook_path)
        markdown_path.write_text(render_markdown(result), encoding="utf-8")
    except Exception:
        workbook_path.unlink(missing_ok=True)
        markdown_path.unlink(missing_ok=True)
        raise
    return workbook_path, markdown_path