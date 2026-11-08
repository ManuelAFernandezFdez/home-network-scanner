from datetime import datetime, timezone

from openpyxl import load_workbook

from home_network_scanner.models import Device, ScanOptions, ScanResult, Service
from home_network_scanner.reports import render_markdown, write_reports


def make_result(hostname="living-room-tv"):
    options = ScanOptions(network="192.168.1.0/24", interface="lan0")
    return ScanResult(
        network=options.network,
        interface=options.interface,
        started_at=datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 11, 8, 12, 1, tzinfo=timezone.utc),
        options=options,
        devices=[
            Device(
                ip="192.168.1.20",
                hostname=hostname,
                mac="00:11:22:33:44:55",
                vendor="Example Vendor",
                device_type="Media/IoT",
                device_type_confidence="medium",
                services=[Service(port=443, protocol="tcp", name="https")],
            )
        ],
        nmap_version="7.95",
    )


def test_mermaid_escapes_device_control_text():
    report = render_markdown(make_result('tv"] --> injected["bad | value'))
    assert 'device_1["192.168.1.20 | tv\' ) --> injected(\'bad | value | Media/IoT"]' in report
    assert "    injected[" not in report
    assert "\\|" in report


def test_reports_include_expected_sheets_and_sanitize_formula(tmp_path):
    result = make_result('=HYPERLINK("https://example.invalid")')
    workbook_path, markdown_path = write_reports(result, tmp_path)

    assert workbook_path.name == "network-inventory-20261108-120000.xlsx"
    assert markdown_path.name == "network-map-20261108-120000.md"
    workbook = load_workbook(workbook_path, data_only=False)
    assert workbook.sheetnames == ["Devices", "Services", "Scan Summary"]
    assert workbook["Devices"]["B2"].value.startswith("'=")
    assert workbook["Services"]["A2"].value == "192.168.1.20"
    assert "flowchart TD" in markdown_path.read_text(encoding="utf-8")


def test_report_generation_does_not_overwrite_existing_files(tmp_path):
    first = write_reports(make_result(), tmp_path)
    second = write_reports(make_result(), tmp_path)
    assert first[0] != second[0]
    assert first[1] != second[1]
    assert all(path.exists() for path in (*first, *second))


def test_markdown_handles_empty_scan():
    result = make_result()
    result.devices = []
    report = render_markdown(result)
    assert "No responsive devices found" in report
    assert "| No responsive devices |" in report