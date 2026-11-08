# Home Network Scanner Specification

## 1. Purpose

Build a Python command-line application that inventories devices on a user's authorized home local network. It discovers responsive hosts, records IP and available identifying information, and makes evidence-based estimates of device type, operating system, and OS version when possible.

The application produces:

- An Excel workbook (`.xlsx`) containing the full inventory and scan metadata.
- A Markdown report (`.md`) containing a Mermaid network diagram and a concise device table.

The tool is for inventory and troubleshooting, not for exploitation or access to devices.

## 2. Scope and Safety

### Initial scope

- Support IPv4 private LANs in the RFC 1918 ranges: `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.
- Scan one explicitly selected or entered subnet per run. A subnet must be on a directly connected local interface and inside an RFC 1918 range.
- Support common home network sizes (up to `/16`), but show the estimated number of addresses and require confirmation for scans larger than `/24`.
- Discover hosts and collect only network-visible metadata. No login, credential testing, configuration changes, exploit attempts, or persistence.
- Do not scan public IP ranges, arbitrary internet targets, or networks not authorized by the user.

### Safe operation

- Require the user to provide or confirm the target subnet before scanning; never silently scan every interface or route.
- Display the resolved target range, selected interface, expected address count, scan methods, and output paths before execution.
- Use conservative timing and bounded concurrency. Provide a stop/cancel mechanism and handle interruption cleanly.
- Use only ordinary host-discovery, limited port/service identification, and optional OS-detection probes. Do not run Nmap NSE vulnerability, brute-force, exploit, or intrusive scripts.
- Make OS fingerprinting and service/version probing explicit opt-in options because they send additional probes and may be inaccurate or trigger device alerts.
- Warn that results are limited to what devices expose and the current network vantage point. Guest-network isolation, firewalls, sleeping devices, and wireless client isolation can hide devices.

### Security requirements

- Treat `docs/security.md` as the durable security policy. This specification defines the scanner's required behavior; implementation, tests, and review must enforce it.
- Limit network probes to the user-confirmed, directly connected private IPv4 subnet. Do not follow redirects, scan discovered adjacent networks, or broaden scope based on host responses.
- Run Nmap as a child process with a fixed executable, argument arrays, `shell=False`, validated arguments, and a timeout. Never invoke a shell, arbitrary user-supplied command, or Nmap scripts; never auto-install tools or request elevated privileges.
- Access only the network interfaces and neighbor information needed for discovery, plus the selected output directory. Do not read credentials, browser profiles, password-manager data, or OS credential stores such as macOS Keychain.
- Keep scan data local. Do not upload results or enable telemetry. Any optional network lookup or data update must be separately disclosed, opt-in, and documented.
- Treat hostnames, banners, MAC vendor strings, and scan output as untrusted input. Sanitize them for Excel and escape them for Markdown/Mermaid; do not execute or interpret them as commands or markup.
- Do not log sensitive scan details unnecessarily. Preserve raw scanner output only when explicitly requested, and avoid overwriting existing reports without consent.
- Changes to target scope, privileges, credential access, subprocess behavior, or outbound network access require an update to `docs/security.md`, tests, and explicit review.

## 3. User Workflow

1. The user starts the CLI and sees available local interfaces and IPv4 subnets.
2. The user selects a detected directly connected private subnet or enters one.
3. The application validates that the subnet is private and directly connected, then summarizes the planned scan.
4. The user chooses discovery defaults and whether to enable optional service/version and OS detection.
5. The scanner runs with progress and a clear way to cancel.
6. The application writes the Excel workbook and Mermaid Markdown report to the chosen output directory, then prints their paths and a short result summary.

The tool must not require an interactive session to be embedded in a GUI. A CLI is the initial interface.

## 4. Functional Requirements

### 4.1 Network discovery

- Enumerate local network interfaces and directly connected IPv4 subnets using a maintained Python library such as `psutil`.
- Validate user-provided CIDRs with Python's `ipaddress` module. Reject non-private, non-local, malformed, or unsupported targets before invoking a scanner.
- Discover active hosts using Nmap host discovery (for example, ARP discovery on an Ethernet segment and appropriate ICMP/TCP discovery where ARP is unavailable).
- Allow an optional bounded TCP port set for service identification. Keep the default port list small and configurable; do not perform a full 65,535-port scan by default.
- Invoke Nmap using argument arrays (not shell interpolation), request XML output, and parse the XML with a standard XML parser. Check that Nmap is installed and report actionable errors if it is missing or exits unsuccessfully.
- Do not require elevated privileges for the basic scan when possible. Explain when privileges may improve local ARP or OS detection results; do not attempt privilege escalation.

### 4.2 Device identification

For each discovered host, record available evidence, including:

- IPv4 address and hostname/reverse-DNS name, if resolved.
- MAC address and vendor, if visible on the local link and available from Nmap or a local neighbor table.
- Reachability and discovery method.
- Open ports, transport protocol, detected service, and service/version banner when requested and available.
- OS family, product, and version guess when requested and available.
- Inferred device category (for example: router/networking, computer, phone/tablet, printer, media/IoT, or unknown).
- Confidence and evidence/source for every inferred OS, version, vendor, and device category.

Identification must distinguish observations from inferences. Use `unknown` rather than inventing a value. OS and device-type inference should be rule-based and explainable in the report, using available fingerprints, service evidence, hostname, and vendor data. Do not present an OS guess as certain or claim an exact version if the evidence supports only a family or range.

### 4.3 Output files

Generate both files for every successful scan:

- `network-inventory-<timestamp>.xlsx`
- `network-map-<timestamp>.md`

The user may select an output directory and filename prefix. Do not overwrite existing files unless the user explicitly requests it.

#### Excel workbook

Include at least these sheets:

1. **Devices**: one row per discovered IP, with IP, hostname, MAC, vendor, inferred device type, OS/product/version guess, confidence, discovery method, and scan timestamp.
2. **Services**: one row per observed open port/service, linked to the device IP, including protocol, port, service name, and version/banner when collected.
3. **Scan Summary**: target CIDR, interface, start/end time, options, tool versions, counts, warnings, and any partial-scan status.

Use clear column names, frozen headers, filters, and sensible widths. Store unknown values as blank or `Unknown`, consistently. Sanitize strings that could be interpreted as spreadsheet formulas.

#### Mermaid Markdown report

- Include a Mermaid `flowchart` or `graph` block that renders in common Mermaid-compatible Markdown viewers.
- Show the scanned subnet and one node per discovered device, with a readable label containing IP and, where available, hostname and inferred type.
- Connect devices to the subnet node; do not imply router-to-device connectivity or physical topology that the scan cannot establish.
- Escape or normalize device-derived text so hostnames, banners, or other input cannot break the Mermaid syntax or inject unintended diagram directives.
- Include a Markdown table with key device details and a short methodology, scan timestamp, options, and limitations.
- The report must remain readable when there are no hosts beyond the scanning machine or when some fields are unknown.

## 5. Non-Functional Requirements

- Python 3.10 or newer.
- Use maintained dependencies and pin or constrain versions in the project dependency definition.
- Keep scan execution, result normalization, classification, and report generation in separable modules so report generation can be tested without running a network scan.
- Provide useful errors for invalid scope, missing Nmap, permission limitations, timeouts, malformed tool output, and file-write failures. A partial scan should still be reportable when results are available.
- Do not transmit scan results or telemetry off the user's machine.
- Keep raw Nmap XML only when explicitly requested; otherwise use temporary storage and remove it after parsing.
- Provide a `--version`, `--help`, configurable timeout, output directory, and a dry-run/plan mode.

## 6. Suggested CLI

```text
home-network-scanner [--network CIDR] [--interface NAME]
                     [--output-dir PATH] [--prefix NAME]
                     [--ports PORTS] [--service-detection]
                     [--os-detection] [--timeout SECONDS]
                     [--dry-run]
```

Defaults should favor a conservative host-discovery scan with no OS or service/version detection. The application should print a clear confirmation prompt before a real scan; a future non-interactive mode may require an explicit `--yes` flag and must retain all target validation.

## 7. Data and Classification

Normalize scanner results into a device record keyed by IP and a collection of service records. Preserve the source of each value (for example, Nmap fingerprint, reverse DNS, neighbor table, or OUI lookup) and a confidence level for inferred values. Classification rules should be deterministic, documented, and covered by tests. Vendor lookup data may be bundled or fetched only through a separately documented, opt-in update mechanism; ordinary scans must work offline.

Recommended confidence levels are `high`, `medium`, `low`, and `unknown`. A confidence level describes the strength of the evidence, not the likelihood that a particular device is safe or trustworthy.

## 8. Testing and Acceptance Criteria

- Unit tests cover CIDR validation, directly connected subnet checks, result normalization, classification rules, Mermaid escaping, spreadsheet formula sanitization, and both report formats.
- Tests use fixture Nmap XML and do not require a live network or elevated permissions.
- Invalid, public, non-local, and malformed target ranges are rejected before Nmap is called.
- A basic run on an authorized private subnet produces both valid output files, including scan metadata and every discovered host returned by the scanner.
- Excel sheets contain the required columns and correctly associate services with device IPs.
- The Mermaid diagram parses/render-checks in a compatible test or is covered by targeted escaping tests; generated device text cannot alter diagram structure.
- OS and device classifications include provenance and confidence, and unknown or conflicting evidence is reported honestly.
- Large subnet confirmation, cancellation, timeout, missing Nmap, and partial-scan behavior are verified.
- No default scan option invokes vulnerability, brute-force, exploit, or other intrusive scripts.

## 9. Out of Scope for the Initial Version

- Scanning public networks, remote networks, or multiple subnets in one run.
- Exploitation, vulnerability assessment, credential discovery, authentication, or device configuration.
- Guaranteed identification of device model, OS, or exact OS version.
- Continuous monitoring, scheduled scans, alerting, a web interface, and device management.
- Claiming physical topology, trust, ownership, or device identity beyond observed network evidence.