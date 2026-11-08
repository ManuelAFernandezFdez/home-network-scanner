# Security Policy

## Purpose

This policy defines the security boundaries for the Home Network Scanner. It applies to the application, its dependencies, build and test workflows, and generated reports. The scanner is a local inventory tool: it observes an explicitly authorized home network and must not attempt to gain access to devices.

The requirements in this document are durable project constraints. Implementation details and feature acceptance criteria live in `SPEC.md`. If a proposed feature conflicts with this policy, do not implement it until the policy has been explicitly reviewed and updated.

## Network Scope

- Scan only one user-confirmed IPv4 subnet per run, within RFC 1918 private address space and directly connected to the selected local interface.
- Reject malformed, public, non-local, or otherwise unsupported targets before starting a scanner process.
- Never scan adjacent subnets, public addresses, or targets inferred from host responses. Do not silently enumerate all interfaces or routes and scan them.
- Display the target, interface, address count, scan options, and expected outputs before a scan. Require additional confirmation for ranges larger than `/24`.
- Use bounded timeouts and concurrency. Keep discovery conservative; service/version and OS fingerprinting are optional and must be disclosed before use.
- Do not use vulnerability, brute-force, exploit, intrusive, or other Nmap NSE scripts. Do not attempt authentication, credential testing, configuration changes, or persistence.
- A direct connection or private address does not prove that the user owns or is authorized to scan the network. The user must confirm authorization.

## Operating System and Process Access

- Run with the current user's privileges. Do not request administrator/root access, change system settings, install drivers, or escalate privileges.
- Limit local reads to interface/address information and neighbor-table data needed for discovery, plus files explicitly selected as output destinations.
- Nmap is the only permitted external scanner process unless a separately reviewed design adds another tool. Locate a trusted executable and invoke it with an argument array, `shell=False`, validated parameters, a controlled environment, and a finite timeout.
- Never build shell commands from user input or scan results. Never accept arbitrary executable paths, shell fragments, or scanner flags from untrusted input. Do not auto-install or update operating-system tools.
- Parse Nmap XML as data. Treat malformed or unexpectedly large output as an error or partial result; do not execute content from scanner output.
- A permission limitation must result in a clear warning or a reduced-capability scan, not a privilege escalation attempt.

## Credentials and Secret Stores

- The scanner has no need for credentials. It must not read, request, store, transmit, or test passwords, tokens, private keys, browser credentials, or authentication cookies.
- Do not access macOS Keychain, Windows Credential Manager, Linux Secret Service/keyrings, password-manager applications, or equivalent operating-system secret stores.
- Do not add a credential-based feature without a separately reviewed threat model, an explicit user need and consent flow, narrowly scoped access, and an update to this policy and the specification.

## Network Egress and Data Handling

- Keep scan results on the user's machine. Do not add telemetry, analytics, cloud reporting, automatic uploads, or remote control channels.
- Ordinary scans must work offline and must not contact third-party services. If reverse DNS is enabled, disclose that the operating system's configured resolver may receive lookup requests; make name resolution configurable and report whether it was used.
- Any future remote lookup or data update must be disabled by default, separately opt-in, documented with the destination and data sent, and designed so scan results are not uploaded.
- Store raw scanner output only when the user explicitly asks for it. Otherwise use temporary storage and remove it after parsing, including on normal error paths.
- Do not overwrite existing outputs without explicit consent. Avoid unnecessary diagnostic logging of hostnames, addresses, MAC addresses, banners, or other inventory details.
- Reports may reveal the layout and devices on a private network. Tell users where reports are written and leave retention/deletion under the user's control.
- Sanitize spreadsheet values that could be interpreted as formulas. Escape or normalize all device-derived data in Markdown and Mermaid so it cannot change document or diagram structure.

## Dependencies and Updates

- Use maintained, purpose-appropriate dependencies and constrain versions through the project's dependency configuration.
- Review dependencies that execute native code, invoke subprocesses, access the network, or handle output files with particular care.
- Do not fetch OUI databases, packages, or other data during a scan. Any update mechanism must be explicit, separately opt-in, and documented.
- Keep secrets out of source control, test fixtures, logs, and generated example reports.

## Required Verification

Security-sensitive behavior must have automated tests where practical. At minimum, tests must verify that:

- Invalid, public, non-local, and out-of-scope targets are rejected before Nmap is invoked.
- Nmap is invoked without a shell, with validated arguments, and with an enforced timeout; no disallowed scripts or options are included.
- Scan results cannot cause command execution, spreadsheet formula evaluation, or unintended Markdown/Mermaid structure.
- Ordinary scans do not make third-party requests, access credential stores, or write outside the selected output location and temporary storage.
- Cancellation, timeouts, permission limitations, malformed output, and partial results fail safely and do not leave unexpected temporary files.

Code review must call out changes to target validation, process execution, privilege requirements, credential or secret access, network egress, data retention, and report generation. A change to any of these boundaries requires updating this policy, `SPEC.md`, and the corresponding tests in the same change.

## Security Issues

Until the project publishes a dedicated security contact or disclosure process, report suspected vulnerabilities privately to the project maintainers rather than including sensitive details in a public issue.