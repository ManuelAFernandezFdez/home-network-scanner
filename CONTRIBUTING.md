# Contributing

Thank you for helping develop Home Network Scanner.

## Before Making a Change

- Read [SPEC.md](SPEC.md) for product requirements and [docs/security.md](docs/security.md) for security boundaries.
- Keep changes focused and consistent with the existing Python and documentation style.
- Do not add behavior that broadens scan scope, accesses credentials, escalates privileges, adds unapproved network traffic, or weakens output sanitization without first updating the security policy and specification.

## Development Expectations

- Target Python 3.10 or newer.
- Run the test suite with `python -m pytest`. Tests should not require a live network, Nmap privileges, or access to personal devices.
- Keep scan execution, result normalization, classification, and report generation independently testable.
- Prefer fixture-based tests for Nmap XML and generated reports. Unit tests should not require a live network, Nmap privileges, or access to personal devices.
- Do not run network scans during development unless you have explicit authorization for the selected network and devices. Never test against public or third-party targets.
- Include regression tests for security-sensitive changes, especially target validation, subprocess invocation, data retention, and Excel/Markdown/Mermaid escaping.
- Update the relevant project documentation whenever behavior, command-line options, supported platforms, or security boundaries change.

## Dependencies

Add only maintained dependencies that are needed for the feature. Explain new dependencies in the change description, constrain versions in the project's dependency configuration, and review their network, subprocess, native-code, and file-access behavior as applicable. Ordinary scans must remain offline and must not fetch packages or data automatically.

## Before Submitting

Run the documented tests relevant to your change. In the change description, summarize behavior changes, note any security-relevant effects, and list checks run or any checks that could not be run.