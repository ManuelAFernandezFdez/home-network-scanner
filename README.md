# Home Network Scanner

A Python desktop application for inventorying devices on an authorized home IPv4 network. It reports observed IP addresses and available device information, with clearly qualified estimates for device type and operating system where evidence permits.

## Project Status

An initial desktop implementation is available. The project is still under development; see [SPEC.md](SPEC.md) for the intended behavior and acceptance criteria.

## Behavior

- Scan one user-confirmed, directly connected RFC 1918 IPv4 subnet at a time.
- Use Nmap for conservative host discovery, with optional service/version and OS detection.
- Generate an Excel inventory and a Markdown report containing a Mermaid network diagram.
- Provide a PySide6 desktop interface with scan progress and cancellation.
- Keep results local and avoid credential access, privilege escalation, vulnerability testing, and telemetry.

OS and device identification will be estimates based on observable network evidence, not guarantees. Results may be incomplete because of firewalls, sleeping devices, or network isolation.

## Project Documents

- [Specification](SPEC.md): planned behavior, outputs, interface, and acceptance criteria.
- [Security Policy](docs/security.md): durable constraints for network scope, local access, credentials, data handling, and verification.
- [Contribution Guide](CONTRIBUTING.md): expectations for changes and tests.

## Install and run

Requires Python 3.10 or newer and Nmap installed separately. The application does not install Nmap or elevate its own privileges.

```sh
python -m pip install .
home-network-scanner
```

The app only scans a private IPv4 subnet directly connected to the selected local interface. Only scan networks you are authorized to inventory.