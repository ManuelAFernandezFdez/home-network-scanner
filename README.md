# Home Network Scanner

A planned Python command-line tool for inventorying devices on an authorized home IPv4 network. It will report observed IP addresses and available device information, with clearly qualified estimates for device type and operating system where evidence permits.

## Project Status

This repository is in the specification stage; the scanner has not yet been implemented. Installation and run instructions will be added when the application and its packaging are in place.

## Planned Behavior

- Scan one user-confirmed, directly connected RFC 1918 IPv4 subnet at a time.
- Use Nmap for conservative host discovery, with optional service/version and OS detection.
- Generate an Excel inventory and a Markdown report containing a Mermaid network diagram.
- Keep results local and avoid credential access, privilege escalation, vulnerability testing, and telemetry.

OS and device identification will be estimates based on observable network evidence, not guarantees. Results may be incomplete because of firewalls, sleeping devices, or network isolation.

## Project Documents

- [Specification](SPEC.md): planned behavior, outputs, interface, and acceptance criteria.
- [Security Policy](docs/security.md): durable constraints for network scope, local access, credentials, data handling, and verification.
- [Contribution Guide](CONTRIBUTING.md): expectations for changes and tests.

## Prerequisites

The planned application requires Python 3.10 or newer and Nmap. Nmap installation and permission requirements will be documented for supported operating systems when implementation begins. The scanner must not install Nmap or elevate its own privileges.