"""Local interface discovery and strict target-scope validation."""

import ipaddress
from collections.abc import Iterable

import psutil

from .models import LocalNetwork

RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
MAX_ADDRESSES = 65_536


def get_local_networks() -> list[LocalNetwork]:
    """Return directly connected RFC 1918 IPv4 networks by interface."""
    networks: list[LocalNetwork] = []
    for interface, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family != psutil.AF_INET or not address.netmask:
                continue
            try:
                ip_interface = ipaddress.ip_interface(f"{address.address}/{address.netmask}")
            except ValueError:
                continue
            if ip_interface.ip.is_loopback or ip_interface.ip.is_link_local:
                continue
            if not any(ip_interface.network.subnet_of(allowed) for allowed in RFC1918_NETWORKS):
                continue
            networks.append(
                LocalNetwork(
                    interface=interface,
                    address=str(ip_interface.ip),
                    network=str(ip_interface.network),
                )
            )
    return networks


def validate_target(
    target: str,
    interface: str,
    local_networks: Iterable[LocalNetwork] | None = None,
) -> ipaddress.IPv4Network:
    """Validate that a target is a bounded RFC 1918 subnet on the interface."""
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError as error:
        raise ValueError("Enter a valid IPv4 network in CIDR notation.") from error

    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Only IPv4 targets are supported.")
    if not any(network.subnet_of(allowed) for allowed in RFC1918_NETWORKS):
        raise ValueError("The target must be inside an RFC 1918 private IPv4 range.")
    if network.prefixlen < 16 or network.num_addresses > MAX_ADDRESSES:
        raise ValueError("The target may contain at most 65,536 addresses (a /16 or smaller subnet).")

    candidates = [
        item
        for item in (local_networks if local_networks is not None else get_local_networks())
        if item.interface == interface
    ]
    if not candidates:
        raise ValueError("Select a local interface with a directly connected private IPv4 network.")

    if not any(network.subnet_of(ipaddress.ip_network(item.network)) for item in candidates):
        raise ValueError("The target must be a subnet of the selected interface's directly connected network.")
    return network