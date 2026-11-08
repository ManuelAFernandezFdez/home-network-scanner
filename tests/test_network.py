import pytest

from home_network_scanner.models import LocalNetwork
from home_network_scanner.network import validate_target


LOCAL_NETWORKS = [LocalNetwork("lan0", "192.168.1.10", "192.168.1.0/24")]


def test_accepts_directly_connected_private_subnet():
    assert str(validate_target("192.168.1.0/24", "lan0", LOCAL_NETWORKS)) == "192.168.1.0/24"


@pytest.mark.parametrize("target", ["not-a-network", "8.8.8.0/24", "192.168.0.0/16", "10.0.0.0/8"])
def test_rejects_malformed_public_or_nonlocal_targets(target):
    with pytest.raises(ValueError):
        validate_target(target, "lan0", LOCAL_NETWORKS)


def test_rejects_ipv6():
    with pytest.raises(ValueError, match="Only IPv4"):
        validate_target("fd00::/64", "lan0", LOCAL_NETWORKS)


def test_rejects_unknown_interface():
    with pytest.raises(ValueError, match="Select a local interface"):
        validate_target("192.168.1.0/24", "wan0", LOCAL_NETWORKS)