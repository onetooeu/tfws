from __future__ import annotations
import ipaddress
import socket
from urllib.parse import urlparse
from .errors import PolicyError

BLOCKED = [
  ipaddress.ip_network("0.0.0.0/8"), ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("100.64.0.0/10"),
  ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("172.16.0.0/12"),
  ipaddress.ip_network("192.0.0.0/24"), ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("198.18.0.0/15"),
  ipaddress.ip_network("224.0.0.0/4"), ipaddress.ip_network("240.0.0.0/4"), ipaddress.ip_network("::1/128"),
  ipaddress.ip_network("fc00::/7"), ipaddress.ip_network("fe80::/10"), ipaddress.ip_network("ff00::/8")]

def validate_public_https_url(url: str, *, resolve: bool = False) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise PolicyError("only unauthenticated HTTPS URLs are allowed")
    if parsed.port not in (None, 443):
        raise PolicyError("non-standard ports are forbidden")
    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        raise PolicyError("local names are forbidden")
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        addresses = []
        if resolve:
            try:
                addresses = [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)]
            except socket.gaierror as exc:
                raise PolicyError("DNS resolution failed") from exc
    for address in addresses:
        if any(address in network for network in BLOCKED):
            raise PolicyError(f"non-public destination forbidden: {address}")
    return url
