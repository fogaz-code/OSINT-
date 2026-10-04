import ipaddress
import socket
from typing import List, Optional, Union
from urllib.parse import urlparse

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# Cloud metadata endpoints that do not all fall inside the non-global ranges (defence in depth).
BLOCKED_IPS = {
    ipaddress.ip_address('169.254.169.254'),
    ipaddress.ip_address('169.254.170.2'),
    ipaddress.ip_address('100.100.100.200'),
    ipaddress.ip_address('fd00:ec2::254'),
}

# IPv6 encodings that carry an IPv4 address in their low bits (6to4 carries it in bits 80-111).
_IPV4_MAPPED = ipaddress.IPv6Network('::ffff:0:0/96')
_IPV4_TRANSLATED = ipaddress.IPv6Network('::ffff:0:0:0/96')
_IPV4_COMPATIBLE = ipaddress.IPv6Network('::/96')
_NAT64_WELL_KNOWN = ipaddress.IPv6Network('64:ff9b::/96')
_SIX_TO_FOUR = ipaddress.IPv6Network('2002::/16')

# IPv6 ranges that are never globally reachable. They are listed explicitly instead of trusting
# `IPv6Address.is_global` alone because Python's copy of the IANA registry lags and differs between
# versions: 3.13 still reports fec0::/10, 5f00::/16 and the whole ::/96 block as global, while 3.10
# does not know 3fff::/20 or 64:ff9b:1::/48 at all.
_NON_GLOBAL_V6 = tuple(
    ipaddress.IPv6Network(net)
    for net in (
        '::/128',  # unspecified
        '::1/128',  # loopback
        '64:ff9b:1::/48',  # NAT64 local-use prefix (RFC 8215), whatever IPv4 it embeds
        '100::/64',  # discard-only
        '2001::/23',  # IETF protocol assignments, including Teredo 2001::/32 (embeds an obfuscated IPv4)
        '2001:db8::/32',  # documentation
        '3fff::/20',  # documentation (RFC 9637)
        '5f00::/16',  # SRv6 SIDs (RFC 9602)
        'fc00::/7',  # unique local
        'fe80::/10',  # link-local
        'fec0::/10',  # deprecated site-local (RFC 3879): still routed internally by some networks
        'ff00::/8',  # multicast
    )
)


class SSRFError(ValueError):
    """Raised when a URL or address is rejected by the SSRF guard."""

    pass


def embedded_ipv4(ip: ipaddress.IPv6Address) -> Optional[ipaddress.IPv4Address]:
    """Return the IPv4 address an IPv6 address routes to, or None if it embeds none.

    Covers IPv4-mapped (::ffff:0:0/96), IPv4-translated (::ffff:0:0:0/96), IPv4-compatible
    (::/96 except :: and ::1), 6to4 (2002::/16) and the NAT64 well-known prefix (64:ff9b::/96).
    The NAT64 local-use prefix and Teredo are rejected wholesale by `_NON_GLOBAL_V6` instead.
    """
    value = int(ip)
    if ip in _IPV4_MAPPED or ip in _IPV4_TRANSLATED or ip in _NAT64_WELL_KNOWN:
        return ipaddress.IPv4Address(value & 0xFFFFFFFF)
    if ip in _IPV4_COMPATIBLE and value > 1:
        return ipaddress.IPv4Address(value & 0xFFFFFFFF)
    if ip in _SIX_TO_FOUR:
        return ipaddress.IPv4Address((value >> 80) & 0xFFFFFFFF)
    return None


def _is_public_ipv4(ip: ipaddress.IPv4Address) -> bool:
    return ip not in BLOCKED_IPS and ip.is_global and not ip.is_multicast


def is_public_ip(ip: Union[str, IPAddress]) -> bool:
    """True only for globally routable addresses (an allowlist, not a blocklist).

    An IPv6 address that embeds an IPv4 address is public only if the IPv6 address is outside every
    non-global IPv6 range AND the embedded IPv4 address is itself public. The embedding prefix is
    judged by this explicit policy rather than by `is_global`, whose verdict on ::ffff:0:0/96,
    2002::/16 and ::/96 depends on the Python version.
    """
    try:
        addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        return _is_public_ipv4(addr)
    if addr in BLOCKED_IPS or any(addr in net for net in _NON_GLOBAL_V6):
        return False
    v4 = embedded_ipv4(addr)
    if v4 is not None:
        return _is_public_ipv4(v4)
    return addr.is_global and not addr.is_multicast


def resolve_public_addresses(host: str, port: int = 443) -> List[str]:
    """Resolve EVERY A/AAAA record of the name and fail if even one of them is not public.

    Rejecting the whole set (instead of dropping the private addresses) stops a mixed
    public/private answer from being used to slip past the check.
    """
    try:
        literal = ipaddress.ip_address(host.strip('[]'))
    except ValueError:
        literal = None
    if literal is not None:
        if not is_public_ip(literal):
            raise SSRFError(f'Blocked non-public address: {literal}')
        return [str(literal)]

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as e:  # UnicodeError: IDNA rejects an empty or oversized label
        raise SSRFError(f'Cannot resolve {host}: {e}') from e
    addresses: List[str] = []
    for info in infos:
        ip = str(info[4][0]).split('%', 1)[0]
        if not is_public_ip(ip):
            raise SSRFError(f'Blocked: {host} resolves to non-public address {ip}')
        if ip not in addresses:
            addresses.append(ip)
    if not addresses:
        raise SSRFError(f'No addresses for {host}')
    return addresses


def is_safe_url(url: str, allowed_schemes: Optional[List[str]] = None) -> bool:
    """Preliminary check only. On its own it does NOT stop DNS rebinding: the real enforcement is
    `GuardedNetworkBackend`, which re-checks the address at connect time."""
    if allowed_schemes is None:
        allowed_schemes = ['http', 'https']
    try:
        parsed = urlparse(url)
        if parsed.scheme not in allowed_schemes or not parsed.hostname:
            return False
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        resolve_public_addresses(parsed.hostname, port)
        return True
    except ValueError:
        return False


def is_safe_ip(ip_str: str) -> bool:
    """Return True if the address is a globally routable public IP."""
    return is_public_ip(ip_str)
