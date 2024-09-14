import ipaddress
import socket

import dns.asyncresolver
import dns.name


class ResolverForZtNetwork:
    def __init__(
            self,
            domain: dns.name.Name,
            servers: tuple[ipaddress.IPv6Address | ipaddress.IPv4Address, ...],
    ):
        self._domain = domain
        self._servers = servers
        self._resolver = dns.asyncresolver.Resolver(configure=False)
        self._resolver.nameservers = list(str(a) for a in servers)
        self._resolver.cache = dns.resolver.Cache()

    def can_resolve(self, domain: dns.name.Name):
        return self._domain.is_superdomain(domain)

    @property
    def resolver(self):
        return self._resolver

    @property
    def domain(self):
        return self._domain

    @property
    def servers(self):
        return self._servers


_proto_for_socktype = {
    socket.SOCK_STREAM: [socket.IPPROTO_TCP],
    socket.SOCK_DGRAM: [socket.IPPROTO_UDP],
}


async def getaddrinfo_async_with_resolver(
        resolver: dns.asyncresolver.Resolver,
        host: dns.name.Name | str,
        service: int,
        family: int = socket.AF_UNSPEC,
        socktype: int = 0,
        proto: int = 0,
        flags: int = 0,
):
    if host is None:
        raise socket.gaierror(
            socket.EAI_FAIL, "Non-recoverable failure in name resolution"
        )

    if socktype == 0:
        socktypes = [socket.SOCK_STREAM, socket.SOCK_DGRAM]
    else:
        socktypes = [socktype]
    type_protos = []
    for t in socktypes:
        possible_protos = _proto_for_socktype.get(t, [])
        if proto != 0:
            if proto in possible_protos:
                possible_protos = [proto]
            else:
                possible_protos = []
        type_protos.extend((t, p) for p in possible_protos)
    if not type_protos:
        raise socket.gaierror(socket.EAI_SOCKTYPE, 'requested socket type is not supported')

    try:
        answers = await resolver.resolve_name(host, family)
        addrs = answers.addresses_and_families()
    except dns.resolver.NXDOMAIN:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    except Exception:
        # We raise EAI_AGAIN here as the failure may be temporary
        # (e.g. a timeout) and EAI_SYSTEM isn't defined on Windows.
        # [Issue #416]
        raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")

    tuples = []
    for addr, af in addrs:
        for socktype, proto in type_protos:
            addr_tuple = dns.inet.low_level_address_tuple((addr, service), af)
            tuples.append((af, socktype, proto, '', addr_tuple))
    if len(tuples) == 0:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    return tuples
