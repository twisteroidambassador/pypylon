import asyncio
import ipaddress
import logging
import sys
import types
from collections.abc import Callable
from typing import NamedTuple

import dns.name
import dns.namedict
import libzt

from pylon import resolvers

logger = logging.getLogger(__name__)


class AssignedAddress(NamedTuple):
    address: ipaddress.IPv6Address | ipaddress.IPv4Address
    netmask: int


class RouteInfo(NamedTuple):
    target: ipaddress.IPv6Network | ipaddress.IPv4Network
    via: ipaddress.IPv6Address | ipaddress.IPv4Address | None
    flags: int
    metric: int


class NetworkInfo(NamedTuple):
    net_id: int
    mac: int
    name: str
    status: libzt.ZtsNetworkStatus
    type: libzt.ZtsNetworkType
    mtu: int
    dhcp: bool
    bridge: bool
    broadcast_enabled: bool
    port_error: int
    netconf_rev: int
    assigned_addrs: tuple[AssignedAddress, ...]
    routes: tuple[RouteInfo, ...]
    # skipping multicast subs
    dns_domain: str
    dns_addresses: tuple[ipaddress.IPv6Address | ipaddress.IPv4Address, ...]


class Node:
    """Controls the lifecycle of a libzt node.

    libzt only support running one node, so do not create more than one instance of this class.
    """
    def __init__(self, path: str, port: int | None = None):
        self._node = libzt.ZeroTierNode()
        self._node.init_from_storage(path)
        if port is not None:
            self._node.init_set_port(port)
        self._node.init_set_event_handler(self._callback)

        self._loop = asyncio.get_running_loop()
        self._node_online = asyncio.Event()

        self._networks: dict[int, NetworkInfo] = {}
        self._network_change_callback: Callable[[NetworkInfo], None] | None = None
        self._routes: set[ipaddress.IPv6Network | ipaddress.IPv4Network] = set()
        self._resolvers: dict[int, resolvers.ResolverForZtNetwork] = {}
        self._topology_change_callback: Callable[[], None] | None = None

    @property
    def id(self):
        return self._node.node_id()

    @property
    def loop(self):
        return self._loop

    @property
    def networks(self):
        return types.MappingProxyType(self._networks)

    @property
    def routes(self):
        return frozenset(self._routes)

    @property
    def resolvers(self):
        return types.MappingProxyType(self._resolvers)

    def _node_is_online(self):
        self._node_online.set()

    def _callback(self, msg):
        try:
            event_code = libzt.ZtsEvent(msg.event_code)
            logger.debug('Event: %r', event_code)

            match event_code:
                case libzt.ZtsEvent.NODE_ONLINE:
                    self._loop.call_soon_threadsafe(self._node_is_online)
                case libzt.ZtsEvent.NODE_FATAL_ERROR:
                    sys.exit('ZTS_EVENT_NODE_FATAL_ERROR occurred. You must regenerate node identity.')

            if msg.network:
                net_info = NetworkInfo(
                    msg.network.net_id,
                    msg.network.mac,
                    msg.network.name,
                    libzt.ZtsNetworkStatus(msg.network.status),
                    libzt.ZtsNetworkType(msg.network.type),
                    msg.network.mtu,
                    bool(msg.network.dhcp),
                    bool(msg.network.bridge),
                    bool(msg.network.broadcast_enabled),
                    msg.network.port_error,
                    msg.network.netconf_rev,
                    tuple(AssignedAddress(
                        ipaddress.ip_address(t[0]),
                        t[1],
                    ) for t in msg.network.get_all_assigned_addresses()),
                    tuple(RouteInfo(
                        ipaddress.ip_network(t[0]),
                        ipaddress.ip_address(t[1][0]) if t[1] is not None else None,
                        t[2],
                        t[3],
                    ) for t in msg.network.get_all_routes()),
                    msg.network.dns_domain,
                    tuple(ipaddress.ip_address(t[0]) for t in msg.network.get_all_dns_addresses()),
                )
                self._loop.call_soon_threadsafe(self._update_network_info, net_info)
        except Exception:
            logger.error('Unhandled exception in libzt event callback', exc_info=True)

    async def __aenter__(self):
        logger.debug('Starting node')
        self._node.node_start()
        await self._node_online.wait()
        logger.debug('Node is online')

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        logger.debug('Stopping node')
        # self._node.init_set_event_handler(None)
        self._node.node_stop()
        # self._node.node_free()

    def join_network(self, network_id: int | str):
        if isinstance(network_id, str):
            network_id = int(network_id, base=16)
        self._node.net_join(network_id)

    def leave_network(self, network_id: int | str):
        if isinstance(network_id, str):
            network_id = int(network_id, base=16)
        self._node.net_leave(network_id)

    def _refresh_routes_resolvers(self) -> bool:
        routes = set()
        current_resolver_info = {k: (v.domain, v.servers) for k, v in self._resolvers.items()}
        new_resolver_info = {}
        changed = False
        for n in self._networks.values():
            if not n.status == libzt.ZtsNetworkStatus.OK:
                continue
            for a in n.assigned_addrs:
                routes.add(ipaddress.ip_network((a.address, a.netmask), strict=False))
            for r in n.routes:
                routes.add(r.target)
            if n.dns_domain and n.dns_addresses:
                domain = dns.name.from_text(n.dns_domain)
                new_resolver_info[n.net_id] = (domain, n.dns_addresses)

        if routes != self._routes:
            logger.debug('Routes updated: %r', routes)
            self._routes = routes
            changed = True

        if new_resolver_info != current_resolver_info:
            logger.debug('Updating resolvers')
            new_resolvers = {}
            for network_id, (domain, servers) in new_resolver_info.items():
                resolver = self._resolvers.get(network_id, None)
                if resolver is not None and resolver.servers != servers:
                    resolver = None
                if resolver is None:
                    resolver = resolvers.ResolverForZtNetwork(domain, servers)
                new_resolvers[network_id] = resolver
            self._resolvers = new_resolvers
            changed = True

        return changed

    def _update_network_info(self, info: NetworkInfo):
        existing_info = self._networks.get(info.net_id)
        if info != existing_info:
            self._networks[info.net_id] = info
            logger.debug('Network updated: %r', info)

            routes_resolvers_changed = self._refresh_routes_resolvers()

            if self._network_change_callback is not None:
                self._network_change_callback(info)

            if routes_resolvers_changed:
                if self._topology_change_callback:
                    self._topology_change_callback()

    def set_network_change_callback(self, callback: Callable[[NetworkInfo], None] | None):
        self._network_change_callback = callback

    def set_topology_change_callback(self, callback: Callable[[], None] | None):
        self._topology_change_callback = callback

    def blacklist_if_prefix(self, prefix: str):
        self._node.init_blacklist_interface_prefix(prefix)
