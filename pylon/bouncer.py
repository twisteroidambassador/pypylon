import asyncio
import collections.abc
import contextlib
import functools
import ipaddress
import itertools
import logging
import socket
import typing

import async_stagger
import async_stagger.aitertools
from async_stagger.resolvers import _interleave_addrinfos
import dns.name
import dns.namedict
import pytricia

import pylon.eventloops
import pylon.resolvers
import pylon.socks


HAPPY_EYEBALLS_CONNECT_DELAY = 0.25
RELAY_BUFSIZE = 16384


AddrInfoType = tuple[int, int, int, str, tuple]

logger = logging.getLogger(__name__)


async def _run_coro_in_loop(desired_loop: asyncio.AbstractEventLoop, coro: typing.Coroutine):
    current_loop = asyncio.get_running_loop()
    if current_loop is desired_loop:
        return await coro
    return await pylon.eventloops.run_coroutine_in_other_loop(coro, desired_loop)


async def _connect_sock(
        addr_info: AddrInfoType,
        local_addr: tuple | None = None,
):
    """Create, bind and connect one socket."""
    loop = asyncio.get_running_loop()
    family, type_, proto, _, address = addr_info
    if hasattr(loop, 'make_socket'):
        socket_factory = loop.make_socket
    else:
        socket_factory = socket.socket

    sock = socket_factory(family, type_, proto)
    try:
        sock.setblocking(False)
        if local_addr is not None:
            sock.bind(local_addr)
        await loop.sock_connect(sock, address)
        return sock
    except:
        sock.close()
        raise


async def _open_connection_get_extras(sock):
    sockname = sock.getsockname()
    peername = sock.getpeername()
    reader, writer = await asyncio.open_connection(sock=sock)
    return reader, writer, peername, sockname


async def close_writer(writer: asyncio.StreamWriter):
    try:
        writer.close()
        await writer.wait_closed()
    except OSError as e:
        logger.debug('Error closing writer %r: %r', writer, e)


async def _read_all_available_from_reader(reader: asyncio.StreamReader) -> list[bytes]:
    """Read as much data as possible quickly from a stream.

    If there is data waiting in the reader's buffer, read all of it. Otherwise, wait for some data to arrive, then
    read all available data.

    If stream is at EOF, returns an empty list. Otherwise, returns a list of one or two bytes objects, each of which
    is guaranteed to be not empty.

    This method "reaches into" the StreamReader, therefore it may break with newer Python versions.
    """
    read_data = []
    if not reader._buffer:
        data = await reader.read(RELAY_BUFSIZE)
        if not data:
            return read_data
        read_data.append(data)
    if buflen := len(reader._buffer):
        read_data.append(await reader.read(buflen))
    return read_data


async def _relay_across_loops(
        log_label: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        reader_loop: asyncio.AbstractEventLoop,
):
    """This must be run from the writer's loop"""
    logger.debug('%s starting', log_label)
    while True:
        await writer.drain()
        read_data = await _run_coro_in_loop(reader_loop, _read_all_available_from_reader(reader))
        if not read_data:
            break
        logger.debug('%s relaying data, length %d', log_label, sum(len(buf) for buf in read_data))
        writer.writelines(read_data)
    logger.debug('%s relaying EOF', log_label)
    writer.write_eof()
    logger.debug('%s finishing', log_label)


async def _relay(
        log_label: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
):
    logger.debug('%s starting', log_label)
    while True:
        await writer.drain()
        read_data = await _read_all_available_from_reader(reader)
        if not read_data:
            break
        logger.debug('%s relaying data, length %d', log_label, sum(len(buf) for buf in read_data))
        writer.writelines(read_data)
    logger.debug('%s relaying EOF', log_label)
    writer.write_eof()
    logger.debug('%s finishing', log_label)


class Bouncer:
    """This class is meant to be immutable and thread safe.
    Once created, it should be safe to call its methods from both event loops.
    """
    def __init__(
            self,
            main_loop: asyncio.AbstractEventLoop,
            zts_loop: asyncio.AbstractEventLoop,
            routes: collections.abc.Iterable[ipaddress.IPv6Network | ipaddress.IPv4Network],
            resolvers: collections.abc.Mapping[int, pylon.resolvers.ResolverForZtNetwork],
    ):
        self._main_loop = main_loop
        self._zts_loop = zts_loop

        self._v6_routes = pytricia.PyTricia(128)
        self._v4_routes = pytricia.PyTricia(32)
        self._domain_to_resolver = dns.namedict.NameDict()

        for a in routes:
            if a.version == 6:
                self._v6_routes[a] = True
            else:
                self._v4_routes[a] = True

        for r in resolvers.values():
            self._domain_to_resolver[r.domain] = r

    def resolver_for_domain(self, name: str | dns.name.Name) -> pylon.resolvers.ResolverForZtNetwork | None:
        if isinstance(name, str):
            name = dns.name.from_text(name)
        try:
            return self._domain_to_resolver.get_deepest_match(name)[1]
        except KeyError:
            return None

    def is_address_in_zt(self, address: str | ipaddress.IPv6Address | ipaddress.IPv4Address) -> bool:
        if isinstance(address, str):
            address = ipaddress.ip_address(address)
        if address.version == 6:
            return address in self._v6_routes
        return address in self._v4_routes

    async def getaddrinfo(self, host: dns.name.Name, port: int, type_: int = 0, proto: int = 0, flags: int = 0):
        resolver = self.resolver_for_domain(host)
        if resolver is not None:
            return await _run_coro_in_loop(self._zts_loop, pylon.resolvers.getaddrinfo_async_with_resolver(
                resolver.resolver, host, port, socktype=type_, proto=proto))
        else:
            current_loop = asyncio.get_running_loop()
            try:
                return await current_loop.getaddrinfo(
                    host.to_text(omit_final_dot=True), port, family=socket.AF_UNSPEC,
                    type=type_, proto=proto, flags=flags)
            except NotImplementedError:
                return await asyncio.to_thread(
                    socket.getaddrinfo,
                    host.to_text(omit_final_dot=True), port, socket.AF_UNSPEC, type_, proto, flags)

    async def _open_connection_with_dns_name(
            self,
            address: dns.name.Name,
            port: int,
            allow_zt_dest: bool = True,
            allow_main_dest: bool = True,
    ):
        """Returns (reader, writer, peername, sockname, loop), or raises Socks5ErrorReply."""
        try:
            addrinfos = await self.getaddrinfo(address, port, socket.SOCK_STREAM)
        except (socket.gaierror, dns.exception.DNSException, OSError) as e:
            logger.info('Resolving address %s failed: %r', address, e)
            raise pylon.socks.Socks5ErrorReply(pylon.socks.SOCKS5Reply.HOST_UNREACHABLE)
        if not addrinfos:
            logger.info('%s address resolution result empty', address)
            raise pylon.socks.Socks5ErrorReply(pylon.socks.SOCKS5Reply.HOST_UNREACHABLE)
        addrinfos = _interleave_addrinfos(addrinfos, 1)
        assert allow_zt_dest or allow_main_dest
        logger.debug('Opening connection to addrinfos %r', addrinfos)
        addresses = [ipaddress.ip_address(a[4][0]) for a in addrinfos]
        addresses_in_zt = [self.is_address_in_zt(a) for a in addresses]
        logger.debug('Is address in zt? %r', addresses_in_zt)
        if not allow_zt_dest:
            addrinfos = list(itertools.compress(addrinfos, (not a for a in addresses_in_zt)))
            addresses_in_zt = [False] * len(addrinfos)
        elif not allow_main_dest:
            addrinfos = list(itertools.compress(addrinfos, addresses_in_zt))
            addresses_in_zt = [True] * len(addrinfos)

        logger.debug('Filtered addrinfos: %r', addrinfos)
        if not addrinfos:
            logger.debug('No allowed addresses for %s', address)
            raise pylon.socks.Socks5ErrorReply(pylon.socks.SOCKS5Reply.CONNECTION_NOT_ALLOWED_BY_RULESET)

        if all(addresses_in_zt):
            logger.debug('All addresses in zt, connecting in zts loop')
            loop = self._zts_loop
        elif not any(addresses_in_zt):
            logger.debug('None of addresses in zt, connecting in main loop')
            loop = self._main_loop
        else:
            logger.debug('Mixed zt and non-zt addresses')
            loop = None

        if loop is not None:
            async def open_connection_from_addrinfo_list():
                connect_coros = list(functools.partial(_connect_sock, a) for a in addrinfos)
                connect_coros_aiter = async_stagger.aitertools.aiter_from_iter(connect_coros)
                sock, _, connect_exceptions, _ = await async_stagger.staggered_race(
                    connect_coros_aiter, HAPPY_EYEBALLS_CONNECT_DELAY)
                if sock is None:
                    reply = pylon.socks.map_exception_to_socks5_reply(connect_exceptions)
                    raise pylon.socks.Socks5ErrorReply(reply)
                try:
                    return await _open_connection_get_extras(sock)
                except:
                    sock.close()
                    raise

            reader, writer, peername, sockname = await _run_coro_in_loop(
                loop, open_connection_from_addrinfo_list())
        else:
            async def connect_sock_in_loop(
                    loop: asyncio.AbstractEventLoop,
                    addr_info: AddrInfoType,
                    local_addr: tuple | None = None,
            ):
                sock = await _run_coro_in_loop(loop, _connect_sock(addr_info, local_addr))
                return sock, loop

            connect_coros = list(
                functools.partial(
                    connect_sock_in_loop,
                    self._zts_loop if in_zt else self._main_loop,
                    a,
                ) for a, in_zt in zip(addrinfos, addresses_in_zt)
            )
            connect_coros_aiter = async_stagger.aitertools.aiter_from_iter(connect_coros)
            result, _, connect_exceptions, _ = await async_stagger.staggered_race(
                connect_coros_aiter, HAPPY_EYEBALLS_CONNECT_DELAY)
            if result is None:
                reply = pylon.socks.map_exception_to_socks5_reply(connect_exceptions)
                raise pylon.socks.Socks5ErrorReply(reply)
            sock, loop = result

            async def open_connection():
                try:
                    return await _open_connection_get_extras(sock)
                except:
                    sock.close()
                    raise

            reader, writer, peername, sockname = await _run_coro_in_loop(loop, open_connection())
        return reader, writer, peername, sockname, loop

    async def _open_connection_with_ip_address(
            self,
            address: ipaddress.IPv6Address | ipaddress.IPv4Address,
            port: int,
            allow_zt_dest: bool = True,
            allow_main_dest: bool = True,
    ):
        address_in_zt = self.is_address_in_zt(address)
        logger.debug('address %r in zt: %r', address, address_in_zt)
        if address_in_zt and not allow_zt_dest:
            raise pylon.socks.Socks5ErrorReply(pylon.socks.SOCKS5Reply.CONNECTION_NOT_ALLOWED_BY_RULESET)
        if not address_in_zt and not allow_main_dest:
            raise pylon.socks.Socks5ErrorReply(pylon.socks.SOCKS5Reply.CONNECTION_NOT_ALLOWED_BY_RULESET)
        if address.version == 6:
            if address.scope_id:
                # This is only possible if the client sent a scoped literal IPv6 address as a host name,
                # and there isn't really a sane way to deal with it
                logger.info('%s scoped IPv6 addresses not supported')
                raise pylon.socks.Socks5ErrorReply(pylon.socks.SOCKS5Reply.HOST_UNREACHABLE)
            family = socket.AF_INET6
            address_tuple = (str(address), port, 0, 0)
        else:
            family = socket.AF_INET
            address_tuple = (str(address), port)
        server_loop = self._zts_loop if address_in_zt else self._main_loop
        addr_info = (
            family,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            '',
            address_tuple,
        )

        async def open_connection_from_addrinfo():
            sock = await _connect_sock(addr_info)
            try:
                return await _open_connection_get_extras(sock)
            except:
                sock.close()
                raise

        result = await _run_coro_in_loop(server_loop, open_connection_from_addrinfo())
        return *result, server_loop

    def _side_label(self, loop: asyncio.AbstractEventLoop):
        if loop is self._zts_loop:
            return 'zt'
        if loop is self._main_loop:
            return 'os'
        assert False, 'Unexpected event loop'

    async def socks5_handler(
            self,
            client_reader: asyncio.StreamReader,
            client_writer: asyncio.StreamWriter,
            allow_zt_dest: bool = True,
            allow_main_dest: bool = True,
    ):
        client_address = client_writer.get_extra_info('peername')
        client_loop = asyncio.get_running_loop()
        client_side = self._side_label(client_loop)
        log_label = f'[{client_side} {client_address} ==> ]'
        logger.debug('%s Received client connection', log_label)

        async with contextlib.AsyncExitStack() as stack:
            @contextlib.contextmanager
            def unhandled_exception_logger():
                try:
                    yield
                except asyncio.CancelledError:
                    logger.info('%s handler cancelled', log_label)
                    raise
                except Exception:
                    logger.error('%s unhandled exception', log_label, exc_info=True)

            stack.enter_context(unhandled_exception_logger())
            stack.push_async_callback(close_writer, client_writer)

            try:
                command, address, port = await pylon.socks.receive_socks5_command_request(client_reader, client_writer)
            except (pylon.socks.Socks5ClientError, asyncio.IncompleteReadError, OSError) as e:
                logger.info('%s client negotiation failed: %r', log_label, e)
                return

            log_label = f'[{client_side} {client_address} {command.name}({address}, {port}) ==> ]'
            logger.debug('%s command received', log_label)

            if command in {pylon.socks.SOCKS5Command.BIND, pylon.socks.SOCKS5Command.UDP_ASSOCIATE}:
                logger.info('%s command %r not yet supported', log_label, command)
                await pylon.socks.send_socks5_command_reply(
                    client_writer, pylon.socks.SOCKS5Reply.COMMAND_NOT_SUPPORTED)
                return

            try:
                if isinstance(address, dns.name.Name):
                    server = await self._open_connection_with_dns_name(address, port, allow_zt_dest, allow_main_dest)
                else:
                    server = await self._open_connection_with_ip_address(address, port, allow_zt_dest, allow_main_dest)
            except OSError as e:
                logger.info('%s error during connect: %r', log_label, e)
                await pylon.socks.send_socks5_command_reply(
                    client_writer, pylon.socks.map_exception_to_socks5_reply(e))
                return
            except pylon.socks.Socks5ErrorReply as e:
                logger.info('%s rejected during connect: %r', log_label, e)
                await pylon.socks.send_socks5_command_reply(client_writer, e.args[0])
                return

            server_reader, server_writer, server_address, server_sockname, server_loop = server
            server_side = self._side_label(server_loop)
            log_label = f'[{client_side} {client_address} {command.name}({address}, {port}) ==> {server_side} {server_address}]'
            logger.debug('%s connected to server', log_label)
            stack.push_async_callback(_run_coro_in_loop, server_loop, close_writer(server_writer))

            await pylon.socks.send_socks5_command_reply(
                client_writer,
                pylon.socks.SOCKS5Reply.SUCCESS,
                ipaddress.ip_address(server_sockname[0]),
                server_sockname[1],
            )

            logger.info('%s established', log_label)
            upstream_log_label = f'[{client_side} {client_address} {command.name}({address}, {port}) --> {server_side} {server_address}]'
            downstream_log_label = f'[{client_side} {client_address} {command.name}({address}, {port}) <-- {server_side} {server_address}]'
            try:
                async with asyncio.TaskGroup() as group:
                    if client_loop is server_loop:
                        group.create_task(_relay(upstream_log_label, client_reader, server_writer))
                        group.create_task(_relay(downstream_log_label, server_reader, client_writer))
                    else:
                        group.create_task(pylon.eventloops.run_coroutine_in_other_loop(
                            _relay_across_loops(upstream_log_label, client_reader, server_writer, client_loop),
                            server_loop,
                        ))
                        group.create_task(_relay_across_loops(
                            downstream_log_label, server_reader, client_writer, server_loop))
            except* OSError as e:
                logger.info('%s errors during relay: %r', log_label, e.exceptions)
            logger.info('%s finishing', log_label)


class BouncerRotator:
    def __init__(self, allow_zt_dest: bool = True, allow_main_dest: bool = True):
        self._allow_zt_dest = allow_zt_dest
        self._allow_main_dest = allow_main_dest
        self._bouncer: Bouncer | None = None

    def update_bouncer(self, bouncer: Bouncer):
        self._bouncer = bouncer

    async def socks5_handler(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
    ):
        return await self._bouncer.socks5_handler(reader, writer, self._allow_zt_dest, self._allow_main_dest)
