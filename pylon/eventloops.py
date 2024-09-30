import asyncio
import collections.abc
import itertools
import logging
import threading
import weakref
from typing import Coroutine

import libzt

import pylon.selectors

import pylon.compat_asserts


logger = logging.getLogger(__name__)


async def run_coroutine_in_other_loop(coro: Coroutine, loop: asyncio.AbstractEventLoop):
    # This is the easy way, using a concurrent.futures.Future to bridge between two event loops.
    # There is also the hard way, which is to use asyncio.futures._chain_future to directly connect two
    # asyncio Futures. It should have marginally better performance.
    fut = asyncio.run_coroutine_threadsafe(coro, loop)
    return await asyncio.wrap_future(fut)


def _guess_address_family(ip_str: str):
    """Make a guess of the address family of an IP literal.

    The event loops implemented here do not support passing hostnames (or any address that needs to be resolved
    to IP addresses) into the various connection creation methods. Callers should always pass in IP address literals.

    When ip_str is a valid IP address literal, it should return the correct family.
    If not, then just make any guess, and let downstream code error out.
    """
    if ':' in ip_str:
        return libzt.ZTS_AF_INET6
    return libzt.ZTS_AF_INET


class LibztSelectorEventLoop(asyncio.selector_events.BaseSelectorEventLoop):
    """Event loop capable of handling libzt sockets."""
    _socket_class = libzt.socket

    def __init__(self):
        self._csock_lock = threading.Lock()
        super().__init__(selector=pylon.selectors.LibztSelector())

    async def getaddrinfo(self, host, port, *,
                          family=0, type=0, proto=0, flags=0):
        raise NotImplementedError('getaddrinfo not supported')

    async def getnameinfo(self, sockaddr, flags=0):
        raise NotImplementedError('getnameinfo not supported')

    def make_socket(self, family: int, type: int, proto: int):
        sock = self._socket_class(family, type, proto)
        # I'm worried that all this cross loop juggling may leak socket objects
        weakref.finalize(sock, sock.close)
        return sock

    def _sock_connect_cb(self, fut, sock, address):
        if fut.done():
            return

        try:
            err = sock.getsockopt(libzt.ZTS_SOL_SOCKET, libzt.ZTS_SO_ERROR)
            if err != 0:
                # Jump to any except clause below.
                raise OSError(err, f'Connect call failed {address}')
        except (BlockingIOError, InterruptedError):
            # socket is still registered, the callback will be retried later
            pass
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException as exc:
            fut.set_exception(exc)
        else:
            fut.set_result(None)
        finally:
            fut = None

    async def create_connection(
            self, protocol_factory, host=None, port=None,
            *, ssl=None, family=0,
            proto=0, flags=0, sock=None,
            local_addr=None, server_hostname=None,
            ssl_handshake_timeout=None,
            ssl_shutdown_timeout=None,
            happy_eyeballs_delay=None, interleave=None):
        """Connect to a TCP server.

        Host names are not supported. *host* must be a literal IP address if *sock* is None.
        """
        if server_hostname is not None and not ssl:
            raise ValueError('server_hostname is only meaningful with ssl')

        if server_hostname is None and ssl:
            # Use host as default for server_hostname.  It is an error
            # if host is empty or not set, e.g. when an
            # already-connected socket was passed or when only a port
            # is given.  To avoid this error, you can pass
            # server_hostname='' -- this will bypass the hostname
            # check.  (This also means that if host is a numeric
            # IP/IPv6 address, we will attempt to verify that exact
            # address; this will probably fail, but it is possible to
            # create a certificate for a specific IP address, so we
            # don't judge it here.)
            raise ValueError('You must set server_hostname')

        if ssl_handshake_timeout is not None and not ssl:
            raise ValueError(
                'ssl_handshake_timeout is only meaningful with ssl')

        if ssl_shutdown_timeout is not None and not ssl:
            raise ValueError(
                'ssl_shutdown_timeout is only meaningful with ssl')

        if host is not None or port is not None:
            if sock is not None:
                raise ValueError(
                    'host/port and sock can not be specified at the same time')
            if family == 0:
                family = _guess_address_family(host)
            sock = self.make_socket(family, libzt.ZTS_SOCK_STREAM, proto)
            sock.setblocking(False)
            if local_addr is not None:
                sock.bind(local_addr)
            await self.sock_connect(sock, (host, port))
        else:
            if sock is None:
                raise ValueError(
                    'host and port was not specified and no sock specified')
            if sock.type != libzt.ZTS_SOCK_STREAM:
                raise ValueError(
                    f'A Stream Socket was expected, got {sock!r}')

        transport, protocol = await self._create_connection_transport(
            sock, protocol_factory, ssl, server_hostname,
            ssl_handshake_timeout=ssl_handshake_timeout,
            ssl_shutdown_timeout=ssl_shutdown_timeout)
        if self._debug:
            # Get the socket from the transport because SSL transport closes
            # the old socket and creates a new SSL socket
            sock = transport.get_extra_info('socket')
            logger.debug("%r connected to %s:%r: (%r, %r)",
                         sock, host, port, transport, protocol)
        return transport, protocol

    async def create_datagram_endpoint(self, protocol_factory,
                                       local_addr=None, remote_addr=None, *,
                                       family=0, proto=0, flags=0,
                                       reuse_port=None,
                                       allow_broadcast=None, sock=None):
        """Create datagram connection.

        Host names are not supported. The address arguments must contain literal IP addresses if provided.
        """
        if sock is not None:
            if sock.type != libzt.ZTS_SOCK_DGRAM:
                raise ValueError(
                    f'A UDP Socket was expected, got {sock!r}')
            if (local_addr or remote_addr or
                    family or proto or flags or
                    reuse_port or allow_broadcast):
                # show the problematic kwargs in exception msg
                opts = dict(local_addr=local_addr, remote_addr=remote_addr,
                            family=family, proto=proto, flags=flags,
                            reuse_port=reuse_port,
                            allow_broadcast=allow_broadcast)
                problems = ', '.join(f'{k}={v}' for k, v in opts.items() if v)
                raise ValueError(
                    f'socket modifier keyword arguments can not be used '
                    f'when sock is specified. ({problems})')
            sock.setblocking(False)
            r_addr = None
        else:
            if family == 0:
                if local_addr:
                    family = _guess_address_family(local_addr[0])
                else:
                    if remote_addr:
                        family = _guess_address_family(remote_addr[0])
                    else:
                        raise ValueError('unexpected address family')

            sock = self.make_socket(family, libzt.ZTS_SOCK_DGRAM, proto)
            r_addr = None
            if reuse_port:
                # This will fail because lwIP has not implemented SO_REUSEPORT, but we honor the request here anyways
                sock.setsockopt(libzt.ZTS_SOL_SOCKET, libzt.ZTS_SO_REUSEPORT, 1)
            if allow_broadcast:
                sock.setsockopt(libzt.ZTS_SOL_SOCKET, libzt.ZTS_SO_BROADCAST, 1)
            sock.setblocking(False)
            if local_addr:
                sock.bind(local_addr)
            if remote_addr:
                if not allow_broadcast:
                    await self.sock_connect(sock, remote_addr)
                r_addr = remote_addr

        protocol = protocol_factory()
        waiter = self.create_future()
        transport = self._make_datagram_transport(
            sock, protocol, r_addr, waiter)
        if self._debug:
            if local_addr:
                logger.info("Datagram endpoint local_addr=%r remote_addr=%r "
                            "created: (%r, %r)",
                            local_addr, remote_addr, transport, protocol)
            else:
                logger.debug("Datagram endpoint remote_addr=%r created: "
                             "(%r, %r)",
                             remote_addr, transport, protocol)

        try:
            await waiter
        except:
            transport.close()
            raise

        return transport, protocol

    def _create_server_fake_getaddrinfo(self, host, port, family, flags):
        """We don't have getaddrinfo, so we have to do some special case handling ourselves.

        Treat None as wildcard, and "localhost" as localhost.
        """
        if host is None:
            return [
                (libzt.ZTS_AF_INET6, libzt.ZTS_SOCK_STREAM, libzt.ZTS_IPPROTO_TCP, '', ('::', port, 0, 0)),
                (libzt.ZTS_AF_INET, libzt.ZTS_SOCK_STREAM, libzt.ZTS_IPPROTO_TCP, '', ('0.0.0.0', port)),
            ]
        if host == 'localhost':
            return [
                (libzt.ZTS_AF_INET6, libzt.ZTS_SOCK_STREAM, libzt.ZTS_IPPROTO_TCP, '', ('::1', port, 0, 0)),
                (libzt.ZTS_AF_INET, libzt.ZTS_SOCK_STREAM, libzt.ZTS_IPPROTO_TCP, '', ('127.0.0.1', port)),
            ]

        if family == 0:
            family = _guess_address_family(host)
        return [(family, libzt.ZTS_SOCK_STREAM, libzt.ZTS_IPPROTO_TCP, '', (host, port))]

    async def create_server(
            self, protocol_factory, host=None, port=None,
            *,
            family=0,
            flags=0,
            sock=None,
            backlog=100,
            ssl=None,
            reuse_address=None,
            reuse_port=None,
            ssl_handshake_timeout=None,
            ssl_shutdown_timeout=None,
            start_serving=True):
        """Create a TCP server.

        The host parameter can be a string, in that case the TCP server is
        bound to host and port.

        The host parameter can also be a sequence of strings and in that case
        the TCP server is bound to all hosts of the sequence. If a host
        appears multiple times, the server is only bound once to that
        host.

        When specified as string(s), the host parameter only supports literal
        IP addresses or "localhost".

        Return a Server object which can be used to stop the service.

        This method is a coroutine.
        """
        if isinstance(ssl, bool):
            raise TypeError('ssl argument must be an SSLContext or None')

        if ssl_handshake_timeout is not None and ssl is None:
            raise ValueError(
                'ssl_handshake_timeout is only meaningful with ssl')

        if ssl_shutdown_timeout is not None and ssl is None:
            raise ValueError(
                'ssl_shutdown_timeout is only meaningful with ssl')

        if host is not None or port is not None:
            if sock is not None:
                raise ValueError(
                    'host/port and sock can not be specified at the same time')

            if reuse_address is None:
                reuse_address = True
            sockets = []
            if host == '':
                hosts = [None]
            elif (isinstance(host, str) or
                  not isinstance(host, collections.abc.Iterable)):
                hosts = [host]
            else:
                hosts = host

            infos = set(itertools.chain.from_iterable(
                self._create_server_fake_getaddrinfo(h, port, family, flags) for h in hosts))

            completed = False
            try:
                for res in infos:
                    af, socktype, proto, canonname, sa = res
                    try:
                        sock = self.make_socket(af, socktype, proto)
                    except OSError:
                        # Assume it's a bad family/type/protocol combination.
                        if self._debug:
                            logger.warning('create_server() failed to create '
                                           'socket.socket(%r, %r, %r)',
                                           af, socktype, proto, exc_info=True)
                        continue
                    sockets.append(sock)
                    if reuse_address:
                        sock.setsockopt(
                            libzt.ZTS_SOL_SOCKET, libzt.ZTS_SO_REUSEADDR, True)
                    if reuse_port:
                        sock.setsockopt(libzt.ZTS_SOL_SOCKET, libzt.ZTS_SO_REUSEPORT, 1)
                    # Disable IPv4/IPv6 dual stack support (enabled by
                    # default on Linux) which makes a single socket
                    # listen on both address families.
                    sock.setsockopt(libzt.ZTS_IPPROTO_IPV6,
                                    libzt.ZTS_IPV6_V6ONLY,
                                    True)
                    try:
                        sock.bind(sa)
                    except OSError as err:
                        raise OSError(err.errno, 'error while attempting '
                                                 'to bind on address %r: %s'
                                      % (sa, err.strerror.lower())) from None
                completed = True
            finally:
                if not completed:
                    for sock in sockets:
                        sock.close()
        else:
            if sock is None:
                raise ValueError('Neither host/port nor sock were specified')
            if sock.type != libzt.ZTS_SOCK_STREAM:
                raise ValueError(f'A Stream Socket was expected, got {sock!r}')
            sockets = [sock]

        for sock in sockets:
            sock.setblocking(False)

        server = asyncio.Server(
            self, sockets, protocol_factory,
            ssl, backlog, ssl_handshake_timeout,
            ssl_shutdown_timeout)
        if start_serving:
            server._start_serving()
            # Skip one loop iteration so that all 'loop.add_reader'
            # go through.
            await asyncio.sleep(0)

        if self._debug:
            logger.info("%r is serving", server)

        return server

    def _make_self_pipe(self):
        # For some reason, lwIP's select()'s wakeup frequency on a loopback tcp socket is sometimes
        # constrained by TCP_TMR_INTERVAL, which is 250ms by default. This means that sometimes
        # the event loop only wakes up once every 250ms from external events that uses _write_to_self,
        # e.g. [call_soon|run_coroutine]_threadsafe(). This is obviously terrible for performance.
        # Luckily, udp sockets are not similarly constrained.
        # We just hope lwIP doesn't drop packets for this "unreliable" loopback transport.
        ssock = self.make_socket(libzt.ZTS_AF_INET6, libzt.ZTS_SOCK_DGRAM, 0)
        ssock.setblocking(False)
        ssock.bind(('::1', 0, 0, 0))
        csock = self.make_socket(libzt.ZTS_AF_INET6, libzt.ZTS_SOCK_DGRAM, 0)
        csock.setblocking(False)
        try:
            csock.connect(ssock.getsockname())
        except BlockingIOError:
            pass
        # Also connect ssock to csock, so ssock ignores packet from any other address
        try:
            ssock.connect(csock.getsockname())
        except BlockingIOError:
            pass
        self._ssock = ssock
        with self._csock_lock:
            self._csock = csock
        self._internal_fds += 1
        self._add_reader(self._ssock.fileno(), self._read_from_self)

    def _close_self_pipe(self):
        self._remove_reader(self._ssock.fileno())
        self._ssock.close()
        self._ssock = None
        with self._csock_lock:
            self._csock.close()
            self._csock = None
        self._internal_fds -= 1

    def _write_to_self(self):
        # This may be called from a different thread, possibly after
        # _close_self_pipe() has been called or even while it is
        # running.  Guard for self._csock being None or closed.  When
        # a socket is closed, send() raises OSError (with errno set to
        # EBADF, but let's not rely on the exact error code).
        # Technically, lwIP sockets are not thread safe. So protect csock
        # with a lock.
        with self._csock_lock:
            csock = self._csock
            if csock is None:
                return

            try:
                csock.send(b'\0')
            except OSError:
                pass

    async def _sendfile_native(self, transp, file, offset, count):
        raise asyncio.SendfileNotAvailableError('libzt does not support sendfile')

    def _make_socket_transport(self, sock, protocol, waiter=None, *,
                               extra=None, server=None):
        return LibztSelectorSocketTransport(
            self, sock, protocol, waiter, extra, server)

    def _make_ssl_transport(
            self, rawsock, protocol, sslcontext, waiter=None,
            *, server_side=False, server_hostname=None,
            extra=None, server=None,
            ssl_handshake_timeout=asyncio.constants.SSL_HANDSHAKE_TIMEOUT,
            ssl_shutdown_timeout=asyncio.constants.SSL_SHUTDOWN_TIMEOUT,
    ):
        ssl_protocol = asyncio.sslproto.SSLProtocol(
            self, protocol, sslcontext, waiter,
            server_side, server_hostname,
            ssl_handshake_timeout=ssl_handshake_timeout,
            ssl_shutdown_timeout=ssl_shutdown_timeout
        )
        LibztSelectorSocketTransport(self, rawsock, ssl_protocol,
                                     extra=extra, server=server)
        return ssl_protocol._app_transport


class LibztSelectorSocketTransport(asyncio.selector_events._SelectorSocketTransport):
    _sendfile_compatible = asyncio.constants._SendfileMode.FALLBACK

    def __init__(self, loop, sock, protocol, waiter=None,
                 extra=None, server=None):
        super().__init__(loop, sock, protocol, waiter, extra, server)
        if hasattr(self, '_write_sendmsg') and self._write_ready == self._write_sendmsg:
            self._write_ready = self._write_send
