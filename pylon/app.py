import argparse
import asyncio
import contextlib
import logging
import signal
import sys

import libzt

import pylon.bouncer
from pylon import nodes
from pylon import zts_io


logger = logging.getLogger(__name__)


async def server_wait_closed_fix(server: asyncio.Server):
    """Server.wait_closed() is supposed to wait until all client connections are closed before returning,
    but Python < 3.12.1 did not do so.
    To properly wait for client connections, await this method after calling server.close().
    Adapted from https://github.com/python/cpython/issues/120866.
    Also see bug reports:
    https://github.com/python/cpython/issues/79033
    https://github.com/python/cpython/issues/104344
    """
    if sys.version_info < (3, 12, 1) and server._waiters is not None:
        waiter = server.get_loop().create_future()
        server._waiters.append(waiter)
        await waiter


async def run_app(args):
    loop = asyncio.get_running_loop()
    this_task = asyncio.current_task()

    def sigterm_handler():
        logger.warning('SIGTERM received, starting graceful shutdown')
        this_task.cancel()
        loop.remove_signal_handler(signal.SIGTERM)

    loop.add_signal_handler(signal.SIGTERM, sigterm_handler)

    node = nodes.Node(args.persistence_path)
    if args.blacklist_if is not None:
        for s in args.blacklist_if:
            node.blacklist_if_prefix(s)

    network_ok = asyncio.Event()
    if args.join is not None:
        networks_online = {i: False for i in args.join}

    def network_change_callback(network_info: nodes.NetworkInfo):
        match network_info.status:
            case libzt.ZtsNetworkStatus.OK:
                logger.info('Network %010x status is OK', network_info.net_id)
                if args.join is not None:
                    if network_info.net_id in networks_online:
                        networks_online[network_info.net_id] = True
                    if all(networks_online.values()):
                        logger.debug('All joined networks are online')
                        network_ok.set()
                else:
                    logger.debug('Some network is online')
                    network_ok.set()
            case libzt.ZtsNetworkStatus.ACCESS_DENIED:
                logger.warning('Network %016x status is ACCESS_DENIED. Please authorize this device in the controller.',
                               network_info.net_id)
            case libzt.ZtsNetworkStatus.NOT_FOUND:
                logger.warning('Network %016x status is NOT_FOUND. Please verify network ID.', network_info.net_id)
            case libzt.ZtsNetworkStatus.PORT_ERROR:
                logger.warning('Network %016x status is PORT_ERROR', network_info.net_id)
            case libzt.ZtsNetworkStatus.CLIENT_TOO_OLD:
                logger.warning('Network %016x status is CLIENT_TOO_OLD', network_info.net_id)

    node.set_network_change_callback(network_change_callback)

    async with contextlib.AsyncExitStack() as stack:
        stack.push_async_callback(asyncio.sleep, 0.2)
        await stack.enter_async_context(node)
        stack.push_async_callback(asyncio.sleep, 0.2)
        logger.info('Node is online, Node ID: %010x', node.id)

        if args.leave:
            for i in args.leave:
                logger.info('Leaving network %01x', i)
                node.leave_network(i)
        if args.join:
            for i in args.join:
                logger.info('Joining network %016x', i)
                node.join_network(i)
        await network_ok.wait()
        logger.info('Network is online')

        if args.outside_port is None and args.zts_port is None:
            logger.warning('No listening port specified, pylon will shutdown now')
            return

        main_bouncer_rotator = pylon.bouncer.BouncerRotator(
            allow_zt_dest=not args.block_zts_dest, allow_main_dest=not args.block_outside_dest)
        zts_bouncer_rotator = pylon.bouncer.BouncerRotator(
            allow_zt_dest=not args.block_zts_dest, allow_main_dest=not args.block_outside_dest)

        async def zts_coro():
            async with contextlib.AsyncExitStack() as stack:
                if args.zts_port is not None:
                    server = await asyncio.start_server(
                        zts_bouncer_rotator.socks5_handler, args.zts_bind, args.zts_port)
                    stack.push_async_callback(server_wait_closed_fix, server)
                    await stack.enter_async_context(server)
                    logger.info('ZTS SOCKS5 proxy server started serving')
                while True:
                    await asyncio.sleep(60)

        io_thread_manager = await stack.enter_async_context(zts_io.ZtsIoThreadManager(zts_coro()))

        def update_bouncer():
            bouncer = pylon.bouncer.Bouncer(node.loop, io_thread_manager.loop, node.routes, node.resolvers)
            main_bouncer_rotator.update_bouncer(bouncer)
            io_thread_manager.loop.call_soon_threadsafe(zts_bouncer_rotator.update_bouncer, bouncer)

        update_bouncer()
        node.set_topology_change_callback(update_bouncer)

        if args.outside_port is not None:
            server = await asyncio.start_server(
                main_bouncer_rotator.socks5_handler, args.outside_bind, args.outside_port)
            stack.push_async_callback(server_wait_closed_fix, server)
            await stack.enter_async_context(server)
            logger.info('Outside SOCKS5 proxy server started serving')
        while True:
            await asyncio.sleep(60)


def parse_validate_network_id(id_str: str) -> int:
    try:
        id_num = int(id_str, base=16)
    except ValueError:
        raise ValueError(f'{id_str} is not a valid network ID')
    if not 0 <= id_num <= 256**8:
        raise ValueError(f'{id_str} is not a valid network ID')
    return id_num


def parse_validate_port_number(port_str: str) -> int:
    port = int(port_str)
    if not 0 <= port <= 65535:
        raise ValueError('Port number out of range')
    return port


def main():
    parser = argparse.ArgumentParser(description='Proxy server into and out of ZeroTier networks')
    parser.add_argument('persistence_path', help='Path where ZeroTier stores node data')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Increase logging verbosity')
    parser.add_argument(
        '-J', '--join', action='append', type=parse_validate_network_id,
        help='Network to join. Can be specified multiple times. All specified networks must be in the OK status before'
             'any SOCKS proxy servers are started.',
    )
    parser.add_argument(
        '-L', '--leave', action='append', type=parse_validate_network_id,
        help='Network to leave. Can be specified multiple times.',
    )
    parser.add_argument(
        '-b', '--blacklist-if', action='append',
        help='Network interface name prefixes to blacklist. Can be specified multiple times.',
    )
    parser.add_argument(
        '-o', '--outside-port', type=parse_validate_port_number,
        help='Start a SOCKS5 proxy server listening on this port on the "outside", i.e. OS networking stack.',
    )
    parser.add_argument(
        '-O', '--outside-bind', action='append',
        help='Bind the "outside" SOCKS5 proxy server to this address. Can be specified multiple times. '
             'When unspecified (and --outside-port is specified), binds to the wildcard address.',
    )
    parser.add_argument(
        '-z', '--zts-port', type=parse_validate_port_number,
        help='Start a SOCKS5 proxy server listening on this port in the ZeroTier network',
    )
    parser.add_argument(
        '-Z', '--zts-bind', action='append',
        help='Bind the ZeroTier SOCKS5 proxy server to this address. Can be specified multiple times. '
             'When unspecified (and --zts-port is specified), binds to the wildcard address.',
    )
    parser.add_argument(
        '--block-outside-dest', action='store_true',
        help='Do not allow connecting to destinations on the "outside" through SOCKS5 proxy servers',
    )
    parser.add_argument(
        '--block-zts-dest', action='store_true',
        help='Do not allow connecting to destinations in the ZeroTier network through SOCKS5 proxy servers',
    )

    args = parser.parse_args()

    asyncio_debug = False
    loglevel = logging.WARNING
    if args.verbose >= 2:
        loglevel = logging.DEBUG
        asyncio_debug = True
    elif args.verbose == 1:
        loglevel = logging.INFO

    logging.basicConfig(level=loglevel, format='%(asctime)s %(levelname)-8s %(message)s')

    logger.debug('Parsed arguments: %r', args)

    with asyncio.Runner(debug=asyncio_debug) as runner:
        try:
            runner.run(run_app(args))
        except asyncio.CancelledError:
            logger.info('Main task cancelled')


if __name__ == '__main__':
    main()
