import asyncio
import collections
import enum
import errno
import ipaddress
import logging
import socket

import dns.name

INADDR_ANY = ipaddress.IPv4Address(0)

HostType = ipaddress.IPv6Address | ipaddress.IPv4Address | dns.name.Name

logger = logging.getLogger(__name__)


class SOCKS5AuthType(enum.IntEnum):
    NO_AUTH = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    NO_OFFERS_ACCEPTABLE = 0xff


class SOCKS5Command(enum.IntEnum):
    CONNECT = 0x01
    BIND = 0x02
    UDP_ASSOCIATE = 0x03


class SOCKS5AddressType(enum.IntEnum):
    IPV4_ADDRESS = 0x01
    DOMAIN_NAME = 0x03
    IPV6_ADDRESS = 0x04


class SOCKS5Reply(enum.IntEnum):
    SUCCESS = 0x00
    GENERAL_FAILURE = 0x01
    CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class Socks5ClientError(RuntimeError):
    """Client did not complete handshake successfully"""


class Socks5ErrorReply(RuntimeError):
    """Represents a error SOCKS5 reply. args should be (reply,)"""


async def receive_socks5_command_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    buf = await reader.readexactly(2)
    if buf[0] != 5:
        raise Socks5ClientError('Invalid request version')
    buf = await reader.readexactly(buf[1])
    if SOCKS5AuthType.NO_AUTH not in buf:
        writer.write(bytes([5, SOCKS5AuthType.NO_OFFERS_ACCEPTABLE]))
        writer.write_eof()
        await writer.drain()
        raise Socks5ClientError('Client did not offer NO_AUTH')
    writer.write(bytes([5, SOCKS5AuthType.NO_AUTH]))

    buf = await reader.readexactly(4)
    if buf[0] != 5 or buf[2] != 0:
        raise Socks5ClientError('Malformed socks5 command')
    try:
        command = SOCKS5Command(buf[1])
    except ValueError:
        raise Socks5ClientError('Unknown socks5 command')
    address_type = buf[3]
    if address_type == SOCKS5AddressType.IPV4_ADDRESS:
        address = ipaddress.IPv4Address(await reader.readexactly(4))
    elif address_type == SOCKS5AddressType.IPV6_ADDRESS:
        address = ipaddress.IPv6Address(await reader.readexactly(16))
    elif address_type == SOCKS5AddressType.DOMAIN_NAME:
        buf = await reader.readexactly(1)
        address = await reader.readexactly(buf[0])
        try:
            address = address.decode('ascii')
        except ValueError:
            # Does any client send a domain name without encoding it in punycode?
            try:
                address = dns.name.from_unicode(address.decode('utf-8'))
            except (ValueError, dns.exception.DNSException):
                await send_socks5_command_reply(writer, SOCKS5Reply.GENERAL_FAILURE)
                raise Socks5ClientError('Invalid host in command')
        else:
            try:
                address = ipaddress.ip_address(address)
            except ValueError:
                try:
                    address = dns.name.from_text(address)
                except (ValueError, dns.exception.DNSException):
                    await send_socks5_command_reply(writer, SOCKS5Reply.GENERAL_FAILURE)
                    raise Socks5ClientError('Invalid host in command')
    else:
        await send_socks5_command_reply(writer, SOCKS5Reply.ADDRESS_TYPE_NOT_SUPPORTED)
        raise Socks5ClientError('Unknown address type')
    port = int.from_bytes(await reader.readexactly(2), 'big')
    return command, address, port


async def send_socks5_command_reply(
        writer: asyncio.StreamWriter,
        reply: SOCKS5Reply,
        host: HostType | None = None,
        port: int = 0,
):
    data = [bytes([5, reply, 0])]
    if host is None:
        host = INADDR_ANY
    if isinstance(host, dns.name.Name):
        host_bytes = host.to_text(omit_final_dot=True).encode('ascii')
        try:
            data.append(bytes([SOCKS5AddressType.DOMAIN_NAME, len(host_bytes)]))
        except ValueError:
            raise RuntimeError('Host name too long')
        data.append(host_bytes)
    else:
        if host.version == 6:
            data.append(bytes([SOCKS5AddressType.IPV6_ADDRESS]))
        else:
            data.append(bytes([SOCKS5AddressType.IPV4_ADDRESS]))
        data.append(host.packed)
    data.append(port.to_bytes(2, 'big'))
    writer.writelines(data)
    await writer.drain()


def map_exception_to_socks5_reply(exc: Exception | list[Exception]) -> SOCKS5Reply:
    if isinstance(exc, list):
        replies = map(map_exception_to_socks5_reply, exc)
        reply_counter = collections.Counter(replies)
        reply_counter.pop(SOCKS5Reply.GENERAL_FAILURE, None)
        if reply_counter:
            return reply_counter.most_common(1)[0][0]
        return SOCKS5Reply.GENERAL_FAILURE
    if isinstance(exc, socket.gaierror):
        return SOCKS5Reply.HOST_UNREACHABLE
    if isinstance(exc, TimeoutError):
        return SOCKS5Reply.TTL_EXPIRED
    if isinstance(exc, ConnectionRefusedError):
        return SOCKS5Reply.CONNECTION_REFUSED
    if isinstance(exc, OSError):
        if exc.errno == errno.ENETUNREACH:
            return SOCKS5Reply.NETWORK_UNREACHABLE
        elif exc.errno == errno.EHOSTUNREACH:
            return SOCKS5Reply.HOST_UNREACHABLE
        elif exc.errno == errno.ECONNREFUSED:
            return SOCKS5Reply.CONNECTION_REFUSED
        elif exc.errno == errno.ETIMEDOUT:
            return SOCKS5Reply.TTL_EXPIRED
        else:
            return SOCKS5Reply.GENERAL_FAILURE
    logger.warning('SOCKS5 reply mapping: unexpected exception', exc_info=exc)
    return SOCKS5Reply.GENERAL_FAILURE
