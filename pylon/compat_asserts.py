import errno
import socket

import libzt

# These most used constants from libzt are equal to those in Linux, so much code using sockets can be used unmodified
assert libzt.ZTS_SOCK_STREAM == socket.SOCK_STREAM
assert libzt.ZTS_SOCK_DGRAM == socket.SOCK_DGRAM
assert libzt.ZTS_AF_INET == socket.AF_INET
assert libzt.ZTS_AF_INET6 == socket.AF_INET6
assert libzt.ZTS_AF_UNSPEC == socket.AF_UNSPEC
assert libzt.ZTS_IPPROTO_TCP == socket.IPPROTO_TCP
assert libzt.ZTS_IPPROTO_UDP == socket.IPPROTO_UDP

assert libzt.ZTS_SHUT_WR == socket.SHUT_WR
assert libzt.ZTS_SHUT_RD == socket.SHUT_RD
assert libzt.ZTS_SHUT_RDWR == socket.SHUT_RDWR

# The error codes are also equal, which is important for the constructor of OSError
assert libzt.ZTS_EAGAIN == errno.EAGAIN
assert libzt.ZTS_EINPROGRESS == errno.EINPROGRESS
assert libzt.ZTS_EALREADY == errno.EALREADY
assert libzt.ZTS_ECONNABORTED == errno.ECONNABORTED
assert libzt.ZTS_ECONNREFUSED == errno.ECONNREFUSED
assert libzt.ZTS_ECONNRESET == errno.ECONNRESET
assert libzt.ZTS_ETIMEDOUT == errno.ETIMEDOUT
assert libzt.ZTS_ENETUNREACH == errno.ENETUNREACH
assert libzt.ZTS_EHOSTUNREACH == errno.EHOSTUNREACH


# The following asserts fail: lwIP's IPPROTO_*, SOL_* and SO_* constants have different values from Linux

# assert libzt.ZTS_SOL_SOCKET == socket.SOL_SOCKET
# assert libzt.ZTS_SO_ERROR == socket.SO_ERROR
