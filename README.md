# py-Pylon

*You must construct additional pylons*

Pylon is a SOCKS5 proxy server,
running entirely in userspace,
that proxies traffic into and out of ZeroTier networks.
It is essentially [zerotier/pylon](https://github.com/zerotier/pylon),
reimplemented in Python,
with extra features.

## Features

- Listening on native or ZeroTier network, forwarding traffic to ZeroTier or native network
- Supports SOCKS5 CONNECT command (initiating TCP connections)
- Supports DNS servers configured on ZeroTier networks just like recent versions of ZeroTier client
- Can join multiple ZeroTier networks simultaneously
- Runs in userspace: no root needed, does not create a tap interface, etc.

### Limitations

- Does not support SOCKS5 BIND and UDP-ASSOCIATE commands yet
- Does not support additional routes configured on ZeroTier networks.
This seems to be a `libzt` limitation,
as `lwIP` does support static routes,
but `libzt` has not implemented them.

## Usage

Python 3.11 is required for now.
(Python 3.12 is untested, and probably won't work yet.)

The short version:

Make a virtualenv,
build and install [my fork of `libzt`](https://github.com/twisteroidambassador/libzt),
install *async_stagger*, *dnspython* and *pytricia*,
`cd` into this repository,
and run `python -m pylon`.

A packaged container image is coming soon.

