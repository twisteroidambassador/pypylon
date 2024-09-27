# py-Pylon

*You must construct additional pylons*

Pylon is a SOCKS5 proxy server,
running entirely in userspace,
that proxies traffic into and out of ZeroTier networks.
It is essentially [zerotier/pylon](https://github.com/zerotier/pylon),
reimplemented in Python,
with extra features.

## Features

(Features not supported by the original pylon is in bold)

- Listening on native or ZeroTier network, forwarding traffic to ZeroTier or native network 
(i.e. proxying into ZeroTier or **out of ZeroTier**)
- Supports IPv4 and **IPv6** inside ZeroTier networks
- Supports SOCKS5 CONNECT command (initiating TCP connections)
- **Supports DNS servers configured on ZeroTier networks just like recent versions of ZeroTier client**
- Can join multiple ZeroTier networks simultaneously
- Runs in userspace: no root needed, does not create a tap interface, etc.

### Limitations

- Does not support SOCKS5 BIND and UDP-ASSOCIATE commands yet
- Does not support additional routes configured on ZeroTier networks.
This seems to be a `libzt` limitation,
as `lwIP` does support static routes,
but `libzt` has not implemented them.

## Installation

Python 3.11 is required for now.
(Python 3.12 is untested, and probably won't work yet.)

This requires my personal fork of `libzt`, which can be found here: https://github.com/twisteroidambassador/libzt
The install methods below all use prebuilt wheels hosted there,
but you can always build from source if you prefer.

### Native Install

```shell
# Clone this repository (or download the code, whichever way you prefer)
$ git clone https://github.com/twisteroidambassador/pypylon.git
$ cd pypylon
# Create a virtual env
$ python3.11 -m venv venv
$ . venv/bin/activate
# Install dependencies
$ pip install -r requirements.txt
# Run pylon
$ python -m pylon --help
```

### Container Install (Docker, Podman, etc.)

Personally, I would recommend using a native install.
Nevertheless, a container image is available in the [Packages](https://github.com/twisteroidambassador/pypylon/pkgs/container/pypylon) section of this repo.

To see the help message, do something like this:

```shell
$ docker run --rm -it ghcr.io/twisteroidambassador/pypylon:main --help
```

Note the following when using the container image:

- Pylon, and ZeroTier in general,
takes advantage of globally routable IPv6 addresses and native access to network interfaces.
Use a networking configuration that allows native host network access if possible.
Also, the interface names inside containers may be different from native interfaces,
so take care when using `--blacklist-if`.

- Remember to persist node data, by mounting a directory inside the container, using a volume, etc.


# Usage

Quick start:

```shell
python -m pylon -v -J 0123456789abcdef -o 1080 --block-outside-dest ./node
```

This will persist node data in `./node`,
join network `0123456789abcdef` (and wait for it to be online before starting the proxy server),
run a SOCKS5 proxy server listening on the outside on port 1080,
and only allow proxying into the ZeroTier network.

The log level is increased to INFO,
so the node ID is printed in the logs.
Remember to authorize this node in your network controller.

For more info, look at the help messages.