#!/usr/bin/env python3
# HTTP CONNECT proxy for split-tunnel mode.
#
# Some apps ignore the macOS PAC setting and only honour HTTPS_PROXY, which
# must be an HTTP proxy. Discord's updater is one of them: without this it
# connects directly, DPI resets the TLS handshake, and the splash screen
# loops on "checking for updates". ciadpi only speaks SOCKS, so this bridge
# accepts CONNECT, sends hosts from the domain list through ciadpi's SOCKS5
# port and connects everything else directly, same as the PAC file.
#
# Usage: connect_bridge.py <listen-port> <socks-port> <domains-file>

import asyncio
import struct
import sys

LISTEN_PORT = int(sys.argv[1])
SOCKS_PORT = int(sys.argv[2])
DOMAINS_FILE = sys.argv[3]


def load_domains():
    with open(DOMAINS_FILE) as f:
        return [l.strip().lower() for l in f if l.strip() and not l.lstrip().startswith("#")]


def routed(host):
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in load_domains())


async def open_socks(host, port):
    reader, writer = await asyncio.open_connection("127.0.0.1", SOCKS_PORT)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    if await reader.readexactly(2) != b"\x05\x00":
        raise ConnectionError("socks auth rejected")
    name = host.encode()
    writer.write(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", port))
    await writer.drain()
    head = await reader.readexactly(4)
    if head[1] != 0:
        raise ConnectionError("socks connect failed: %d" % head[1])
    atyp = head[3]
    if atyp == 1:
        await reader.readexactly(4 + 2)
    elif atyp == 4:
        await reader.readexactly(16 + 2)
    else:
        await reader.readexactly((await reader.readexactly(1))[0] + 2)
    return reader, writer


async def pipe(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


async def handle(creader, cwriter):
    try:
        head = await creader.readuntil(b"\r\n\r\n")
        method, target, _ = head.split(b"\r\n", 1)[0].decode("latin-1").split(" ", 2)
        if method.upper() != "CONNECT":
            cwriter.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            await cwriter.drain()
            cwriter.close()
            return
        host, _, port = target.rpartition(":")
        host, port = host.strip("[]"), int(port)
        if routed(host):
            ureader, uwriter = await open_socks(host, port)
        else:
            ureader, uwriter = await asyncio.open_connection(host, port)
    except Exception:
        try:
            cwriter.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await cwriter.drain()
            cwriter.close()
        except Exception:
            pass
        return
    cwriter.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await cwriter.drain()
    await asyncio.gather(pipe(creader, uwriter), pipe(ureader, cwriter))


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", LISTEN_PORT)
    async with server:
        await server.serve_forever()


asyncio.run(main())
