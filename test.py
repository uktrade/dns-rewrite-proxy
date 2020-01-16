import asyncio
import socket
import unittest


from aiodnsresolver import (
    TYPES,
    Resolver,
    IPv4AddressExpiresAt,
    DnsResponseCode,
)
from dnsrewriteproxy import (
    DnsProxy,
)


def async_test(func):
    def wrapper(*args, **kwargs):
        future = func(*args, **kwargs)
        loop = asyncio.get_event_loop()
        loop.run_until_complete(future)
    return wrapper


class TestProxy(unittest.TestCase):
    def add_async_cleanup(self, coroutine):
        self.addCleanup(asyncio.get_running_loop().run_until_complete, coroutine())

    @async_test
    async def test_e2e_no_match_rule(self):
        resolve, clear_cache = get_resolver()
        self.add_async_cleanup(clear_cache)
        start = DnsProxy(get_socket=get_socket)
        stop = await start()
        self.add_async_cleanup(stop)

        with self.assertRaises(DnsResponseCode):
            await resolve('www.google.com', TYPES.A)

    @async_test
    async def test_e2e_match_all(self):
        resolve, clear_cache = get_resolver()
        self.add_async_cleanup(clear_cache)
        start = DnsProxy(get_socket=get_socket, rules=((r'(^.*$)', r'\1'),))
        stop = await start()
        self.add_async_cleanup(stop)

        response = await resolve('www.google.com', TYPES.A)

        self.assertTrue(isinstance(response[0], IPv4AddressExpiresAt))


def get_socket():
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind(('', 3535))
    return sock


def get_resolver():
    async def get_nameservers(_, __):
        for _ in range(0, 5):
            yield (0.5, ('127.0.0.1', 3535))

    return Resolver(get_nameservers=get_nameservers)
