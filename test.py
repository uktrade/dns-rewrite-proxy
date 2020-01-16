import asyncio
import socket
import unittest


from aiodnsresolver import (
    TYPES,
    Resolver,
    IPv4AddressExpiresAt,
    DnsResponseCode,
    DnsRecordDoesNotExist,
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
        resolve, clear_cache = get_resolver(3535)
        self.add_async_cleanup(clear_cache)
        start = DnsProxy(get_socket=get_socket(3535))
        stop = await start()
        self.add_async_cleanup(stop)

        with self.assertRaises(DnsResponseCode) as cm:
            await resolve('www.google.com', TYPES.A)

        self.assertEqual(cm.exception.args[0], 5)

    @async_test
    async def test_e2e_match_all(self):
        resolve, clear_cache = get_resolver(3535)
        self.add_async_cleanup(clear_cache)
        start = DnsProxy(get_socket=get_socket(3535), rules=((r'(^.*$)', r'\1'),))
        stop = await start()
        self.add_async_cleanup(stop)

        response = await resolve('www.google.com', TYPES.A)

        self.assertTrue(isinstance(response[0], IPv4AddressExpiresAt))

    @async_test
    async def test_e2e_default_port_match_all(self):
        resolve, clear_cache = get_resolver(53)
        self.add_async_cleanup(clear_cache)
        start = DnsProxy(rules=((r'(^.*$)', r'\1'),))
        stop = await start()
        self.add_async_cleanup(stop)

        response = await resolve('www.google.com', TYPES.A)

        self.assertTrue(isinstance(response[0], IPv4AddressExpiresAt))

    @async_test
    async def test_e2e_default_resolver_match_all_non_existing_domain(self):
        resolve, clear_cache = get_resolver(53)
        self.add_async_cleanup(clear_cache)
        start = DnsProxy(rules=((r'(^.*$)', r'\1'),))
        stop = await start()
        self.add_async_cleanup(stop)

        with self.assertRaises(DnsRecordDoesNotExist):
            await resolve('doesnotexist.charemza.name', TYPES.A)

    @async_test
    async def test_e2e_default_resolver_match_all_bad_upstream(self):
        resolve, clear_cache = get_resolver(53, timeout=100)
        self.add_async_cleanup(clear_cache)

        start = DnsProxy(rules=((r'(^.*$)', r'\1'),), get_resolver=lambda: get_resolver(54))
        stop = await start()
        self.add_async_cleanup(stop)

        with self.assertRaises(DnsResponseCode) as cm:
            await resolve('www.google.com', TYPES.A)

        self.assertEqual(cm.exception.args[0], 2)

    @async_test
    async def test_e2e_default_resolver_match_none_non_existing_domain(self):
        resolve, clear_cache = get_resolver(53)
        self.add_async_cleanup(clear_cache)
        start = DnsProxy()
        stop = await start()
        self.add_async_cleanup(stop)

        with self.assertRaises(DnsResponseCode) as cm:
            await resolve('doesnotexist.charemza.name', TYPES.A)

        self.assertEqual(cm.exception.args[0], 5)


def get_socket(port):
    def _get_socket():
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(('', port))
        return sock
    return _get_socket


def get_resolver(port, timeout=0.5):
    async def get_nameservers(_, __):
        for _ in range(0, 5):
            yield (timeout, ('127.0.0.1', port))

    return Resolver(get_nameservers=get_nameservers)
