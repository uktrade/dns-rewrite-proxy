import asyncio
import ipaddress
import socket
import struct
import unittest


from aiodnsresolver import (
    RESPONSE,
    TYPES,
    DnsRecordDoesNotExist,
    DnsResponseCode,
    DnsTimeout,
    IPv4AddressExpiresAt,
    Message,
    ResourceRecord,
    QuestionRecord,
    Resolver,
    pack,
    parse,
    recvfrom,
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

        self.assertEqual(type(response[0]), IPv4AddressExpiresAt)

    @async_test
    async def test_e2e_default_port_match_all(self):
        resolve, clear_cache = get_resolver(53)
        self.add_async_cleanup(clear_cache)
        start = DnsProxy(rules=((r'(^.*$)', r'\1'),))
        stop = await start()
        self.add_async_cleanup(stop)

        response = await resolve('www.google.com', TYPES.A)

        self.assertEqual(type(response[0]), IPv4AddressExpiresAt)

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
    async def test_e2e_default_resolver_rewrite_non_existing_to_existing(self):
        resolve, clear_cache = get_resolver(53)
        self.add_async_cleanup(clear_cache)
        start = DnsProxy(rules=((r'^doesnotexist\.charemza\.name$', r'www.google.com'),))
        stop = await start()
        self.add_async_cleanup(stop)

        response = await resolve('doesnotexist.charemza.name', TYPES.A)
        self.assertEqual(type(response[0]), IPv4AddressExpiresAt)

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

    @async_test
    async def test_many_responses_with_small_socket_buffer(self):
        resolve, clear_cache = get_resolver(53)
        self.add_async_cleanup(clear_cache)

        start = DnsProxy(rules=((r'(^.*$)', r'\1'),), get_socket=get_small_socket,
                         get_resolver=get_fixed_resolver)
        stop = await start()
        self.add_async_cleanup(stop)

        tasks = [
            asyncio.create_task(resolve('www.google.com', TYPES.A))
            for _ in range(0, 100000)
        ]

        responses = await asyncio.gather(*tasks)

        for response in responses:
            self.assertEqual(str(response[0]), '1.2.3.4')

        bing_responses = await resolve('www.bing.com', TYPES.A)
        self.assertEqual(type(bing_responses[0]), IPv4AddressExpiresAt)

    @async_test
    async def test_proxy_returns_error_from_upstream(self):
        rcode = 4

        async def get_response(query_data):
            query = parse(query_data)
            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=rcode,
                qd=query.qd, an=(), ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(54, get_response)
        self.add_async_cleanup(stop_nameserver)

        resolve, clear_cache = get_resolver(53)
        self.add_async_cleanup(clear_cache)

        start = DnsProxy(rules=((r'(^.*$)', r'\1'),), get_resolver=lambda: get_resolver(54))
        stop = await start()
        self.add_async_cleanup(stop)

        with self.assertRaises(DnsResponseCode) as cm:
            await resolve('www.google.com', TYPES.A)

        self.assertEqual(cm.exception.args[0], 4)

        rcode = 5
        with self.assertRaises(DnsResponseCode) as cm:
            await resolve('www.google.com', TYPES.A)

        self.assertEqual(cm.exception.args[0], 5)

    @async_test
    async def test_sending_bad_messages_not_affect_later_queries_a(self):
        resolve, clear_cache = get_resolver(53)
        self.add_async_cleanup(clear_cache)

        start = DnsProxy(rules=((r'(^.*$)', r'\1'),))
        stop = await start()
        self.add_async_cleanup(stop)

        response = await resolve('www.google.com', TYPES.A)
        self.assertEqual(type(response[0]), IPv4AddressExpiresAt)

        for _ in range(0, 100000):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b'not-a-valid-message', ('127.0.0.1', 53))
            sock.close()

        tasks = [
            asyncio.create_task(resolve('www.google.com', TYPES.A))
            for _ in range(0, 100000)
        ]
        responses = await asyncio.gather(*tasks)
        for response in responses:
            self.assertEqual(type(response[0]), IPv4AddressExpiresAt)

    @async_test
    async def test_sending_bad_messages_not_affect_later_queries_b(self):
        resolve, clear_cache = get_resolver(53)
        self.add_async_cleanup(clear_cache)

        start = DnsProxy(rules=((r'(^.*$)', r'\1'),))
        stop = await start()
        self.add_async_cleanup(stop)

        response = await resolve('www.google.com', TYPES.A)
        self.assertEqual(type(response[0]), IPv4AddressExpiresAt)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(0, 100000):
            sock.sendto(b'not-a-valid-message', ('127.0.0.1', 53))
        sock.close()

        tasks = [
            asyncio.create_task(resolve('www.google.com', TYPES.A))
            for _ in range(0, 100000)
        ]
        responses = await asyncio.gather(*tasks)
        for response in responses:
            self.assertEqual(type(response[0]), IPv4AddressExpiresAt)

    @async_test
    async def test_sending_pointer_loop_not_affect_later_queries_c(self):
        resolve, clear_cache = get_resolver(53)
        self.add_async_cleanup(clear_cache)

        start = DnsProxy(rules=((r'(^.*$)', r'\1'),))
        stop = await start()
        self.add_async_cleanup(stop)

        response = await resolve('www.google.com', TYPES.A)
        self.assertEqual(type(response[0]), IPv4AddressExpiresAt)

        name = b'mydomain.com'
        question_record = QuestionRecord(name, TYPES.A, qclass=1)
        record_1 = ResourceRecord(
            name=name, qtype=TYPES.A, qclass=1, ttl=0,
            rdata=ipaddress.IPv4Address('123.100.124.1').packed,
        )
        response = Message(
            qid=1, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
            qd=(question_record,), an=(record_1,), ns=(), ar=(),
        )

        data = pack(response)
        packed_name = b''.join(
            component
            for label in name.split(b'.')
            for component in (bytes([len(label)]), label)
        ) + b'\0'

        occurance_1 = data.index(packed_name)
        occurance_1_end = occurance_1 + len(packed_name)
        occurance_2 = occurance_1_end + data[occurance_1_end:].index(packed_name)
        occurance_2_end = occurance_2 + len(packed_name)

        data_compressed = \
            data[:occurance_2] + \
            struct.pack('!H', (192 * 256) + occurance_2 + 4) + \
            struct.pack('!H', (192 * 256) + occurance_2) + \
            struct.pack('!H', (192 * 256) + occurance_2 + 2) + \
            data[occurance_2_end:]

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(data_compressed, ('127.0.0.1', 53))
        sock.close()

        tasks = [
            asyncio.create_task(resolve('www.google.com', TYPES.A))
            for _ in range(0, 100000)
        ]
        responses = await asyncio.gather(*tasks)
        for response in responses:
            self.assertEqual(type(response[0]), IPv4AddressExpiresAt)

    @async_test
    async def test_too_large_response_from_upstream_not_affect_later(self):
        num_records = 200

        async def get_response(query_data):
            query = parse(query_data)
            response_records = tuple(
                ResourceRecord(
                    name=query.qd[0].name,
                    qtype=TYPES.A,
                    qclass=1,
                    ttl=0,
                    rdata=ipaddress.IPv4Address('123.100.123.' + str(i)).packed,
                ) for i in range(0, num_records)
            )

            response = Message(
                qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
                qd=query.qd, an=response_records, ns=(), ar=(),
            )
            return pack(response)

        stop_nameserver = await start_nameserver(54, get_response)
        self.add_async_cleanup(stop_nameserver)

        resolve, clear_cache = get_resolver(53)
        self.add_async_cleanup(clear_cache)

        start = DnsProxy(rules=((r'(^.*$)', r'\1'),), get_resolver=lambda: get_resolver(54))
        stop = await start()
        self.add_async_cleanup(stop)

        tasks = [
            asyncio.create_task(resolve('www.google.com', TYPES.A))
            for _ in range(0, 100000)
        ]

        for task in tasks:
            with self.assertRaises(DnsTimeout):
                await task

        num_records = 1
        tasks = [
            asyncio.create_task(resolve('www.google.com', TYPES.A))
            for _ in range(0, 100000)
        ]
        responses = await asyncio.gather(*tasks)
        for response in responses:
            self.assertEqual(str(response[0]), '123.100.123.0')


def get_socket(port):
    def _get_socket():
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(('', port))
        return sock
    return _get_socket


def get_small_socket():
    # For linux, the minimum buffer size is 1024
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)
    sock.setblocking(False)
    sock.bind(('', 53))
    return sock


def get_resolver(port, timeout=0.5):
    async def get_nameservers(_, __):
        for _ in range(0, 5):
            yield (timeout, ('127.0.0.1', port))

    return Resolver(get_nameservers=get_nameservers)


def get_fixed_resolver():
    async def get_host(_, fqdn, qtype):
        hosts = {
            b'www.google.com': {
                TYPES.A: IPv4AddressExpiresAt('1.2.3.4', expires_at=0),
            },
        }
        try:
            return hosts[fqdn.lower()][qtype]
        except KeyError:
            return None

    return Resolver(get_host=get_host)


async def start_nameserver(port, get_response):
    # For some tests we need to control the responses from upstream, especially in the cases
    # where it's not behaving
    loop = asyncio.get_event_loop()

    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind(('', port))

    async def server():
        client_tasks = []
        try:
            while True:
                data, addr = await recvfrom(loop, [sock], 512)
                client_tasks.append(asyncio.ensure_future(client_task(data, addr)))
        finally:
            for task in client_tasks:
                task.cancel()

    async def client_task(data, addr):
        response = await get_response(data)
        sock.sendto(response, addr)

    server_task = asyncio.ensure_future(server())

    async def stop():
        server_task.cancel()
        await asyncio.sleep(0)
        sock.close()

    return stop
