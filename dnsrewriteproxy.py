from asyncio import (
    CancelledError,
    Queue,
    create_task,
    get_running_loop,
)
from enum import (
    IntEnum,
)
import logging
import re
import socket

from aiodnsresolver import (
    RESPONSE,
    TYPES,
    DnsRecordDoesNotExist,
    DnsResponseCode,
    Message,
    Resolver,
    ResourceRecord,
    pack,
    parse,
    recvfrom,
)


def get_socket_default():
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind(('', 53))
    return sock


def get_resolver_default():
    return Resolver()


def get_logger_default():
    return logging.getLogger('dnsrewriteproxy')


def DnsProxy(
        get_resolver=get_resolver_default, get_logger=get_logger_default,
        get_socket=get_socket_default, num_workers=1000,
        rules=(),
):

    class ERRORS(IntEnum):
        FORMERR = 1
        SERVFAIL = 2
        NXDOMAIN = 3
        REFUSED = 5

    loop = get_running_loop()
    logger = get_logger()

    # The "main" task of the server: it receives incoming requests and puts
    # them in a queue that is then fetched from and processed by the proxy
    # workers

    async def server_worker(sock, resolve):
        upstream_queue = Queue(maxsize=num_workers)

        # We have multiple upstream workers to be able to send multiple
        # requests upstream concurrently
        upstream_worker_tasks = [
            create_task(upstream_worker(sock, resolve, upstream_queue))
            for _ in range(0, num_workers)]

        try:
            while True:
                request_data, addr = await recvfrom(loop, [sock], 512)
                await upstream_queue.put((request_data, addr))
        finally:
            # Finish upstream requests
            await upstream_queue.join()
            for upstream_task in upstream_worker_tasks:
                upstream_task.cancel()

            for upstream_task in upstream_worker_tasks:
                try:
                    await upstream_task
                except CancelledError:
                    pass

    async def upstream_worker(sock, resolve, upstream_queue):
        while True:
            request_data, addr = await upstream_queue.get()

            try:
                response_data = await get_response_data(resolve, request_data)
                # Sendto for non-blocking UDP sockets cannot raise a BlockingIOError
                # https://stackoverflow.com/a/59794872/1319998
                sock.sendto(response_data, addr)
            except Exception:
                logger.exception('Processing request from %s', addr)
            finally:
                upstream_queue.task_done()

    async def get_response_data(resolve, request_data):
        # This may raise an exception, which is handled at a higher level.
        # We can't [and I suspect shouldn't try to] return an error to the
        # client, since we're not able to extract the QID, so the client won't
        # be able to match it with an outgoing request
        query = parse(request_data)

        try:
            return pack(
                error(query, ERRORS.REFUSED) if query.qd[0].qtype != TYPES.A else
                (await proxy(resolve, query))
            )
        except Exception:
            logger.exception('Failed to proxy %s', query)
            return pack(error(query, ERRORS.SERVFAIL))

    async def proxy(resolve, query):
        name_bytes = query.qd[0].name
        name_str_lower = query.qd[0].name.lower().decode('idna')

        for pattern, replace in rules:
            rewritten_name_str, num_matches = re.subn(pattern, replace, name_str_lower)
            if num_matches:
                break
        else:
            # No break was triggered, i.e. no match
            return error(query, ERRORS.REFUSED)

        try:
            ip_addresses = await resolve(rewritten_name_str, TYPES.A)
        except DnsRecordDoesNotExist:
            return error(query, ERRORS.NXDOMAIN)
        except DnsResponseCode as dns_response_code_error:
            return error(query, dns_response_code_error.args[0])

        now = loop.time()

        def ttl(ip_address):
            return int(max(0.0, ip_address.expires_at - now))

        reponse_records = tuple(
            ResourceRecord(name=name_bytes, qtype=TYPES.A,
                           qclass=1, ttl=ttl(ip_address), rdata=ip_address.packed)
            for ip_address in ip_addresses
        )
        return Message(
            qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=0,
            qd=query.qd, an=reponse_records, ns=(), ar=(),
        )

    async def start():
        # The socket is created synchronously and passed to the server worker,
        # so if there is an error creating it, this function will raise an
        # exception. If no exeption is raise, we are indeed listening#
        sock = get_socket()

        # The resolver is also created synchronously, since it can parse
        # /etc/hosts or /etc/resolve.conf, and can raise an exception if
        # something goes wrong with that
        resolve, clear_cache = get_resolver()
        server_worker_task = create_task(server_worker(sock, resolve))

        async def stop():
            server_worker_task.cancel()
            try:
                await server_worker_task
            except CancelledError:
                pass

            sock.close()
            await clear_cache()

        return stop

    return start


def error(query, rcode):
    return Message(
        qid=query.qid, qr=RESPONSE, opcode=0, aa=0, tc=0, rd=0, ra=1, z=0, rcode=rcode,
        qd=query.qd, an=(), ns=(), ar=(),
    )
