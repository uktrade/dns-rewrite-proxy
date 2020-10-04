# dns-rewrite-proxy [![CircleCI](https://circleci.com/gh/uktrade/dns-rewrite-proxy.svg?style=svg)](https://circleci.com/gh/uktrade/dns-rewrite-proxy) [![Test Coverage](https://api.codeclimate.com/v1/badges/33dcaf0af24e5a1a5bdf/test_coverage)](https://codeclimate.com/github/uktrade/dns-rewrite-proxy/test_coverage)

A DNS proxy server that conditionally rewrites and filters A record requests. Written in Python, all code is in a single module, and there is a single dependency, [aiodnsresolver](https://github.com/michalc/aiodnsresolver).

CNAMEs are followed and resolved by the proxy to IP addresses, and never returned to the client.


## Installation

```bash
pip install dnsrewriteproxy
```


## Usage

By default the proxy will listen on port 53, and proxy requests to the servers in `/etc/resolv.conf`. However, by default all requests are blocked without explicit rules, so to proxy requests you must configure at least one rewrite rule.

```python
from dnsrewriteproxy import DnsProxy

# Proxy all incoming A record requests without any rewriting
start = DnsProxy(rules=((r'(^.*$)', r'\1'),))

# Run proxy, accepting UDP requests on port 53
await start()
```

The `rules` parameter must be an iterable [e.g. a list or a tuple] of tuples, where each tuple is regex pattern/replacement pair, passed to [re.subn](https://docs.python.org/3/library/re.html#re.subn) under the hood. On each incoming DNS request from downstream for a domain

- this list is iterated over;
- the first rule that matches the incoming domain name is used to rewrite the domain, the upstream DNS server is queried for A records, and these records, or error code, is returned downstream;
- and if no rule matches a NXDOMAIN response is returned downstream.

The response of NXDOMAIN is deliberate, since clients often expect domains to not exist, and are more likely to gracefully handle errors.

So to rewrite all queries for `www.source.com` to `www.target.com`, and to _refuse_ to proxy any others, you can use the following configuration.

```python
start = DnsProxy(rules=(
    (r'^www\.source\.com$', r'www.target.com'),
))
```

Alternatively, do the same rewriting, but to _allow_ all other requests, you can use the following.

```python
start = DnsProxy(rules=(
    (r'^www\.source\.com$', r'www.target.com'),
    (r'(^.*$)', r'\1'),
))
```

To proxy to a server other than that specified in `/etc/resolv.conf`, you can pass a customised `Resolver` via `get_resolver`.


```python
from aiodnsresolver import Resolver
from dnsrewriteproxy import DnsProxy

def get_resolver():
    async def get_nameservers(_, __):
        for _ in range(0, 5):
            yield (0.5, ('8.8.8.8', 53))
    return Resolver(get_nameserver=get_nameservers)

start = DnsProxy(
    rules=((r'(^.*$)', r'\1'),),
    get_resolver=get_resolver,
)
```


## Server lifecycle

In the above example `await start()` completes just after the server has started listening. The coroutine `start` returns the underlying _task_ to give control over the server lifecycle. A task can be seen as an "asyncio thread"; this is exposed to allow the server to sit in a larger asyncio Python program that may have a specific startup/shutdown procedure.


### Run forever

You can run the server forever [or until it hits some non-recoverable error] by awaiting this task.

```python
from dnsrewriteproxy import DnsProxy

start = DnsProxy(rules=((r'(^.*$)', r'\1'),))
server_task = await start()

# Waiting here until the server is stopped
await server_task
```


### Stopping the server

To stop the server, you can `cancel` the returned task.

```python
from dnsrewriteproxy import DnsProxy

start = DnsProxy(rules=((r'(^.*$)', r'\1'),))
proxy_task = await start()

# ... Receive requests

# Initiate stopping: new requests will not be processed...
proxy_task.cancel()

try:
    # ... and we wait until previously received requests have been processed
    await proxy_task
except asyncio.CancelledError:
    pass
```


### Graceful shutdown example

A full example of a server that would do a graceful shutdown on SIGINT or SIGTERM is below.

```python
import asyncio
import signal

from dnsrewriteproxy import (
    DnsProxy,
)

async def async_main():
    start = DnsProxy(rules=((r'(^.*$)', r'\1'),))
    proxy_task = await start()

    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, proxy_task.cancel)
    loop.add_signal_handler(signal.SIGTERM, proxy_task.cancel)

    try:
        await proxy_task
    except asyncio.CancelledError:
        pass

asyncio.run(async_main())
print('End of program')
```
