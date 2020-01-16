# dns-rewrite-proxy [![CircleCI](https://circleci.com/gh/uktrade/dns-rewrite-proxy.svg?style=svg)](https://circleci.com/gh/uktrade/dns-rewrite-proxy) [![Test Coverage](https://api.codeclimate.com/v1/badges/33dcaf0af24e5a1a5bdf/test_coverage)](https://codeclimate.com/github/uktrade/dns-rewrite-proxy/test_coverage)

A DNS proxy server that conditionally rewrites and filters A record requests


## Usage

By default the proxy will listen on port 53, and proxy requests to the servers in `/etc/resolve.conf`. However, by default all requests are blocked without explicit rules, so to proxy requests you must configure at least one rewrite rule.

```python
from dnsrewriteproxy import DnsProxy

# Proxy all incoming A record requests without any rewriting
start = DnsProxy(rules=((r'(^.*$)', r'\1'),))

# Proxy is running, accepting UDP requests on port 53
stop = await start()

# Stopped
await stop()
```
