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

The `rules` parameter must be an iterable [e.g. a list or a tuple] of tuples, where each tuple is regex pattern/replacement pair, passed to [re.subn](https://docs.python.org/3/library/re.html#re.subn) under the hood. On each incoming DNS request for a domain

- this list is iterated over;
- the first rule that matches the incoming domain name is used to rewrite the domain, the upstream DNS server is queries for A records, and these records, or error code, is returned downstream;
- and if no rule matches, the request fails, with a REFUSED response returned.

The response of REFUSED is deliberate for clients to be able to help differentiate between a configuration issue on the proxy, the proxy not working or not being contactable, and a domain actually not existing.
