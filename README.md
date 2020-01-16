# dns-rewrite-proxy [![CircleCI](https://circleci.com/gh/uktrade/dns-rewrite-proxy.svg?style=svg)](https://circleci.com/gh/uktrade/dns-rewrite-proxy) [![Test Coverage](https://api.codeclimate.com/v1/badges/33dcaf0af24e5a1a5bdf/test_coverage)](https://codeclimate.com/github/uktrade/dns-rewrite-proxy/test_coverage)

A DNS proxy server that conditionally rewrites and filters A record requests


## Usage

```python
from dnsrewriteproxy import DnsProxy

start = DnsProxy()

# Proxy is running, accepting UDP requests on port 53
stop = await start()

# Stopped
await stop()
```
