# dns-rewrite-proxy

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
