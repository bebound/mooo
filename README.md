Mooo
---------

[![PyPI version](https://badge.fury.io/py/mooo.svg)](https://badge.fury.io/py/mooo)

Mooo is a lightweight HTTP proxy written in Python. You can run it in a server then use it to access the internet.

## Quick Start

### Option 1: Start Python server

1. Install moon with `pip install mooo`

2. Start the proxy server

```bash
mooo --host 0.0.0.0 --port 8080
```

> [!WARNING]
> The proxy server automatically proxies the local network, it could pose a security risk.
> It is recommended to use it in Docker or specify `--domain` or `--profile` to limit the domain that the proxy server
> can
> access.

### Option 2: Start Docker server

```bash
docker run -p 8080:8080 bebound/mooo --host 0.0.0.0 --port=8080
```

### Use Mooo

```bash
curl http://your_proxy_server:8080/{http_url}
git clone http://your_proxy_server:8080/{github_url}
```

## Parameters

| Parameter          | Description                                                            | Default   | Example                  |
|--------------------|------------------------------------------------------------------------|-----------|--------------------------|
| `--host`           | The listening host                                                     | 127.0.0.1 | 0.0.0.0                  |
| `--port`           | The listening port                                                     | 8080      |                          |
| `--debug`          | Show debug logging                                                     | False     |                          |
| `--domain`         | Once it's set, the request domain must match the wildcard domain list. | None      | `*.github.com`           | 
| `--cookie`         | Pass the cookie to the server                                          | False     |                          |
| `--default-domain` | The default domain to proxy                                            | None      | `https://www.github.com` |
| `--profile`        | Use pre-defined profile                                                | None      | `github`                 |
