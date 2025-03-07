Mooo
---------

[![PyPI version](https://badge.fury.io/py/mooo.svg)](https://badge.fury.io/py/mooo)

Mooo is a lightweight HTTP proxy written in Python. You can run it in a server then use it to access the internet.

## Quick Start

> [!WARNING]
> By default, mooo porxy all domains, which means it can retrieve the local network. This poses a security risk.
> It is recommended to specify `--domain` or `--profile` to limit the domain that the proxy server

### Option 1: Use Python package

1. Install moon with `pip install mooo`

2. Start the proxy server

```bash
mooo --host 0.0.0.0 --port 8080
```


### Option 2: Use Docker image

```bash
docker run -p 8080:8080 bebound/mooo --host 0.0.0.0 --port 8080
```

### Use mooo

```bash
curl http://your_proxy_server:8080/{http_url}
git clone http://your_proxy_server:8080/{github_url}
```

#### Use pre-defined profile

Mooo provides some pre-defined profiles, you can use it to proxy some popular websites. Currently, it supports `github`, `google` and `docker`.

Use mooo to proxy github.com
```bash
mooo --profile github --profile github
```

Use mooo to proxy multiple profile with same port. You need to use reverse proxy to route the request to mooo with specific domain. Mooo routes the request to different profile based on the domain. For example, access `github.custom.domain` will route to github.com and `docker.custom.domain` will route to docker registry.
```bash
mooo --profile github docker google --smart-route
```

## Parameters

| Parameter          | Description                                                           | Default   | Example                  |
|--------------------|-----------------------------------------------------------------------|-----------|--------------------------|
| `--host`           | The listening host                                                    | 127.0.0.1 | 0.0.0.0                  |
| `--port`           | The listening port                                                    | 8080      |                          |
| `--debug`          | Show debug logging                                                    | False     |                          |
| `--domain`         | Once it's set, the request domain must match the wildcard domain list | None      | `*.github.com`           | 
| `--cookie`         | Pass the cookie to the server                                         | False     |                          |
| `--default-domain` | The default domain to proxy                                           | None      | `https://www.github.com` |
| `--profile`        | Use pre-defined profile                                               | None      | `github`                 |
| `--smart-route`    | Apply profile rules based on host domain                              | False     |                          | 
