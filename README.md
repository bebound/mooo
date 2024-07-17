mooo
---------

`mooo` is a lightweight HTTP proxy written in Python. You can run it in a server then use it to access the internet.

## Quick Start

### Installation

`pip install mooo`

### Usage

1. Start the proxy server

```bash
mooo --host 0.0.0.0 --port 8080
```

2. Use the proxy server to access the internet

```bash
curl http://your_proxy_server:8080/{http_url}
git clone http://your_proxy_server:8080/{github_url}
```

> [!WARNING]
> The proxy server auto proxy the local network, it could be a security issue.
> Please use it in docker or specify `--allow-domain` to limit the domain that the proxy server can access.

## Docker Guide

```bash
docker run -p 8080:8080 bebound/mooo --host 0.0.0.0 --port=8080
```

## Parameters

| Parameter | Description        | Default   |
|-----------|--------------------|-----------|
| `--host`  | The listening host | 127.0.0.1 |
| `--port`  | The listening port | 8080      |
