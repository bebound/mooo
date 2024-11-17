import argparse
import logging

from aiohttp import web, ClientSession
from aiohttp.web import middleware


class Config:
    GLOBAL_PROFILE = {
        'github': {'domain': ['*.github.com', '*.githubusercontent.com'], 'default_domain': 'https://www.github.com'},
        'google': {'domain': ['*.google.com'], 'default_domain': 'https://www.google.com'},
        # 'docker': {'domain': ['*.docker.com', '*.docker.io'], 'default_domain': 'https://registry-1.docker.io'}
    }

    def __init__(self):
        self.domain = set()
        self.cookie = False
        self.default_domain = None

    def add_domain(self, *domains):
        self.domain.update(domains)

    def set_default_domain(self, domain):
        if self.default_domain:
            logging.getLogger('aiohttp.access').warning(
                f'Setting default domain from {self.default_domain} to {domain}')
        self.default_domain = domain

    def update_from_args(self, args):
        self.cookie = args.cookie
        self.domain = set(args.domain)
        if args.default_domain and not is_url(args.default_domain):
            raise ValueError(f'Default path {args.default_domain} is not a valid URL')
        self.default_domain = args.default_domain

        for p in args.profile:
            assert p in self.GLOBAL_PROFILE, f'Profile {p} not found'
            self.add_domain(*self.GLOBAL_PROFILE[p]['domain'])
            self.set_default_domain(self.GLOBAL_PROFILE[p]['default_domain'])


def is_url(url):
    # modified from https://github.com/django/django/blob/stable/1.3.x/django/core/validators.py#L45
    import re
    regex = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return regex.match(url)


def get_domain(url):
    from urllib.parse import urlparse
    return urlparse(url).netloc


@middleware
async def check_url(request, handler):
    from fnmatch import fnmatch
    url = request.match_info.get('url')
    if url:
        if not is_url(url):
            if not config.default_domain:
                logging.getLogger('aiohttp.access').info(f'Requested url {url} is not valid')
                return web.Response(text=f'Requested url {url} is not valid', status=400)
        else:
            domain = get_domain(url)
            if config.domain and not any(fnmatch(domain, pattern) for pattern in config.domain):
                logging.getLogger('aiohttp.access').info(f'Requested domain {domain} is not allowed')
                return web.Response(text=f'Requested domain {domain} is not allowed', status=403)
    resp = await handler(request)
    return resp


async def proxy(request):
    method = request.method
    url = request.match_info.get('url')
    if not url:
        if config.default_domain:
            url = config.default_domain
        else:
            url = 'https://github.com/bebound/mooo'
    if not is_url(url) and config.default_domain:
        import urllib.parse
        url = urllib.parse.urljoin(config.default_domain, url)
    request_headers = dict(request.headers)
    # Reset the host header to the requested host
    if 'Host' in request_headers:
        request_headers['Host'] = get_domain(url)
    if not config.cookie and 'Cookie' in request_headers:
        request_headers.pop('Cookie')

    request_params = dict(request.rel_url.query)

    request_data = await request.read()
    # Use `auto_decompress=False` to disable automatic decompression, so the returned content-encoding is still gzip
    # see https://github.com/aio-libs/aiohttp/issues/1992

    # skip auto headers `'Accept-Encoding': 'gzip, deflate'`, to prevent an unexpected gzip content returned
    async with ClientSession(auto_decompress=False, skip_auto_headers=('Accept-Encoding',)) as session:
        async with session.request(method, url, data=request_data, headers=request_headers,
                                   params=request_params) as response:
            response_headers = dict(response.headers)
            if not config.cookie and 'Set-Cookie' in response_headers:
                response_headers.pop('Set-Cookie')
            resp = web.StreamResponse(
                status=response.status,
                headers=response_headers
            )
            await resp.prepare(request)
            async for chunk in response.content.iter_chunked(64 * 1024):
                await resp.write(chunk)
            await resp.write_eof()
            return resp


def parse_args():
    parser = argparse.ArgumentParser(
        description='Mooo is a lightweight HTTP proxy written in Python. You can run it in a server then use it to access the internet.')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='The host to listen on')
    parser.add_argument('--port', type=int, default=8080, help='The port to listen on')
    parser.add_argument('--debug', type=bool, default=False, action=argparse.BooleanOptionalAction,
                        help='Enable debug logging')
    parser.add_argument('--domain', action='append', nargs='*', help='Allow requests to these domains', default=list())
    parser.add_argument('--default-domain', type=str, help='Default domain to redirect to')
    parser.add_argument('--cookie', type=bool, default=False, action=argparse.BooleanOptionalAction,
                        help='Enable cookie')
    parser.add_argument('--profile', action='append', nargs='*', help='Use pre-defined profile', default=list())
    return parser.parse_args()


def main():
    args = parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    # domain list needs to be flattened.
    args.domain = [j for i in args.domain for j in i]
    args.profile = [j for i in args.profile for j in i]
    config.update_from_args(args)
    print(f'Listening on http://{args.host}:{args.port}')
    web.run_app(app, host=args.host, port=args.port)


routes = web.RouteTableDef()
app = web.Application(middlewares=[check_url])
config = Config()
app.add_routes([web.route('*', '/{url:.*}', proxy)])

if __name__ == '__main__':
    main()
