import argparse
import logging
from collections import namedtuple

from aiohttp import web, ClientSession
from aiohttp.web import middleware

RewriteHeader = namedtuple('RewriteRule', ['source', 'target'])
RewriteUrl = namedtuple('RewriteRule', ['source', 'target'])
RewriteParam = namedtuple('RewriteRule', ['url', 'param', 'old_value', 'new_value'])


class Config:
    GLOBAL_PROFILE = {
        'github': {'domain': ['*.github.com', '*.githubusercontent.com'], 'default_domain': 'https://www.github.com/'},
        'google': {'domain': ['*.google.com'], 'default_domain': 'https://www.google.com/'},
        'docker': {'domain': ['*.docker.io'], 'default_domain': 'https://registry-1.docker.io/',
                   'rewrite_headers': {
                       'WWW-Authenticate': [
                           RewriteHeader(r'Bearer realm="(.*?)"', r'Bearer realm="http://{host}/\1"')]},
                   # v2/hello-world/manifests -> v2/library/hello-world/manifests
                   'rewrite_urls': [RewriteUrl(r'^https://registry-1.docker.io/v2/([^/]+)/manifests/',
                                               r'https://registry-1.docker.io/v2/library/\1/manifests/'),
                                    RewriteUrl(r'^https://registry-1.docker.io/v2/([^/]+)/blobs/',
                                               r'https://registry-1.docker.io/v2/library/\1/blobs/')],
                   # repository:hello-world:pull => repository:library/hello-world:pull
                   'rewrite_params': [
                       RewriteParam('https://auth.docker.io/token', 'scope', r'^repository:([^:/]+):([^:]+)$',
                                    r'repository:library/\1:\2')],
                   'domain_map': {
                       # 'wat/': 'https://auth.docker.io',
                   }},
    }

    def __init__(self):
        self.domain: set = set()
        self.port: int = 8080
        self.cookie: bool = False
        self._default_domain: str = ''
        self._rewrite_headers: dict = {}
        self.domain_map: dict = {}
        self._rewrite_urls: list = []
        self._rewrite_params: list = []
        self.smart_route: bool = False
        self.enabled_profile: dict = {}

    def get_default_domain(self, server_host=None):
        if not self.smart_route:
            return self._default_domain
        else:
            for web_domain, config in self.GLOBAL_PROFILE.items():
                if web_domain in server_host:
                    return config['default_domain']

    def add_domain(self, *domains):
        self.domain.update(domains)

    def add_rewrite_headers(self, new_rules):
        for header, rules in new_rules.items():
            ori_value = self._rewrite_headers.get(header, [])
            self._rewrite_headers[header] = ori_value + rules

    def add_rewrite_urls(self, rules):
        self._rewrite_urls.extend(rules)

    def add_rewrite_params(self, rules):
        self._rewrite_params.extend(rules)

    def add_domain_map(self, domain_map):
        self.domain_map.update(domain_map)

    def set_default_domain(self, domain):
        if self._default_domain:
            logging.getLogger('aiohttp.access').warning(
                f'Setting default domain from {self._default_domain} to {domain}')
        self._default_domain = domain

    @staticmethod
    def more_variables(host):
        return {'host': host, 'port': config.port, 'domain': host.split(':')[0]}

    def rules_by_host(self, server_host, property, default=None):
        for domain, domain_config in self.enabled_profile.items():
            if domain in server_host:
                return domain_config.get(property, default)

    def rewrite_headers(self, original_headers: dict, server_host: str):
        if not self._rewrite_headers:
            return
        import re
        rules = self._rewrite_headers
        if self.smart_route:
            rules = self.rules_by_host(server_host, 'rewrite_headers', {})
        for h in original_headers:
            if h in rules:
                for rule in rules[h]:
                    new_value = re.sub(rule.source, rule.target.format(**self.more_variables(server_host)),
                                                 original_headers[h])
                    if new_value != original_headers[h]:
                        _print('rewrite header:', h, 'from', original_headers[h], 'to', new_value)
                        original_headers[h] = new_value

    def rewrite_url(self, original_url: str, server_host: str):
        if not self._rewrite_urls:
            return original_url
        import re
        rules = self._rewrite_urls
        if self.smart_route:
            rules = self.rules_by_host(server_host, 'rewrite_urls', [])
        for rule in rules:
            new_value = re.sub(rule.source, rule.target.format(**self.more_variables(server_host)), original_url)
            if new_value != original_url:
                _print('rewrite url:', original_url, 'to', new_value)
                original_url = new_value
        return original_url

    def rewrite_param(self, original_url: str, original_param: dict, server_host: str):
        if not self._rewrite_params:
            return original_param
        import re
        rules = self._rewrite_params
        if self.smart_route:
            rules = self.rules_by_host(server_host, 'rewrite_params', [])
        for rule in rules:
            if rule.url == original_url and rule.param in original_param:
                new_value = re.sub(rule.old_value,
                                   rule.new_value.format(**self.more_variables(server_host)),
                                   original_param[rule.param])
                if new_value != original_param[rule.param]:
                    _print('rewrite param:', rule.param, 'old value', original_param[rule.param], 'new value',
                           new_value)
                    original_param[rule.param] = new_value
        return original_param

    def update_from_args(self, args):
        self.cookie = args.cookie
        self.domain = set(args.domain)
        self.port = int(args.port)
        self.debug = args.debug
        if args.default_domain and not is_url(args.default_domain):
            raise ValueError(f'Default path {args.default_domain} is not a valid URL')
        self.default_domain = args.default_domain
        self.smart_route = args.smart_route

        for p in args.profile:
            assert p in self.GLOBAL_PROFILE, f'Profile {p} not found'
            self.add_domain(*self.GLOBAL_PROFILE[p]['domain'])
            self.set_default_domain(self.GLOBAL_PROFILE[p]['default_domain'])
            self.enabled_profile[p] = self.GLOBAL_PROFILE[p]
            self.add_rewrite_headers(self.GLOBAL_PROFILE[p].get('rewrite_headers', {}))
            self.add_rewrite_urls(self.GLOBAL_PROFILE[p].get('rewrite_urls', []))
            self.add_rewrite_params(self.GLOBAL_PROFILE[p].get('rewrite_params', []))
            self.add_domain_map(self.GLOBAL_PROFILE[p].get('domain_map', {}))


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
    server_host = request.headers.get('Host')
    if url:
        if not is_url(url):
            if not config.get_default_domain(server_host):
                logging.getLogger('aiohttp.access').info(f'Requested url {url} is not valid')
                logging.getLogger('aiohttp.access').info(f'header {dict(request.headers)}')
                return web.Response(text=f'Requested url {url} is not valid', status=400)
        else:
            domain = get_domain(url)
            if config.domain and not any(fnmatch(domain, pattern) for pattern in config.domain):
                logging.getLogger('aiohttp.access').info(f'Requested domain {domain} is not allowed')
                return web.Response(text=f'Requested domain {domain} is not allowed', status=403)
    resp = await handler(request)
    return resp


def _print(*args, **kwargs):
    if config.debug:
        print(*args, **kwargs)


async def proxy(request):
    server_host = request.headers.get('Host')
    method = request.method
    url = request.match_info.get('url')
    ori_url = url
    if not url:
        if config.get_default_domain(server_host):
            url = config.get_default_domain(server_host)
        else:
            url = 'https://github.com/bebound/mooo/'
    if not is_url(url):
        if config.domain_map:
            for pattern, target in config.domain_map.items():
                from fnmatch import fnmatch
                if fnmatch(url, pattern):
                    url = target
                    break

        if config.get_default_domain(server_host):
            import urllib.parse
            url = urllib.parse.urljoin(config.get_default_domain(server_host), url)

    request_headers = dict(request.headers)
    # The proxy server's request url is conflicted with the host header, remove it.
    request_headers.pop('Host', None)
    # X-Forwarded header causes "The request signature we calculated does not match the signature you provided. Check your key and signing method"
    for i in request_headers.copy():
        if i.startswith('X-'):
            request_headers.pop(i)
    new_url = config.rewrite_url(url, server_host)
    if new_url != url:
        _print(f'Rewrite url from {url} to {new_url}')
        url = new_url
    _print(f'Proxying {method} {url} from {server_host}/{ori_url}')

    if not config.cookie and 'Cookie' in request_headers:
        request_headers.pop('Cookie')

    request_params = dict(request.rel_url.query)
    if request_params:
        _print('request params:', request_params)
        new_params = config.rewrite_param(url, request_params, server_host)
        if request_params != new_params:
            _print('new params:', new_params)
            request_params = new_params

    request_data = await request.read()
    # Use `auto_decompress=False` to disable automatic decompression, so the returned content-encoding is still gzip
    # see https://github.com/aio-libs/aiohttp/issues/1992
    _print('request headers:', request_headers)

    # skip auto headers `'Accept-Encoding': 'gzip, deflate'`, to prevent an unexpected gzip content returned
    async with ClientSession(auto_decompress=False, skip_auto_headers=('Accept-Encoding',)) as session:
        async with session.request(method, url, data=request_data, headers=request_headers,
                                   params=request_params, timeout=30) as response:
            response_headers = dict(response.headers)

            if not config.cookie and 'Set-Cookie' in response_headers:
                response_headers.pop('Set-Cookie')
            config.rewrite_headers(response_headers, server_host)
            resp = web.StreamResponse(
                status=response.status,
                headers=response_headers
            )
            _print('response headers:', response_headers)
            _print('response status', response.status)
            try:
                await resp.prepare(request)
                async for chunk in response.content.iter_chunked(32 * 1024):
                    await resp.write(chunk)
                await resp.write_eof()
            except ConnectionResetError:
                # ignore error when client closed the connection
                pass
            return resp


def parse_args():
    parser = argparse.ArgumentParser(
        description='Mooo is a lightweight HTTP proxy written in Python. You can run it in a server then use it to '
                    'access the internet.')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='The host to listen on')
    parser.add_argument('--port', type=int, default=8080, help='The port to listen on')
    parser.add_argument('--debug', type=bool, default=False, action=argparse.BooleanOptionalAction,
                        help='Enable debug logging')
    parser.add_argument('--domain', nargs='+', help='Allow requests to these domains', default=list())
    parser.add_argument('--default-domain', type=str, help='Default domain to redirect to')
    parser.add_argument('--cookie', type=bool, default=False, action=argparse.BooleanOptionalAction,
                        help='Enable cookie')
    parser.add_argument('--profile', nargs='+', help='Use pre-defined profile',
                        default=list())
    parser.add_argument('--smart-route', type=bool, default=False, action=argparse.BooleanOptionalAction,
                        help='Smart route by server host')
    return parser.parse_args()


def main():
    args = parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    config.update_from_args(args)
    if config.enabled_profile:
        print('Enabled profiles:', ', '.join(sorted(config.enabled_profile.keys())))
    web.run_app(app, host=args.host, port=args.port)


routes = web.RouteTableDef()
app = web.Application(middlewares=[check_url])
config = Config()
app.add_routes([web.route('*', '/{url:.*}', proxy)])

if __name__ == '__main__':
    main()
