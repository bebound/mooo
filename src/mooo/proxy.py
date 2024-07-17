import argparse

from yarl import URL
from aiohttp import web, ClientSession
from aiohttp.web import middleware
import logging

routes = web.RouteTableDef()


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


@middleware
async def check_url(request, handler):
    url = request.match_info.get('url')
    if url:
        if not is_url(url):
            logging.getLogger('aiohttp.access').info(f'Requested url {url} is not valid')
            return web.Response(text=f'Requested url {url} is not valid', status=400)
    resp = await handler(request)
    return resp


@routes.get('/{url:.*}')
@routes.post('/{url:.*}')
async def proxy(request):
    method = request.method
    url = request.match_info.get('url')
    if not url:
        url = 'https://github.com/bebound/mooo'
    request_headers = dict(request.headers)
    # Reset the host header to the requested host
    if 'Host' in request_headers:
        request_headers['Host'] = URL(url).host
    if not args.enable_cookie and 'Cookie' in request_headers:
        request_headers.pop('Cookie')

    request_params = dict(request.rel_url.query)

    request_data = await request.read()
    # Disable automatic decompression, so the content length will be correct
    # see https://github.com/aio-libs/aiohttp/issues/1992

    # skip auto headers 'Accept-Encoding': 'gzip, deflate', to prevent an unexpected gzip content returned
    async with ClientSession(auto_decompress=False, skip_auto_headers=('Accept-Encoding',)) as session:
        async with session.request(method, url, data=request_data, headers=request_headers,
                                   params=request_params) as response:
            response_headers = dict(response.headers)
            if not args.enable_cookie and 'Set-Cookie' in response_headers:
                response_headers.pop('Set-Cookie')
            resp = web.StreamResponse(
                headers=response_headers
            )
            await resp.prepare(request)
            async for chunk in response.content.iter_chunked(64 * 1024):
                await resp.write(chunk)
            await resp.write_eof()
            return resp


app = web.Application(middlewares=[check_url])

app.add_routes(routes)


def main():
    global args
    parser = argparse.ArgumentParser(description='proxy')
    parser.add_argument('--host', type=str, default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--debug', type=bool, default=False)
    parser.add_argument('--allow-domain',type=lambda x: x.split(','), default=[])
    parser.add_argument('--insane', type=bool, default=False)
    parser.add_argument('--enable-cookie', type=bool, default=False)
    args = parser.parse_args()
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    print(f'Listening on http://{args.host}:{args.port}')
    web.run_app(app, host=args.host, port=args.port)


if __name__ == '__main__':
    main()
