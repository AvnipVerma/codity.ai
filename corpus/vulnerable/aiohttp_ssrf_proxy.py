import aiohttp
from aiohttp import web


async def proxy(request):
    target = request.query["url"]
    async with aiohttp.ClientSession() as session:
        async with session.get(target) as upstream:
            body = await upstream.read()
    return web.Response(body=body)


app = web.Application()
app.router.add_get("/proxy", proxy)
