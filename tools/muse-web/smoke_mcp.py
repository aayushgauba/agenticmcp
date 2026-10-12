"""Discover Muse tools through the official MCP client; never invoke GitHub."""
import asyncio
import os
from urllib.parse import urlsplit
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


async def main():
    url = os.environ.get('MUSE_MCP_URL', 'http://127.0.0.1:8000/mcp')
    parsed = urlsplit(url)
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('localhost', '127.0.0.1')):
        raise SystemExit('HTTPS required for remote MCP connections')
    token = os.environ.get('MUSE_CONNECTOR_TOKEN')
    if not token:
        raise SystemExit('Set MUSE_CONNECTOR_TOKEN locally; do not provide the GitHub token')
    async with streamablehttp_client(url, headers={'Authorization': 'Bearer ' + token}) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            print('Connected to Muse. Tools: ' + ', '.join(tool.name for tool in tools.tools))


if __name__ == '__main__':
    asyncio.run(main())
