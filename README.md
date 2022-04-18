## aiohttp-socks5
The `aiohttp-socks5` package provides a SOCKS5 proxy connector for [aiohttp](https://github.com/aio-libs/aiohttp). 

## Requirements
- Python >= 3.8
- aiohttp >= 3.0.0

## Installation
```
pip install git+https://github.com/HMaker/aiohttp-socks5.git@latest
```

## Usage
```python
import asyncio
import aiohttp
from aiohttp_socks5 import SOCKSConnector


async def print_ip(proxy: str):
    async with aiohttp.ClientSession(connector=SOCKSConnector()) as session:
        # you can set SOCKS5 or HTTP proxies per request below
        async with session.get("https://api.ipify.org?format=json", proxy=proxy) as response:
            print(await response.json())

asyncio.run(print_ip("socks5://user:pass@socks.example.com:1080"))
```

## Why yet another SOCKS connector for aiohttp
Unlike [aiohttp-socks](https://github.com/romis2012/aiohttp-socks), `aiohttp-socks5` support proxies
per request and allows you to rotate proxies without recreating aiohttp sessions.
