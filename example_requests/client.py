import asyncio
import aiohttp

indicators = ["a.com", "b.com", "c.com", "d.com", "e.com", "malicious.com"]
ingest_url = 'http://localhost:8000/ingest/'


async def send_requests_to_scan(session, indicator: str):
    async with session.post(ingest_url + indicator) as response:
        print(await response.text())


async def main():
    async with aiohttp.ClientSession() as session:
        requests = [asyncio.create_task(send_requests_to_scan(session, indicator)) for indicator in indicators]
        await asyncio.gather(*requests)


if __name__ == '__main__':
    asyncio.run(main())
