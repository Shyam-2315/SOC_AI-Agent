import argparse
import asyncio
from pathlib import Path
import sys


if __package__ in {None, ""}:
    sys.path.append(str(Path(__file__).resolve().parents[1]))

import websockets


async def listen(url: str, token: str):
    websocket_url = f"{url}?token={token}"
    async with websockets.connect(websocket_url) as websocket:
        await websocket.send(
            '{"action":"subscribe","replace":true,"event_types":["soc.alert.created"]}'
        )
        while True:
            print(await websocket.recv())


def parse_args():
    parser = argparse.ArgumentParser(description="Listen for tenant-scoped alerts.")
    parser.add_argument("--url", default="ws://127.0.0.1:8000/ws/alerts")
    parser.add_argument("--token", required=True)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(listen(args.url, args.token))
