import asyncio
import websockets


async def test_socket():

    uri = "ws://127.0.0.1:8000/ws/alerts"

    print("Connecting to AI SOC WebSocket...")

    async with websockets.connect(uri) as websocket:

        print("Connected to SOC WebSocket")

        # keep socket alive
        await websocket.send("SOC Client Connected")

        while True:

            response = await websocket.recv()

            print("\nNEW REAL-TIME EVENT:")
            print(response)


asyncio.run(test_socket())