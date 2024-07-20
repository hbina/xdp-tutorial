import asyncio
import websockets


async def hello():
    uri = "wss://echo.websocket.org"

    async with websockets.connect(uri) as websocket:
        while True:
            await websocket.send("hello world")
            data = await websocket.recv()
            print(data)


if __name__ == "__main__":
    asyncio.run(hello())
