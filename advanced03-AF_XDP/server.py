import asyncio
import socket
import websockets
import random
import time


async def send_random_messages(websocket, path):
    while True:
        message = f"Random number: {random.randint(1, 100)}"
        await websocket.send(message)
        print(f"Sent: {message}")
        await asyncio.sleep(1)  # Send a message every second


async def main():
    # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # sock.bind(("10.11.1.1", 8080))
    async with websockets.serve(
        send_random_messages, "10.11.1.1", 8080, compression=None
    ):
        print("listening...")
        await asyncio.Future()  # Run forever


if __name__ == "__main__":
    asyncio.run(main())
