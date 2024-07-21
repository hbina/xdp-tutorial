import threading
import socket
import websockets
from websockets.sync.client import connect


uri = "ws://10.11.1.1:8080"
interface = "10.11.1.2"


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((interface, 0))  # 0 means bind to any available port

# Use the socket in the WebSocket connection
with connect(uri, sock=sock) as websocket:
    while True:
        msg = websocket.recv()
        print(f"Received: {msg}")
