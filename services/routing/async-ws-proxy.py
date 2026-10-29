# File: /opt/nginxbandits/services/routing/async-ws-proxy.py
# Purpose: Asynchronous WebSocket/raw SSH proxy behind the shared TCP router.

import asyncio
import logging
import os
from collections import defaultdict

MAX_CONN_PER_IP = 200
ip_conn_count = defaultdict(int)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 22

# The shared HAProxy front end owns public port 80. Keep this service on a
# loopback-only backend port, while retaining the independent raw port 8880.
HTTP_HOST = os.getenv("NGINXBANDITS_WS_HTTP_HOST", "0.0.0.0")
HTTP_PORT = int(os.getenv("NGINXBANDITS_WS_HTTP_PORT", "80"))
RAW_HOST = os.getenv("NGINXBANDITS_WS_RAW_HOST", "0.0.0.0")
RAW_PORT = int(os.getenv("NGINXBANDITS_WS_RAW_PORT", "8880"))


async def forward_stream(src_reader, dst_writer, direction):
    """Asynchronously forward bytes between two streams."""
    try:
        while True:
            data = await src_reader.read(8192)
            if not data:
                break
            dst_writer.write(data)
            await dst_writer.drain()
    except ConnectionResetError:
        pass
    except Exception as exc:
        logging.debug("Stream error (%s): %s", direction, exc)
    finally:
        if not dst_writer.is_closing():
            dst_writer.close()
            try:
                await dst_writer.wait_closed()
            except Exception:
                pass


async def handle_client(reader, writer):
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else "unknown"

    if ip_conn_count[peer_ip] >= MAX_CONN_PER_IP:
        writer.close()
        await writer.wait_closed()
        return

    ip_conn_count[peer_ip] += 1
    backend_writer = None

    try:
        data = await asyncio.wait_for(reader.read(8192), timeout=5.0)
        if not data:
            return

        req_str = data.decode("utf-8", errors="ignore")
        is_http = "HTTP/" in req_str or "Upgrade:" in req_str or "upgrade:" in req_str

        # Preserve the existing HTTP Injector/WebSocket handshake behavior.
        if is_http:
            writer.write(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\n"
                b"Connection: Upgrade\r\n\r\n"
            )
            await writer.drain()

        backend_reader, backend_writer = await asyncio.open_connection(
            BACKEND_HOST, BACKEND_PORT
        )

        if not is_http:
            backend_writer.write(data)
            await backend_writer.drain()

        await asyncio.gather(
            forward_stream(reader, backend_writer, "client-to-backend"),
            forward_stream(backend_reader, writer, "backend-to-client"),
        )

    except asyncio.TimeoutError:
        logging.warning("Timeout reading initial payload from %s", peer_ip)
    except Exception as exc:
        logging.error("Handler exception for %s: %s", peer_ip, exc)
    finally:
        ip_conn_count[peer_ip] -= 1
        if ip_conn_count[peer_ip] <= 0:
            del ip_conn_count[peer_ip]
        if backend_writer and not backend_writer.is_closing():
            backend_writer.close()
            try:
                await backend_writer.wait_closed()
            except Exception:
                pass
        if not writer.is_closing():
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def main():
    http_server = await asyncio.start_server(handle_client, HTTP_HOST, HTTP_PORT)
    raw_server = await asyncio.start_server(handle_client, RAW_HOST, RAW_PORT)

    logging.info(
        "Async SSH/WebSocket backend listening on %s:%s and raw port %s:%s",
        HTTP_HOST,
        HTTP_PORT,
        RAW_HOST,
        RAW_PORT,
    )

    async with http_server, raw_server:
        await asyncio.gather(
            http_server.serve_forever(),
            raw_server.serve_forever(),
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Shutting down proxy.")
