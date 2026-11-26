"""Layers that wrap every request, before any endpoint code runs.

They are written as plain ASGI callables (the interface every Python web server speaks),
so they can inspect a request before FastAPI reads or parses any of it.
"""

from __future__ import annotations

from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class BodySizeLimit:
    """Refuse request bodies larger than `max_bytes` before anything parses them.

    Checks the declared Content-Length first (cheap), then also counts the bytes that
    actually arrive, because a chunked upload declares no length at all. Without this,
    one client could send a gigabyte of JSON and the server would try to hold it all.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            if not declared.isdigit():
                await JSONResponse({"detail": "invalid Content-Length"}, 400)(scope, receive, send)
                return
            if int(declared) > self.max_bytes:
                await self._too_large(scope, receive, send)
                return

        received: list[Message] = []
        size = 0
        while True:
            message = await receive()
            received.append(message)
            if message["type"] != "http.request":  # e.g. the client disconnected
                break
            size += len(message.get("body", b""))
            if size > self.max_bytes:
                await self._too_large(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        replay = iter(received)

        async def receive_again() -> Message:
            return next(replay, None) or await receive()

        await self.app(scope, receive_again, send)

    async def _too_large(self, scope: Scope, receive: Receive, send: Send) -> None:
        detail = f"request body is larger than {self.max_bytes} bytes"
        await JSONResponse({"detail": detail}, status_code=413)(scope, receive, send)


class SecurityHeaders:
    """Add protective headers to every response.

    * nosniff: browsers must trust the declared content type, never guess another one.
    * no-store: alerts are sensitive, so no browser or proxy should keep a copy.
    * no-referrer: never leak API addresses to other sites through the Referer header.
    """

    HEADERS = (
        (b"x-content-type-options", b"nosniff"),
        (b"cache-control", b"no-store"),
        (b"referrer-policy", b"no-referrer"),
    )

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                message = {**message, "headers": [*message.get("headers", []), *self.HEADERS]}
            await send(message)

        await self.app(scope, receive, send_with_headers)
