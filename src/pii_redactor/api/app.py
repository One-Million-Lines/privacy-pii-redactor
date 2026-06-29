"""
FastAPI application factory.

``create_app`` is the entry point for constructing the FastAPI application
with all middleware, routes, and configuration applied.

Usage (ASGI server)::

    uvicorn pii_redactor.api.app:app --host 0.0.0.0 --port 8000

Usage (programmatic)::

    from pii_redactor.api.app import create_app
    app = create_app(config=Settings(port=9000))
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from pii_redactor.api.routes import router
from pii_redactor.config import Settings, configure_logging

logger = logging.getLogger(__name__)


def create_app(config: Settings | None = None) -> FastAPI:
    """
    Construct and configure the FastAPI application.

    Sets up:
        - Request size limit middleware
        - CORS middleware (permissive defaults; tighten for production)
        - All API routes from :mod:`~pii_redactor.api.routes`
        - Optional Swagger / ReDoc UI based on ``config.docs_enabled``
        - Safe structured logging (no PII in log output)

    Args:
        config: Application settings. If ``None``, loads from environment
            via :class:`~pii_redactor.config.Settings`.

    Returns:
        Configured :class:`fastapi.FastAPI` application instance.
    """
    settings = config or Settings()
    configure_logging(settings)

    @asynccontextmanager
    async def _lifespan(app: FastAPI):  # noqa: ARG001
        logger.info(
            "Privacy PII Redactor starting up (env=%s, port=%d)",
            settings.app_env,
            settings.port,
        )
        yield
        logger.info("Privacy PII Redactor shutting down")

    # Conditionally expose Swagger / ReDoc
    docs_url = "/docs" if settings.docs_enabled else None
    redoc_url = "/redoc" if settings.docs_enabled else None
    openapi_url = "/openapi.json" if settings.docs_enabled else None

    application = FastAPI(
        title="Privacy PII Redactor",
        description=(
            "A self-hosted proxy that detects and removes sensitive information "
            "before text is sent to external LLM providers."
        ),
        version="0.1.0",
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
        lifespan=_lifespan,
    )

    # ── Middleware ────────────────────────────────────────────────────────────

    # Request size limit — reject oversized bodies early
    application.add_middleware(
        _RequestSizeLimitMiddleware,
        max_bytes=settings.max_request_size_bytes,
    )

    # CORS — allow all origins by default (tighten in production)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routes ────────────────────────────────────────────────────────────────

    application.include_router(router)

    # ── Exception handlers ────────────────────────────────────────────────────

    @application.exception_handler(HTTPException)
    async def _http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        """
        Convert FastAPI HTTPExceptions to the standard error response format.

        Ensures all error responses have the shape::

            {"error": {"code": "...", "message": "..."}}
        """
        detail = exc.detail
        # If detail is already in our error format, pass it through
        if isinstance(detail, dict) and "error" in detail:
            return JSONResponse(status_code=exc.status_code, content=detail)
        # Otherwise wrap it
        if isinstance(detail, dict):
            code = detail.get("code", "ERROR")
            message = detail.get("message", str(detail))
        else:
            code = "ERROR"
            message = str(detail)
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": code, "message": message}},
        )

    return application


# ── Request size limit middleware ─────────────────────────────────────────────


class _RequestSizeLimitMiddleware:
    """
    ASGI middleware that rejects requests whose body exceeds *max_bytes*.

    Returns HTTP 413 (Request Entity Too Large) with a structured error body
    when the ``Content-Length`` header or the actual body size exceeds the
    configured limit.

    Args:
        app: The ASGI application to wrap.
        max_bytes: Maximum allowed request body size in bytes.
    """

    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Check Content-Length header first for an early rejection
        headers = dict(scope.get("headers", []))
        content_length_raw = headers.get(b"content-length")
        if content_length_raw:
            try:
                content_length = int(content_length_raw)
                if content_length > self.max_bytes:
                    await self._send_413(send)
                    return
            except ValueError:
                pass  # Malformed header — let downstream handle it

        # Wrap the receive channel to enforce size on streaming bodies
        total_bytes = 0

        async def _limited_receive():
            nonlocal total_bytes
            message = await receive()
            if message["type"] == "http.request":
                chunk = message.get("body", b"")
                total_bytes += len(chunk)
                if total_bytes > self.max_bytes:
                    await self._send_413(send)
                    raise _BodyTooLargeError(
                        f"Request body exceeds {self.max_bytes} bytes"
                    )
            return message

        try:
            await self.app(scope, _limited_receive, send)
        except _BodyTooLargeError:
            pass  # Already sent 413

    @staticmethod
    async def _send_413(send) -> None:
        """Send an HTTP 413 response with a structured error body."""
        import json as _json

        body = _json.dumps(
            {"error": {"code": "TEXT_TOO_LARGE", "message": "Request body exceeds maximum allowed size"}}
        ).encode()
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})


class _BodyTooLargeError(Exception):
    """Sentinel raised internally to abort body streaming on size overflow."""


# ── Module-level app instance (for uvicorn entry point) ──────────────────────

app = create_app()
