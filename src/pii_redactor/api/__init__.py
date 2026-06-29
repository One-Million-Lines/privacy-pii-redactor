"""
API sub-package.

Exposes the FastAPI application factory function and all HTTP route handlers.
"""

from pii_redactor.api.app import app, create_app

__all__ = ["app", "create_app"]
