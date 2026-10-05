"""Vercel entry point: the WardLink PQ dashboard and API as one WSGI app.

Locally, run the full system instead: python -m wardlink demo
"""

from wardlink.serverless import app

__all__ = ["app"]
