"""Small, dependency-free security helpers for the Flask application."""

import hmac
import secrets
import time
from collections import defaultdict, deque
from functools import wraps

from flask import abort, request, session


def csrf_token():
    """Return a per-session token used by every state-changing form."""
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def install_csrf(app):
    @app.context_processor
    def expose_csrf_token():
        return {"csrf_token": csrf_token}

    @app.before_request
    def verify_csrf_token():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            submitted = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not expected or not hmac.compare_digest(submitted, expected):
                abort(400, "Недействительный защитный токен. Обновите страницу и повторите запрос.")


class RateLimiter:
    """In-process limiter. Suitable for one Flask worker; use a shared store in production."""

    def __init__(self):
        self._hits = defaultdict(deque)

    def limit(self, maximum, window_seconds):
        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                key = (view.__name__, request.remote_addr or "unknown")
                now = time.monotonic()
                hits = self._hits[key]
                while hits and hits[0] <= now - window_seconds:
                    hits.popleft()
                if len(hits) >= maximum:
                    abort(429, "Слишком много запросов. Попробуйте позже.")
                hits.append(now)
                return view(*args, **kwargs)
            return wrapped
        return decorator
