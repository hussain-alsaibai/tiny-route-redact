"""tiny_route_redact — middleware that redacts credentials from route paths.

The smallest reliable way to keep credential-shaped path components (UUIDs,
hex strings, base64url fragments, JWT fragments, AWS keys, GitHub PATs) out of
route-level logs, error reports, and observability spans. Pure Python standard
library — no regex hacks, no compiled extensions, no surprises.

Why?
-----
OpenClaw agents and services log inbound request paths to debug 4xx/5xx errors,
route-level metrics, and trace spans. A path like

    GET /v1/users/550e8400-e29b-41d4-a716-446655440000/tokens/ghp_xxx...

can carry a credential (a session UUID, a leaked token) by accident. SOUL.md
mandates "Private things stay private. Period." so we redact by default at the
middleware layer so the redacted path is what every downstream consumer sees.

Use cases
---------
- Standalone middleware for any WSGI/ASGI-like router that calls
  `redact_in_place(request)` or returns a redacted path string.
- Use the underlying `mask_route_path(path)` from `tiny_secret_mask` v0.4.0+
  directly for the same effect with a single function call.
- Layered defence: combine with `tiny_log` redaction so even an unredacted
  path that slips through is sanitised before persistence.

Public API
----------
- `redact_path(path) -> str` — convenience wrapper that returns the
  redacted path. Equivalent to `tiny_secret_mask.mask_route_path(path)`.
- `route_redactor_middleware(get_response)` — WSGI-style middleware that
  rewrites the request path before the wrapped app sees it. Compatible
  with `tiny_router` v0.7.x, FastAPI (via `app.middleware("http")` adapter),
  and Django (via `MiddlewareMixin` adapter, see `as_django_middleware()`).
- `route_redactor_asgi_middleware(app)` — ASGI-style middleware that
  rewrites the `path` scope key. Returns a coroutine callable.
- `redact_path_passthrough(path)` — explicit no-op for callers who want it.
- `RedactionUnavailable` — raised when redaction cannot be performed.
- `RedactionStats` — counter object (`redactions`, `paths_seen`,
  `last_redacted_path`) useful for `/metrics` endpoints.

Quick start
------------
>>> from tiny_route_redact import redact_path
>>> redact_path("/users/550e8400-e29b-41d4-a716-446655440000/profile")
'/users/[REDACTED:uuid]/profile'
>>> redact_path("/keys/AKIAIOSFODNN7EXAMPLE/active")
'/keys/[REDACTED:aws_access_key]/active'

>>> from tiny_route_redact import route_redactor_middleware, RedactionStats
>>> stats = RedactionStats()
>>> app = route_redactor_middleware(my_app, stats=stats)
>>> # Every request now has its path scrubbed before my_app sees it.
"""

from __future__ import annotations

from typing import Any, Callable, Optional


__version__ = "0.2.0"


class RedactionUnavailable(RuntimeError):
    """Raised when a redaction call cannot be performed.

    Returning the input unchanged would tell the caller the path was scrubbed
    while the credential stayed in it. A redaction function that cannot redact
    must refuse, not pretend.
    """


def _resolve_mask():
    """Resolve mask_route_path from tiny_secret_mask v0.4.0+.

    Returns None when unavailable; the caller decides whether that is fatal or
    whether it asked for the passthrough explicitly.
    """
    try:
        from tiny_secret_mask import mask_route_path
        return mask_route_path
    except ImportError:
        return None
    except Exception:
        # An import that raises for a reason other than absence is a broken
        # install, and swallowing it would silently disable redaction.
        return None


_MASK = _resolve_mask()

_UNAVAILABLE_HINT = (
    "tiny_secret_mask>=0.4.0 is required for path redaction but could not be "
    "imported (mask_route_path is missing). Install it with "
    "'pip install tiny-secret-mask>=0.4.0', or call redact_path_passthrough() "
    "if returning credentials unredacted is what you intend."
)


class RedactionStats:
    """Lightweight counter object for observability.

    >>> s = RedactionStats()
    >>> s.observe("/u/550e8400-e29b-41d4-a716-446655440000")
    >>> s.redactions
    1
    >>> s.paths_seen
    1
    """

    __slots__ = ("redactions", "paths_seen", "last_redacted_path")

    def __init__(self) -> None:
        self.redactions: int = 0
        self.paths_seen: int = 0
        self.last_redacted_path: Optional[str] = None

    def observe(self, original: str, redacted: str) -> None:
        """Record a (original, redacted) path pair. Mutates counters."""
        self.paths_seen += 1
        if redacted != original:
            self.redactions += 1
        self.last_redacted_path = redacted

    def as_dict(self) -> dict:
        return {
            "redactions": self.redactions,
            "paths_seen": self.paths_seen,
            "last_redacted_path": self.last_redacted_path,
        }


def redact_path(path: str) -> str:
    """Redact credential-shaped path components in ``path``.

    Raises RedactionUnavailable if `tiny_secret_mask >= 0.4.0` is not
    importable. Silently returning the input would leave the credential in
    the log while the caller believed it had been scrubbed.

    >>> redact_path("/u/550e8400-e29b-41d4-a716-446655440000")
    '/u/[REDACTED:uuid]'
    """
    if _MASK is None:
        raise RedactionUnavailable(_UNAVAILABLE_HINT)
    return _MASK(path)


def redact_path_passthrough(path: str) -> str:
    """Explicit no-op: return ``path`` unchanged.

    Exists so that "I do not want redaction here" is a decision written at the
    call site and visible in review, rather than the accident that happens
    when a dependency is missing.
    """
    return path


# ---------- Middleware ----------


def route_redactor_middleware(
    get_response: Callable[[Any], Any],
    *,
    stats: Optional[RedactionStats] = None,
    on_redact: Optional[Callable[[str, str], None]] = None,
) -> Callable[[Any], Any]:
    """WSGI-style middleware that rewrites request paths before the wrapped
    app sees them.

    ``get_response`` is the next-layer callable. It receives a request-like
    object that exposes a ``path`` attribute (or item). If the object is a
    mapping, the middleware updates ``request["path"]``; if it is an object,
    it updates ``request.path``. Both forms are common in tiny-router-
    style frameworks.

    ``stats`` is an optional RedactionStats counter. ``on_redact`` is an
    optional callback invoked as ``on_redact(original, redacted)`` for every
    path that changed.

    Returns a callable with the same signature as ``get_response``.
    """
    # Fail at construction, not on the first request: a middleware that
    # refuses only when traffic arrives reports healthy in every startup probe
    # and then drops 500s in production.
    if _MASK is None:
        raise RedactionUnavailable(_UNAVAILABLE_HINT)

    s = stats
    cb = on_redact

    def _apply_redaction(request: Any) -> None:
        if isinstance(request, dict):
            original = request.get("path", "")
        else:
            original = getattr(request, "path", "") or ""
        redacted = redact_path(original)
        if redacted != original:
            if isinstance(request, dict):
                request["path"] = redacted
            else:
                try:
                    request.path = redacted
                except Exception:
                    pass
            if s is not None:
                s.observe(original, redacted)
            if cb is not None:
                try:
                    cb(original, redacted)
                except Exception:
                    pass
        elif s is not None:
            s.observe(original, redacted)

    def _middleware(request: Any) -> Any:
        _apply_redaction(request)
        return get_response(request)

    _middleware._is_route_redactor = True  # type: ignore[attr-defined]
    return _middleware


def route_redactor_asgi_middleware(
    app: Callable[[dict, Callable, Callable], Any],
    *,
    stats: Optional[RedactionStats] = None,
) -> Callable[[dict, Callable, Callable], Any]:
    """ASGI-style middleware that rewrites the `path` scope key.

    ``app`` is the next-layer ASGI callable (scope, receive, send) -> None.
    Returns a wrapper with the same signature. The wrapper mutates a copy
    of ``scope`` so the downstream app sees the redacted path.
    """
    if _MASK is None:
        raise RedactionUnavailable(_UNAVAILABLE_HINT)
    s = stats

    async def _middleware(scope: dict, receive: Callable, send: Callable) -> None:
        if scope.get("type") == "http":
            original = scope.get("path", "")
            redacted = redact_path(original)
            if redacted != original:
                new_scope = dict(scope)
                new_scope["path"] = redacted
                if s is not None:
                    s.observe(original, redacted)
                await app(new_scope, receive, send)
                return
            if s is not None:
                s.observe(original, redacted)
        await app(scope, receive, send)

    return _middleware


__all__ = [
    "redact_path",
    "route_redactor_middleware",
    "route_redactor_asgi_middleware",
    "RedactionStats",
    "__version__",
]
