# tiny-route-redact

[![PyPI version](https://badge.fury.io/py/tiny-route-redact.svg)](https://badge.fury.io/py/tiny-route-redact)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Middleware that redacts credentials from route paths so logs, error reports, and observability spans never leak them.

## Why

Most request paths are safe. Some are not:

```
GET /v1/users/550e8400-e29b-41d4-a716-446655440000/tokens/ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

A path like that can carry a session UUID and a leaked token by accident. SOUL.md mandates "Private things stay private. Period." so we redact by default at the middleware layer.

`tiny-route-redact` is the smallest reliable way to keep credential-shaped path components (UUIDs, hex strings, base64url fragments, JWT fragments, AWS keys, GitHub PATs, Stripe keys, OpenAI keys, Google API keys) out of every log line and trace span that touches a request path.

## Install

```bash
pip install tiny-route-redact
# also requires tiny-secret-mask >= 0.4.0 (auto-installed)
```

If that dependency is missing, the library raises `RedactionUnavailable` rather
than passing credentials through — see [Failure behaviour](#failure-behaviour).

## Quick start

```python
from tiny_route_redact import route_redactor_middleware, RedactionStats

stats = RedactionStats()
app = route_redactor_middleware(my_app, stats=stats)
# Every request now has its path scrubbed before my_app sees it.
```

Standalone function:

```python
from tiny_route_redact import redact_path

>>> redact_path("/users/550e8400-e29b-41d4-a716-446655440000/profile")
'/users/[REDACTED:uuid]/profile'
>>> redact_path("/keys/AKIAIOSFODNN7EXAMPLE/active")
'/keys/[REDACTED:aws_access_key]/active'
```

## API

### `redact_path(path: str) -> str`

Returns the redacted path string.

Raises `RedactionUnavailable` if `tiny-secret-mask >= 0.4.0` cannot be imported.
It does **not** return the input unchanged. A redaction layer that quietly
passes credentials through is worse than no redaction layer: the deployment
believes the path is scrubbed, and the logs say nothing.

If you genuinely want no redaction at a call site, say so:

```python
from tiny_route_redact import redact_path_passthrough
redact_path_passthrough(path)  # visible in review as a deliberate no-op
```

### `route_redactor_middleware(get_response, *, stats=None, on_redact=None)`

WSGI-style middleware that rewrites request paths before the wrapped app sees them. Works with dict-style requests (`request["path"]`) and object-style requests (`request.path`).

Raises `RedactionUnavailable` at construction if redaction is unavailable. The
check happens when the middleware is built, not on the first request — a
middleware that fails only under traffic passes every startup probe and then
serves unredacted paths in production.

- `stats: RedactionStats | None` — optional counter object.
- `on_redact: Callable[[str, str], None] | None` — optional callback invoked as `on_redact(original, redacted)` for every path that changed.

### `route_redactor_asgi_middleware(app, *, stats=None)`

ASGI-style middleware that rewrites the `path` scope key. Returns a coroutine callable with the same signature as the wrapped app.

### `RedactionStats`

Lightweight counter object. Fields: `redactions: int`, `paths_seen: int`, `last_redacted_path: str | None`. `as_dict()` returns a JSON-serializable snapshot for `/metrics` endpoints.

## Failure behaviour

Version 0.1.0 returned the input path unchanged when its dependency was
missing. The module docstring claimed "a warning is emitted once"; no warning
existed. A service that had lost `tiny-secret-mask` in an image rebuild went on
logging full credentials, and `RedactionStats.redactions` stayed at `0`, which
reads like a quiet week rather than a leak.

As of 0.2.0:

```python
>>> import tiny_route_redact as t
>>> t._MASK = None                      # simulate a missing dependency
>>> t.redact_path("/u/550e8400-e29b-41d4-a716-446655440000")
Traceback (most recent call last):
    ...
tiny_route_redact.RedactionUnavailable: tiny_secret_mask>=0.4.0 is required
for path redaction but could not be imported (mask_route_path is missing).
Install it with 'pip install tiny-secret-mask>=0.4.0', or call
redact_path_passthrough() if returning credentials unredacted is what you
intend.
```

The message names both the fix and the opt-out, so the person reading a
production traceback does not have to find this README.

## What gets redacted

`tiny-route-redact` delegates the rule set to `tiny-secret-mask` v0.4.0+. The default catalogue covers:

| Rule | Severity | Example |
|------|----------|---------|
| `uuid` | low | `550e8400-e29b-41d4-a716-446655440000` |
| `hex_32` | medium | MD5-shaped strings |
| `hex_64` | medium | SHA-256-shaped strings |
| `base64url_20` | low | 20+ char base64url fragments |
| `jwt_fragment` | high | Three-segment JWTs |
| `aws_access_key` | critical | `AKIA...` (16 chars) |
| `github_pat` | critical | `ghp_...` (40 chars) |
| `github_fine_grained_pat` | critical | `github_pat_...` (82 chars) |
| `slack_token` | critical | `xox[abprs]-...` |
| `stripe_live` | critical | `sk_live_...` |
| `openai_key` | critical | `sk-...T3BlbkFJ...` |
| `google_api_key` | critical | `AIza...` (39 chars) |

## License

MIT
