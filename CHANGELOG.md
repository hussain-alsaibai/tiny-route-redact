# Changelog

All notable changes to tiny-route-redact are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-11-09

### Changed (breaking)
- **`redact_path()` raises `RedactionUnavailable` instead of returning the input
  unchanged** when `tiny_secret_mask >= 0.4.0` cannot be imported. Version 0.1.0
  returned the path untouched, so a deployment without the dependency logged
  full credentials while every call site looked correct. Its docstring claimed
  "a warning is emitted once"; no warning was ever emitted.
- `route_redactor_middleware()` and `route_redactor_asgi_middleware()` now raise
  `RedactionUnavailable` **at construction**. A middleware that refuses only on
  the first request passes every startup probe and then serves unredacted
  paths in production.

### Added
- `redact_path_passthrough(path)` - an explicitly named no-op, so "do not
  redact here" is a decision at the call site rather than an accident.
- `RedactionUnavailable` - exported exception type. Its message names both the
  install command and the passthrough opt-out.
- 5 tests covering the failure modes; 4 of them fail against 0.1.0.

### Migration
If you relied on the no-op fallback, either install the dependency or call
`redact_path_passthrough()` explicitly at the sites that want it.

## [0.1.0] - 2026-10-14

### Added
- `redact_path(path)` - convenience wrapper around `tiny_secret_mask.mask_route_path`.
- `route_redactor_middleware(get_response, *, stats=None, on_redact=None)` - WSGI-style middleware that rewrites request paths.
- `route_redactor_asgi_middleware(app, *, stats=None)` - ASGI-style middleware that rewrites the `path` scope key.
- `RedactionStats` - counter object with `redactions`, `paths_seen`, `last_redacted_path`, and `as_dict()`.
- 19 unit tests in `tests/test_tiny_route_redact.py` (all green).

### Dependencies
- `tiny-secret-mask >= 0.4.0` (auto-installed). As of 0.2.0, a missing or
  unimportable dependency raises `RedactionUnavailable` rather than no-op'ing.

## Notes
- The redaction is idempotent: a second pass on an already-redacted path is a no-op.
- The middleware mutates the request in place (object attribute or dict item). If your framework forbids mutation, pass a copy of the request.
- The `on_redact` callback is invoked only when a redaction actually changed the path. Passthrough paths do not trigger the callback.
