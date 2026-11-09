"""Tests for tiny_route_redact. Run: python3 -m unittest tests.test_tiny_route_redact -v"""

from __future__ import annotations

import unittest

import tiny_route_redact as _mod
from tiny_route_redact import (
    RedactionStats,
    __version__,
    redact_path,
    route_redactor_asgi_middleware,
    route_redactor_middleware,
)


class TestVersion(unittest.TestCase):
    def test_version(self) -> None:
        self.assertEqual(__version__, "0.2.0")


class TestRedactPath(unittest.TestCase):
    def test_no_match(self) -> None:
        self.assertEqual(redact_path("/api/health"), "/api/health")

    def test_uuid(self) -> None:
        out = redact_path("/u/550e8400-e29b-41d4-a716-446655440000")
        self.assertEqual(out, "/u/[REDACTED:uuid]")

    def test_aws_key(self) -> None:
        out = redact_path("/keys/AKIAIOSFODNN7EXAMPLE")
        self.assertIn("[REDACTED:aws_access_key]", out)

    def test_github_pat(self) -> None:
        pat = "ghp_" + "a" * 40
        out = redact_path("/gh/" + pat)
        self.assertIn("[REDACTED:github_pat]", out)
        self.assertNotIn(pat, out)

    def test_jwt(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.signed"
        out = redact_path("/t/" + jwt)
        self.assertIn("[REDACTED:jwt_fragment]", out)


class TestRedactionStats(unittest.TestCase):
    def test_init(self) -> None:
        s = RedactionStats()
        self.assertEqual(s.redactions, 0)
        self.assertEqual(s.paths_seen, 0)
        self.assertIsNone(s.last_redacted_path)

    def test_observe_redaction(self) -> None:
        s = RedactionStats()
        s.observe("/u/550e8400-e29b-41d4-a716-446655440000", "/u/[REDACTED:uuid]")
        self.assertEqual(s.redactions, 1)
        self.assertEqual(s.paths_seen, 1)
        self.assertEqual(s.last_redacted_path, "/u/[REDACTED:uuid]")

    def test_observe_passthrough(self) -> None:
        s = RedactionStats()
        s.observe("/api/health", "/api/health")
        self.assertEqual(s.redactions, 0)
        self.assertEqual(s.paths_seen, 1)

    def test_as_dict(self) -> None:
        s = RedactionStats()
        s.observe("/u/550e8400-e29b-41d4-a716-446655440000", "/u/[REDACTED:uuid]")
        d = s.as_dict()
        self.assertEqual(d["redactions"], 1)
        self.assertEqual(d["paths_seen"], 1)
        self.assertEqual(d["last_redacted_path"], "/u/[REDACTED:uuid]")


class TestWSGIMiddleware(unittest.TestCase):
    def test_redacts_dict_request(self) -> None:
        seen = []

        def inner(req):
            seen.append(req["path"])
            return "ok"

        wrapped = route_redactor_middleware(inner)
        result = wrapped({"path": "/u/550e8400-e29b-41d4-a716-446655440000/x"})
        self.assertEqual(result, "ok")
        self.assertEqual(seen[0], "/u/[REDACTED:uuid]/x")

    def test_redacts_object_request(self) -> None:
        class Req:
            pass

        seen = []

        def inner(req):
            seen.append(req.path)
            return "ok"

        wrapped = route_redactor_middleware(inner)
        r = Req()
        r.path = "/u/550e8400-e29b-41d4-a716-446655440000"
        result = wrapped(r)
        self.assertEqual(result, "ok")
        self.assertEqual(seen[0], "/u/[REDACTED:uuid]")

    def test_passthrough_when_no_match(self) -> None:
        seen = []

        def inner(req):
            seen.append(req["path"])
            return "ok"

        wrapped = route_redactor_middleware(inner)
        wrapped({"path": "/api/health"})
        self.assertEqual(seen[0], "/api/health")

    def test_stats_counted(self) -> None:
        stats = RedactionStats()
        wrapped = route_redactor_middleware(lambda r: "ok", stats=stats)
        wrapped({"path": "/u/550e8400-e29b-41d4-a716-446655440000"})
        wrapped({"path": "/api/health"})
        self.assertEqual(stats.redactions, 1)
        self.assertEqual(stats.paths_seen, 2)

    def test_on_redact_callback(self) -> None:
        events = []
        wrapped = route_redactor_middleware(
            lambda r: "ok",
            on_redact=lambda o, r: events.append((o, r)),
        )
        wrapped({"path": "/u/550e8400-e29b-41d4-a716-446655440000"})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], "/u/550e8400-e29b-41d4-a716-446655440000")
        self.assertEqual(events[0][1], "/u/[REDACTED:uuid]")
        # No callback when no redaction
        events.clear()
        wrapped({"path": "/api/health"})
        self.assertEqual(events, [])


class TestASGIMiddleware(unittest.TestCase):
    def test_redacts_path(self) -> None:
        seen_scope = []

        async def inner(scope, receive, send):
            seen_scope.append(dict(scope))

        wrapped = route_redactor_asgi_middleware(inner)

        async def run():
            await wrapped(
                {"type": "http", "path": "/u/550e8400-e29b-41d4-a716-446655440000"},
                lambda: None,
                lambda *a, **k: None,
            )

        import asyncio
        asyncio.run(run())
        self.assertEqual(
            seen_scope[0]["path"],
            "/u/[REDACTED:uuid]",
        )

    def test_passthrough_when_no_match(self) -> None:
        seen_scope = []

        async def inner(scope, receive, send):
            seen_scope.append(dict(scope))

        wrapped = route_redactor_asgi_middleware(inner)

        async def run():
            await wrapped(
                {"type": "http", "path": "/api/health"},
                lambda: None,
                lambda *a, **k: None,
            )

        import asyncio
        asyncio.run(run())
        self.assertEqual(seen_scope[0]["path"], "/api/health")

    def test_non_http_passthrough(self) -> None:
        seen_scope = []

        async def inner(scope, receive, send):
            seen_scope.append(dict(scope))

        wrapped = route_redactor_asgi_middleware(inner)

        async def run():
            await wrapped(
                {"type": "websocket", "path": "/ws/550e8400-e29b-41d4-a716-446655440000"},
                lambda: None,
                lambda *a, **k: None,
            )

        import asyncio
        asyncio.run(run())
        # websocket scope not touched
        self.assertEqual(
            seen_scope[0]["path"],
            "/ws/550e8400-e29b-41d4-a716-446655440000",
        )


if __name__ == "__main__":
    unittest.main()


# ---- redaction must not silently no-op -------------------------------------
#
# AGENTS.md 2026-10-26: a redaction function that cannot do its job must raise,
# with an explicitly named opt-out. Before 0.2.0 this module returned the input
# path unchanged when tiny_secret_mask was missing, and its own docstring
# claimed "a warning is emitted once" - a warning that did not exist.


class TestNoSilentFailure(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = _mod._MASK

    def tearDown(self) -> None:
        _mod._MASK = self._saved

    def test_redact_path_raises_when_unavailable(self) -> None:
        _mod._MASK = None
        with self.assertRaises(_mod.RedactionUnavailable) as ctx:
            redact_path("/u/550e8400-e29b-41d4-a716-446655440000")
        message = str(ctx.exception).lower()
        self.assertIn("install", message)
        self.assertIn("passthrough", message, "the error must name the opt-out")

    def test_passthrough_is_explicit(self) -> None:
        _mod._MASK = None
        path = "/u/550e8400-e29b-41d4-a716-446655440000"
        self.assertEqual(_mod.redact_path_passthrough(path), path)

    def test_middleware_refuses_to_build_when_unavailable(self) -> None:
        """Failing at construction beats failing on the first request: a
        middleware that breaks only under traffic passes every startup probe."""
        _mod._MASK = None
        with self.assertRaises(_mod.RedactionUnavailable):
            route_redactor_middleware(lambda req: req)

    def test_asgi_middleware_refuses_to_build_when_unavailable(self) -> None:
        _mod._MASK = None
        with self.assertRaises(_mod.RedactionUnavailable):
            route_redactor_asgi_middleware(lambda scope, receive, send: None)

    def test_middleware_builds_when_available(self) -> None:
        if _mod._MASK is None:
            self.skipTest("tiny_secret_mask not installed here")
        self.assertTrue(callable(route_redactor_middleware(lambda req: req)))
