"""MCP transport guard: Host/Origin validation on /mcp, not on the rest."""

from __future__ import annotations

import tempfile
import unittest

from fastapi.testclient import TestClient

from app.config import Config
from app.main import create_app

_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    },
}
_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


class McpGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cfg = Config(
            token="t",
            repos=["octo-org/web-app"],
            db_path=f"{self.tmp.name}/test.db",
            mcp_allowed_hosts=["mcp.example.com"],
        )
        self.client = TestClient(create_app(cfg))
        self.client.__enter__()  # run lifespan: MCP session manager task group
        self.addCleanup(self.client.__exit__, None, None, None)

    def _init(self, **headers: str):
        return self.client.post("/mcp", json=_INIT, headers={**_HEADERS, **headers})

    def test_plain_initialize_succeeds(self) -> None:
        r = self._init()
        self.assertEqual(200, r.status_code)
        self.assertIn("protocolVersion", r.text)

    def test_rebinding_host_rejected(self) -> None:
        self.assertEqual(421, self._init(Host="attacker.example.com").status_code)

    def test_configured_host_allowed(self) -> None:
        self.assertEqual(200, self._init(Host="mcp.example.com").status_code)

    def test_cross_origin_rejected(self) -> None:
        self.assertEqual(403, self._init(Origin="http://evil.example.com").status_code)

    def test_same_origin_allowed(self) -> None:
        self.assertEqual(200, self._init(Origin="http://testserver").status_code)

    def test_dashboard_unaffected_by_guard(self) -> None:
        # The guard is scoped to /mcp; the dashboard keeps serving any Host.
        self.assertEqual(200, self.client.get("/", headers={"Host": "anything.example.com"}).status_code)


if __name__ == "__main__":
    unittest.main()
