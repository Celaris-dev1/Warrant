import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from warrant import Agent, Denied, wrap_tool  # noqa: E402


class FakePEP(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FakePEP.seen.append((self.path, dict(self.headers), body))
        if self.headers.get("Authorization") != "Bearer good":
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'{"allow":false,"error":"no scope in token allows this call"}')
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True, "echo": body}).encode())

    def log_message(self, *a):
        pass


class SDKTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), FakePEP)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_wrap_tool_routes_through_pep(self):
        agent = Agent(self.url, self.url)
        agent.token, agent.svid = "good", "svid"
        ran = []

        @wrap_tool(agent, "fs.read", resource=lambda path, mode="r": "repo/" + path)
        def read(path, mode="r"):
            ran.append(1)

        out = read("a.txt")
        self.assertEqual(out["echo"], {"resource": "repo/a.txt", "args": {"path": "a.txt", "mode": "r"}})
        path, headers, _ = FakePEP.seen[-1]
        self.assertEqual(path, "/call/fs.read")
        self.assertEqual(headers["X-Warrant-Svid"], "svid")
        self.assertEqual(ran, [], "tool body must not run in-process")

    def test_denied_raises(self):
        agent = Agent(self.url, self.url)
        agent.token = "bad"
        with self.assertRaises(Denied) as cm:
            agent.call("fs.write", "x")
        self.assertEqual(cm.exception.status, 403)

    def test_approval_attached_once(self):
        agent = Agent(self.url, self.url)
        agent.token = "good"
        agent.use_approval("db.exec", "appr")
        agent.call("db.exec", "db")
        self.assertEqual(FakePEP.seen[-1][1].get("X-Warrant-Approval"), "appr")
        agent.call("db.exec", "db")
        self.assertIsNone(FakePEP.seen[-1][1].get("X-Warrant-Approval"))


if __name__ == "__main__":
    unittest.main()
