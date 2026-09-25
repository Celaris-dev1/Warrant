import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from warrant import Agent  # noqa: E402
from warrant import adapters  # noqa: E402


class FakeBroker(BaseHTTPRequestHandler):
    """A minimal /v1/authorize stand-in: allows fs.read under repo/docs/*,
    denies everything else, exactly like a real Warrant policy would."""

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(length))
        call = body["call"]
        allow = call["tool"] == "fs.read" and str(call["resource"]).startswith("repo/docs/")
        if allow:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"allow": True, "reason": "ok"}).encode())
        else:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(json.dumps({"allow": False, "reason": "no scope allows this call"}).encode())

    def log_message(self, *a):
        pass


class AdaptersTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), FakeBroker)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def agent(self):
        a = Agent(self.url, self.url)
        a.token, a.svid = "good", "svid"
        return a

    def resource_of(self, **kwargs):
        return "repo/docs/" + kwargs.get("path", "")

    # --- LangChain ---

    def test_langchain_tool_allow_and_deny(self):
        agent = self.agent()
        ran = []
        fn = lambda path: ran.append(path) or "ok"  # noqa: E731
        tool = adapters.langchain_tool(agent, "fs.read", self.resource_of, fn)
        self.assertEqual(tool._run(path="intro.md"), "ok")
        self.assertEqual(ran, ["intro.md"])

        ran.clear()
        deny_tool = adapters.langchain_tool(agent, "fs.write", self.resource_of, fn)
        out = deny_tool._run(path="intro.md")
        self.assertIn("denied", out)
        self.assertEqual(ran, [], "tool body must not run on denial")

    # --- LlamaIndex ---

    def test_llamaindex_function_tool_allow_and_deny(self):
        agent = self.agent()
        ran = []
        fn = lambda path: ran.append(path) or "ok"  # noqa: E731
        tool = adapters.llamaindex_function_tool(agent, "fs.read", self.resource_of, fn)
        out = tool.call(path="intro.md")
        self.assertFalse(out.is_error)
        self.assertEqual(ran, ["intro.md"])

        ran.clear()
        deny_tool = adapters.llamaindex_function_tool(agent, "fs.write", self.resource_of, fn)
        out = deny_tool.call(path="intro.md")
        self.assertTrue(out.is_error)
        self.assertEqual(ran, [])

    # --- CrewAI ---

    def test_crewai_tool_allow_and_deny(self):
        agent = self.agent()
        ran = []
        fn = lambda path: ran.append(path) or "ok"  # noqa: E731
        tool = adapters.crewai_tool(agent, "fs.read", "reads a file", self.resource_of, fn)
        self.assertEqual(tool._run(path="intro.md"), "ok")

        ran.clear()
        deny_tool = adapters.crewai_tool(agent, "fs.write", "writes a file", self.resource_of, fn)
        out = deny_tool._run(path="intro.md")
        self.assertIn("denied", out)
        self.assertEqual(ran, [])

    # --- AutoGen ---

    def test_autogen_function_map_allow_and_deny(self):
        agent = self.agent()
        ran = []
        fn_map = {"fs.read": lambda path: ran.append(path) or "ok", "fs.write": lambda path: ran.append(path) or "ok"}
        wrapped = adapters.autogen_function_map(agent, fn_map, {"fs.read": self.resource_of, "fs.write": self.resource_of})

        self.assertEqual(wrapped["fs.read"](path="intro.md"), "ok")
        self.assertEqual(ran, ["intro.md"])

        ran.clear()
        out = wrapped["fs.write"](path="intro.md")
        self.assertIn("denied", out)
        self.assertEqual(ran, [])

    # --- OpenAI Agents SDK ---

    def test_openai_agents_function_tool_allow_and_deny(self):
        agent = self.agent()
        ran = []
        fn = lambda path: ran.append(path) or "ok"  # noqa: E731
        tool = adapters.openai_agents_function_tool(agent, "fs.read", self.resource_of, fn)
        out = tool.on_invoke_tool(None, json.dumps({"path": "intro.md"}))
        self.assertEqual(out, "ok")
        self.assertEqual(ran, ["intro.md"])

        ran.clear()
        deny_tool = adapters.openai_agents_function_tool(agent, "fs.write", self.resource_of, fn)
        out = deny_tool.on_invoke_tool(None, json.dumps({"path": "intro.md"}))
        self.assertIn("denied", out)
        self.assertEqual(ran, [])

    # --- Anthropic tool runner ---

    def test_anthropic_tool_runner_allow_and_deny(self):
        agent = self.agent()
        ran = []
        tools = {"fs.read": lambda path: ran.append(path) or "ok"}
        run = adapters.anthropic_tool_runner(agent, tools, {"fs.read": self.resource_of})

        class Block:
            def __init__(self, id, name, input):
                self.id, self.name, self.input = id, name, input

        out = run(Block("1", "fs.read", {"path": "intro.md"}))
        self.assertFalse(out.get("is_error"))
        self.assertEqual(ran, ["intro.md"])

        ran.clear()
        out = run(Block("2", "fs.write", {"path": "intro.md"}))
        self.assertTrue(out.get("is_error"))
        self.assertEqual(out["tool_use_id"], "2")
        self.assertEqual(ran, [])

    # --- Semantic Kernel ---

    def test_semantic_kernel_function_allow_and_deny(self):
        agent = self.agent()
        ran = []
        fn = lambda path: ran.append(path) or "ok"  # noqa: E731
        wrapped = adapters.semantic_kernel_function(agent, "fs.read", self.resource_of, fn)
        self.assertEqual(wrapped(path="intro.md"), "ok")

        ran.clear()
        deny_wrapped = adapters.semantic_kernel_function(agent, "fs.write", self.resource_of, fn)
        with self.assertRaises(adapters.Denied):
            deny_wrapped(path="intro.md")
        self.assertEqual(ran, [])

    # --- Haystack ---

    def test_haystack_component_allow_and_deny(self):
        agent = self.agent()
        ran = []
        fn = lambda path: ran.append(path) or "ok"  # noqa: E731
        comp = adapters.haystack_component(agent, "fs.read", self.resource_of, fn)
        out = comp.run(path="intro.md")
        self.assertEqual(out["result"], "ok")

        ran.clear()
        deny_comp = adapters.haystack_component(agent, "fs.write", self.resource_of, fn)
        out = deny_comp.run(path="intro.md")
        self.assertIn("error", out)
        self.assertEqual(ran, [])

    # --- Pydantic-AI ---

    def test_pydantic_ai_tool_allow_and_deny(self):
        agent = self.agent()
        ran = []
        fn = lambda path: ran.append(path) or "ok"  # noqa: E731
        wrapped = adapters.pydantic_ai_tool(agent, "fs.read", self.resource_of, fn)
        self.assertEqual(wrapped(path="intro.md"), "ok")

        ran.clear()
        deny_wrapped = adapters.pydantic_ai_tool(agent, "fs.write", self.resource_of, fn)
        with self.assertRaises(adapters.Denied):
            deny_wrapped(path="intro.md")
        self.assertEqual(ran, [])


if __name__ == "__main__":
    unittest.main()
