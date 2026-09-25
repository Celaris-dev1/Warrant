"""Thin, tested Warrant PEP wrappers for Python agent frameworks.

Every adapter here does the same thing: call ``agent.authorize(tool,
resource, args)`` against the Warrant broker's ``/v1/authorize`` endpoint,
and only call the wrapped tool function's body if that succeeds. On denial
the function body never runs, and the adapter returns (or raises) whatever
shape that framework expects for a tool failure.

Standard library only. None of these modules import a real agent-framework
SDK — each accepts and returns plain callables/dicts that duck-type the
documented shape of that framework's tool objects, so this file has zero
import-time dependency on LangChain, LlamaIndex, CrewAI, AutoGen, the OpenAI
Agents SDK, Semantic Kernel, Haystack or Pydantic-AI. Import assumptions
(the exact attribute names/shape assumed) are documented per adapter and in
docs/adapters.md.
"""
from __future__ import annotations

import inspect
from typing import Any, Callable, Dict, Optional

from . import Agent, Denied

__all__ = [
    "langchain_tool",
    "llamaindex_function_tool",
    "crewai_tool",
    "autogen_function_map",
    "openai_agents_function_tool",
    "anthropic_tool_runner",
    "semantic_kernel_function",
    "haystack_component",
    "pydantic_ai_tool",
]


def _authorize(agent: Agent, tool: str, resource_of: Callable[..., str], args: Dict[str, Any]) -> None:
    resource = resource_of(**args) if resource_of else "*"
    agent.authorize(tool, resource, args)


def _call_kwargs(fn: Callable, args: tuple, kwargs: dict) -> Dict[str, Any]:
    """Bind positional+keyword call args to fn's declared parameter names,
    the same way every adapter below turns a framework's call into the
    Warrant `args` dict (and the input `resource_of` receives as **kwargs).
    """
    sig = inspect.signature(fn)
    bound = sig.bind_partial(*args, **kwargs)
    bound.apply_defaults()
    return dict(bound.arguments)


class _Denied(Denied):
    """Raised by adapters whose framework has no other channel for a typed
    failure and must propagate the denial as an exception."""


# --- LangChain --------------------------------------------------------------
# Assumes langchain_core.tools.BaseTool's shape: an object with `.name` and a
# callable `._run(*args, **kwargs)` (sync) that LangChain's executor invokes.
# Version assumption: langchain-core >= 0.1 tool-calling contract.

def langchain_tool(agent: Agent, tool_name: str, resource_of: Callable[..., str], fn: Callable) -> Any:
    """Wrap `fn` (a LangChain tool's `_run` body) with a BaseTool-shaped
    object. On denial, `_run` returns the denial text as its string
    observation (LangChain tools convert any returned string to an
    observation), matching this repo's Go WrapLangChainTool.
    """

    class _Tool:
        name = tool_name

        def _run(self, *args, **kwargs):
            call_args = _call_kwargs(fn, args, kwargs)
            try:
                _authorize(agent, tool_name, resource_of, call_args)
            except Denied as e:
                return f"Tool call denied by Warrant policy: {e}"
            return fn(*args, **kwargs)

        run = _run  # some BaseTool versions call .run() directly

    return _Tool()


# --- LlamaIndex ---------------------------------------------------------------
# Assumes llama_index.core.tools.FunctionTool's shape: an object with `.fn`
# and a `.call(*args, **kwargs)` method returning a ToolOutput-like value;
# callers read `.content`/`.raw_output`. Version assumption: llama-index-core
# >= 0.10's FunctionTool.from_defaults contract.

def llamaindex_function_tool(agent: Agent, tool_name: str, resource_of: Callable[..., str], fn: Callable) -> Any:
    """Wrap `fn` as a FunctionTool-shaped object. On denial, `.call` returns
    a ToolOutput-shaped object with `is_error=True` and the denial text as
    content, instead of running fn — matching how LlamaIndex already surfaces
    a failed tool call to the agent loop.
    """

    class _ToolOutput:
        def __init__(self, content: str, is_error: bool = False):
            self.content = content
            self.raw_output = content
            self.is_error = is_error

    class _FunctionTool:
        def __init__(self):
            self.fn = fn
            self.metadata = type("Meta", (), {"name": tool_name})()

        def call(self, *args, **kwargs):
            call_args = _call_kwargs(fn, args, kwargs)
            try:
                _authorize(agent, tool_name, resource_of, call_args)
            except Denied as e:
                return _ToolOutput(f"denied: {e}", is_error=True)
            return _ToolOutput(fn(*args, **kwargs))

    return _FunctionTool()


# --- CrewAI -------------------------------------------------------------------
# Assumes crewai.tools.BaseTool's shape: an object with `.name`, `.description`
# and a `._run(*args, **kwargs)` method. Version assumption: crewai >= 0.30's
# tool contract (same call convention as LangChain's BaseTool).

def crewai_tool(agent: Agent, tool_name: str, description: str, resource_of: Callable[..., str], fn: Callable) -> Any:
    """Wrap `fn` as a CrewAI BaseTool-shaped object. On denial, `._run`
    returns the denial text as its string result so the crew's agent sees a
    structured refusal instead of a raised exception breaking the run.
    """

    tool_description = description

    class _Tool:
        name = tool_name
        description = tool_description

        def _run(self, *args, **kwargs):
            call_args = _call_kwargs(fn, args, kwargs)
            try:
                _authorize(agent, tool_name, resource_of, call_args)
            except Denied as e:
                return f"Tool call denied by Warrant policy: {e}"
            return fn(*args, **kwargs)

    return _Tool()


# --- AutoGen -------------------------------------------------------------------
# Assumes AutoGen's (pyautogen / ag2) ConversableAgent.function_map: a plain
# `Dict[str, Callable]` the agent looks up by function name and calls with
# the model-provided kwargs. Version assumption: autogen/ag2's classic
# function-calling function_map contract (pre- and post- AutoGen 0.4 both
# support this dict-of-callables shape for tool execution).

def autogen_function_map(agent: Agent, function_map: Dict[str, Callable], resource_of: Dict[str, Callable[..., str]]) -> Dict[str, Callable]:
    """Wrap every entry of an AutoGen `function_map` so each call is
    authorized before the mapped function runs. `resource_of` supplies one
    resource-deriving callable per function name (same keys as
    `function_map`). On denial, the wrapped function returns the denial text
    as its string result, which AutoGen feeds back into the conversation as
    the function's output.
    """

    def _wrap(name: str, fn: Callable, res_of: Callable[..., str]) -> Callable:
        def wrapped(*args, **kwargs):
            call_args = _call_kwargs(fn, args, kwargs)
            try:
                _authorize(agent, name, res_of, call_args)
            except Denied as e:
                return f"Tool call denied by Warrant policy: {e}"
            return fn(*args, **kwargs)

        return wrapped

    return {name: _wrap(name, fn, resource_of.get(name, lambda **_: "*")) for name, fn in function_map.items()}


# --- OpenAI Agents SDK ----------------------------------------------------------
# Assumes the `openai-agents` package's `function_tool` shape: a decorated
# tool object exposing `.name` and an `on_invoke_tool(ctx, arguments_json)`
# coroutine-or-sync callable that receives the raw JSON arguments string
# and returns the tool's string output. Version assumption: openai-agents
# >= 0.0.x's FunctionTool contract.

def openai_agents_function_tool(agent: Agent, tool_name: str, resource_of: Callable[..., str], fn: Callable) -> Any:
    """Wrap `fn` as an openai-agents FunctionTool-shaped object. On denial,
    `on_invoke_tool` returns the denial text as the tool's string output
    (the Agents SDK feeds a tool's return value back to the model as-is),
    instead of invoking fn.
    """
    import json as _json

    class _FunctionTool:
        name = tool_name

        def on_invoke_tool(self, ctx, arguments_json: str):
            call_args = _json.loads(arguments_json) if arguments_json else {}
            try:
                _authorize(agent, tool_name, resource_of, call_args)
            except Denied as e:
                return f"Tool call denied by Warrant policy: {e}"
            return fn(**call_args)

    return _FunctionTool()


# --- Anthropic tool runner -----------------------------------------------------
# Assumes a Messages-API-style tool runner: a dict mapping tool name to a
# handler `fn(**input)`, driven by `tool_use` content blocks with `.name`,
# `.input` (dict) and `.id`. Not tied to any particular runner package —
# matches the shape the Anthropic Python SDK's documented tool-use examples
# use for dispatching a `tool_use` block to a local function.

def anthropic_tool_runner(agent: Agent, tools: Dict[str, Callable], resource_of: Dict[str, Callable[..., str]]) -> Callable[[Any], Dict[str, Any]]:
    """Return a `run(tool_use_block) -> tool_result content block` function.
    `tool_use_block` must have `.id`, `.name` and `.input` (a dict), matching
    an Anthropic Messages API tool_use content block. On denial, the handler
    in `tools` is never called and the returned tool_result has
    `is_error: True`.
    """

    def run(block: Any) -> Dict[str, Any]:
        name = block.name
        args = dict(block.input or {})
        fn = tools.get(name)
        res_of = resource_of.get(name, lambda **_: "*")
        try:
            _authorize(agent, name, res_of, args)
        except Denied as e:
            return {"type": "tool_result", "tool_use_id": block.id, "content": str(e), "is_error": True}
        if fn is None:
            return {"type": "tool_result", "tool_use_id": block.id, "content": f"unknown tool {name}", "is_error": True}
        return {"type": "tool_result", "tool_use_id": block.id, "content": str(fn(**args))}

    return run


# --- Semantic Kernel -------------------------------------------------------------
# Assumes Semantic Kernel's `@kernel_function`-decorated plain function
# contract: a callable invoked with keyword arguments matching its declared
# parameters, whose return value becomes the function result. Version
# assumption: semantic-kernel's Python SDK >= 1.0 kernel_function decorator
# call convention.

def semantic_kernel_function(agent: Agent, tool_name: str, resource_of: Callable[..., str], fn: Callable) -> Callable:
    """Wrap `fn` so Semantic Kernel invokes an authorized call. On denial,
    raises `_Denied` (a `Denied` subclass) rather than returning a plain
    string, since Semantic Kernel treats a function's raised exception as a
    kernel function failure it surfaces to the caller/planner.
    """

    def wrapped(*args, **kwargs):
        call_args = _call_kwargs(fn, args, kwargs)
        try:
            _authorize(agent, tool_name, resource_of, call_args)
        except Denied as e:
            raise _Denied(403, str(e)) from None
        return fn(*args, **kwargs)

    wrapped.__name__ = getattr(fn, "__name__", tool_name)
    return wrapped


# --- Haystack --------------------------------------------------------------------
# Assumes Haystack 2.x's `Component` shape: an object with a `.run(**kwargs)`
# method returning a dict of named outputs. Version assumption: haystack-ai
# >= 2.0's Component.run contract.

def haystack_component(agent: Agent, tool_name: str, resource_of: Callable[..., str], fn: Callable, output_name: str = "result") -> Any:
    """Wrap `fn` as a Haystack Component-shaped object. On denial, `.run`
    returns `{"error": <denial text>}` instead of `{output_name: ...}`,
    matching how a Haystack component reports a handled failure without
    raising (pipeline runs continue and downstream components see the
    error output).
    """

    class _Component:
        def run(self, **kwargs):
            try:
                _authorize(agent, tool_name, resource_of, kwargs)
            except Denied as e:
                return {"error": f"Tool call denied by Warrant policy: {e}"}
            return {output_name: fn(**kwargs)}

    return _Component()


# --- Pydantic-AI -------------------------------------------------------------------
# Assumes pydantic-ai's plain-function tool contract: a tool is a callable
# taking a `RunContext` (or nothing) plus keyword arguments, registered via
# `@agent.tool`. Version assumption: pydantic-ai's tool-registration call
# convention as of 0.0.x, where a tool raising `ModelRetry` is fed back to
# the model as a retryable error message.

def pydantic_ai_tool(agent: Agent, tool_name: str, resource_of: Callable[..., str], fn: Callable) -> Callable:
    """Wrap `fn` (a pydantic-ai tool function, `fn(ctx, **kwargs)` or
    `fn(**kwargs)`) so every call is authorized first. On denial, raises
    `_Denied`; wire it through pydantic-ai's `ModelRetry` at the call site if
    you want the model to see it as a retryable tool error instead of a hard
    failure.
    """

    def wrapped(*args, **kwargs):
        call_args = _call_kwargs(fn, args, kwargs)
        # RunContext (if present as the first positional arg) isn't part of
        # the Warrant call's args.
        call_args.pop("ctx", None)
        try:
            _authorize(agent, tool_name, resource_of, call_args)
        except Denied as e:
            raise _Denied(403, str(e)) from None
        return fn(*args, **kwargs)

    wrapped.__name__ = getattr(fn, "__name__", tool_name)
    return wrapped
