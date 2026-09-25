# Framework adapters

Every adapter routes a framework's own tool-call shape through Warrant
authorization before the tool body ever runs: deny means the wrapped
function/handler is never called, and the caller gets a framework-native
denial (an error, a string observation, an `is_error` result, a `403`, or a
rejected task) instead of a bare exception. Each row below is "tested against
[the framework's documented] payload shape, not [against the] live SDK" —
these adapters accept minimal, dependency-free structs/duck-typed objects
that match what the framework's own docs describe, so this repo has no
build- or import-time dependency on any of the frameworks themselves. Where a
framework's calling convention has moved across versions, the adapter's
doc comment states the version assumption.

## Go (`adapters/`)

| Framework / protocol | Entry point | File | Status |
|---|---|---|---|
| Generic `net/http` | `HTTPMiddleware` | `adapters/http.go` | tested against payload shape, not live SDK |
| Model Context Protocol — client call | `MCPGate` | `adapters/mcp.go` | tested against payload shape, not live SDK |
| Model Context Protocol — server-side handler middleware | `MCPHandlerMiddleware` | `adapters/mcpserver.go` | tested against payload shape, not live SDK |
| A2A (Agent2Agent) task submission | `A2AGate` | `adapters/a2a.go` | tested against payload shape, not live SDK |
| OpenAI function calling | `OpenAIFunctionGate` | `adapters/openai.go` | tested against payload shape, not live SDK |
| LangChain-Go tool | `WrapLangChainTool` | `adapters/langchain.go` | tested against payload shape, not live SDK |
| Anthropic Messages API `tool_use` | `AnthropicToolGate` | `adapters/anthropic.go` | tested against payload shape, not live SDK |
| Google Gemini `functionCall` | `GeminiFunctionGate` | `adapters/gemini.go` | tested against payload shape, not live SDK |
| AWS Bedrock Converse `toolUse` | `BedrockToolGate` | `adapters/bedrock.go` | tested against payload shape, not live SDK |
| Generic gRPC unary interceptor | `GRPCUnaryInterceptor` | `adapters/grpc.go` | tested against payload shape, not live SDK |
| `net/rpc`-style method | `WrapRPCMethod` | `adapters/rpcfunc.go` | tested against payload shape, not live SDK |
| Generic Go function/worker | `WrapFunc` | `adapters/rpcfunc.go` | tested against payload shape, not live SDK |

## Python (`sdk/python/warrant/adapters.py`)

Standard library only; nothing here imports a real framework SDK at module
load — each function accepts/returns plain, duck-typed objects matching that
framework's documented tool contract.

| Framework | Entry point | Status |
|---|---|---|
| LangChain `BaseTool` | `langchain_tool` | tested against payload shape, not live SDK |
| LlamaIndex `FunctionTool` | `llamaindex_function_tool` | tested against payload shape, not live SDK |
| CrewAI `BaseTool` | `crewai_tool` | tested against payload shape, not live SDK |
| AutoGen / ag2 `function_map` | `autogen_function_map` | tested against payload shape, not live SDK |
| OpenAI Agents SDK `function_tool` | `openai_agents_function_tool` | tested against payload shape, not live SDK |
| Anthropic tool runner (Messages API `tool_use`) | `anthropic_tool_runner` | tested against payload shape, not live SDK |
| Semantic Kernel `kernel_function` | `semantic_kernel_function` | tested against payload shape, not live SDK |
| Haystack `Component` | `haystack_component` | tested against payload shape, not live SDK |
| Pydantic-AI tool | `pydantic_ai_tool` | tested against payload shape, not live SDK |

## Shared mechanism

- **Go**: every adapter calls `adapters.Enforcer.Authorize`, which runs
  in-process against a `*broker.Service` (the same one `warrantd`'s HTTP API
  wraps). A denial is always a `*adapters.Denied` (structured reason, token
  id, action hash); `errors.As` recovers it.
- **Python**: every adapter calls `warrant.Agent.authorize(tool, resource,
  args)`, which POSTs to the broker's `/v1/authorize` endpoint (decision
  only — it never forwards execution) and raises `warrant.Denied` on refusal.
  The wrapped tool function's body runs only if that call succeeds.

Both mechanisms mean a single policy change in `internal/policy` (Go
broker/PEP) applies identically across every framework adapter, in either
language.
