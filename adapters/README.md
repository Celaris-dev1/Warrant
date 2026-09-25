# adapters

Thin, tested Warrant PEP wrappers for the calling conventions agent
frameworks actually use. Every adapter builds a `token.Call` from the
framework's own request shape and authorizes it in-process against a
`broker.Service` via `adapters.Enforcer` (or, for `HTTPMiddleware`, over the
same headers the standalone PEP gateway understands). A denial is always a
`*adapters.Denied` with a structured reason, token id and action hash.

| Adapter | File | For | Denial surfaces as |
|---|---|---|---|
| `HTTPMiddleware` | `http.go` | Any `net/http` service — wrap a handler/router to gate every request | `403` JSON body `{"allow":false,"error":{...}}` |
| `MCPGate` | `mcp.go` | MCP `tools/call` handlers | Return as an MCP tool result with `isError: true` |
| `A2AGate` | `a2a.go` | A2A task submission | Return as an A2A task in the `rejected` state |
| `OpenAIFunctionGate` | `openai.go` | OpenAI (or compatible) `tool_calls[].function` results | Feed back as a `role: "tool"` message |
| `WrapLangChainTool` | `langchain.go` | LangChain-Go `Tool.Func`-shaped functions | Returned as the tool's string observation |

All five share `Enforcer.Authorize` (`adapters.go`), so a single policy
change in `internal/policy` applies identically across every framework.

For the full list of framework adapters (Go and Python, 15+ frameworks in
all — Anthropic, Gemini, Bedrock, gRPC, net/rpc, MCP server middleware,
LangChain, LlamaIndex, CrewAI, AutoGen, OpenAI Agents SDK, Semantic Kernel,
Haystack, Pydantic-AI and more), see [`docs/adapters.md`](../docs/adapters.md).

## Usage

```go
enf := adapters.New(brokerService) // the same *broker.Service warrantd's HTTP API wraps
creds := adapters.Credentials{Token: capToken, SVID: svid}

// MCP
_, err := adapters.MCPGate(ctx, enf, creds, adapters.MCPToolCall{
    Name: "fs.read", Resource: "repo/docs/intro.md", Arguments: args,
})

// OpenAI function calling
_, args, err := adapters.OpenAIFunctionGate(ctx, enf, creds, toolCall,
    func(args map[string]any) string { return "repo/docs/" + args["path"].(string) })

// LangChain-Go tool
gated := adapters.WrapLangChainTool(enf, creds, adapters.LangChainToolInput{ToolName: "fs.read"},
    resourceOf, myTool.Func)

// Generic HTTP
mux.Handle("/files/", adapters.HTTPMiddleware(enf, "fs.read",
    func(r *http.Request) string { return "repo/docs" + r.URL.Path })(fileHandler))
```
