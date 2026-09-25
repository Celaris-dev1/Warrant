package adapters

import "context"

// MCPToolHandler mirrors the shape MCP server SDKs use for a registered
// tool's handler (e.g. mark3labs/mcp-go's server.ToolHandlerFunc and the
// official modelcontextprotocol/go-sdk's tool handler): given the call's
// name and already-decoded arguments object, return an arbitrary result (the
// tool's CallToolResult-shaped payload) or an error.
//
// Version assumption: matches the MCP spec's tools/call request/response
// shape (name, arguments -> content/isError) independent of any one SDK's
// concrete Go types.
type MCPToolHandler func(ctx context.Context, name string, arguments map[string]any) (any, error)

// MCPCredentialsFunc extracts Warrant credentials for one MCP session/call
// (e.g. from the MCP session's stored auth context or an initialize-time
// header).
type MCPCredentialsFunc func(ctx context.Context) Credentials

// MCPHandlerMiddleware wraps an MCP server's tool handler so every
// tools/call is authorized by Warrant before the handler body runs. Unlike
// MCPGate (which authorizes an already-extracted MCPToolCall), this wraps
// the handler function itself, for servers that register one handler per
// tool (or one dispatch handler for all tools) and want the gate applied
// transparently at registration time:
//
//	srv.AddTool(tool, adapters.MCPHandlerMiddleware(enf, credsOf, resourceOf, myHandler))
//
// On denial, next is never called and the returned error should be surfaced
// as the tool result's isError: true (as MCP servers do for any handler
// error), not a transport-level failure.
func MCPHandlerMiddleware(e *Enforcer, credsOf MCPCredentialsFunc, resourceOf func(name string, arguments map[string]any) string, next MCPToolHandler) MCPToolHandler {
	return func(ctx context.Context, name string, arguments map[string]any) (any, error) {
		creds := Credentials{}
		if credsOf != nil {
			creds = credsOf(ctx)
		}
		resource := "*"
		if resourceOf != nil {
			resource = resourceOf(name, arguments)
		}
		if _, err := e.Authorize(ctx, creds, name, resource, arguments); err != nil {
			return nil, err
		}
		return next(ctx, name, arguments)
	}
}
