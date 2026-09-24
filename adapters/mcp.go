package adapters

import (
	"context"

	"github.com/Celaris-dev1/Warrant/internal/broker"
)

// MCPToolCall is the shape of an MCP "tools/call" request's params, kept
// minimal and dependency-free (no MCP SDK import) so this adapter compiles
// against any MCP client/server library. Name is the tool name; Arguments
// is the call's JSON arguments object; Resource is Warrant's resource
// string for this call — MCP has no native resource concept, so the caller
// derives one (e.g. from an argument like a file path or URL) and passes it
// here.
type MCPToolCall struct {
	Name      string
	Resource  string
	Arguments map[string]any
}

// MCPGate authorizes one MCP tools/call before it reaches the real tool
// implementation. Call this from your MCP server's tools/call handler; on
// denial, return the error text as the MCP tool result's error content
// (isError: true) rather than a transport-level failure, so the model sees
// a structured refusal it can react to instead of retrying blindly.
func MCPGate(ctx context.Context, e *Enforcer, creds Credentials, call MCPToolCall) (broker.Decision, error) {
	return e.Authorize(ctx, creds, call.Name, call.Resource, call.Arguments)
}
