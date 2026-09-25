package adapters

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/Celaris-dev1/Warrant/internal/broker"
)

// AnthropicToolUse mirrors one `tool_use` content block from the Anthropic
// Messages API (role: "assistant", content[].type == "tool_use"): ID is the
// block's id (echoed back in the tool_result), Name is the tool name, and
// Input is the already-parsed JSON object of tool arguments. Kept
// dependency-free so this compiles without the Anthropic Go SDK.
//
// Version assumption: matches the Messages API tool_use block shape as of
// the 2023-06-01 API version (id, name, input) — unchanged across current
// Claude model versions.
type AnthropicToolUse struct {
	ID    string
	Name  string
	Input map[string]any
}

// AnthropicToolResult is the shape of a `tool_result` content block to send
// back in the next user message: ToolUseID must echo the AnthropicToolUse's
// ID, Content is the text to show the model, and IsError marks a denial so
// the model treats it as a refusal rather than tool output.
type AnthropicToolResult struct {
	Type      string `json:"type"`
	ToolUseID string `json:"tool_use_id"`
	Content   string `json:"content"`
	IsError   bool   `json:"is_error,omitempty"`
}

// AnthropicToolGate authorizes one Anthropic tool_use block before your code
// executes the tool. On denial, do not run the tool: send back the returned
// AnthropicToolResult (IsError: true) as the corresponding tool_result
// content block in your next user message instead, so the model sees a
// structured refusal it can adapt to.
func AnthropicToolGate(ctx context.Context, e *Enforcer, creds Credentials, block AnthropicToolUse, resourceOf func(input map[string]any) string) (broker.Decision, AnthropicToolResult, error) {
	resource := "*"
	if resourceOf != nil {
		resource = resourceOf(block.Input)
	}
	d, err := e.Authorize(ctx, creds, block.Name, resource, block.Input)
	if err != nil {
		var den *Denied
		msg := err.Error()
		if errors.As(err, &den) {
			b, _ := json.Marshal(den)
			msg = string(b)
		}
		return d, AnthropicToolResult{Type: "tool_result", ToolUseID: block.ID, Content: msg, IsError: true}, err
	}
	return d, AnthropicToolResult{}, nil
}
