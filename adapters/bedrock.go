package adapters

import (
	"context"

	"github.com/Celaris-dev1/Warrant/internal/broker"
)

// BedrockToolUse mirrors one `toolUse` content block from the AWS Bedrock
// Converse API (output.message.content[].toolUse): ToolUseID is echoed back
// in the toolResult block, Name is the tool name, and Input is the
// already-decoded document (a JSON-object-shaped `document` value). Kept
// dependency-free so this compiles without the AWS SDK for Go v2's
// bedrockruntime/types package.
//
// Version assumption: matches the Converse API's toolUse/toolResult block
// shape (toolUseId, name, input / toolUseId, content, status) as documented
// for aws-sdk-go-v2 bedrockruntime.
type BedrockToolUse struct {
	ToolUseID string
	Name      string
	Input     map[string]any
}

// BedrockToolResult is the shape of a `toolResult` content block to send
// back in the next "user" message turn.
type BedrockToolResult struct {
	ToolUseID string           `json:"toolUseId"`
	Content   []map[string]any `json:"content"`
	Status    string           `json:"status,omitempty"` // "success" or "error"
}

// BedrockToolGate authorizes one Bedrock Converse toolUse block before your
// code executes it. On denial, do not run the tool: send back the returned
// BedrockToolResult (Status: "error") as the next toolResult content block
// instead of a transport-level failure, so the model can adapt.
func BedrockToolGate(ctx context.Context, e *Enforcer, creds Credentials, block BedrockToolUse, resourceOf func(input map[string]any) string) (broker.Decision, BedrockToolResult, error) {
	resource := "*"
	if resourceOf != nil {
		resource = resourceOf(block.Input)
	}
	d, err := e.Authorize(ctx, creds, block.Name, resource, block.Input)
	if err != nil {
		return d, BedrockToolResult{
			ToolUseID: block.ToolUseID,
			Content:   []map[string]any{{"text": err.Error()}},
			Status:    "error",
		}, err
	}
	return d, BedrockToolResult{}, nil
}
