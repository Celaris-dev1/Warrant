package adapters

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Celaris-dev1/Warrant/internal/broker"
)

// OpenAIFunctionCall mirrors the shape the OpenAI (and OpenAI-compatible)
// chat completions API returns for a tool/function call: Name is the
// function name, Arguments is the raw JSON string the model produced.
// ResourceOf derives a Warrant resource string from the parsed arguments
// (e.g. args["path"]); pass nil to authorize with resource "*".
type OpenAIFunctionCall struct {
	Name      string
	Arguments string // raw JSON, as returned on message.tool_calls[i].function.arguments
}

// OpenAIFunctionGate parses a model-produced function call's JSON
// arguments and authorizes it before your code actually executes the
// function. On denial, feed the error text back to the model as the tool
// result message (role: "tool") instead of executing anything, so the
// model can adapt its next call instead of the process crashing or the
// call silently going through.
func OpenAIFunctionGate(ctx context.Context, e *Enforcer, creds Credentials, call OpenAIFunctionCall, resourceOf func(args map[string]any) string) (broker.Decision, map[string]any, error) {
	var args map[string]any
	if call.Arguments != "" {
		if err := json.Unmarshal([]byte(call.Arguments), &args); err != nil {
			return broker.Decision{}, nil, fmt.Errorf("adapters: invalid function arguments JSON: %w", err)
		}
	}
	resource := "*"
	if resourceOf != nil {
		resource = resourceOf(args)
	}
	d, err := e.Authorize(ctx, creds, call.Name, resource, args)
	return d, args, err
}
