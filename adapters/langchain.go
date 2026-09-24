package adapters

import (
	"context"
	"fmt"
)

// LangChainToolInput is the JSON contract this adapter expects: LangChain
// (Go or Python via a thin subprocess/HTTP shim) tools typically take a
// single string or a struct of named fields. We accept `any` and marshal it
// through Warrant's arg constraints the same way OpenAI function arguments
// are, so the same policy rules apply to both. ToolName maps to Warrant's
// `tool` scope, and ResourceOf derives the resource from the parsed input.
type LangChainToolInput struct {
	ToolName string
	Input    any // string, map[string]any, or a struct
}

// LangChainToolFunc is the shape of a LangChain Go tool's Func: it takes a
// context and the tool's (already-parsed) input and returns a string
// result or an error.
type LangChainToolFunc func(ctx context.Context, input any) (string, error)

// WrapLangChainTool returns a LangChainToolFunc that authorizes the call
// with Warrant before delegating to fn. Use it to wrap an existing
// LangChain-Go tool's Func without changing the tool's own signature — the
// gate is transparent to the chain/agent executor. On denial the tool
// returns the denial's Error() text as its string result (LangChain models
// treat a tool's returned string as an observation, so the agent sees a
// structured refusal instead of a hard failure).
func WrapLangChainTool(e *Enforcer, creds Credentials, in LangChainToolInput, resourceOf func(input any) string, fn LangChainToolFunc) LangChainToolFunc {
	return func(ctx context.Context, input any) (string, error) {
		args, err := marshalArgs(input)
		if err != nil {
			return "", err
		}
		resource := "*"
		if resourceOf != nil {
			resource = resourceOf(input)
		}
		if _, err := e.Authorize(ctx, creds, in.ToolName, resource, args); err != nil {
			var den *Denied
			if d, ok := err.(*Denied); ok {
				den = d
				return fmt.Sprintf("Tool call denied by Warrant policy: %s", den.Error()), nil
			}
			return "", err
		}
		return fn(ctx, input)
	}
}
