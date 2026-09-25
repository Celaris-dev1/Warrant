package adapters

import (
	"context"

	"github.com/Celaris-dev1/Warrant/internal/broker"
)

// GeminiFunctionCall mirrors one `functionCall` part from the Google Gemini
// API's response (candidates[].content.parts[].functionCall): Name is the
// function name and Args is the already-decoded struct of arguments. Kept
// dependency-free so this compiles without google.golang.org/genai or the
// older generativelanguage client.
//
// Version assumption: matches the Gemini API's functionCall part shape
// (name, args) as documented for the v1beta generateContent/GenerateContent
// function-calling feature.
type GeminiFunctionCall struct {
	Name string
	Args map[string]any
}

// GeminiFunctionResponse is the shape of a `functionResponse` part to send
// back as the next content turn (role: "function" / "tool"), so the model
// sees the outcome of its call.
type GeminiFunctionResponse struct {
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}

// GeminiFunctionGate authorizes one Gemini functionCall before your code
// executes it. On denial, do not run the function: send back the returned
// GeminiFunctionResponse (with an "error" key) as the next functionResponse
// part instead of a transport-level failure, so the model can react.
func GeminiFunctionGate(ctx context.Context, e *Enforcer, creds Credentials, call GeminiFunctionCall, resourceOf func(args map[string]any) string) (broker.Decision, GeminiFunctionResponse, error) {
	resource := "*"
	if resourceOf != nil {
		resource = resourceOf(call.Args)
	}
	d, err := e.Authorize(ctx, creds, call.Name, resource, call.Args)
	if err != nil {
		return d, GeminiFunctionResponse{Name: call.Name, Response: map[string]any{"error": err.Error()}}, err
	}
	return d, GeminiFunctionResponse{}, nil
}
