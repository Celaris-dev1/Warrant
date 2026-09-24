package adapters

import (
	"context"

	"github.com/Celaris-dev1/Warrant/internal/broker"
)

// A2ATask is the shape of an Agent2Agent task submission Warrant needs to
// gate: which remote agent/skill is being invoked (Tool, e.g.
// "agent.<name>.<skill>") and what it targets (Resource — an A2A task ID,
// URL or similar) plus the task's message payload as args.
type A2ATask struct {
	Tool     string
	Resource string
	Message  map[string]any
}

// A2AGate authorizes one A2A task submission before it is dispatched to the
// remote agent. Denial should surface as an A2A task in the "rejected"
// state carrying the structured reason, not a bare transport error, so the
// calling agent can adjust rather than retry.
func A2AGate(ctx context.Context, e *Enforcer, creds Credentials, task A2ATask) (broker.Decision, error) {
	return e.Authorize(ctx, creds, task.Tool, task.Resource, task.Message)
}
