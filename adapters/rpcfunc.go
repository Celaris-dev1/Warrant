package adapters

import "context"

// RPCMethod mirrors the signature net/rpc requires of an exported method on
// a registered service: func (t *T) Name(args *Args, reply *Reply) error.
// Wrapping a method with this shape (rather than net/rpc's *rpc.Server
// directly) keeps this adapter dependency-free and usable for any
// net/rpc-style or hand-rolled RPC framework built around the same
// (args, reply) error-returning convention.
type RPCMethod[Args any, Reply any] func(args *Args, reply *Reply) error

// WrapRPCMethod returns an RPCMethod that authorizes the call with Warrant
// before delegating to fn, for net/rpc-registered methods (or anything
// sharing net/rpc's (args *Args, reply *Reply) error method shape). Because
// net/rpc method calls carry no per-call context, creds and resourceOf are
// fixed at wrap time (creds for a long-lived server-to-server credential;
// resourceOf derives the resource from the decoded args). On denial, fn is
// never called and the returned error is a *Denied, which net/rpc delivers
// to the client as the call's Error field.
func WrapRPCMethod[Args any, Reply any](e *Enforcer, creds Credentials, tool string, resourceOf func(*Args) string, fn RPCMethod[Args, Reply]) RPCMethod[Args, Reply] {
	return func(args *Args, reply *Reply) error {
		margs, err := marshalArgs(args)
		if err != nil {
			return err
		}
		resource := "*"
		if resourceOf != nil {
			resource = resourceOf(args)
		}
		if _, err := e.Authorize(context.Background(), creds, tool, resource, margs); err != nil {
			return err
		}
		return fn(args, reply)
	}
}

// Func is the shape of a plain Go function this adapter can gate: takes a
// context and an arbitrary (JSON-marshalable) input, returns an arbitrary
// output or an error. Use this for any bespoke RPC/task-queue/worker
// framework whose handlers don't match one of the other adapters' shapes.
type Func func(ctx context.Context, input any) (any, error)

// WrapFunc returns a Func that authorizes the call with Warrant before
// delegating to fn. On denial, fn is never called and the returned error is
// a *Denied.
func WrapFunc(e *Enforcer, creds Credentials, tool string, resourceOf func(input any) string, fn Func) Func {
	return func(ctx context.Context, input any) (any, error) {
		args, err := marshalArgs(input)
		if err != nil {
			return nil, err
		}
		resource := "*"
		if resourceOf != nil {
			resource = resourceOf(input)
		}
		if _, err := e.Authorize(ctx, creds, tool, resource, args); err != nil {
			return nil, err
		}
		return fn(ctx, input)
	}
}
