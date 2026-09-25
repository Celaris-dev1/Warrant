package adapters

import (
	"context"
	"errors"
)

// GRPCUnaryHandler and GRPCUnaryInfo mirror google.golang.org/grpc's
// UnaryHandler and UnaryServerInfo types exactly in shape (method set and
// field names), so a *GRPCUnaryInfo/GRPCUnaryHandler pair from this package
// is a drop-in argument list for real grpc.UnaryServerInterceptor callers,
// without importing google.golang.org/grpc here. Kept dependency-free so
// this compiles for services that don't otherwise pull in grpc-go.
//
// Version assumption: matches the grpc-go interceptor shape as of v1.5x+
// (ctx, req, info, handler) -> (resp, error); that signature has been
// stable since unary interceptors were introduced.
type GRPCUnaryHandler func(ctx context.Context, req any) (any, error)

// GRPCUnaryInfo carries the RPC's full method name, e.g. "/pkg.Service/Method".
type GRPCUnaryInfo struct {
	FullMethod string
}

// GRPCCredentialsFunc extracts Warrant credentials from an incoming RPC
// context (e.g. from gRPC metadata via metadata.FromIncomingContext).
type GRPCCredentialsFunc func(ctx context.Context) Credentials

// GRPCUnaryInterceptor returns a generic unary server interceptor function
// with grpc.UnaryServerInterceptor's exact shape: assign it directly as a
// grpc.ServerOption via grpc.UnaryInterceptor(adapters.GRPCUnaryInterceptor(...))
// (the real grpc package's types are structurally identical to
// GRPCUnaryHandler/GRPCUnaryInfo, so no adapter shim is needed at the call
// site). Tool is derived from the RPC's method name unless toolOf is given;
// resourceOf derives Warrant's resource string from the request. On denial,
// handler is never called and a *Denied error is returned, which grpc-go
// serializes as an Unknown-code error unless the caller further maps it to a
// grpc/codes.Code (e.g. PermissionDenied) with status.New.
func GRPCUnaryInterceptor(e *Enforcer, credsOf GRPCCredentialsFunc, toolOf func(info *GRPCUnaryInfo) string, resourceOf func(info *GRPCUnaryInfo, req any) string) func(ctx context.Context, req any, info *GRPCUnaryInfo, handler GRPCUnaryHandler) (any, error) {
	return func(ctx context.Context, req any, info *GRPCUnaryInfo, handler GRPCUnaryHandler) (any, error) {
		if credsOf == nil {
			return nil, errors.New("adapters: GRPCUnaryInterceptor requires credsOf")
		}
		tool := info.FullMethod
		if toolOf != nil {
			tool = toolOf(info)
		}
		resource := "*"
		if resourceOf != nil {
			resource = resourceOf(info, req)
		}
		args, err := marshalArgs(req)
		if err != nil {
			return nil, err
		}
		if _, err := e.Authorize(ctx, credsOf(ctx), tool, resource, args); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}
