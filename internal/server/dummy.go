package server

import (
	"context"

	"github.com/LLKennedy/mercury/httpapi"
	"github.com/LLKennedy/mercury/proxy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type dProxy struct {
	srv *proxy.Server
	httpapi.UnimplementedExposedServiceServer
}

func (d *dProxy) ProxyUnary(ctx context.Context, req *httpapi.Request) (*httpapi.Response, error) {
	if d != nil && d.srv != nil {
		return d.srv.ProxyUnary(ctx, req)
	}
	return nil, status.Errorf(codes.Unimplemented, "method ProxyUnary not implemented")
}
func (d *dProxy) ProxyStream(stream httpapi.ExposedService_ProxyStreamServer) error {
	if d != nil && d.srv != nil {
		return d.srv.ProxyStream(stream)
	}
	return status.Errorf(codes.Unimplemented, "method ProxyStream not implemented")
}
