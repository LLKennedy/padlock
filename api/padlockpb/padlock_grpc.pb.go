// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package padlockpb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion7

// PadlockClient is the client API for Padlock service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type PadlockClient interface {
	// Hello initiates a session with the application, generating an authentication token
	Hello(ctx context.Context, in *AuthHello, opts ...grpc.CallOption) (*AuthToken, error)
	// ApplicationListModules lists modules already connected to the application
	ApplicationListModules(ctx context.Context, in *ApplicationListModulesRequest, opts ...grpc.CallOption) (*ApplicationListModulesResponse, error)
	// ApplicationConnect connects a new module to the application
	ApplicationConnect(ctx context.Context, in *ApplicationConnectRequest, opts ...grpc.CallOption) (Padlock_ApplicationConnectClient, error)
	// ModuleListSlots
	ModuleListSlots(ctx context.Context, in *ModuleListSlotsRequest, opts ...grpc.CallOption) (*ModuleListSlotsResponse, error)
}

type padlockClient struct {
	cc grpc.ClientConnInterface
}

func NewPadlockClient(cc grpc.ClientConnInterface) PadlockClient {
	return &padlockClient{cc}
}

func (c *padlockClient) Hello(ctx context.Context, in *AuthHello, opts ...grpc.CallOption) (*AuthToken, error) {
	out := new(AuthToken)
	err := c.cc.Invoke(ctx, "/padlock.Padlock/Hello", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *padlockClient) ApplicationListModules(ctx context.Context, in *ApplicationListModulesRequest, opts ...grpc.CallOption) (*ApplicationListModulesResponse, error) {
	out := new(ApplicationListModulesResponse)
	err := c.cc.Invoke(ctx, "/padlock.Padlock/ApplicationListModules", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *padlockClient) ApplicationConnect(ctx context.Context, in *ApplicationConnectRequest, opts ...grpc.CallOption) (Padlock_ApplicationConnectClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Padlock_serviceDesc.Streams[0], "/padlock.Padlock/ApplicationConnect", opts...)
	if err != nil {
		return nil, err
	}
	x := &padlockApplicationConnectClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type Padlock_ApplicationConnectClient interface {
	Recv() (*ApplicationConnectUpdate, error)
	grpc.ClientStream
}

type padlockApplicationConnectClient struct {
	grpc.ClientStream
}

func (x *padlockApplicationConnectClient) Recv() (*ApplicationConnectUpdate, error) {
	m := new(ApplicationConnectUpdate)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *padlockClient) ModuleListSlots(ctx context.Context, in *ModuleListSlotsRequest, opts ...grpc.CallOption) (*ModuleListSlotsResponse, error) {
	out := new(ModuleListSlotsResponse)
	err := c.cc.Invoke(ctx, "/padlock.Padlock/ModuleListSlots", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PadlockServer is the server API for Padlock service.
// All implementations must embed UnimplementedPadlockServer
// for forward compatibility
type PadlockServer interface {
	// Hello initiates a session with the application, generating an authentication token
	Hello(context.Context, *AuthHello) (*AuthToken, error)
	// ApplicationListModules lists modules already connected to the application
	ApplicationListModules(context.Context, *ApplicationListModulesRequest) (*ApplicationListModulesResponse, error)
	// ApplicationConnect connects a new module to the application
	ApplicationConnect(*ApplicationConnectRequest, Padlock_ApplicationConnectServer) error
	// ModuleListSlots
	ModuleListSlots(context.Context, *ModuleListSlotsRequest) (*ModuleListSlotsResponse, error)
	mustEmbedUnimplementedPadlockServer()
}

// UnimplementedPadlockServer must be embedded to have forward compatible implementations.
type UnimplementedPadlockServer struct {
}

func (UnimplementedPadlockServer) Hello(context.Context, *AuthHello) (*AuthToken, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Hello not implemented")
}
func (UnimplementedPadlockServer) ApplicationListModules(context.Context, *ApplicationListModulesRequest) (*ApplicationListModulesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ApplicationListModules not implemented")
}
func (UnimplementedPadlockServer) ApplicationConnect(*ApplicationConnectRequest, Padlock_ApplicationConnectServer) error {
	return status.Errorf(codes.Unimplemented, "method ApplicationConnect not implemented")
}
func (UnimplementedPadlockServer) ModuleListSlots(context.Context, *ModuleListSlotsRequest) (*ModuleListSlotsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ModuleListSlots not implemented")
}
func (UnimplementedPadlockServer) mustEmbedUnimplementedPadlockServer() {}

// UnsafePadlockServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to PadlockServer will
// result in compilation errors.
type UnsafePadlockServer interface {
	mustEmbedUnimplementedPadlockServer()
}

func RegisterPadlockServer(s *grpc.Server, srv PadlockServer) {
	s.RegisterService(&_Padlock_serviceDesc, srv)
}

func _Padlock_Hello_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthHello)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PadlockServer).Hello(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/padlock.Padlock/Hello",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PadlockServer).Hello(ctx, req.(*AuthHello))
	}
	return interceptor(ctx, in, info, handler)
}

func _Padlock_ApplicationListModules_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ApplicationListModulesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PadlockServer).ApplicationListModules(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/padlock.Padlock/ApplicationListModules",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PadlockServer).ApplicationListModules(ctx, req.(*ApplicationListModulesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Padlock_ApplicationConnect_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ApplicationConnectRequest)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(PadlockServer).ApplicationConnect(m, &padlockApplicationConnectServer{stream})
}

type Padlock_ApplicationConnectServer interface {
	Send(*ApplicationConnectUpdate) error
	grpc.ServerStream
}

type padlockApplicationConnectServer struct {
	grpc.ServerStream
}

func (x *padlockApplicationConnectServer) Send(m *ApplicationConnectUpdate) error {
	return x.ServerStream.SendMsg(m)
}

func _Padlock_ModuleListSlots_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ModuleListSlotsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PadlockServer).ModuleListSlots(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/padlock.Padlock/ModuleListSlots",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PadlockServer).ModuleListSlots(ctx, req.(*ModuleListSlotsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Padlock_serviceDesc = grpc.ServiceDesc{
	ServiceName: "padlock.Padlock",
	HandlerType: (*PadlockServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Hello",
			Handler:    _Padlock_Hello_Handler,
		},
		{
			MethodName: "ApplicationListModules",
			Handler:    _Padlock_ApplicationListModules_Handler,
		},
		{
			MethodName: "ModuleListSlots",
			Handler:    _Padlock_ModuleListSlots_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ApplicationConnect",
			Handler:       _Padlock_ApplicationConnect_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "padlock.proto",
}
