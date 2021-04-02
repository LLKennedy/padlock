package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"

	"github.com/LLKennedy/mercury"
	"github.com/LLKennedy/padlock/api/padlockpb"
	"github.com/LLKennedy/padlock/padlocklib"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Handle is a handle to the Server object
type Handle struct {
	padlockpb.UnimplementedPadlockServer
	app *padlocklib.Application
}

// Config is the config for the server
type Config struct {
	Address  string
	Port     uint16
	CertFile string
	KeyFile  string
	CAFiles  []string
	FS       fs.FS
}

// NewHandle creates a new server handle
func NewHandle(cfg Config) (*Handle, error) {
	h := &Handle{
		app: padlocklib.NewApplication(),
	}
	if cfg.FS == nil {
		cfg.FS = os.DirFS("")
	}
	certBytes, err := fs.ReadFile(cfg.FS, cfg.CertFile)
	if err != nil {
		return nil, fmt.Errorf("reading cert file %s: %v", cfg.CertFile, err)
	}
	keyBytes, err := fs.ReadFile(cfg.FS, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("reading key file %s: %v", cfg.KeyFile, err)
	}
	caData := make([][]byte, len(cfg.CAFiles))
	for i, caFile := range cfg.CAFiles {
		caData[i], err = fs.ReadFile(cfg.FS, caFile)
		if err != nil {
			return nil, fmt.Errorf("reading ca file %s: %v", caFile, err)
		}
	}
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing cert and key: %v", err)
	}
	certPool := x509.NewCertPool()
	for _, ca := range caData {
		ok := certPool.AppendCertsFromPEM(ca)
		if !ok {
			log.Printf("Could not load CA cert(s) from file %s, failed to parse PEM\n", ca)
		}
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.Address, cfg.Port))
	if err != nil {
		return nil, fmt.Errorf("listening on address %s:%d: %v", cfg.Address, cfg.Port, err)
	}
	addr := listener.Addr()
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			cert,
		},
		RootCAs: certPool,
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)), grpc.StreamInterceptor(h.StreamInterceptor), grpc.UnaryInterceptor(h.UnaryInterceptor))
	mercury.NewServer()
	return h, nil
}

// UnaryInterceptor intercepts Unary RPCs
func (h *Handle) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	return handler(ctx, req)
}

// StreamInterceptor intercepts Stream RPCs
func (h *Handle) StreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, ss)
}

// Hello initiates a session with the application, generating an authentication token
func (h *Handle) Hello(ctx context.Context, req *padlockpb.AuthHello) (*padlockpb.AuthToken, error) {
	return h.UnimplementedPadlockServer.PostHello(ctx, req)
}

// ApplicationListModules lists modules already connected to the application
func (h *Handle) ApplicationListModules(ctx context.Context, req *padlockpb.ApplicationListModulesRequest) (*padlockpb.ApplicationListModulesResponse, error) {
	return h.UnimplementedPadlockServer.GetApplicationListModules(ctx, req)
}

// ApplicationConnect connects a new module to the application
func (h *Handle) ApplicationConnect(req *padlockpb.ApplicationConnectRequest, stream padlockpb.Padlock_PostApplicationConnectServer) error {
	return h.UnimplementedPadlockServer.PostApplicationConnect(req, stream)
}

// ModuleListSlots lists the slots on a module
func (h *Handle) ModuleListSlots(ctx context.Context, req *padlockpb.ModuleListSlotsRequest) (*padlockpb.ModuleListSlotsResponse, error) {
	return h.UnimplementedPadlockServer.GetModuleListSlots(ctx, req)
}

// ModuleInfo gets info for a specific module
func (h *Handle) ModuleInfo(ctx context.Context, req *padlockpb.ModuleInfoRequest) (*padlockpb.ModuleInfoResponse, error) {
	return h.UnimplementedPadlockServer.GetModuleInfo(ctx, req)
}

// SlotListMechanisms lists the mechanisms available on a slot
func (h *Handle) SlotListMechanisms(ctx context.Context, req *padlockpb.SlotListMechanismsRequest) (*padlockpb.SlotListMechanismsResponse, error) {
	return h.UnimplementedPadlockServer.GetSlotListMechanisms(ctx, req)
}

// SlotInitToken creates the token in the slot
func (h *Handle) SlotInitToken(ctx context.Context, req *padlockpb.SlotInitTokenRequest) (*padlockpb.SlotInitTokenResponse, error) {
	return h.UnimplementedPadlockServer.PostSlotInitToken(ctx, req)
}

// SlotOpenSession creates a session on the slot
func (h *Handle) SlotOpenSession(req *padlockpb.SlotOpenSessionRequest, stream padlockpb.Padlock_PostSlotOpenSessionServer) error {
	return h.UnimplementedPadlockServer.PostSlotOpenSession(req, stream)
}

// SessionLogin logs into the session at the application level
func (h *Handle) SessionLogin(ctx context.Context, req *padlockpb.SessionLoginRequest) (*padlockpb.SessionLoginResponse, error) {
	return h.UnimplementedPadlockServer.PutSessionLogin(ctx, req)
}

// SessionLogout logs out of the session at the application level
func (h *Handle) SessionLogout(ctx context.Context, req *padlockpb.SessionID) (*padlockpb.SessionLogoutResponse, error) {
	return h.UnimplementedPadlockServer.PutSessionLogout(ctx, req)
}

// SessionListObjects lists the objects available in the session
func (h *Handle) SessionListObjects(req *padlockpb.SessionListObjectsRequest, stream padlockpb.Padlock_GetSessionListObjectsServer) error {
	return h.UnimplementedPadlockServer.GetSessionListObjects(req, stream)
}

// ObjectListAttributeValues lists values for the requested attributes
func (h *Handle) ObjectListAttributeValues(req *padlockpb.ObjectListAttributeValuesRequest, stream padlockpb.Padlock_GetObjectListAttributeValuesServer) error {
	return h.UnimplementedPadlockServer.GetObjectListAttributeValues(req, stream)
}
