package server

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/LLKennedy/mercury"
	"github.com/LLKennedy/mercury/httpapi"
	"github.com/LLKennedy/mercury/logs"
	"github.com/LLKennedy/padlock/api/padlockpb"
	"github.com/LLKennedy/padlock/padlocklib"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// handle is a handle to the Server object
type handle struct {
	padlockpb.UnimplementedExposedPadlockServer
	padlockpb.UnimplementedPadlockServer
	app      *padlocklib.Application
	authkey  []byte
	authData []byte
	// Map session IDs to auth token IDs
	sessions map[string]string
}

// Config is the config for the server
type Config struct {
	Address  string   `json:"address"`
	Port     uint16   `json:"port"`
	CertFile string   `json:"cert_file"`
	KeyFile  string   `json:"key_file"`
	CAFiles  []string `json:"ca_files"`
	FS       fs.FS    `json:"-"`
}

// Serve creates a new server handle and starts serving traffic
func Serve(cfg Config) error {
	keyData := make([]byte, 32)
	_, err := rand.Read(keyData)
	if err != nil {
		return fmt.Errorf("generating auth key: %v", err)
	}
	authData := make([]byte, 16)
	_, err = rand.Read(authData)
	if err != nil {
		return fmt.Errorf("generating auth data: %v", err)
	}
	h := &handle{
		app:      padlocklib.NewApplication(),
		authkey:  keyData,
		authData: authData,
		sessions: make(map[string]string, 1),
	}
	if cfg.FS == nil {
		cfg.FS = os.DirFS("")
	}
	certBytes, err := fs.ReadFile(cfg.FS, cfg.CertFile)
	if err != nil {
		return fmt.Errorf("reading cert file %s: %v", cfg.CertFile, err)
	}
	keyBytes, err := fs.ReadFile(cfg.FS, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("reading key file %s: %v", cfg.KeyFile, err)
	}
	caData := make([][]byte, len(cfg.CAFiles))
	for i, caFile := range cfg.CAFiles {
		caData[i], err = fs.ReadFile(cfg.FS, caFile)
		if err != nil {
			return fmt.Errorf("reading ca file %s: %v", caFile, err)
		}
	}
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return fmt.Errorf("parsing cert and key: %v", err)
	}
	certPool := x509.NewCertPool()
	for _, ca := range caData {
		ok := certPool.AppendCertsFromPEM(ca)
		if !ok {
			log.Printf("Could not load CA cert(s) from file %s, failed to parse PEM\n", ca)
		}
	}
	httpListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", cfg.Address, cfg.Port))
	if err != nil {
		return fmt.Errorf("listening on address %s:%d: %v", cfg.Address, cfg.Port, err)
	}
	grpcListener, err := net.Listen("tcp", fmt.Sprintf("%s:0", cfg.Address))
	if err != nil {
		return fmt.Errorf("listening on address %s:0: %v", cfg.Address, err)
	}
	addr := grpcListener.Addr()
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			cert,
		},
		RootCAs:    certPool,
		ClientCAs:  certPool,
		MinVersion: tls.VersionTLS13,
	}
	mainCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)), grpc.StreamInterceptor(h.StreamInterceptor), grpc.UnaryInterceptor(h.UnaryInterceptor))
	d := &dProxy{
		srv: nil,
	}
	httpapi.RegisterExposedServiceServer(srv, d)
	padlockpb.RegisterPadlockServer(srv, h)
	errChan := make(chan error, 2)
	go func() {
		errChan <- srv.Serve(grpcListener)
		cancel()
	}()
	var client *grpc.ClientConn
	aborted := false
	client, err = grpc.Dial(fmt.Sprintf("localhost:%s", strings.Split(addr.String(), ":")[1]), grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		log.Printf("First client connection attempt failed (%v), waiting for server startup...\n", err)
		ticker := time.NewTicker(100 * time.Millisecond)
		for err != nil && !aborted {
			log.Printf("Client connection attempt failed: %v\n", err)
			select {
			case <-mainCtx.Done():
				log.Println("Encountered error starting service(s) before getting client connection, aborting client connection")
				aborted = true
			case <-ticker.C:
				client, err = grpc.Dial(addr.String(), grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
			}
		}
		ticker.Stop()
	}
	var httpSrv *http.Server
	if !aborted {
		real, err := mercury.NewServer(&padlockpb.UnimplementedExposedPadlockServer{}, padlockpb.NewPadlockClient(client), srv, false)
		if err != nil {
			return fmt.Errorf("creating mercury proxy: %v", err)
		}
		d.srv = real
		httpSrv = &http.Server{
			Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.Header().Add("Access-Control-Allow-Origin", "https://localhost:3000")
				rw.Header().Add("Access-Control-Allow-Headers", "Content-Type")
				if r.Method == http.MethodOptions {
					rw.WriteHeader(200)
					return
				}
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				go func() {
					<-mainCtx.Done()
					cancel()
				}()
				if client == nil {
					http.Error(rw, "Server not read", http.StatusPreconditionFailed)
				}
				mercury.ProxyRequest(ctx, rw, r, r.URL.Path[1:], client, uuid.New().String(), logs.StdOutLogger{})
			}),
			TLSConfig: tlsConfig,
		}
	}
	go func() {
		errChan <- httpSrv.ServeTLS(httpListener, "", "")
		cancel()
	}()
	err = <-errChan
	go func() {
		<-errChan
		close(errChan)
	}()
	return err
}

// UnaryInterceptor intercepts Unary RPCs
func (h *handle) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	methodName := "(unknown method name)"
	defer func() {
		if r := recover(); r != nil {
			err = status.Errorf(codes.Internal, "caught panic in unary call %s: %v", methodName, r)
			log.Printf("stack trace: %s\n", debug.Stack())
		}
	}()
	methodName = info.FullMethod
	log.Printf("%s: method called\n", methodName)
	resp, err = handler(ctx, req)
	_, ok := status.FromError(err)
	if ok {
		return
	}
	err = status.Errorf(codes.Internal, "endpoint %s returned with non-RPC error: %v", err)
	return
}

// StreamInterceptor intercepts Stream RPCs
func (h *handle) StreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
	methodName := "(unknown method name)"
	defer func() {
		if r := recover(); r != nil {
			err = status.Errorf(codes.Internal, "caught panic in unary call %s: %v", methodName, r)
			log.Printf("stack trace: %s\n", debug.Stack())
		}
	}()
	methodName = info.FullMethod
	log.Printf("%s: method called\n", methodName)
	err = handler(srv, ss)
	_, ok := status.FromError(err)
	if ok {
		return
	}
	err = status.Errorf(codes.Internal, "endpoint %s returned with non-RPC error: %v", err)
	return
}

func (h *handle) getGCM() cipher.AEAD {
	if h == nil || h.authkey == nil {
		return nil
	}
	key, err := aes.NewCipher(h.authkey)
	if err != nil {
		log.Printf("Could not get AES key as cipher block: %v\n", err)
	}
	crypt, err := cipher.NewGCM(key)
	if err != nil {
		log.Printf("Could not get AES key as GCM: %v\n", err)
	}
	return crypt
}
