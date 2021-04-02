package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/LLKennedy/mercury"
	"github.com/LLKennedy/mercury/logs"
	"github.com/LLKennedy/padlock/api/padlockpb"
	"github.com/LLKennedy/padlock/padlocklib"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// handle is a handle to the Server object
type handle struct {
	padlockpb.UnimplementedPadlockServer
	app *padlocklib.Application
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
	h := &handle{
		app: padlocklib.NewApplication(),
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
		RootCAs: certPool,
	}
	mainCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)), grpc.StreamInterceptor(h.StreamInterceptor), grpc.UnaryInterceptor(h.UnaryInterceptor))
	proxySrv, err := mercury.NewServer(&padlockpb.UnimplementedPadlockServer{}, h, srv, true)
	if err != nil {
		return fmt.Errorf("creating mercury proxy: %v", err)
	}
	errChan := make(chan error, 2)
	go func() {
		errChan <- proxySrv.Serve(grpcListener)
		cancel()
	}()
	var client *grpc.ClientConn
	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
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
	client, err = grpc.Dial(addr.String(), grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		log.Printf("First client connection attempt failed (%v), waiting for server startup...\n", err)
		ticker := time.NewTicker(100 * time.Millisecond)
	WAIT_LOOP:
		for err != nil {
			log.Printf("Client connection attempt failed: %v\n", err)
			select {
			case <-mainCtx.Done():
				log.Println("Encountered error starting service(s) before getting client connection, aborting client connection")
				break WAIT_LOOP
			case <-ticker.C:
				client, err = grpc.Dial(addr.String(), grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
			}
		}
		ticker.Stop()
	}
	go func() {
		errChan <- httpSrv.Serve(httpListener)
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
	return handler(ctx, req)
}

// StreamInterceptor intercepts Stream RPCs
func (h *handle) StreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, ss)
}
