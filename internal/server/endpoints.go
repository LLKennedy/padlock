package server

import (
	"context"
	"crypto/rand"
	"log"

	"github.com/LLKennedy/padlock/api/padlockpb"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Hello initiates a session with the application, generating an authentication token
func (h *handle) Hello(ctx context.Context, req *padlockpb.AuthHello) (*padlockpb.AuthToken, error) {
	id := uuid.New()
	gcm := h.getGCM()
	nonce := make([]byte, gcm.NonceSize())
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate nonce: %v", err)
	}
	encrypted := gcm.Seal(nil, nonce, []byte(id.String()), h.authData)
	return &padlockpb.AuthToken{
		Data: append(nonce, encrypted...),
	}, nil
}

func (h *handle) authenticate(auth *padlockpb.AuthToken) (id uuid.UUID, err error) {
	gcm := h.getGCM()
	if len(auth.GetData()) <= gcm.NonceSize() {
		err = status.Error(codes.Unauthenticated, "insufficient auth data provided")
		return
	}
	nonce := auth.GetData()[:gcm.NonceSize()]
	data := auth.GetData()[gcm.NonceSize():]
	decrypted, decryptErr := gcm.Open(nil, nonce, data, h.authData)
	if decryptErr != nil {
		err = status.Errorf(codes.Unauthenticated, "failed to decrypt auth data: %v", decryptErr)
		return
	}
	id, err = uuid.ParseBytes(decrypted)
	if err != nil {
		err = status.Errorf(codes.Unauthenticated, "could not parse decrypted auth data as UUID: %v", err)
	}
	return
}

// ApplicationListModules lists modules already connected to the application
func (h *handle) ApplicationListModules(ctx context.Context, req *padlockpb.ApplicationListModulesRequest) (*padlockpb.ApplicationListModulesResponse, error) {
	return h.UnimplementedExposedPadlockServer.GetApplicationListModules(ctx, req)
}

// ApplicationConnect connects a new module to the application
func (h *handle) ApplicationConnect(req *padlockpb.ApplicationConnectRequest, stream padlockpb.Padlock_ApplicationConnectServer) error {
	id, err := h.authenticate(req.GetAuth())
	if err != nil {
		return err
	}
	log.Printf("Connecting for %s\n", id)
	module, err := h.app.Connect(req.GetModule())
	if err != nil {
		return status.Errorf(codes.NotFound, "connecting to module: %v", err)
	}
	info, err := module.Info()
	if err != nil {
		return status.Errorf(codes.NotFound, "listing slots on module: %v", err)
	}
	err = stream.Send(&padlockpb.ApplicationConnectUpdate{
		Update: &padlockpb.ApplicationConnectUpdate_Info{
			Info: &padlockpb.ModuleInfo{
				CryptokiVersion: &padlockpb.Version{
					Major: uint32(info.CryptokiVersion.Major),
					Minor: uint32(info.CryptokiVersion.Minor),
				},
				ManufacturerId:     info.ManufacturerID,
				Flags:              uint64(info.Flags), // TOOD: probably parse flags individually once we know what they are
				LibraryDescription: info.LibraryDescription,
				LibraryVersion: &padlockpb.Version{
					Major: uint32(info.LibraryVersion.Major),
					Minor: uint32(info.LibraryVersion.Minor),
				},
			},
		},
	})
	if err != nil {
		return status.Errorf(codes.Aborted, "sending data back to client: %v", err)
	}
	// TODO: hold stream open and give updates on module state changes
	// For now, wait forever
	<-make(chan struct{})
	return nil
}

// ModuleListSlots lists the slots on a module
func (h *handle) ModuleListSlots(ctx context.Context, req *padlockpb.ModuleListSlotsRequest) (*padlockpb.ModuleListSlotsResponse, error) {
	id, err := h.authenticate(req.GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Listing slots for %s\n", id)
	return h.UnimplementedExposedPadlockServer.GetModuleListSlots(ctx, req)
}

// ModuleInfo gets info for a specific module
func (h *handle) ModuleInfo(ctx context.Context, req *padlockpb.ModuleInfoRequest) (*padlockpb.ModuleInfoResponse, error) {
	id, err := h.authenticate(req.GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Getting module info for %s\n", id)
	return h.UnimplementedExposedPadlockServer.GetModuleInfo(ctx, req)
}

// SlotListMechanisms lists the mechanisms available on a slot
func (h *handle) SlotListMechanisms(ctx context.Context, req *padlockpb.SlotListMechanismsRequest) (*padlockpb.SlotListMechanismsResponse, error) {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Listing slot mechanisms for %s\n", id)
	return h.UnimplementedExposedPadlockServer.GetSlotListMechanisms(ctx, req)
}

// SlotInitToken creates the token in the slot
func (h *handle) SlotInitToken(ctx context.Context, req *padlockpb.SlotInitTokenRequest) (*padlockpb.SlotInitTokenResponse, error) {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Initialising slot token for %s\n", id)
	return h.UnimplementedExposedPadlockServer.PostSlotInitToken(ctx, req)
}

// SlotOpenSession creates a session on the slot
func (h *handle) SlotOpenSession(req *padlockpb.SlotOpenSessionRequest, stream padlockpb.Padlock_SlotOpenSessionServer) error {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return err
	}
	log.Printf("Opening session for %s\n", id)
	return h.UnimplementedExposedPadlockServer.GetSlotOpenSession(req, stream)
}

// SessionLogin logs into the session at the application level
func (h *handle) SessionLogin(ctx context.Context, req *padlockpb.SessionLoginRequest) (*padlockpb.SessionLoginResponse, error) {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Logging into session for %s\n", id)
	return h.UnimplementedExposedPadlockServer.PutSessionLogin(ctx, req)
}

// SessionLogout logs out of the session at the application level
func (h *handle) SessionLogout(ctx context.Context, req *padlockpb.SessionID) (*padlockpb.SessionLogoutResponse, error) {
	id, err := h.authenticate(req.GetSlot().GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Logging out of session for %s\n", id)
	return h.UnimplementedExposedPadlockServer.PutSessionLogout(ctx, req)
}

// SessionListObjects lists the objects available in the session
func (h *handle) SessionListObjects(req *padlockpb.SessionListObjectsRequest, stream padlockpb.Padlock_SessionListObjectsServer) error {
	// id, err := h.authenticate(req.Get)
	// if err != nil {
	// 	return nil, err
	// }
	// log.Printf("Logging into session for %s\n", id)
	return h.UnimplementedExposedPadlockServer.GetSessionListObjects(req, stream)
}

// ObjectListAttributeValues lists values for the requested attributes
func (h *handle) ObjectListAttributeValues(req *padlockpb.ObjectListAttributeValuesRequest, stream padlockpb.Padlock_ObjectListAttributeValuesServer) error {
	return h.UnimplementedExposedPadlockServer.GetObjectListAttributeValues(req, stream)
}
