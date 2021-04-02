package server

import (
	"context"
	"log"

	"github.com/LLKennedy/padlock/api/padlockpb"
	"github.com/LLKennedy/padlock/padlocklib"
)

// Hello initiates a session with the application, generating an authentication token
func (h *handle) Hello(ctx context.Context, req *padlockpb.AuthHello) (*padlockpb.AuthToken, error) {
	return h.UnimplementedPadlockServer.PostHello(ctx, req)
}

// ApplicationListModules lists modules already connected to the application
func (h *handle) ApplicationListModules(ctx context.Context, req *padlockpb.ApplicationListModulesRequest) (*padlockpb.ApplicationListModulesResponse, error) {
	return h.UnimplementedPadlockServer.GetApplicationListModules(ctx, req)
}

// ApplicationConnect connects a new module to the application
func (h *handle) ApplicationConnect(req *padlockpb.ApplicationConnectRequest, stream padlockpb.Padlock_PostApplicationConnectServer) error {
	srv := &padlocklib.Application{}
	err := srv.Connect(`D:\Downloads\SecurityServerEvaluation-V4.40.0.2\Software\Windows\x86-64\Crypto_APIs\PKCS11_R3\lib\cs_pkcs11_R3.dll`)
	if err != nil {
		log.Fatalln(err)
	}
	return h.UnimplementedPadlockServer.PostApplicationConnect(req, stream)
}

// ModuleListSlots lists the slots on a module
func (h *handle) ModuleListSlots(ctx context.Context, req *padlockpb.ModuleListSlotsRequest) (*padlockpb.ModuleListSlotsResponse, error) {
	return h.UnimplementedPadlockServer.GetModuleListSlots(ctx, req)
}

// ModuleInfo gets info for a specific module
func (h *handle) ModuleInfo(ctx context.Context, req *padlockpb.ModuleInfoRequest) (*padlockpb.ModuleInfoResponse, error) {
	return h.UnimplementedPadlockServer.GetModuleInfo(ctx, req)
}

// SlotListMechanisms lists the mechanisms available on a slot
func (h *handle) SlotListMechanisms(ctx context.Context, req *padlockpb.SlotListMechanismsRequest) (*padlockpb.SlotListMechanismsResponse, error) {
	return h.UnimplementedPadlockServer.GetSlotListMechanisms(ctx, req)
}

// SlotInitToken creates the token in the slot
func (h *handle) SlotInitToken(ctx context.Context, req *padlockpb.SlotInitTokenRequest) (*padlockpb.SlotInitTokenResponse, error) {
	return h.UnimplementedPadlockServer.PostSlotInitToken(ctx, req)
}

// SlotOpenSession creates a session on the slot
func (h *handle) SlotOpenSession(req *padlockpb.SlotOpenSessionRequest, stream padlockpb.Padlock_PostSlotOpenSessionServer) error {
	return h.UnimplementedPadlockServer.PostSlotOpenSession(req, stream)
}

// SessionLogin logs into the session at the application level
func (h *handle) SessionLogin(ctx context.Context, req *padlockpb.SessionLoginRequest) (*padlockpb.SessionLoginResponse, error) {
	return h.UnimplementedPadlockServer.PutSessionLogin(ctx, req)
}

// SessionLogout logs out of the session at the application level
func (h *handle) SessionLogout(ctx context.Context, req *padlockpb.SessionID) (*padlockpb.SessionLogoutResponse, error) {
	return h.UnimplementedPadlockServer.PutSessionLogout(ctx, req)
}

// SessionListObjects lists the objects available in the session
func (h *handle) SessionListObjects(req *padlockpb.SessionListObjectsRequest, stream padlockpb.Padlock_GetSessionListObjectsServer) error {
	return h.UnimplementedPadlockServer.GetSessionListObjects(req, stream)
}

// ObjectListAttributeValues lists values for the requested attributes
func (h *handle) ObjectListAttributeValues(req *padlockpb.ObjectListAttributeValuesRequest, stream padlockpb.Padlock_GetObjectListAttributeValuesServer) error {
	return h.UnimplementedPadlockServer.GetObjectListAttributeValues(req, stream)
}
