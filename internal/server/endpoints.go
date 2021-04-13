package server

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"log"
	"reflect"
	"sync"
	"time"
	"unsafe"

	"github.com/LLKennedy/padlock/api/padlockpb"
	"github.com/google/uuid"
	"github.com/llkennedy/pkcs11"
	"github.com/llkennedy/pkcs11/p11"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
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
	_, err := h.authenticate(req.GetAuth())
	if err != nil {
		return nil, err
	}
	res := &padlockpb.ApplicationListModulesResponse{
		Modules: map[string]*padlockpb.ModuleInfo{},
	}
	modulesCopy := map[string]p11.Module{}
	h.app.ModulesMx.RLock()
	for key, m := range h.app.Modules {
		modulesCopy[key] = m
	}
	h.app.ModulesMx.RUnlock()
	for key, m := range modulesCopy {
		info, err := m.Info()
		if err != nil {
			return nil, status.Errorf(codes.Aborted, "getting module info: %v", err)
		}
		res.Modules[key] = &padlockpb.ModuleInfo{
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
		}
	}
	return res, nil
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
		return status.Errorf(codes.Aborted, "listing slots on module: %v", err)
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
	module, exists := h.app.Modules[req.GetModule()]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "no module for path %s", req.GetModule())
	}
	slots, err := module.Slots()
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "listing slots: %v", err)
	}
	res := &padlockpb.ModuleListSlotsResponse{}
	for _, slot := range slots {
		slotID := slot.ID()
		info, err := slot.Info()
		if err != nil {
			return nil, status.Errorf(codes.Aborted, "getting slot info for slot %d: %v", slotID, err)
		}
		newSlot := &padlockpb.SlotInfo{
			Id:              uint64(slotID),
			SlotDescription: info.SlotDescription,
			ManufacturerId:  info.ManufacturerID,
			Flags:           uint64(info.Flags), // TOOD: probably parse flags individually once we know what they are
			HardwareVersion: &padlockpb.Version{
				Major: uint32(info.HardwareVersion.Major),
				Minor: uint32(info.HardwareVersion.Minor),
			},
			FirmwareVersion: &padlockpb.Version{
				Major: uint32(info.FirmwareVersion.Major),
				Minor: uint32(info.FirmwareVersion.Minor),
			},
		}
		res.Slots = append(res.Slots, newSlot)
		tokenInfo, err := slot.TokenInfo()
		if err != nil {
			log.Printf("no token for slot %d with description %s", slotID, info.SlotDescription)
		}
		// TODO: better way to test for token presence
		if tokenInfo.Label == "" {
			continue
		}
		newSlot.TokenInfo = &padlockpb.TokenInfo{
			Label:              tokenInfo.Label,
			ManufacturerId:     tokenInfo.ManufacturerID,
			Model:              tokenInfo.Model,
			SerialNumber:       tokenInfo.SerialNumber,
			Flags:              uint64(tokenInfo.Flags), // TOOD: probably parse flags individually once we know what they are
			MaxSessionCount:    uint64(tokenInfo.MaxSessionCount),
			SessionCount:       uint64(tokenInfo.SessionCount),
			MaxRwSessionCount:  uint64(tokenInfo.MaxRwSessionCount),
			RwSessionCount:     uint64(tokenInfo.RwSessionCount),
			MaxPinLen:          uint64(tokenInfo.MaxPinLen),
			MinPinLen:          uint64(tokenInfo.MinPinLen),
			TotalPublicMemory:  uint64(tokenInfo.TotalPublicMemory),
			FreePublicMemory:   uint64(tokenInfo.FreePublicMemory),
			TotalPrivateMemory: uint64(tokenInfo.TotalPrivateMemory),
			FreePrivateMemory:  uint64(tokenInfo.FreePrivateMemory),
			HardwareVersion: &padlockpb.Version{
				Major: uint32(tokenInfo.HardwareVersion.Major),
				Minor: uint32(tokenInfo.HardwareVersion.Minor),
			},
			FirmwareVersion: &padlockpb.Version{
				Major: uint32(tokenInfo.FirmwareVersion.Major),
				Minor: uint32(tokenInfo.FirmwareVersion.Minor),
			},
			Utctime: tokenInfo.UTCTime,
		}
	}
	return res, nil
}

// ModuleInfo gets info for a specific module
func (h *handle) ModuleInfo(ctx context.Context, req *padlockpb.ModuleInfoRequest) (*padlockpb.ModuleInfoResponse, error) {
	id, err := h.authenticate(req.GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Getting module info for %s\n", id)
	module, exists := h.app.Modules[req.GetModule()]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "no module for path %s", req.GetModule())
	}
	info, err := module.Info()
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "listing slots on module: %v", err)
	}
	parsedInfo := &padlockpb.ModuleInfo{
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
	}
	return &padlockpb.ModuleInfoResponse{
		Info: parsedInfo,
	}, nil
}

func (h *handle) getSlotByID(module string, id uint64) (slot p11.Slot, err error) {
	m, exists := h.app.Modules[module]
	if !exists {
		err = status.Error(codes.NotFound, "no module for path %s")
		return
	}
	slots, err := m.Slots()
	if err != nil {
		err = status.Errorf(codes.Aborted, "listing slots: %v", err)
		return
	}
	for _, slot = range slots {
		if id == uint64(slot.ID()) {
			return
		}
	}
	err = status.Errorf(codes.NotFound, "no slot found with ID %d", id)
	return
}

type localMechanism struct {
	mechanism *pkcs11.Mechanism
	slot      p11.Slot
}

// SlotListMechanisms lists the mechanisms available on a slot
func (h *handle) SlotListMechanisms(ctx context.Context, req *padlockpb.SlotListMechanismsRequest) (*padlockpb.SlotListMechanismsResponse, error) {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Listing slot mechanisms for %s\n", id)
	slot, err := h.getSlotByID(req.GetId().GetModule(), req.GetId().GetSlot())
	if err != nil {
		return nil, err
	}
	mechanisms, err := slot.Mechanisms()
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "listing mechanisms: %v", err)
	}
	res := &padlockpb.SlotListMechanismsResponse{}
	for _, mechanism := range mechanisms {
		// This is really bad, but it's the only way without rewriting p11
		innerMech := *(*uint)(unsafe.Pointer(reflect.ValueOf(mechanism).FieldByName("mechanism").Elem().FieldByName("Mechanism").UnsafeAddr()))
		info, err := mechanism.Info()
		if err != nil {
			return nil, status.Errorf(codes.Aborted, "getting mechanism info: %v", err)
		}
		flagData := make([]byte, 8)
		binary.BigEndian.PutUint64(flagData, uint64(info.Flags))
		newMech := &padlockpb.SupportedMechanism{
			Type:       MechanismP11toPB(innerMech),
			MinKeySize: uint64(info.MinKeySize),
			MaxKeySize: uint64(info.MaxKeySize),
			Flags:      flagData, // TODO: trim this data down to size
		}
		res.Mechanisms = append(res.Mechanisms, newMech)
	}
	return res, nil
}

// SlotInitToken creates the token in the slot
func (h *handle) SlotInitToken(ctx context.Context, req *padlockpb.SlotInitTokenRequest) (*padlockpb.SlotInitTokenResponse, error) {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Initialising slot token for %s\n", id)
	slot, err := h.getSlotByID(req.GetId().GetModule(), req.GetId().GetSlot())
	if err != nil {
		return nil, err
	}
	err = slot.InitToken(req.GetSecurityOfficerPin(), req.GetTokenLabel())
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "initialising token: %v", err)
	}
	return &padlockpb.SlotInitTokenResponse{}, nil
}

// SlotOpenSession creates a session on the slot
func (h *handle) SlotOpenSession(req *padlockpb.SlotOpenSessionRequest, stream padlockpb.Padlock_SlotOpenSessionServer) error {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return err
	}
	log.Printf("Opening session for %s\n", id)
	slot, err := h.getSlotByID(req.GetId().GetModule(), req.GetId().GetSlot())
	if err != nil {
		return err
	}
	session, err := slot.OpenSession()
	if err != nil {
		return status.Errorf(codes.Aborted, "opening session: %v", err)
	}
	sessID := uuid.New().String()
	h.sessionMx.Lock()
	ss := &serverSession{
		sess:     session,
		mx:       &sync.Mutex{},
		objs:     make(map[string]p11.Object),
		lastUsed: time.Now(),
	}
	h.sessions[sessID] = ss
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		for {
			<-ticker.C
			ss.mx.Lock()
			latest := ss.lastUsed
			ss.mx.Unlock()
			if time.Now().Sub(latest) > time.Minute {
				ticker.Stop()
				h.sessionMx.Lock()
				delete(h.sessions, sessID)
				h.sessionMx.Unlock()
				return
			}
		}
	}()
	h.sessionAuth[sessID] = id.String()
	h.sessionMx.Unlock()
	err = stream.Send(&padlockpb.SlotOpenSessionUpdate{
		Update: &padlockpb.SlotOpenSessionUpdate_Uuid{
			Uuid: sessID,
		},
	})
	if err != nil {
		return status.Errorf(codes.Aborted, "could not return session ID to client: %v", err)
	}
	// TODO: hold stream open and give updates on login state changes
	// For now, wait forever
	<-make(chan struct{})
	return nil
}

func (h *handle) getSession(sessID, auth string) (sess *serverSession, err error) {
	h.sessionMx.RLock()
	authID := h.sessionAuth[sessID]
	sess = h.sessions[sessID]
	h.sessionMx.RUnlock()
	if auth != authID {
		return nil, status.Error(codes.PermissionDenied, "not allowed to access this session or session does not exist")
	}
	sess.mx.Lock()
	sess.lastUsed = time.Now()
	return sess, nil
}

// SessionKeepalive keeps the session alive
func (h *handle) SessionKeepAlive(ctx context.Context, req *padlockpb.SessionID) (*emptypb.Empty, error) {
	id, err := h.authenticate(req.GetAuth())
	if err != nil {
		return nil, err
	}
	sessID := req.GetUuid()
	sess, err := h.getSession(sessID, id.String())
	if err != nil {
		return nil, err
	}
	sess.mx.Unlock()
	return &emptypb.Empty{}, nil
}

// SessionClose closes the session
func (h *handle) SessionClose(ctx context.Context, req *padlockpb.SessionCloseRequest) (*padlockpb.SessionCloseResponse, error) {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Closing session for %s\n", id)
	sessID := req.GetId().GetUuid()
	sess, err := h.getSession(sessID, id.String())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	err = sess.sess.Close()
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "closing session: %v", err)
	}
	h.sessionMx.Lock()
	delete(h.sessionAuth, sessID)
	delete(h.sessions, sessID)
	h.sessionMx.Unlock()
	return &padlockpb.SessionCloseResponse{}, nil
}

// SessionLogin logs into the session at the application level
func (h *handle) SessionLogin(ctx context.Context, req *padlockpb.SessionLoginRequest) (*padlockpb.SessionLoginResponse, error) {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Logging into session for %s\n", id)
	sess, err := h.getSession(req.GetId().GetUuid(), id.String())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	if req.GetLoginAsSecurityOfficer() {
		err = sess.sess.LoginSecurityOfficer(req.GetPin())
	} else {
		err = sess.sess.Login(req.GetPin())
	}
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "login failed: %v", err)
	}
	// TODO: propagate login/logout state update to all sessions on this slot
	return &padlockpb.SessionLoginResponse{}, nil
}

// SessionLogout logs out of the session at the application level
func (h *handle) SessionLogout(ctx context.Context, req *padlockpb.SessionID) (*padlockpb.SessionLogoutResponse, error) {
	id, err := h.authenticate(req.GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Logging out of session for %s\n", id)
	sess, err := h.getSession(req.GetUuid(), id.String())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	err = sess.sess.Logout()
	if err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "logout failed: %v", err)
	}
	// TODO: propagate login/logout state update to all sessions on this slot
	return &padlockpb.SessionLogoutResponse{}, nil
}

func (h *handle) addObject(sess *serverSession, obj p11.Object) *padlockpb.P11Object {
	var objID string
	set := false
	for key, val := range sess.objs {
		if val.ObjectHandle == obj.ObjectHandle {
			objID = key
			set = true
			break
		}
	}
	if !set {
		objID = uuid.New().String()
		sess.objs[objID] = obj
	}
	label, err := obj.Label()
	if err != nil {
		log.Printf("cannot get label for object %s: %v\n", objID, err)
	}
	return &padlockpb.P11Object{
		Label: label,
		Uuid:  objID,
	}
}

// SessionListObjects lists the objects available in the session
func (h *handle) SessionListObjects(req *padlockpb.SessionListObjectsRequest, stream padlockpb.Padlock_SessionListObjectsServer) error {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return err
	}
	log.Printf("Listing objects for %s\n", id)
	sess, err := h.getSession(req.GetId().GetUuid(), id.String())
	if err != nil {
		return err
	}
	defer sess.mx.Unlock()
	template := AttributesPBtoP11(req.GetTemplate())
	objs, err := sess.sess.FindObjects(template)
	if err != nil {
		return status.Errorf(codes.Aborted, "listing objects: %v", err)
	}
	for _, obj := range objs {
		err = stream.Send(h.addObject(sess, obj))
		if err != nil {
			return status.Errorf(codes.Aborted, "sending object to client: %v", err)
		}
	}
	return nil
}

func (h *handle) SessionCreateObject(ctx context.Context, req *padlockpb.SessionCreateObjectRequest) (*padlockpb.P11Object, error) {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Creating object on %s\n", id)
	sess, err := h.getSession(req.GetId().GetUuid(), id.String())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	p11Obj, err := sess.sess.CreateObject(AttributesPBtoP11(req.GetAttributes()))
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "creating object: %v", err)
	}
	return h.addObject(sess, p11Obj), nil
}

func (h *handle) SessionGenerateRandom(ctx context.Context, req *padlockpb.SessionGenerateRandomRequest) (*padlockpb.SessionGenerateRandomResponse, error) {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Generating random on %s\n", id)
	sess, err := h.getSession(req.GetId().GetUuid(), id.String())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	data, err := sess.sess.GenerateRandom(int(req.GetLength()))
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "generating random data: %v", err)
	}
	return &padlockpb.SessionGenerateRandomResponse{
		Data: data,
	}, nil
}

func (h *handle) SessionGenerateKeyPair(ctx context.Context, req *padlockpb.SessionGenerateKeyPairRequest) (*padlockpb.SessionGenerateKeyPairResponse, error) {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Generating keypair on %s\n", id)
	sess, err := h.getSession(req.GetId().GetUuid(), id.String())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	keyPair, err := sess.sess.GenerateKeyPair(p11.GenerateKeyPairRequest{
		Mechanism:            *MechanismPBtoP11(req.GetMech()),
		PublicKeyAttributes:  AttributesPBtoP11(req.GetPublicAttributes()),
		PrivateKeyAttributes: AttributesPBtoP11(req.GetPrivateAttributes()),
	})
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "generating keypair: %v", err)
	}
	return &padlockpb.SessionGenerateKeyPairResponse{
		Private: h.addObject(sess, p11.Object(keyPair.Private)),
		Public:  h.addObject(sess, p11.Object(keyPair.Public)),
	}, nil
}

func (h *handle) SessionGenerateKey(ctx context.Context, req *padlockpb.SessionGenerateKeyRequest) (*padlockpb.P11Object, error) {
	id, err := h.authenticate(req.GetId().GetAuth())
	if err != nil {
		return nil, err
	}
	log.Printf("Generating key on %s\n", id)
	sess, err := h.getSession(req.GetId().GetUuid(), id.String())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	key, err := sess.sess.GenerateKey(p11.GenerateKeyRequest{
		Mechanism:     *MechanismPBtoP11(req.GetMech()),
		KeyAttributes: AttributesPBtoP11(req.GetAttributes()),
	})
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "generating key: %v", err)
	}
	return h.addObject(sess, p11.Object(*key)), nil
}

func (h *handle) getObject(id *padlockpb.ObjectID) (objID uuid.UUID, sess *serverSession, obj p11.Object, err error) {
	objID, err = h.authenticate(id.GetSessionId().GetAuth())
	if err != nil {
		return
	}
	sess, err = h.getSession(id.GetSessionId().GetUuid(), id.String())
	if err != nil {
		return
	}
	var exists bool
	obj, exists = sess.objs[id.GetObjectId()]
	if !exists {
		sess.mx.Unlock()
		err = status.Error(codes.NotFound, "object deleted or does not exist")
	}
	return
}

// ObjectListAttributeValues lists values for the requested attributes
func (h *handle) ObjectListAttributeValues(req *padlockpb.ObjectListAttributeValuesRequest, stream padlockpb.Padlock_ObjectListAttributeValuesServer) error {
	id, sess, obj, err := h.getObject(req.GetObjectId())
	if err != nil {
		return err
	}
	defer sess.mx.Unlock()
	log.Printf("Listing attribute values for %s\n", id)
	for _, attr := range req.GetRequestedAttributes() {
		val, err := obj.Attribute(AttributePBtoP11(attr))
		if err != nil {
			log.Printf("attribute %s not found: %v\n", attr, err)
			err = stream.Send(&padlockpb.ObjectListAttributeValuesUpdate{
				Update: &padlockpb.ObjectListAttributeValuesUpdate_NotFound{
					NotFound: attr,
				},
			})
		} else {
			err = stream.Send(&padlockpb.ObjectListAttributeValuesUpdate{
				Update: &padlockpb.ObjectListAttributeValuesUpdate_Attribute{
					Attribute: &padlockpb.Attribute{
						Type:  attr,
						Value: val,
					},
				},
			})
		}
		// error from sending back to client
		if err != nil {
			return status.Errorf(codes.Aborted, "sending response to client: %v", err)
		}
	}
	return nil
}

func (h *handle) Encrypt(ctx context.Context, req *padlockpb.ObjectEncryptRequest) (*padlockpb.ObjectEncryptResponse, error) {
	id, sess, obj, err := h.getObject(req.GetObjectId())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	log.Printf("encrypting data on %s\n", id)
	encrypted, err := sess.sess.Encrypt(obj, MechanismsPBtoP11(req.GetMechs()), req.GetPlainText())
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "encrypting data: %v", err)
	}
	return &padlockpb.ObjectEncryptResponse{
		Encrypted: encrypted,
	}, nil
}

func (h *handle) EncryptSegmented(srv padlockpb.Padlock_EncryptSegmentedServer) error {
	firstReq, err := srv.Recv()
	if err != nil {
		return status.Errorf(codes.Aborted, "failed to get first request from client: %v", err)
	}
	first, ok := firstReq.GetStages().(*padlockpb.ObjectEncryptSegmentedRequest_First)
	if !ok || first == nil {
		return status.Errorf(codes.InvalidArgument, "first message must be the First message type, received")
	}
	req := first.First
	id, sess, obj, err := h.getObject(req.GetId())
	if err != nil {
		return err
	}
	ctx := srv.Context()
	defer sess.mx.Unlock()
	log.Printf("encrypting segmented data on %s\n", id)
	parts := make(chan []byte, 1)
	final := make(chan struct{}, 1)
	defer close(parts)
	defer close(final)
	dataChan, errChan := sess.sess.EncryptSegmented(ctx, obj, MechanismsPBtoP11(req.GetMechs()), parts, final)
	for {
		done := false
		msg, err := srv.Recv()
		if err != nil || msg == nil || msg.GetStages() == nil {
			return status.Errorf(codes.Aborted, "failed to get next message from client: %v", err)
		}
		switch stage := msg.GetStages().(type) {
		case *padlockpb.ObjectEncryptSegmentedRequest_First:
			return status.Error(codes.InvalidArgument, "cannot send first stage multiple times")
		case *padlockpb.ObjectEncryptSegmentedRequest_Last:
			final <- struct{}{}
			done = true
		case *padlockpb.ObjectEncryptSegmentedRequest_MessagePart:
			var next []byte
			if stage != nil {
				next = stage.MessagePart
			}
			parts <- next
		}
		select {
		case <-ctx.Done():
			return status.Error(codes.DeadlineExceeded, "context canceled or expired")
		case err := <-errChan:
			return status.Errorf(codes.Aborted, "encrypting segmented data: %v", err)
		case data := <-dataChan:
			err = srv.Send(&padlockpb.ObjectEncryptSegmentedResponse{
				EncryptedPart: data,
			})
			if err != nil {
				return status.Errorf(codes.Aborted, "encrypting segmented data: %v", err)
			}
			if done {
				return nil
			}
		}
	}
}

func (h *handle) Decrypt(ctx context.Context, req *padlockpb.ObjectDecryptRequest) (*padlockpb.ObjectDecryptResponse, error) {
	id, sess, obj, err := h.getObject(req.GetObjectId())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	log.Printf("decrypting data on %s\n", id)
	decrypted, err := sess.sess.Decrypt(obj, MechanismsPBtoP11(req.GetMechs()), req.GetEncrypted())
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "decrypting data: %v", err)
	}
	return &padlockpb.ObjectDecryptResponse{
		PlainText: decrypted,
	}, nil
}

func (h *handle) DecryptSegmented(srv padlockpb.Padlock_DecryptSegmentedServer) error {
	firstReq, err := srv.Recv()
	if err != nil {
		return status.Errorf(codes.Aborted, "failed to get first request from client: %v", err)
	}
	first, ok := firstReq.GetStages().(*padlockpb.ObjectDecryptSegmentedRequest_First)
	if !ok || first == nil {
		return status.Errorf(codes.InvalidArgument, "first message must be the First message type, received")
	}
	req := first.First
	id, sess, obj, err := h.getObject(req.GetId())
	if err != nil {
		return err
	}
	ctx := srv.Context()
	defer sess.mx.Unlock()
	log.Printf("decrypting segmented data on %s\n", id)
	parts := make(chan []byte, 1)
	final := make(chan struct{}, 1)
	defer close(parts)
	defer close(final)
	dataChan, errChan := sess.sess.DecryptSegmented(ctx, obj, MechanismsPBtoP11(req.GetMechs()), parts, final)
	for {
		done := false
		msg, err := srv.Recv()
		if err != nil || msg == nil || msg.GetStages() == nil {
			return status.Errorf(codes.Aborted, "failed to get next message from client: %v", err)
		}
		switch stage := msg.GetStages().(type) {
		case *padlockpb.ObjectDecryptSegmentedRequest_First:
			return status.Error(codes.InvalidArgument, "cannot send first stage multiple times")
		case *padlockpb.ObjectDecryptSegmentedRequest_Last:
			final <- struct{}{}
			done = true
		case *padlockpb.ObjectDecryptSegmentedRequest_MessagePart:
			var next []byte
			if stage != nil {
				next = stage.MessagePart
			}
			parts <- next
		}
		select {
		case <-ctx.Done():
			return status.Error(codes.DeadlineExceeded, "context canceled or expired")
		case err := <-errChan:
			return status.Errorf(codes.Aborted, "decrypting segmented data: %v", err)
		case data := <-dataChan:
			err = srv.Send(&padlockpb.ObjectDecryptSegmentedResponse{
				PlainTextPart: data,
			})
			if err != nil {
				return status.Errorf(codes.Aborted, "decrypting segmented data: %v", err)
			}
			if done {
				return nil
			}
		}
	}
}

func (h *handle) Sign(ctx context.Context, req *padlockpb.ObjectSignRequest) (*padlockpb.ObjectSignResponse, error) {
	id, sess, obj, err := h.getObject(req.GetObjectId())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	log.Printf("signing data on %s\n", id)
	sig, err := sess.sess.Sign(obj, MechanismsPBtoP11(req.GetMechs()), req.GetMessage())
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "signing data: %v", err)
	}
	return &padlockpb.ObjectSignResponse{
		Signature: sig,
	}, nil
}

func (h *handle) SignSegmented(srv padlockpb.Padlock_SignSegmentedServer) error {
	firstReq, err := srv.Recv()
	if err != nil {
		return status.Errorf(codes.Aborted, "failed to get first request from client: %v", err)
	}
	first, ok := firstReq.GetStages().(*padlockpb.ObjectSignSegmentedRequest_First)
	if !ok || first == nil {
		return status.Errorf(codes.InvalidArgument, "first message must be the First message type, received")
	}
	req := first.First
	id, sess, obj, err := h.getObject(req.GetId())
	if err != nil {
		return err
	}
	ctx := srv.Context()
	defer sess.mx.Unlock()
	log.Printf("signing segmented data on %s\n", id)
	parts := make(chan []byte, 1)
	final := make(chan struct{}, 1)
	defer close(parts)
	defer close(final)
	dataChan, errChan := sess.sess.SignSegmented(ctx, obj, MechanismsPBtoP11(req.GetMechs()), parts, final)
	for {
		msg, err := srv.Recv()
		if err != nil || msg == nil || msg.GetStages() == nil {
			return status.Errorf(codes.Aborted, "failed to get next message from client: %v", err)
		}
		switch stage := msg.GetStages().(type) {
		case *padlockpb.ObjectSignSegmentedRequest_First:
			return status.Error(codes.InvalidArgument, "cannot send first stage multiple times")
		case *padlockpb.ObjectSignSegmentedRequest_Last:
			final <- struct{}{}
		case *padlockpb.ObjectSignSegmentedRequest_MessagePart:
			var next []byte
			if stage != nil {
				next = stage.MessagePart
			}
			parts <- next
		}
		select {
		case <-ctx.Done():
			return status.Error(codes.DeadlineExceeded, "context canceled or expired")
		case err := <-errChan:
			return status.Errorf(codes.Aborted, "signing segmented data: %v", err)
		case data := <-dataChan:
			err = srv.SendAndClose(&padlockpb.ObjectSignSegmentedResponse{
				Signature: data,
			})
			if err != nil {
				return status.Errorf(codes.Aborted, "signing segmented data: %v", err)
			}
			return nil
		}
	}
}

func (h *handle) Verify(ctx context.Context, req *padlockpb.ObjectVerifyRequest) (*padlockpb.ObjectVerifyResponse, error) {
	id, sess, obj, err := h.getObject(req.GetObjectId())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	log.Printf("verifying data and signature on %s\n", id)
	err = sess.sess.Verify(obj, MechanismsPBtoP11(req.GetMechs()), req.GetMessage(), req.GetSignature())
	if err != nil {
		return nil, status.Errorf(codes.Aborted, "signing data: %v", err)
	}
	return &padlockpb.ObjectVerifyResponse{
		Valid: true,
	}, nil
}

func (h *handle) VerifySegmented(srv padlockpb.Padlock_VerifySegmentedServer) error {
	firstReq, err := srv.Recv()
	if err != nil {
		return status.Errorf(codes.Aborted, "failed to get first request from client: %v", err)
	}
	first, ok := firstReq.GetStages().(*padlockpb.ObjectVerifySegmentedRequest_First)
	if !ok || first == nil {
		return status.Errorf(codes.InvalidArgument, "first message must be the First message type, received")
	}
	req := first.First
	id, sess, obj, err := h.getObject(req.GetId())
	if err != nil {
		return err
	}
	ctx := srv.Context()
	defer sess.mx.Unlock()
	log.Printf("verifying segmented data and signature on %s\n", id)
	parts := make(chan []byte, 1)
	signature := make(chan []byte, 1)
	defer close(parts)
	defer close(signature)
	errChan := sess.sess.VerifySegmented(ctx, obj, MechanismsPBtoP11(req.GetMechs()), parts, signature)
	for {
		msg, err := srv.Recv()
		if err != nil || msg == nil || msg.GetStages() == nil {
			return status.Errorf(codes.Aborted, "failed to get next message from client: %v", err)
		}
		switch stage := msg.GetStages().(type) {
		case *padlockpb.ObjectVerifySegmentedRequest_First:
			return status.Error(codes.InvalidArgument, "cannot send first stage multiple times")
		case *padlockpb.ObjectVerifySegmentedRequest_Signature:
			var sig []byte
			if stage != nil {
				sig = stage.Signature
			}
			signature <- sig
		case *padlockpb.ObjectVerifySegmentedRequest_MessagePart:
			var next []byte
			if stage != nil {
				next = stage.MessagePart
			}
			parts <- next
		}
		select {
		case <-ctx.Done():
			return status.Error(codes.DeadlineExceeded, "context canceled or expired")
		case err := <-errChan:
			if err != nil {
				return status.Errorf(codes.Aborted, "signing segmented data: %v", err)
			}
			err = srv.SendAndClose(&padlockpb.ObjectVerifySegmentedResponse{
				Valid: true,
			})
			if err != nil {
				return status.Errorf(codes.Aborted, "signing segmented data: %v", err)
			}
			return nil
		}
	}
}

func (h *handle) WrapKey(ctx context.Context, req *padlockpb.ObjectWrapKeyRequest) (*padlockpb.ObjectWrapKeyResponse, error) {
	id, sess, obj, err := h.getObject(req.GetWrappingKey())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	log.Printf("wrapping key on %s\n", id)
	return nil, status.Errorf(codes.Unimplemented, "method WrapKey not implemented")
}

func (h *handle) UnwrapKey(ctx context.Context, req *padlockpb.ObjectUnwrapKeyRequest) (*padlockpb.P11Object, error) {
	id, sess, obj, err := h.getObject(req.GetObjectId())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	log.Printf("unwrapping key on %s\n", id)
	return nil, status.Errorf(codes.Unimplemented, "method UnwrapKey not implemented")
}

func (h *handle) DestroyObject(ctx context.Context, req *padlockpb.ObjectDestroyObjectRequest) (*padlockpb.ObjectDestroyObjectResponse, error) {
	id, sess, obj, err := h.getObject(req.GetObjectId())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	log.Printf("destroying object on %s\n", id)
	return nil, status.Errorf(codes.Unimplemented, "method DestroyObject not implemented")
}

func (h *handle) CopyObject(ctx context.Context, req *padlockpb.ObjectCopyObjectRequest) (*padlockpb.P11Object, error) {
	id, sess, obj, err := h.getObject(req.GetObjectId())
	if err != nil {
		return nil, err
	}
	defer sess.mx.Unlock()
	log.Printf("copying object on %s\n", id)
	return nil, status.Errorf(codes.Unimplemented, "method CopyObject not implemented")
}
