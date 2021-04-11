/**
 * Code generated by mercury. DO NOT EDIT.
 * versions:
 * 	mercury v0.9.0
 * 	protoc   v3.10.1
 * source: padlock.proto
 */

import * as mercury from "@llkennedy/mercury";
import { google } from "@llkennedy/protoc-gen-tsjson";
import { AuthHello as padlock__AuthHello, SessionLogoutResponse as padlock__SessionLogoutResponse, SlotInitTokenResponse as padlock__SlotInitTokenResponse, ApplicationListModulesRequest as padlock__ApplicationListModulesRequest, AuthToken as padlock__AuthToken, SlotOpenSessionUpdate as padlock__SlotOpenSessionUpdate, SessionCloseResponse as padlock__SessionCloseResponse, SessionCloseRequest as padlock__SessionCloseRequest, SessionLoginRequest as padlock__SessionLoginRequest, ObjectListAttributeValuesRequest as padlock__ObjectListAttributeValuesRequest, ApplicationConnectUpdate as padlock__ApplicationConnectUpdate, ModuleListSlotsResponse as padlock__ModuleListSlotsResponse, ModuleListSlotsRequest as padlock__ModuleListSlotsRequest, ModuleInfoResponse as padlock__ModuleInfoResponse, ApplicationListModulesResponse as padlock__ApplicationListModulesResponse, SlotInitTokenRequest as padlock__SlotInitTokenRequest, SessionListObjectsRequest as padlock__SessionListObjectsRequest, SlotListMechanismsRequest as padlock__SlotListMechanismsRequest, SlotListMechanismsResponse as padlock__SlotListMechanismsResponse, SessionID as padlock__SessionID, SlotOpenSessionRequest as padlock__SlotOpenSessionRequest, SessionLoginResponse as padlock__SessionLoginResponse, ApplicationConnectRequest as padlock__ApplicationConnectRequest, ObjectListAttributeValuesUpdate as padlock__ObjectListAttributeValuesUpdate, ModuleInfoRequest as padlock__ModuleInfoRequest } from "./padlock";
import { P11Object as padlock__P11Object } from "./pkcs11";

export class ExposedPadlockClient extends mercury.Client {
	constructor(basePath: string | undefined = "localhost/api/ExposedPadlock", useTLS: boolean | undefined = true, client: mercury.AxiosInstance | undefined = undefined) {
		super(basePath, useTLS, client);
	}
	public async Hello(req: padlock__AuthHello): Promise<padlock__AuthToken> {
		return this.SendUnary("Hello", mercury.HTTPMethod.POST, req, padlock__AuthToken.Parse);
	}
	public async ApplicationListModules(req: padlock__ApplicationListModulesRequest): Promise<padlock__ApplicationListModulesResponse> {
		return this.SendUnary("ApplicationListModules", mercury.HTTPMethod.GET, req, padlock__ApplicationListModulesResponse.Parse);
	}
	public async ApplicationConnect(req: padlock__ApplicationConnectRequest): Promise<mercury.ServerStream<padlock__ApplicationConnectRequest, padlock__ApplicationConnectUpdate>> {
		return this.StartServerStream<padlock__ApplicationConnectRequest, padlock__ApplicationConnectUpdate>("ApplicationConnect", req, padlock__ApplicationConnectUpdate.Parse);
	}
	public async ModuleListSlots(req: padlock__ModuleListSlotsRequest): Promise<padlock__ModuleListSlotsResponse> {
		return this.SendUnary("ModuleListSlots", mercury.HTTPMethod.GET, req, padlock__ModuleListSlotsResponse.Parse);
	}
	public async ModuleInfo(req: padlock__ModuleInfoRequest): Promise<padlock__ModuleInfoResponse> {
		return this.SendUnary("ModuleInfo", mercury.HTTPMethod.GET, req, padlock__ModuleInfoResponse.Parse);
	}
	public async SlotListMechanisms(req: padlock__SlotListMechanismsRequest): Promise<padlock__SlotListMechanismsResponse> {
		return this.SendUnary("SlotListMechanisms", mercury.HTTPMethod.GET, req, padlock__SlotListMechanismsResponse.Parse);
	}
	public async SlotInitToken(req: padlock__SlotInitTokenRequest): Promise<padlock__SlotInitTokenResponse> {
		return this.SendUnary("SlotInitToken", mercury.HTTPMethod.POST, req, padlock__SlotInitTokenResponse.Parse);
	}
	public async SlotOpenSession(req: padlock__SlotOpenSessionRequest): Promise<mercury.ServerStream<padlock__SlotOpenSessionRequest, padlock__SlotOpenSessionUpdate>> {
		return this.StartServerStream<padlock__SlotOpenSessionRequest, padlock__SlotOpenSessionUpdate>("SlotOpenSession", req, padlock__SlotOpenSessionUpdate.Parse);
	}
	public async SessionKeepAlive(req: padlock__SessionID): Promise<google.protobuf.Empty> {
		return this.SendUnary("SessionKeepAlive", mercury.HTTPMethod.POST, req, google.protobuf.Empty.Parse);
	}
	public async SessionClose(req: padlock__SessionCloseRequest): Promise<padlock__SessionCloseResponse> {
		return this.SendUnary("SessionClose", mercury.HTTPMethod.DELETE, req, padlock__SessionCloseResponse.Parse);
	}
	public async SessionLogin(req: padlock__SessionLoginRequest): Promise<padlock__SessionLoginResponse> {
		return this.SendUnary("SessionLogin", mercury.HTTPMethod.PUT, req, padlock__SessionLoginResponse.Parse);
	}
	public async SessionLogout(req: padlock__SessionID): Promise<padlock__SessionLogoutResponse> {
		return this.SendUnary("SessionLogout", mercury.HTTPMethod.PUT, req, padlock__SessionLogoutResponse.Parse);
	}
	public async SessionListObjects(req: padlock__SessionListObjectsRequest): Promise<mercury.ServerStream<padlock__SessionListObjectsRequest, padlock__P11Object>> {
		return this.StartServerStream<padlock__SessionListObjectsRequest, padlock__P11Object>("SessionListObjects", req, padlock__P11Object.Parse);
	}
	public async ObjectListAttributeValues(req: padlock__ObjectListAttributeValuesRequest): Promise<mercury.ServerStream<padlock__ObjectListAttributeValuesRequest, padlock__ObjectListAttributeValuesUpdate>> {
		return this.StartServerStream<padlock__ObjectListAttributeValuesRequest, padlock__ObjectListAttributeValuesUpdate>("ObjectListAttributeValues", req, padlock__ObjectListAttributeValuesUpdate.Parse);
	}
}
