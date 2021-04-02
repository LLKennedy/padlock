/**
 * Code generated by mercury. DO NOT EDIT.
 * versions:
 * 	mercury v0.9.0
 * 	protoc   v3.10.1
 * source: padlock.proto
 */

import * as mercury from "@llkennedy/mercury";
import { SessionLogoutResponse as padlock__SessionLogoutResponse, SlotOpenSessionRequest as padlock__SlotOpenSessionRequest, SessionLoginRequest as padlock__SessionLoginRequest, ModuleInfoRequest as padlock__ModuleInfoRequest, ModuleInfoResponse as padlock__ModuleInfoResponse, SlotInitTokenResponse as padlock__SlotInitTokenResponse, SessionID as padlock__SessionID, ModuleListSlotsRequest as padlock__ModuleListSlotsRequest, SessionListObjectsRequest as padlock__SessionListObjectsRequest, ModuleListSlotsResponse as padlock__ModuleListSlotsResponse, ApplicationListModulesRequest as padlock__ApplicationListModulesRequest, SlotInitTokenRequest as padlock__SlotInitTokenRequest, AuthHello as padlock__AuthHello, SlotListMechanismsRequest as padlock__SlotListMechanismsRequest, SlotListMechanismsResponse as padlock__SlotListMechanismsResponse, SlotOpenSessionUpdate as padlock__SlotOpenSessionUpdate, AuthToken as padlock__AuthToken, ApplicationConnectUpdate as padlock__ApplicationConnectUpdate, ApplicationListModulesResponse as padlock__ApplicationListModulesResponse, SessionLoginResponse as padlock__SessionLoginResponse, ApplicationConnectRequest as padlock__ApplicationConnectRequest, ObjectListAttributeValuesRequest as padlock__ObjectListAttributeValuesRequest } from "padlock";
import { Object as padlock__Object, Attribute as padlock__Attribute } from "pkcs11";

export class PadlockClient extends mercury.Client {
	constructor(basePath: string | undefined = "localhost/api/Padlock", useTLS: boolean | undefined = true, client: mercury.AxiosInstance | undefined = undefined) {
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
	public async SessionLogin(req: padlock__SessionLoginRequest): Promise<padlock__SessionLoginResponse> {
		return this.SendUnary("SessionLogin", mercury.HTTPMethod.PUT, req, padlock__SessionLoginResponse.Parse);
	}
	public async SessionLogout(req: padlock__SessionID): Promise<padlock__SessionLogoutResponse> {
		return this.SendUnary("SessionLogout", mercury.HTTPMethod.PUT, req, padlock__SessionLogoutResponse.Parse);
	}
	public async SessionListObjects(req: padlock__SessionListObjectsRequest): Promise<mercury.ServerStream<padlock__SessionListObjectsRequest, padlock__Object>> {
		return this.StartServerStream<padlock__SessionListObjectsRequest, padlock__Object>("SessionListObjects", req, padlock__Object.Parse);
	}
	public async ObjectListAttributeValues(req: padlock__ObjectListAttributeValuesRequest): Promise<mercury.ServerStream<padlock__ObjectListAttributeValuesRequest, padlock__Attribute>> {
		return this.StartServerStream<padlock__ObjectListAttributeValuesRequest, padlock__Attribute>("ObjectListAttributeValues", req, padlock__Attribute.Parse);
	}
}
