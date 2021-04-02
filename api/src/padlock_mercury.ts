/**
 * Code generated by mercury. DO NOT EDIT.
 * versions:
 * 	mercury v0.9.0
 * 	protoc   v3.10.1
 * source: padlock.proto
 */

import * as mercury from "@llkennedy/mercury";
import { ModuleListSlotsResponse as padlock__ModuleListSlotsResponse, SlotOpenSessionUpdate as padlock__SlotOpenSessionUpdate, ModuleInfoRequest as padlock__ModuleInfoRequest, ModuleListSlotsRequest as padlock__ModuleListSlotsRequest, ModuleInfoResponse as padlock__ModuleInfoResponse, SlotListMechanismsRequest as padlock__SlotListMechanismsRequest, ObjectListAttributeValuesRequest as padlock__ObjectListAttributeValuesRequest, SlotInitTokenRequest as padlock__SlotInitTokenRequest, SessionID as padlock__SessionID, SlotListMechanismsResponse as padlock__SlotListMechanismsResponse, ApplicationListModulesResponse as padlock__ApplicationListModulesResponse, SessionLoginRequest as padlock__SessionLoginRequest, SessionLogoutResponse as padlock__SessionLogoutResponse, SessionLoginResponse as padlock__SessionLoginResponse, SlotInitTokenResponse as padlock__SlotInitTokenResponse, SlotOpenSessionRequest as padlock__SlotOpenSessionRequest, ApplicationListModulesRequest as padlock__ApplicationListModulesRequest, ApplicationConnectUpdate as padlock__ApplicationConnectUpdate, SessionListObjectsRequest as padlock__SessionListObjectsRequest, AuthToken as padlock__AuthToken, ApplicationConnectRequest as padlock__ApplicationConnectRequest, AuthHello as padlock__AuthHello } from "./padlock";
import { P11Object as padlock__P11Object, Attribute as padlock__Attribute } from "./pkcs11";

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
	public async SessionLogin(req: padlock__SessionLoginRequest): Promise<padlock__SessionLoginResponse> {
		return this.SendUnary("SessionLogin", mercury.HTTPMethod.PUT, req, padlock__SessionLoginResponse.Parse);
	}
	public async SessionLogout(req: padlock__SessionID): Promise<padlock__SessionLogoutResponse> {
		return this.SendUnary("SessionLogout", mercury.HTTPMethod.PUT, req, padlock__SessionLogoutResponse.Parse);
	}
	public async SessionListObjects(req: padlock__SessionListObjectsRequest): Promise<mercury.ServerStream<padlock__SessionListObjectsRequest, padlock__P11Object>> {
		return this.StartServerStream<padlock__SessionListObjectsRequest, padlock__P11Object>("SessionListObjects", req, padlock__P11Object.Parse);
	}
	public async ObjectListAttributeValues(req: padlock__ObjectListAttributeValuesRequest): Promise<mercury.ServerStream<padlock__ObjectListAttributeValuesRequest, padlock__Attribute>> {
		return this.StartServerStream<padlock__ObjectListAttributeValuesRequest, padlock__Attribute>("ObjectListAttributeValues", req, padlock__Attribute.Parse);
	}
}
