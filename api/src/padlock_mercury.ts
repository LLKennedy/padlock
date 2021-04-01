/**
 * Code generated by mercury. DO NOT EDIT.
 * versions:
 * 	mercury v0.9.0
 * 	protoc   v3.10.1
 * source: padlock.proto
 */

import * as mercury from "@llkennedy/mercury";
import { ApplicationConnectUpdate as padlock__ApplicationConnectUpdate, AuthToken as padlock__AuthToken, ModuleInfoRequest as padlock__ModuleInfoRequest, ModuleInfoResponse as padlock__ModuleInfoResponse, ModuleListSlotsRequest as padlock__ModuleListSlotsRequest, ApplicationConnectRequest as padlock__ApplicationConnectRequest, ModuleListSlotsResponse as padlock__ModuleListSlotsResponse, ApplicationListModulesRequest as padlock__ApplicationListModulesRequest, AuthHello as padlock__AuthHello, ApplicationListModulesResponse as padlock__ApplicationListModulesResponse } from "padlock";

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
		return this.SendUnary("ModuleListSlots", mercury.HTTPMethod.POST, req, padlock__ModuleListSlotsResponse.Parse);
	}
	public async ModuleInfo(req: padlock__ModuleInfoRequest): Promise<padlock__ModuleInfoResponse> {
		return this.SendUnary("ModuleInfo", mercury.HTTPMethod.GET, req, padlock__ModuleInfoResponse.Parse);
	}
}
