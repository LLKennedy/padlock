/**
 * Code generated by protoc-gen-tsjson. DO NOT EDIT.
 * versions:
 * 	protoc-gen-tsjson v0.5.3
 * 	protoc            v3.10.1
 * source: padlock.proto
 */

import * as tsjson from "@llkennedy/protoc-gen-tsjson";
import { google } from "@llkennedy/protoc-gen-tsjson";
import { 
	ModuleInfo as padlock__ModuleInfo,
	SlotInfo as padlock__SlotInfo,
	Attribute as padlock__Attribute,
	Mechanism as padlock__Mechanism,
	SupportedMechanism as padlock__SupportedMechanism,
	P11Object as padlock__P11Object
} from "./pkcs11";
import { 
	AttributeType as padlock__AttributeType
} from "./attributes";

/** A message */
export class AuthHello extends Object implements tsjson.ProtoJSONCompatible {
	public ToProtoJSON(): Object {
		return {
		};
	}
	public static async Parse(data: any): Promise<AuthHello> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new AuthHello();
		return res;
	}
}

/** A message */
export class AuthToken extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public data?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			data: tsjson.ToProtoJSON.Bytes(this.data),
		};
	}
	public static async Parse(data: any): Promise<AuthToken> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new AuthToken();
		res.data = await tsjson.Parse.Bytes(objData, "data", "data");
		return res;
	}
}

/** A message */
export class ApplicationListModulesRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public auth?: AuthToken;
	public ToProtoJSON(): Object {
		return {
			auth: this.auth?.ToProtoJSON(),
		};
	}
	public static async Parse(data: any): Promise<ApplicationListModulesRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ApplicationListModulesRequest();
		res.auth = await tsjson.Parse.Message(objData, "auth", "auth", AuthToken.Parse);
		return res;
	}
}

/** A message */
export class ApplicationListModulesResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public modules?: ReadonlyMap<string, padlock__ModuleInfo | null>;
	public ToProtoJSON(): Object {
		return {
			modules: tsjson.ToProtoJSON.Map(val => val?.ToProtoJSON(), this.modules),
		};
	}
	public static async Parse(data: any): Promise<ApplicationListModulesResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ApplicationListModulesResponse();
		res.modules = await tsjson.Parse.Map(objData, "modules", "modules", async val => val, async val => tsjson.Parse.Message({"value":val}, "value", "value", padlock__ModuleInfo.Parse));
		return res;
	}
}

/** A message */
export class ApplicationConnectRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public auth?: AuthToken;
	/** A field */
	public module?: string;
	public ToProtoJSON(): Object {
		return {
			auth: this.auth?.ToProtoJSON(),
			module: tsjson.ToProtoJSON.String(this.module),
		};
	}
	public static async Parse(data: any): Promise<ApplicationConnectRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ApplicationConnectRequest();
		res.auth = await tsjson.Parse.Message(objData, "auth", "auth", AuthToken.Parse);
		res.module = await tsjson.Parse.String(objData, "module", "module");
		return res;
	}
}

/** A message */
export class ApplicationConnectUpdate extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public info?: padlock__ModuleInfo;
	/** A field */
	public changedSlots?: ModuleListSlotsResponse;
	public ToProtoJSON(): Object {
		return {
			info: this.info?.ToProtoJSON(),
			changedSlots: this.changedSlots?.ToProtoJSON(),
		};
	}
	public static async Parse(data: any): Promise<ApplicationConnectUpdate> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ApplicationConnectUpdate();
		res.info = await tsjson.Parse.Message(objData, "info", "info", padlock__ModuleInfo.Parse);
		res.changedSlots = await tsjson.Parse.Message(objData, "changedSlots", "changed_slots", ModuleListSlotsResponse.Parse);
		return res;
	}
}

/** A message */
export class ModuleInfoRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public auth?: AuthToken;
	/** A field */
	public module?: string;
	public ToProtoJSON(): Object {
		return {
			auth: this.auth?.ToProtoJSON(),
			module: tsjson.ToProtoJSON.String(this.module),
		};
	}
	public static async Parse(data: any): Promise<ModuleInfoRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ModuleInfoRequest();
		res.auth = await tsjson.Parse.Message(objData, "auth", "auth", AuthToken.Parse);
		res.module = await tsjson.Parse.String(objData, "module", "module");
		return res;
	}
}

/** A message */
export class ModuleInfoResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public info?: padlock__ModuleInfo;
	public ToProtoJSON(): Object {
		return {
			info: this.info?.ToProtoJSON(),
		};
	}
	public static async Parse(data: any): Promise<ModuleInfoResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ModuleInfoResponse();
		res.info = await tsjson.Parse.Message(objData, "info", "info", padlock__ModuleInfo.Parse);
		return res;
	}
}

/** A message */
export class ModuleListSlotsRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public auth?: AuthToken;
	/** A field */
	public module?: string;
	public ToProtoJSON(): Object {
		return {
			auth: this.auth?.ToProtoJSON(),
			module: tsjson.ToProtoJSON.String(this.module),
		};
	}
	public static async Parse(data: any): Promise<ModuleListSlotsRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ModuleListSlotsRequest();
		res.auth = await tsjson.Parse.Message(objData, "auth", "auth", AuthToken.Parse);
		res.module = await tsjson.Parse.String(objData, "module", "module");
		return res;
	}
}

/** A message */
export class ModuleListSlotsResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public slots?: padlock__SlotInfo[];
	public ToProtoJSON(): Object {
		return {
			slots: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.slots),
		};
	}
	public static async Parse(data: any): Promise<ModuleListSlotsResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ModuleListSlotsResponse();
		res.slots = await tsjson.Parse.Repeated(objData, "slots", "slots", padlock__SlotInfo.Parse);
		return res;
	}
}

/** A message */
export class SlotID extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public auth?: AuthToken;
	/** A field */
	public module?: string;
	/** A field */
	public slot?: number;
	public ToProtoJSON(): Object {
		return {
			auth: this.auth?.ToProtoJSON(),
			module: tsjson.ToProtoJSON.String(this.module),
			slot: tsjson.ToProtoJSON.StringNumber(this.slot),
		};
	}
	public static async Parse(data: any): Promise<SlotID> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SlotID();
		res.auth = await tsjson.Parse.Message(objData, "auth", "auth", AuthToken.Parse);
		res.module = await tsjson.Parse.String(objData, "module", "module");
		res.slot = await tsjson.Parse.Number(objData, "slot", "slot");
		return res;
	}
}

/** A message */
export class SlotListMechanismsRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public id?: SlotID;
	public ToProtoJSON(): Object {
		return {
			id: this.id?.ToProtoJSON(),
		};
	}
	public static async Parse(data: any): Promise<SlotListMechanismsRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SlotListMechanismsRequest();
		res.id = await tsjson.Parse.Message(objData, "id", "id", SlotID.Parse);
		return res;
	}
}

/** A message */
export class SlotListMechanismsResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public mechanisms?: padlock__SupportedMechanism[];
	public ToProtoJSON(): Object {
		return {
			mechanisms: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.mechanisms),
		};
	}
	public static async Parse(data: any): Promise<SlotListMechanismsResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SlotListMechanismsResponse();
		res.mechanisms = await tsjson.Parse.Repeated(objData, "mechanisms", "mechanisms", padlock__SupportedMechanism.Parse);
		return res;
	}
}

/** A message */
export class SlotInitTokenRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public id?: SlotID;
	/** A field */
	public securityOfficerPin?: string;
	/** A field */
	public tokenLabel?: string;
	public ToProtoJSON(): Object {
		return {
			id: this.id?.ToProtoJSON(),
			securityOfficerPin: tsjson.ToProtoJSON.String(this.securityOfficerPin),
			tokenLabel: tsjson.ToProtoJSON.String(this.tokenLabel),
		};
	}
	public static async Parse(data: any): Promise<SlotInitTokenRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SlotInitTokenRequest();
		res.id = await tsjson.Parse.Message(objData, "id", "id", SlotID.Parse);
		res.securityOfficerPin = await tsjson.Parse.String(objData, "securityOfficerPin", "security_officer_pin");
		res.tokenLabel = await tsjson.Parse.String(objData, "tokenLabel", "token_label");
		return res;
	}
}

/** A message */
export class SlotInitTokenResponse extends Object implements tsjson.ProtoJSONCompatible {
	public ToProtoJSON(): Object {
		return {
		};
	}
	public static async Parse(data: any): Promise<SlotInitTokenResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SlotInitTokenResponse();
		return res;
	}
}

/** A message */
export class SlotOpenSessionRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public id?: SlotID;
	/** A field */
	public writeSession?: boolean;
	public ToProtoJSON(): Object {
		return {
			id: this.id?.ToProtoJSON(),
			writeSession: tsjson.ToProtoJSON.Bool(this.writeSession),
		};
	}
	public static async Parse(data: any): Promise<SlotOpenSessionRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SlotOpenSessionRequest();
		res.id = await tsjson.Parse.Message(objData, "id", "id", SlotID.Parse);
		res.writeSession = await tsjson.Parse.Bool(objData, "writeSession", "write_session");
		return res;
	}
}

/** A message */
export class SlotOpenSessionUpdate extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public uuid?: string;
	/** A field */
	public loggedIn?: boolean;
	public ToProtoJSON(): Object {
		return {
			uuid: tsjson.ToProtoJSON.String(this.uuid),
			loggedIn: tsjson.ToProtoJSON.Bool(this.loggedIn),
		};
	}
	public static async Parse(data: any): Promise<SlotOpenSessionUpdate> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SlotOpenSessionUpdate();
		res.uuid = await tsjson.Parse.String(objData, "uuid", "uuid");
		res.loggedIn = await tsjson.Parse.Bool(objData, "loggedIn", "logged_in");
		return res;
	}
}

/** A message */
export class SessionID extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public auth?: AuthToken;
	/** A field */
	public uuid?: string;
	public ToProtoJSON(): Object {
		return {
			auth: this.auth?.ToProtoJSON(),
			uuid: tsjson.ToProtoJSON.String(this.uuid),
		};
	}
	public static async Parse(data: any): Promise<SessionID> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SessionID();
		res.auth = await tsjson.Parse.Message(objData, "auth", "auth", AuthToken.Parse);
		res.uuid = await tsjson.Parse.String(objData, "uuid", "uuid");
		return res;
	}
}

/** A message */
export class SessionCloseRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public id?: SessionID;
	public ToProtoJSON(): Object {
		return {
			id: this.id?.ToProtoJSON(),
		};
	}
	public static async Parse(data: any): Promise<SessionCloseRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SessionCloseRequest();
		res.id = await tsjson.Parse.Message(objData, "id", "id", SessionID.Parse);
		return res;
	}
}

/** A message */
export class SessionCloseResponse extends Object implements tsjson.ProtoJSONCompatible {
	public ToProtoJSON(): Object {
		return {
		};
	}
	public static async Parse(data: any): Promise<SessionCloseResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SessionCloseResponse();
		return res;
	}
}

/** A message */
export class SessionLoginRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public id?: SessionID;
	/** A field */
	public pin?: string;
	/** A field */
	public loginAsSecurityOfficer?: boolean;
	public ToProtoJSON(): Object {
		return {
			id: this.id?.ToProtoJSON(),
			pin: tsjson.ToProtoJSON.String(this.pin),
			loginAsSecurityOfficer: tsjson.ToProtoJSON.Bool(this.loginAsSecurityOfficer),
		};
	}
	public static async Parse(data: any): Promise<SessionLoginRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SessionLoginRequest();
		res.id = await tsjson.Parse.Message(objData, "id", "id", SessionID.Parse);
		res.pin = await tsjson.Parse.String(objData, "pin", "pin");
		res.loginAsSecurityOfficer = await tsjson.Parse.Bool(objData, "loginAsSecurityOfficer", "login_as_security_officer");
		return res;
	}
}

/** A message */
export class SessionLoginResponse extends Object implements tsjson.ProtoJSONCompatible {
	public ToProtoJSON(): Object {
		return {
		};
	}
	public static async Parse(data: any): Promise<SessionLoginResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SessionLoginResponse();
		return res;
	}
}

/** A message */
export class SessionLogoutResponse extends Object implements tsjson.ProtoJSONCompatible {
	public ToProtoJSON(): Object {
		return {
		};
	}
	public static async Parse(data: any): Promise<SessionLogoutResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SessionLogoutResponse();
		return res;
	}
}

/** A message */
export class SessionListObjectsRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public id?: SessionID;
	/** A field */
	public template?: padlock__Attribute[];
	public ToProtoJSON(): Object {
		return {
			id: this.id?.ToProtoJSON(),
			template: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.template),
		};
	}
	public static async Parse(data: any): Promise<SessionListObjectsRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SessionListObjectsRequest();
		res.id = await tsjson.Parse.Message(objData, "id", "id", SessionID.Parse);
		res.template = await tsjson.Parse.Repeated(objData, "template", "template", padlock__Attribute.Parse);
		return res;
	}
}

/** A message */
export class SessionCreateObjectRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public id?: SessionID;
	/** A field */
	public attributes?: padlock__Attribute[];
	public ToProtoJSON(): Object {
		return {
			id: this.id?.ToProtoJSON(),
			attributes: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.attributes),
		};
	}
	public static async Parse(data: any): Promise<SessionCreateObjectRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SessionCreateObjectRequest();
		res.id = await tsjson.Parse.Message(objData, "id", "id", SessionID.Parse);
		res.attributes = await tsjson.Parse.Repeated(objData, "attributes", "attributes", padlock__Attribute.Parse);
		return res;
	}
}

/** A message */
export class SessionGenerateRandomRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public id?: SessionID;
	/** A field */
	public length?: number;
	public ToProtoJSON(): Object {
		return {
			id: this.id?.ToProtoJSON(),
			length: tsjson.ToProtoJSON.Number(this.length),
		};
	}
	public static async Parse(data: any): Promise<SessionGenerateRandomRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SessionGenerateRandomRequest();
		res.id = await tsjson.Parse.Message(objData, "id", "id", SessionID.Parse);
		res.length = await tsjson.Parse.Number(objData, "length", "length");
		return res;
	}
}

/** A message */
export class SessionGenerateRandomResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public data?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			data: tsjson.ToProtoJSON.Bytes(this.data),
		};
	}
	public static async Parse(data: any): Promise<SessionGenerateRandomResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SessionGenerateRandomResponse();
		res.data = await tsjson.Parse.Bytes(objData, "data", "data");
		return res;
	}
}

/** A message */
export class SessionGenerateKeyPairRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public id?: SessionID;
	/** A field */
	public mech?: padlock__Mechanism;
	/** A field */
	public privateAttributes?: padlock__Attribute[];
	/** A field */
	public publicAttributes?: padlock__Attribute[];
	public ToProtoJSON(): Object {
		return {
			id: this.id?.ToProtoJSON(),
			mech: this.mech?.ToProtoJSON(),
			privateAttributes: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.privateAttributes),
			publicAttributes: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.publicAttributes),
		};
	}
	public static async Parse(data: any): Promise<SessionGenerateKeyPairRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SessionGenerateKeyPairRequest();
		res.id = await tsjson.Parse.Message(objData, "id", "id", SessionID.Parse);
		res.mech = await tsjson.Parse.Message(objData, "mech", "mech", padlock__Mechanism.Parse);
		res.privateAttributes = await tsjson.Parse.Repeated(objData, "privateAttributes", "private_attributes", padlock__Attribute.Parse);
		res.publicAttributes = await tsjson.Parse.Repeated(objData, "publicAttributes", "public_attributes", padlock__Attribute.Parse);
		return res;
	}
}

/** A message */
export class SessionGenerateKeyPairResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public private?: padlock__P11Object;
	/** A field */
	public public?: padlock__P11Object;
	public ToProtoJSON(): Object {
		return {
			private: this.private?.ToProtoJSON(),
			public: this.public?.ToProtoJSON(),
		};
	}
	public static async Parse(data: any): Promise<SessionGenerateKeyPairResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SessionGenerateKeyPairResponse();
		res.private = await tsjson.Parse.Message(objData, "private", "private", padlock__P11Object.Parse);
		res.public = await tsjson.Parse.Message(objData, "public", "public", padlock__P11Object.Parse);
		return res;
	}
}

/** A message */
export class SessionGenerateKeyRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public id?: SessionID;
	/** A field */
	public mech?: padlock__Mechanism;
	/** A field */
	public attributes?: padlock__Attribute[];
	public ToProtoJSON(): Object {
		return {
			id: this.id?.ToProtoJSON(),
			mech: this.mech?.ToProtoJSON(),
			attributes: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.attributes),
		};
	}
	public static async Parse(data: any): Promise<SessionGenerateKeyRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new SessionGenerateKeyRequest();
		res.id = await tsjson.Parse.Message(objData, "id", "id", SessionID.Parse);
		res.mech = await tsjson.Parse.Message(objData, "mech", "mech", padlock__Mechanism.Parse);
		res.attributes = await tsjson.Parse.Repeated(objData, "attributes", "attributes", padlock__Attribute.Parse);
		return res;
	}
}

/** A message */
export class ObjectID extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public sessionId?: SessionID;
	/** A field */
	public objectId?: string;
	public ToProtoJSON(): Object {
		return {
			sessionId: this.sessionId?.ToProtoJSON(),
			objectId: tsjson.ToProtoJSON.String(this.objectId),
		};
	}
	public static async Parse(data: any): Promise<ObjectID> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectID();
		res.sessionId = await tsjson.Parse.Message(objData, "sessionId", "session_id", SessionID.Parse);
		res.objectId = await tsjson.Parse.String(objData, "objectId", "object_id");
		return res;
	}
}

/** A message */
export class ObjectListAttributeValuesRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public objectId?: ObjectID;
	/** A field */
	public requestedAttributes?: padlock__AttributeType[];
	public ToProtoJSON(): Object {
		return {
			objectId: this.objectId?.ToProtoJSON(),
			requestedAttributes: tsjson.ToProtoJSON.Repeated(val => tsjson.ToProtoJSON.Enum(padlock__AttributeType, val), this.requestedAttributes),
		};
	}
	public static async Parse(data: any): Promise<ObjectListAttributeValuesRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectListAttributeValuesRequest();
		res.objectId = await tsjson.Parse.Message(objData, "objectId", "object_id", ObjectID.Parse);
		res.requestedAttributes = await tsjson.Parse.Repeated(objData, "requestedAttributes", "requested_attributes", tsjson.PrimitiveParse.Enum(padlock__AttributeType));
		return res;
	}
}

/** A message */
export class ObjectListAttributeValuesUpdate extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public attribute?: padlock__Attribute;
	/** A field */
	public notFound?: padlock__AttributeType;
	public ToProtoJSON(): Object {
		return {
			attribute: this.attribute?.ToProtoJSON(),
			notFound: tsjson.ToProtoJSON.Enum(padlock__AttributeType, this.notFound),
		};
	}
	public static async Parse(data: any): Promise<ObjectListAttributeValuesUpdate> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectListAttributeValuesUpdate();
		res.attribute = await tsjson.Parse.Message(objData, "attribute", "attribute", padlock__Attribute.Parse);
		res.notFound = await tsjson.Parse.Enum(objData, "notFound", "not_found", padlock__AttributeType);
		return res;
	}
}

/** A message */
export class ObjectEncryptRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public objectId?: ObjectID;
	/** A field */
	public mechs?: padlock__Mechanism[];
	/** A field */
	public plainText?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			objectId: this.objectId?.ToProtoJSON(),
			mechs: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.mechs),
			plainText: tsjson.ToProtoJSON.Bytes(this.plainText),
		};
	}
	public static async Parse(data: any): Promise<ObjectEncryptRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectEncryptRequest();
		res.objectId = await tsjson.Parse.Message(objData, "objectId", "object_id", ObjectID.Parse);
		res.mechs = await tsjson.Parse.Repeated(objData, "mechs", "mechs", padlock__Mechanism.Parse);
		res.plainText = await tsjson.Parse.Bytes(objData, "plainText", "plain_text");
		return res;
	}
}

/** A message */
export class ObjectEncryptResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public encrypted?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			encrypted: tsjson.ToProtoJSON.Bytes(this.encrypted),
		};
	}
	public static async Parse(data: any): Promise<ObjectEncryptResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectEncryptResponse();
		res.encrypted = await tsjson.Parse.Bytes(objData, "encrypted", "encrypted");
		return res;
	}
}

/** A message */
export class ObjectEncryptSegmentedRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public first?: ObjectCryptoSegmentedInit;
	/** A field */
	public messagePart?: Uint8Array;
	/** A field */
	public last?: google.protobuf.Empty;
	public ToProtoJSON(): Object {
		return {
			first: this.first?.ToProtoJSON(),
			messagePart: tsjson.ToProtoJSON.Bytes(this.messagePart),
			last: this.last?.ToProtoJSON(),
		};
	}
	public static async Parse(data: any): Promise<ObjectEncryptSegmentedRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectEncryptSegmentedRequest();
		res.first = await tsjson.Parse.Message(objData, "first", "first", ObjectCryptoSegmentedInit.Parse);
		res.messagePart = await tsjson.Parse.Bytes(objData, "messagePart", "message_part");
		res.last = await tsjson.Parse.Message(objData, "last", "last", google.protobuf.Empty.Parse);
		return res;
	}
}

/** A message */
export class ObjectCryptoSegmentedInit extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public id?: ObjectID;
	/** A field */
	public mechs?: padlock__Mechanism[];
	public ToProtoJSON(): Object {
		return {
			id: this.id?.ToProtoJSON(),
			mechs: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.mechs),
		};
	}
	public static async Parse(data: any): Promise<ObjectCryptoSegmentedInit> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectCryptoSegmentedInit();
		res.id = await tsjson.Parse.Message(objData, "id", "id", ObjectID.Parse);
		res.mechs = await tsjson.Parse.Repeated(objData, "mechs", "mechs", padlock__Mechanism.Parse);
		return res;
	}
}

/** A message */
export class ObjectEncryptSegmentedResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public encryptedPart?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			encryptedPart: tsjson.ToProtoJSON.Bytes(this.encryptedPart),
		};
	}
	public static async Parse(data: any): Promise<ObjectEncryptSegmentedResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectEncryptSegmentedResponse();
		res.encryptedPart = await tsjson.Parse.Bytes(objData, "encryptedPart", "encrypted_part");
		return res;
	}
}

/** A message */
export class ObjectDecryptRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public objectId?: ObjectID;
	/** A field */
	public mechs?: padlock__Mechanism[];
	/** A field */
	public encrypted?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			objectId: this.objectId?.ToProtoJSON(),
			mechs: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.mechs),
			encrypted: tsjson.ToProtoJSON.Bytes(this.encrypted),
		};
	}
	public static async Parse(data: any): Promise<ObjectDecryptRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectDecryptRequest();
		res.objectId = await tsjson.Parse.Message(objData, "objectId", "object_id", ObjectID.Parse);
		res.mechs = await tsjson.Parse.Repeated(objData, "mechs", "mechs", padlock__Mechanism.Parse);
		res.encrypted = await tsjson.Parse.Bytes(objData, "encrypted", "encrypted");
		return res;
	}
}

/** A message */
export class ObjectDecryptResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public plainText?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			plainText: tsjson.ToProtoJSON.Bytes(this.plainText),
		};
	}
	public static async Parse(data: any): Promise<ObjectDecryptResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectDecryptResponse();
		res.plainText = await tsjson.Parse.Bytes(objData, "plainText", "plain_text");
		return res;
	}
}

/** A message */
export class ObjectDecryptSegmentedRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public first?: ObjectCryptoSegmentedInit;
	/** A field */
	public messagePart?: Uint8Array;
	/** A field */
	public last?: google.protobuf.Empty;
	public ToProtoJSON(): Object {
		return {
			first: this.first?.ToProtoJSON(),
			messagePart: tsjson.ToProtoJSON.Bytes(this.messagePart),
			last: this.last?.ToProtoJSON(),
		};
	}
	public static async Parse(data: any): Promise<ObjectDecryptSegmentedRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectDecryptSegmentedRequest();
		res.first = await tsjson.Parse.Message(objData, "first", "first", ObjectCryptoSegmentedInit.Parse);
		res.messagePart = await tsjson.Parse.Bytes(objData, "messagePart", "message_part");
		res.last = await tsjson.Parse.Message(objData, "last", "last", google.protobuf.Empty.Parse);
		return res;
	}
}

/** A message */
export class ObjectDecryptSegmentedResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public plainTextPart?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			plainTextPart: tsjson.ToProtoJSON.Bytes(this.plainTextPart),
		};
	}
	public static async Parse(data: any): Promise<ObjectDecryptSegmentedResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectDecryptSegmentedResponse();
		res.plainTextPart = await tsjson.Parse.Bytes(objData, "plainTextPart", "plain_text_part");
		return res;
	}
}

/** A message */
export class ObjectSignRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public objectId?: ObjectID;
	/** A field */
	public mechs?: padlock__Mechanism[];
	/** A field */
	public message?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			objectId: this.objectId?.ToProtoJSON(),
			mechs: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.mechs),
			message: tsjson.ToProtoJSON.Bytes(this.message),
		};
	}
	public static async Parse(data: any): Promise<ObjectSignRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectSignRequest();
		res.objectId = await tsjson.Parse.Message(objData, "objectId", "object_id", ObjectID.Parse);
		res.mechs = await tsjson.Parse.Repeated(objData, "mechs", "mechs", padlock__Mechanism.Parse);
		res.message = await tsjson.Parse.Bytes(objData, "message", "message");
		return res;
	}
}

/** A message */
export class ObjectSignResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public signature?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			signature: tsjson.ToProtoJSON.Bytes(this.signature),
		};
	}
	public static async Parse(data: any): Promise<ObjectSignResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectSignResponse();
		res.signature = await tsjson.Parse.Bytes(objData, "signature", "signature");
		return res;
	}
}

/** A message */
export class ObjectSignSegmentedRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public first?: ObjectCryptoSegmentedInit;
	/** A field */
	public messagePart?: Uint8Array;
	/** A field */
	public last?: google.protobuf.Empty;
	public ToProtoJSON(): Object {
		return {
			first: this.first?.ToProtoJSON(),
			messagePart: tsjson.ToProtoJSON.Bytes(this.messagePart),
			last: this.last?.ToProtoJSON(),
		};
	}
	public static async Parse(data: any): Promise<ObjectSignSegmentedRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectSignSegmentedRequest();
		res.first = await tsjson.Parse.Message(objData, "first", "first", ObjectCryptoSegmentedInit.Parse);
		res.messagePart = await tsjson.Parse.Bytes(objData, "messagePart", "message_part");
		res.last = await tsjson.Parse.Message(objData, "last", "last", google.protobuf.Empty.Parse);
		return res;
	}
}

/** A message */
export class ObjectSignSegmentedResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public signature?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			signature: tsjson.ToProtoJSON.Bytes(this.signature),
		};
	}
	public static async Parse(data: any): Promise<ObjectSignSegmentedResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectSignSegmentedResponse();
		res.signature = await tsjson.Parse.Bytes(objData, "signature", "signature");
		return res;
	}
}

/** A message */
export class ObjectVerifyRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public objectId?: ObjectID;
	/** A field */
	public mechs?: padlock__Mechanism[];
	/** A field */
	public message?: Uint8Array;
	/** A field */
	public signature?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			objectId: this.objectId?.ToProtoJSON(),
			mechs: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.mechs),
			message: tsjson.ToProtoJSON.Bytes(this.message),
			signature: tsjson.ToProtoJSON.Bytes(this.signature),
		};
	}
	public static async Parse(data: any): Promise<ObjectVerifyRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectVerifyRequest();
		res.objectId = await tsjson.Parse.Message(objData, "objectId", "object_id", ObjectID.Parse);
		res.mechs = await tsjson.Parse.Repeated(objData, "mechs", "mechs", padlock__Mechanism.Parse);
		res.message = await tsjson.Parse.Bytes(objData, "message", "message");
		res.signature = await tsjson.Parse.Bytes(objData, "signature", "signature");
		return res;
	}
}

/** A message */
export class ObjectVerifyResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public valid?: boolean;
	public ToProtoJSON(): Object {
		return {
			valid: tsjson.ToProtoJSON.Bool(this.valid),
		};
	}
	public static async Parse(data: any): Promise<ObjectVerifyResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectVerifyResponse();
		res.valid = await tsjson.Parse.Bool(objData, "valid", "valid");
		return res;
	}
}

/** A message */
export class ObjectVerifySegmentedRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public first?: ObjectCryptoSegmentedInit;
	/** A field */
	public messagePart?: Uint8Array;
	/** A field */
	public signature?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			first: this.first?.ToProtoJSON(),
			messagePart: tsjson.ToProtoJSON.Bytes(this.messagePart),
			signature: tsjson.ToProtoJSON.Bytes(this.signature),
		};
	}
	public static async Parse(data: any): Promise<ObjectVerifySegmentedRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectVerifySegmentedRequest();
		res.first = await tsjson.Parse.Message(objData, "first", "first", ObjectCryptoSegmentedInit.Parse);
		res.messagePart = await tsjson.Parse.Bytes(objData, "messagePart", "message_part");
		res.signature = await tsjson.Parse.Bytes(objData, "signature", "signature");
		return res;
	}
}

/** A message */
export class ObjectVerifySegmentedResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public valid?: boolean;
	public ToProtoJSON(): Object {
		return {
			valid: tsjson.ToProtoJSON.Bool(this.valid),
		};
	}
	public static async Parse(data: any): Promise<ObjectVerifySegmentedResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectVerifySegmentedResponse();
		res.valid = await tsjson.Parse.Bool(objData, "valid", "valid");
		return res;
	}
}

/** A message */
export class ObjectWrapKeyRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public wrappingKey?: ObjectID;
	/** A field */
	public mechs?: padlock__Mechanism[];
	/** A field */
	public keyToWrap?: ObjectID;
	public ToProtoJSON(): Object {
		return {
			wrappingKey: this.wrappingKey?.ToProtoJSON(),
			mechs: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.mechs),
			keyToWrap: this.keyToWrap?.ToProtoJSON(),
		};
	}
	public static async Parse(data: any): Promise<ObjectWrapKeyRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectWrapKeyRequest();
		res.wrappingKey = await tsjson.Parse.Message(objData, "wrappingKey", "wrapping_key", ObjectID.Parse);
		res.mechs = await tsjson.Parse.Repeated(objData, "mechs", "mechs", padlock__Mechanism.Parse);
		res.keyToWrap = await tsjson.Parse.Message(objData, "keyToWrap", "key_to_wrap", ObjectID.Parse);
		return res;
	}
}

/** A message */
export class ObjectWrapKeyResponse extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public wrapped?: Uint8Array;
	public ToProtoJSON(): Object {
		return {
			wrapped: tsjson.ToProtoJSON.Bytes(this.wrapped),
		};
	}
	public static async Parse(data: any): Promise<ObjectWrapKeyResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectWrapKeyResponse();
		res.wrapped = await tsjson.Parse.Bytes(objData, "wrapped", "wrapped");
		return res;
	}
}

/** A message */
export class ObjectUnwrapKeyRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public objectId?: ObjectID;
	/** A field */
	public mechs?: padlock__Mechanism[];
	/** A field */
	public wrapped?: Uint8Array;
	/** A field */
	public attributes?: padlock__Attribute[];
	public ToProtoJSON(): Object {
		return {
			objectId: this.objectId?.ToProtoJSON(),
			mechs: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.mechs),
			wrapped: tsjson.ToProtoJSON.Bytes(this.wrapped),
			attributes: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.attributes),
		};
	}
	public static async Parse(data: any): Promise<ObjectUnwrapKeyRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectUnwrapKeyRequest();
		res.objectId = await tsjson.Parse.Message(objData, "objectId", "object_id", ObjectID.Parse);
		res.mechs = await tsjson.Parse.Repeated(objData, "mechs", "mechs", padlock__Mechanism.Parse);
		res.wrapped = await tsjson.Parse.Bytes(objData, "wrapped", "wrapped");
		res.attributes = await tsjson.Parse.Repeated(objData, "attributes", "attributes", padlock__Attribute.Parse);
		return res;
	}
}

/** A message */
export class ObjectDestroyObjectRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public objectId?: ObjectID;
	public ToProtoJSON(): Object {
		return {
			objectId: this.objectId?.ToProtoJSON(),
		};
	}
	public static async Parse(data: any): Promise<ObjectDestroyObjectRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectDestroyObjectRequest();
		res.objectId = await tsjson.Parse.Message(objData, "objectId", "object_id", ObjectID.Parse);
		return res;
	}
}

/** A message */
export class ObjectDestroyObjectResponse extends Object implements tsjson.ProtoJSONCompatible {
	public ToProtoJSON(): Object {
		return {
		};
	}
	public static async Parse(data: any): Promise<ObjectDestroyObjectResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectDestroyObjectResponse();
		return res;
	}
}

/** A message */
export class ObjectCopyObjectRequest extends Object implements tsjson.ProtoJSONCompatible {
	/** A field */
	public objectId?: ObjectID;
	/** A field */
	public attributes?: padlock__Attribute[];
	public ToProtoJSON(): Object {
		return {
			objectId: this.objectId?.ToProtoJSON(),
			attributes: tsjson.ToProtoJSON.Repeated(val => val.ToProtoJSON(), this.attributes),
		};
	}
	public static async Parse(data: any): Promise<ObjectCopyObjectRequest> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectCopyObjectRequest();
		res.objectId = await tsjson.Parse.Message(objData, "objectId", "object_id", ObjectID.Parse);
		res.attributes = await tsjson.Parse.Repeated(objData, "attributes", "attributes", padlock__Attribute.Parse);
		return res;
	}
}

/** A message */
export class ObjectCopyObjectResponse extends Object implements tsjson.ProtoJSONCompatible {
	public ToProtoJSON(): Object {
		return {
		};
	}
	public static async Parse(data: any): Promise<ObjectCopyObjectResponse> {
		let objData: Object = tsjson.AnyToObject(data);
		let res = new ObjectCopyObjectResponse();
		return res;
	}
}

