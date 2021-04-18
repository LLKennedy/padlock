import { DecodeUint32 } from "./Decode";
import { EncodeUint32 } from "./Encode";

export enum ObjectClass {
	INVALID = -1,
	CKO_DATA = 0x00000000,
	CKO_CERTIFICATE = 0x00000001,
	CKO_PUBLIC_KEY = 0x00000002,
	CKO_PRIVATE_KEY = 0x00000003,
	CKO_SECRET_KEY = 0x00000004,
	CKO_HW_FEATURE = 0x00000005,
	CKO_DOMAIN_PARAMETERS = 0x00000006,
	CKO_MECHANISM = 0x00000007,
	CKO_OTP_KEY = 0x00000008,
	CKO_VENDOR_DEFINED = 0x80000000,
}

export async function DecodeObjectClass(raw?: Uint8Array): Promise<ObjectClass | undefined> {
	let parsed: number | undefined;
	try {
		parsed = await DecodeUint32(raw);
	} catch (err) {
		console.error(err);
		return ObjectClass.INVALID;
	}
	if (parsed === undefined) {
		return ObjectClass.INVALID;
	}
	switch (parsed) {
		case ObjectClass.INVALID:
		case ObjectClass.CKO_DATA:
		case ObjectClass.CKO_CERTIFICATE:
		case ObjectClass.CKO_PUBLIC_KEY:
		case ObjectClass.CKO_PRIVATE_KEY:
		case ObjectClass.CKO_SECRET_KEY:
		case ObjectClass.CKO_HW_FEATURE:
		case ObjectClass.CKO_DOMAIN_PARAMETERS:
		case ObjectClass.CKO_MECHANISM:
		case ObjectClass.CKO_OTP_KEY:
		case ObjectClass.CKO_VENDOR_DEFINED:
			return parsed as ObjectClass;
		default:
			console.error(`invalid object class: ${parsed}`);
			return ObjectClass.INVALID;
	}
}

export function EncodeObjectClass(cl?: ObjectClass): Promise<Uint8Array | undefined> {
	if (cl === ObjectClass.INVALID) {
		throw new Error("cannot encode invalid object class");
	}
	return EncodeUint32(cl as (number | undefined));
}
