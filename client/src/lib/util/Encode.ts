import { Attribute, AttributeType, ObjectClass } from "@llkennedy/padlock-api";

export function MakeAttribute(type: AttributeType, value?: Uint8Array): Attribute {
	let attr = new Attribute();
	attr.type = type;
	attr.value = value;
	return attr;
}

export function EncodeString(str?: string): Uint8Array | undefined {
	if (str === undefined) {
		return str;
	}
	return new Uint8Array(Array.from(str).map(val => val.charCodeAt(0)))
}

export const CKTrue = new Uint8Array([1]);
export const CKFalse = new Uint8Array([0]);

export async function EncodeObjectClass(cl?: ObjectClass): Promise<Uint8Array | undefined> {
	if (cl === undefined) {
		return undefined;
	}
	switch (cl) {
		case ObjectClass.CKO_UNDEFINED_UNKNOWN:
			throw new Error("cannot encode invalid object class");
		case ObjectClass.CKO_DATA:
			return new Uint8Array([0, 0, 0, 1]);
		case ObjectClass.CKO_CERTIFICATE:
			return new Uint8Array([0, 0, 0, 2]);
		case ObjectClass.CKO_PUBLIC_KEY:
			return new Uint8Array([0, 0, 0, 3]);
		case ObjectClass.CKO_PRIVATE_KEY:
			return new Uint8Array([0, 0, 0, 4]);
		case ObjectClass.CKO_SECRET_KEY:
			return new Uint8Array([0, 0, 0, 5]);
		case ObjectClass.CKO_HW_FEATURE:
			return new Uint8Array([0, 0, 0, 6]);
		case ObjectClass.CKO_DOMAIN_PARAMETERS:
			return new Uint8Array([0, 0, 0, 7]);
		case ObjectClass.CKO_MECHANISM:
			return new Uint8Array([0, 0, 0, 8]);
		case ObjectClass.CKO_OTP_KEY:
			return new Uint8Array([0, 0, 0, 1]);
		case ObjectClass.CKO_VENDOR_DEFINED:
			return new Uint8Array([0x80, 0, 0, 0]);
	}
}