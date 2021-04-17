export enum ObjectClass {
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

export async function EncodeObjectClass(cl?: ObjectClass): Promise<Uint8Array | undefined> {
	if (cl === undefined) {
		return undefined;
	}
	switch (cl) {
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
		default:
			throw new Error("cannot encode invalid object class");
	}
}
