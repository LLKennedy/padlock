import { DecodeUint32 } from "./Decode";
import { EncodeUint32 } from "./Encode";

export enum KeyTypes {
	INVALID = -1,
	CKK_RSA = 0x00000000,
	CKK_DSA = 0x00000001,
	CKK_DH = 0x00000002,
	CKK_ECDSA = 0x00000003,
	CKK_EC = 0x00000003,
	CKK_X9_42_DH = 0x00000004,
	CKK_KEA = 0x00000005,
	CKK_GENERIC_SECRET = 0x00000010,
	CKK_RC2 = 0x00000011,
	CKK_RC4 = 0x00000012,
	CKK_DES = 0x00000013,
	CKK_DES2 = 0x00000014,
	CKK_DES3 = 0x00000015,
	CKK_CAST = 0x00000016,
	CKK_CAST3 = 0x00000017,
	CKK_CAST5 = 0x00000018,
	CKK_CAST128 = 0x00000018,
	CKK_RC5 = 0x00000019,
	CKK_IDEA = 0x0000001A,
	CKK_SKIPJACK = 0x0000001B,
	CKK_BATON = 0x0000001C,
	CKK_JUNIPER = 0x0000001D,
	CKK_CDMF = 0x0000001E,
	CKK_AES = 0x0000001F,
	CKK_BLOWFISH = 0x00000020,
	CKK_TWOFISH = 0x00000021,
	CKK_SECURID = 0x00000022,
	CKK_HOTP = 0x00000023,
	CKK_ACTI = 0x00000024,
	CKK_CAMELLIA = 0x00000025,
	CKK_ARIA = 0x00000026,
	CKK_SHA512_224_HMAC = 0x00000027,
	CKK_SHA512_256_HMAC = 0x00000028,
	CKK_SHA512_T_HMAC = 0x00000029,
	CKK_SHA_1_HMAC = 0x00000028,
	CKK_SHA224_HMAC = 0x0000002E,
	CKK_SHA256_HMAC = 0x0000002B,
	CKK_SHA384_HMAC = 0x0000002C,
	CKK_SHA512_HMAC = 0x0000002D,
	CKK_SEED = 0x0000002F,
	CKK_GOSTR3410 = 0x00000030,
	CKK_GOSTR3411 = 0x00000031,
	CKK_GOST28147 = 0x00000032,
	CKK_SHA3_224_HMAC = 0x00000033,
	CKK_SHA3_256_HMAC = 0x00000034,
	CKK_SHA3_384_HMAC = 0x00000035,
	CKK_SHA3_512_HMAC = 0x00000036,
	CKK_VENDOR_DEFINED = 0x80000000,
}

export async function DecodeKeyType(raw: Uint8Array): Promise<KeyTypes> {
	let parsed: number | undefined;
	try {
		parsed = await DecodeUint32(raw);
	} catch (err) {
		console.error(err);
		return KeyTypes.INVALID;
	}
	if (parsed === undefined) {
		return KeyTypes.INVALID;
	}
	switch (parsed) {
		case KeyTypes.CKK_RSA:
		case KeyTypes.CKK_DSA:
		case KeyTypes.CKK_DH:
		case KeyTypes.CKK_ECDSA:
		case KeyTypes.CKK_EC:
		case KeyTypes.CKK_X9_42_DH:
		case KeyTypes.CKK_KEA:
		case KeyTypes.CKK_GENERIC_SECRET:
		case KeyTypes.CKK_RC2:
		case KeyTypes.CKK_RC4:
		case KeyTypes.CKK_DES:
		case KeyTypes.CKK_DES2:
		case KeyTypes.CKK_DES3:
		case KeyTypes.CKK_CAST:
		case KeyTypes.CKK_CAST3:
		case KeyTypes.CKK_CAST5:
		case KeyTypes.CKK_CAST128:
		case KeyTypes.CKK_RC5:
		case KeyTypes.CKK_IDEA:
		case KeyTypes.CKK_SKIPJACK:
		case KeyTypes.CKK_BATON:
		case KeyTypes.CKK_JUNIPER:
		case KeyTypes.CKK_CDMF:
		case KeyTypes.CKK_AES:
		case KeyTypes.CKK_BLOWFISH:
		case KeyTypes.CKK_TWOFISH:
		case KeyTypes.CKK_SECURID:
		case KeyTypes.CKK_HOTP:
		case KeyTypes.CKK_ACTI:
		case KeyTypes.CKK_CAMELLIA:
		case KeyTypes.CKK_ARIA:
		case KeyTypes.CKK_SHA512_224_HMAC:
		case KeyTypes.CKK_SHA512_256_HMAC:
		case KeyTypes.CKK_SHA512_T_HMAC:
		case KeyTypes.CKK_SHA_1_HMAC:
		case KeyTypes.CKK_SHA224_HMAC:
		case KeyTypes.CKK_SHA256_HMAC:
		case KeyTypes.CKK_SHA384_HMAC:
		case KeyTypes.CKK_SHA512_HMAC:
		case KeyTypes.CKK_SEED:
		case KeyTypes.CKK_GOSTR3410:
		case KeyTypes.CKK_GOSTR3411:
		case KeyTypes.CKK_GOST28147:
		case KeyTypes.CKK_SHA3_224_HMAC:
		case KeyTypes.CKK_SHA3_256_HMAC:
		case KeyTypes.CKK_SHA3_384_HMAC:
		case KeyTypes.CKK_SHA3_512_HMAC:
		case KeyTypes.CKK_VENDOR_DEFINED:
			return parsed as KeyTypes;
		default:
			console.error(`invalid key type: ${parsed}`);
			return KeyTypes.INVALID;
	}
}

export function EncodeKeyType(kt?: KeyTypes): Promise<Uint8Array | undefined> {
	if (kt === KeyTypes.INVALID) {
		throw new Error("cannot encode invalid key type");
	}
	return EncodeUint32(kt as (number | undefined));
}