import { DecodeUint32 } from "./Decode";
import { EncodeUint32 } from "./Encode";

export enum HashingAlgorithm {
	INVALID = -1,
	CKG_MGF1_SHA1 = 0x00000001,
	CKG_MGF1_SHA224 = 0x00000005,
	CKG_MGF1_SHA256 = 0x00000002,
	CKG_MGF1_SHA384 = 0x00000003,
	CKG_MGF1_SHA512 = 0x00000004,
	CKG_MGF1_SHA3_224 = 0x00000006,
	CKG_MGF1_SHA3_256 = 0x00000007,
	CKG_MGF1_SHA3_384 = 0x00000008,
	CKG_MGF1_SHA3_512 = 0x00000009,
}

export async function DecodeHashingAlgorithm(raw?: Uint8Array): Promise<HashingAlgorithm | undefined> {
	let parsed: number | undefined;
	try {
		parsed = await DecodeUint32(raw);
	} catch (err) {
		console.error(err);
		return HashingAlgorithm.INVALID;
	}
	if (parsed === undefined) {
		return HashingAlgorithm.INVALID;
	}
	switch (parsed) {
		case HashingAlgorithm.CKG_MGF1_SHA1:
		case HashingAlgorithm.CKG_MGF1_SHA224:
		case HashingAlgorithm.CKG_MGF1_SHA256:
		case HashingAlgorithm.CKG_MGF1_SHA384:
		case HashingAlgorithm.CKG_MGF1_SHA512:
		case HashingAlgorithm.CKG_MGF1_SHA3_224:
		case HashingAlgorithm.CKG_MGF1_SHA3_256:
		case HashingAlgorithm.CKG_MGF1_SHA3_384:
		case HashingAlgorithm.CKG_MGF1_SHA3_512:
			return parsed as HashingAlgorithm;
		default:
			console.error(`invalid object class: ${parsed}`);
			return HashingAlgorithm.INVALID;
	}
}

export function EncodeHashingAlgorithm(cl?: HashingAlgorithm): Promise<Uint8Array | undefined> {
	if (cl === HashingAlgorithm.INVALID) {
		throw new Error("cannot encode invalid object class");
	}
	return EncodeUint32(cl as (number | undefined));
}
