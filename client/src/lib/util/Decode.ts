import { AttributeType } from "@llkennedy/padlock-api";
import { DecodeKeyType, KeyTypes } from "./KeyType";
import { DecodeObjectClass, ObjectClass } from "./ObjectClass";

export async function Decode(type: AttributeType, value: Uint8Array): Promise<string> {
	switch (type) {
		case AttributeType.CKA_KEY_TYPE:
			return KeyTypes[await DecodeKeyType(value)];
		case AttributeType.CKA_CLASS:
			return ObjectClass[await DecodeObjectClass(value) ?? ObjectClass.INVALID];
		default:
			if (value.length === 0) {
				return "NULL";
			}
			let str = "0x";
			for (let n of value) {
				str = str + toHex(n);
			}
			return str;
	}
}

function toHex(n: number): string {
	let hex = n.toString(16);
	if (hex.length % 2 !== 0) {
		hex = "0" + hex;
	}
	return hex.toUpperCase();
}

export async function DecodeBool(val?: Uint8Array): Promise<boolean | undefined> {
	if (val === undefined || val.length === 0) {
		return undefined;
	}
	return val[0] === 1;
}

export async function DecodeUint32(val?: Uint8Array): Promise<number | undefined> {
	if (val === undefined || val.length === 0) {
		return undefined;
	}
	let result = 0;
	for (let i = 0; i < val.length && i < 4; i++) {
		result = result | (val[i] << (i * 8));
	}
	return result;
}