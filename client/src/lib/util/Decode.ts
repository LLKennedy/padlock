import { AttributeType } from "@llkennedy/padlock-api";
import { AttrToKeyType, KeyTypes } from "./KeyType";

export function Decode(type: AttributeType, value: Uint8Array) {
	switch (type) {
		case AttributeType.CKA_KEY_TYPE:
			return KeyTypes[AttrToKeyType(value)];
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