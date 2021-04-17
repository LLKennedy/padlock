import { Attribute, AttributeType } from "@llkennedy/padlock-api";
import { ObjectClass } from "./ObjectClass";

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
