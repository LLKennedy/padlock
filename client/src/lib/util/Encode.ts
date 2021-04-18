import { Attribute, AttributeType } from "@llkennedy/padlock-api";

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

export async function EncodeUint32(val?: number): Promise<Uint8Array | undefined> {
	if (val === undefined) return undefined;
	return new Uint8Array([(val & 0xFF000000) >>> 24, (val & 0x00FF0000) >>> 16, (val & 0x0000FF00) >>> 8, val & 0x000000FF]);
}