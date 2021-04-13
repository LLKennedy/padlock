import Client from "./Client";
import React from "react";
import { AttributeType, ObjectID, ObjectListAttributeValuesRequest, ObjectListAttributeValuesUpdate, P11Object as protoP11, SessionID } from "@llkennedy/padlock-api";
import { AttrToKeyType, KeyTypes } from "./const/KeyType";
import { EOFError, ServerStream } from "@llkennedy/mercury";
import { Decode } from "./const/Decode";

export interface Props {
	client: Client,
	obj: protoP11,
	session: SessionID,
	type: Uint8Array,
}

export class State {
	keyType: KeyTypes = KeyTypes.INVALID;
	attrs?: ReadonlyMap<AttributeType, Uint8Array>;
}

const requestAttrs: ReadonlyMap<KeyTypes, readonly AttributeType[]> = new Map<KeyTypes, readonly AttributeType[]>([
	[KeyTypes.CKK_AES, [
		AttributeType.CKA_TOKEN,
		AttributeType.CKA_CHECK_VALUE,
		AttributeType.CKA_CLASS,
		AttributeType.CKA_PRIVATE,
		AttributeType.CKA_SENSITIVE,
		AttributeType.CKA_ALWAYS_SENSITIVE,
		AttributeType.CKA_TRUSTED,
		AttributeType.CKA_EXTRACTABLE,
		AttributeType.CKA_MODIFIABLE,
		AttributeType.CKA_ENCRYPT,
		AttributeType.CKA_DECRYPT,
		AttributeType.CKA_WRAP,
		AttributeType.CKA_UNWRAP,
		AttributeType.CKA_SIGN,
		AttributeType.CKA_SIGN_RECOVER,
		AttributeType.CKA_VERIFY,
		AttributeType.CKA_VERIFY_RECOVER,
		AttributeType.CKA_COPYABLE,
		AttributeType.CKA_DESTROYABLE,
		AttributeType.CKA_ID,
		AttributeType.CKA_LABEL,
		AttributeType.CKA_VALUE_LEN,
	]],
	[KeyTypes.CKK_RSA, [
		AttributeType.CKA_TOKEN,
		AttributeType.CKA_CHECK_VALUE,
		AttributeType.CKA_CLASS,
		AttributeType.CKA_PRIVATE,
		AttributeType.CKA_SENSITIVE,
		AttributeType.CKA_ALWAYS_SENSITIVE,
		AttributeType.CKA_TRUSTED,
		AttributeType.CKA_EXTRACTABLE,
		AttributeType.CKA_MODIFIABLE,
		AttributeType.CKA_ENCRYPT,
		AttributeType.CKA_DECRYPT,
		AttributeType.CKA_WRAP,
		AttributeType.CKA_UNWRAP,
		AttributeType.CKA_SIGN,
		AttributeType.CKA_SIGN_RECOVER,
		AttributeType.CKA_VERIFY,
		AttributeType.CKA_VERIFY_RECOVER,
		AttributeType.CKA_COPYABLE,
		AttributeType.CKA_DESTROYABLE,
		AttributeType.CKA_ID,
		AttributeType.CKA_LABEL,
		AttributeType.CKA_VALUE_LEN,
	]],
	[KeyTypes.CKK_ECDSA, [
		AttributeType.CKA_TOKEN,
		AttributeType.CKA_CHECK_VALUE,
		AttributeType.CKA_CLASS,
		AttributeType.CKA_PRIVATE,
		AttributeType.CKA_SENSITIVE,
		AttributeType.CKA_ALWAYS_SENSITIVE,
		AttributeType.CKA_TRUSTED,
		AttributeType.CKA_EXTRACTABLE,
		AttributeType.CKA_MODIFIABLE,
		AttributeType.CKA_ENCRYPT,
		AttributeType.CKA_DECRYPT,
		AttributeType.CKA_WRAP,
		AttributeType.CKA_UNWRAP,
		AttributeType.CKA_SIGN,
		AttributeType.CKA_SIGN_RECOVER,
		AttributeType.CKA_VERIFY,
		AttributeType.CKA_VERIFY_RECOVER,
		AttributeType.CKA_COPYABLE,
		AttributeType.CKA_DESTROYABLE,
		AttributeType.CKA_ID,
		AttributeType.CKA_LABEL,
		AttributeType.CKA_VALUE_LEN,
	]],
	[KeyTypes.CKK_DES, [
		AttributeType.CKA_TOKEN,
		AttributeType.CKA_CHECK_VALUE,
		AttributeType.CKA_CLASS,
		AttributeType.CKA_PRIVATE,
		AttributeType.CKA_SENSITIVE,
		AttributeType.CKA_ALWAYS_SENSITIVE,
		AttributeType.CKA_TRUSTED,
		AttributeType.CKA_EXTRACTABLE,
		AttributeType.CKA_MODIFIABLE,
		AttributeType.CKA_ENCRYPT,
		AttributeType.CKA_DECRYPT,
		AttributeType.CKA_WRAP,
		AttributeType.CKA_UNWRAP,
		AttributeType.CKA_SIGN,
		AttributeType.CKA_SIGN_RECOVER,
		AttributeType.CKA_VERIFY,
		AttributeType.CKA_VERIFY_RECOVER,
		AttributeType.CKA_COPYABLE,
		AttributeType.CKA_DESTROYABLE,
		AttributeType.CKA_ID,
		AttributeType.CKA_LABEL,
		AttributeType.CKA_VALUE_LEN,
	]],
	[KeyTypes.CKK_DES2, [
		AttributeType.CKA_TOKEN,
		AttributeType.CKA_CHECK_VALUE,
		AttributeType.CKA_CLASS,
		AttributeType.CKA_PRIVATE,
		AttributeType.CKA_SENSITIVE,
		AttributeType.CKA_ALWAYS_SENSITIVE,
		AttributeType.CKA_TRUSTED,
		AttributeType.CKA_EXTRACTABLE,
		AttributeType.CKA_MODIFIABLE,
		AttributeType.CKA_ENCRYPT,
		AttributeType.CKA_DECRYPT,
		AttributeType.CKA_WRAP,
		AttributeType.CKA_UNWRAP,
		AttributeType.CKA_SIGN,
		AttributeType.CKA_SIGN_RECOVER,
		AttributeType.CKA_VERIFY,
		AttributeType.CKA_VERIFY_RECOVER,
		AttributeType.CKA_COPYABLE,
		AttributeType.CKA_DESTROYABLE,
		AttributeType.CKA_ID,
		AttributeType.CKA_LABEL,
		AttributeType.CKA_VALUE_LEN,
	]],
	[KeyTypes.CKK_DES3, [
		AttributeType.CKA_TOKEN,
		AttributeType.CKA_CHECK_VALUE,
		AttributeType.CKA_CLASS,
		AttributeType.CKA_PRIVATE,
		AttributeType.CKA_SENSITIVE,
		AttributeType.CKA_ALWAYS_SENSITIVE,
		AttributeType.CKA_TRUSTED,
		AttributeType.CKA_EXTRACTABLE,
		AttributeType.CKA_MODIFIABLE,
		AttributeType.CKA_ENCRYPT,
		AttributeType.CKA_DECRYPT,
		AttributeType.CKA_WRAP,
		AttributeType.CKA_UNWRAP,
		AttributeType.CKA_SIGN,
		AttributeType.CKA_SIGN_RECOVER,
		AttributeType.CKA_VERIFY,
		AttributeType.CKA_VERIFY_RECOVER,
		AttributeType.CKA_COPYABLE,
		AttributeType.CKA_DESTROYABLE,
		AttributeType.CKA_ID,
		AttributeType.CKA_LABEL,
		AttributeType.CKA_VALUE_LEN,
	]],
	[KeyTypes.CKK_GENERIC_SECRET, [
		AttributeType.CKA_TOKEN,
		AttributeType.CKA_CHECK_VALUE,
		AttributeType.CKA_CLASS,
		AttributeType.CKA_PRIVATE,
		AttributeType.CKA_SENSITIVE,
		AttributeType.CKA_ALWAYS_SENSITIVE,
		AttributeType.CKA_TRUSTED,
		AttributeType.CKA_EXTRACTABLE,
		AttributeType.CKA_MODIFIABLE,
		AttributeType.CKA_ENCRYPT,
		AttributeType.CKA_DECRYPT,
		AttributeType.CKA_WRAP,
		AttributeType.CKA_UNWRAP,
		AttributeType.CKA_SIGN,
		AttributeType.CKA_SIGN_RECOVER,
		AttributeType.CKA_VERIFY,
		AttributeType.CKA_VERIFY_RECOVER,
		AttributeType.CKA_COPYABLE,
		AttributeType.CKA_DESTROYABLE,
		AttributeType.CKA_ID,
		AttributeType.CKA_LABEL,
		AttributeType.CKA_VALUE_LEN,
	]],
]);

export class P11Object extends React.Component<Props, State> {
	constructor(props: Props) {
		super(props);
		let state = new State();
		state.keyType = AttrToKeyType(props.type);
		this.state = state;
	}
	async componentDidMount() {
		let req = new ObjectListAttributeValuesRequest();
		let objID = new ObjectID();
		objID.objectId = this.props.obj.uuid;
		objID.sessionId = this.props.session;
		req.objectId = objID;
		let reqAttrs = requestAttrs.get(this.state.keyType);
		if (reqAttrs === undefined) {
			console.warn(`Key type ${KeyTypes[this.state.keyType]}=${this.state.keyType} not supported`);
			return;
		}
		req.requestedAttributes = [...reqAttrs];
		let stream: ServerStream<ObjectListAttributeValuesRequest, ObjectListAttributeValuesUpdate>;
		try {
			stream = await this.props.client.ObjectListAttributeValues(req);
		} catch (err) {
			const errString = `Failed to list key-specific attributes: ${err}`;
			console.error(errString);
			alert(errString);
			return;
		}
		let attrs = new Map<AttributeType, Uint8Array>();
		while (true) {
			try {
				let attr = await stream.Recv();
				if (attr.attribute?.value !== undefined && attr.attribute?.type !== undefined) {
					attrs.set(attr.attribute.type, attr.attribute.value);
				}
				this.setState({
					attrs: attrs,
				})
			} catch (err) {
				if (err instanceof EOFError) {
					break;
				}
				const errString = `Failed to get key-specific attribute: ${err}`;
				console.error(errString);
				alert(errString);
				return;
			}
		}
		this.setState({
			attrs: attrs,
		})
	}
	render() {
		return <div>
			<h2>{this.props.obj.label}</h2>
			<div>{KeyTypes[this.state.keyType]}={this.state.keyType}</div>
			<div>
				{this.state.attrs === undefined ? null : Array.from(this.state.attrs).map(([type, val]) => {
					return <div>{AttributeType[type]}={Decode(type, val)}</div>
				})}
			</div>
		</div>
	}
}

export default P11Object;