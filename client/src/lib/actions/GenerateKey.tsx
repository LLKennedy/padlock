import Client from "../Client";
import React from "react";
import { AttributeType, Mechanism, MechanismType, P11Object, SessionGenerateKeyRequest, SessionID } from "@llkennedy/padlock-api";
import { CKFalse, CKTrue, EncodeString, MakeAttribute } from "../util/Encode";
import { KeyTypes } from "../util/KeyType";

export class GenerateKeyProps {
	client: Client;
	session: SessionID;
	objects: P11Object[];
	constructor(client: Client, session: SessionID, objects: P11Object[]) {
		this.client = client;
		this.session = session;
		this.objects = objects;
	}
}

export class State { }

export class GenerateKey extends React.Component<GenerateKeyProps, State> {
	constructor(props: GenerateKeyProps) {
		super(props);
		let state = new State();
		this.state = state;
	}
	render() {
		return <div>
			<div>Generate</div>
			<button onClick={async () => {
				let req = new SessionGenerateKeyRequest();
				req.mech = new Mechanism();
				req.mech.type = MechanismType.CKM_AES_KEY_GEN;
				req.id = this.props.session;
				req.attributes = [
					MakeAttribute(AttributeType.CKA_VALUE_LEN, new Uint8Array([0, 0, 0, 16])),
					MakeAttribute(AttributeType.CKA_LABEL, EncodeString("test aes key")),
					MakeAttribute(AttributeType.CKA_TOKEN, CKTrue),
					MakeAttribute(AttributeType.CKA_SENSITIVE, CKTrue),
					MakeAttribute(AttributeType.CKA_PRIVATE, CKTrue),
					// MakeAttribute(AttributeType.CKA_ENCRYPT, CKTrue),
					// MakeAttribute(AttributeType.CKA_DECRYPT, CKTrue),
					// MakeAttribute(AttributeType.CKA_WRAP, CKTrue),
					// MakeAttribute(AttributeType.CKA_UNWRAP, CKTrue),
					// MakeAttribute(AttributeType.CKA_SIGN, CKFalse),
					// MakeAttribute(AttributeType.CKA_VERIFY, CKFalse),
					// MakeAttribute(AttributeType.CKA_, CKTrue),
				];
				try {
					let newObj = await this.props.client.SessionGenerateKey(req);
					this.props.objects.push(newObj);
				} catch (err) {
					const errString = `Failed to generate test key: ${err}`;
					console.error(errString);
					alert(errString);
				}
			}}>TODO</button>
		</div>
	}
}