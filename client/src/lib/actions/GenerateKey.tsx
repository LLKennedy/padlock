import Client from "../Client";
import React from "react";
import { AttributeType, Mechanism, MechanismType, P11Object, SessionGenerateKeyPairRequest, SessionGenerateKeyRequest, SessionID } from "@llkennedy/padlock-api";
import { CKFalse, CKTrue, EncodeString, MakeAttribute } from "../util/Encode";
import { KeyTypes } from "../util/KeyType";
import { AttributeBuilder } from "../AttributeBuilder";

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
			<AttributeBuilder knownTypes={[]} />
			<button onClick={async () => {
				let req = new SessionGenerateKeyPairRequest();
				req.mech = new Mechanism();
				req.mech.type = MechanismType.CKM_RSA_PKCS_KEY_PAIR_GEN;
				req.id = this.props.session;
				req.publicAttributes = [
					// MakeAttribute(AttributeType.CKA_VALUE_LEN, new Uint8Array([0, 0, 0, 16])),
					MakeAttribute(AttributeType.CKA_LABEL, EncodeString("test rsa public key")),
					MakeAttribute(AttributeType.CKA_ID, EncodeString("0")),
					MakeAttribute(AttributeType.CKA_TOKEN, CKTrue),
					MakeAttribute(AttributeType.CKA_ENCRYPT, CKTrue),
					MakeAttribute(AttributeType.CKA_VERIFY, CKTrue),
					MakeAttribute(AttributeType.CKA_WRAP, CKTrue),
					MakeAttribute(AttributeType.CKA_MODULUS_BITS, new Uint8Array([0x00, 0x00, 0x08, 0x00])),
					MakeAttribute(AttributeType.CKA_PUBLIC_EXPONENT, new Uint8Array([0x01, 0x00, 0x01])),
					// MakeAttribute(AttributeType.CKA_SENSITIVE, CKTrue),
					// MakeAttribute(AttributeType.CKA_PRIVATE, CKTrue),
					// MakeAttribute(AttributeType.CKA_EXTRACTABLE, CKTrue),
					// MakeAttribute(AttributeType.CKA_COPYABLE, CKFalse), // Inconsistent
					// MakeAttribute(AttributeType.CKA_DECRYPT, CKTrue),
					// MakeAttribute(AttributeType.CKA_UNWRAP, CKTrue),
					// MakeAttribute(AttributeType.CKA_SIGN, CKFalse),
					// MakeAttribute(AttributeType.CKA_APPLICATION, CKFalse),
					// MakeAttribute(AttributeType.CKA_DESTROYABLE, CKTrue), 
				];
				req.privateAttributes = [
					MakeAttribute(AttributeType.CKA_LABEL, EncodeString("test rsa private key")),
					MakeAttribute(AttributeType.CKA_ID, EncodeString("0")),
					MakeAttribute(AttributeType.CKA_TOKEN, CKTrue),
					MakeAttribute(AttributeType.CKA_PRIVATE, CKTrue),
					MakeAttribute(AttributeType.CKA_SENSITIVE, CKTrue),
					MakeAttribute(AttributeType.CKA_DECRYPT, CKTrue),
					MakeAttribute(AttributeType.CKA_SIGN, CKTrue),
					MakeAttribute(AttributeType.CKA_UNWRAP, CKTrue),
				];
				try {
					let newObj = await this.props.client.SessionGenerateKeyPair(req);
					if (newObj.private !== undefined) {
						this.props.objects.push(newObj.private);
					}
					if (newObj.public !== undefined) {
						this.props.objects.push(newObj.public);
					}
				} catch (err) {
					const errString = `Failed to generate test keypair: ${err}`;
					console.error(errString);
					alert(errString);
				}
			}}>TODO</button>
		</div>
	}
}