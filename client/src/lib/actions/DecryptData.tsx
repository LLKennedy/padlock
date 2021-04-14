import Client from "../Client";
import React from "react";
import { P11Object, SessionID } from "@llkennedy/padlock-api";

export class DecryptDataProps {
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

export class DecryptData extends React.Component<DecryptDataProps, State> {
	constructor(props: DecryptDataProps) {
		super(props);
		let state = new State();
		this.state = state;
	}
	render() {
		return <div>Decrypt</div>
	}
}