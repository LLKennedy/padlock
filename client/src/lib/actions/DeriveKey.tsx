import Client from "../Client";
import React from "react";
import { P11Object, SessionID } from "@llkennedy/padlock-api";

export class DeriveKeyProps {
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

export class DeriveKey extends React.Component<DeriveKeyProps, State> {
	constructor(props: DeriveKeyProps) {
		super(props);
		let state = new State();
		this.state = state;
	}
	render() {
		return <div>Derive</div>
	}
}