import Client from "../Client";
import React from "react";
import { P11Object, SessionID } from "@llkennedy/padlock-api";

export interface Props {
	client: Client;
	session: SessionID;
	objects: P11Object[];
}

export class State { }

export class CopyObject extends React.Component<Props, State> {
	constructor(props: Props) {
		super(props);
		let state = new State();
		this.state = state;
	}
}