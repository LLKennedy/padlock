import Client from "./Client";
import React from "react";

export interface Props {
	client: Client
}

export class State { }

export class Module extends React.Component<Props, State> {
	render() {
		return <div>TODO</div>
	}
}