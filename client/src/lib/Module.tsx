import Client from "./Client";
import React from "react";
import { ModuleInfo } from "@llkennedy/padlock-api";

export interface Props {
	client: Client;
	info: ModuleInfo;
}

export class State { }

export class Module extends React.Component<Props, State> {
	render() {
		return <div>TODO</div>
	}
}

export default Module;