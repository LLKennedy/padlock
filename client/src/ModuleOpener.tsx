import React from "react";

import Module from "./lib/Module"
import Slot from "./lib/Slot"
import P11Object from "./lib/P11Object"
import { ApplicationConnectRequest, AuthHello, AuthToken, ExposedPadlockClient, ModuleInfo } from "@llkennedy/padlock-api";
import { LoadServerConfig } from "./conf/server";
import "./ModuleOpener.css";

const serverConfig = LoadServerConfig();

const openerID = "padlock-module-opener"

export interface Props {

}

export class State {
	client: ExposedPadlockClient = new ExposedPadlockClient(serverConfig.addressAndPort);
	selectedModule: string = serverConfig.defaultModule;
	auth?: AuthToken;
	info?: ModuleInfo;
}

export class ModuleOpener extends React.Component<Props, State> {
	constructor(props: Props) {
		super(props);
		this.state = new State();
	}
	componentDidMount() {
		this.state.client.Hello(new AuthHello())
			.then(token => {
				this.setState({ auth: token });
			})
			.catch(err => {
				console.error(`Failed to initiate server: ${err}`);
			})
	}
	render() {
		if (this.state.info === undefined) return <div id={openerID}>
			<label key={0}>Module Path</label>
			<input key={1} value={this.state.selectedModule} onChange={e => this.setState({ selectedModule: e.target.value })}></input>
			<button key={2} onClick={async () => {
				let req = new ApplicationConnectRequest();
				req.auth = this.state.auth;
				req.module = this.state.selectedModule;
				try {
					let stream = await this.state.client.ApplicationConnect(req);
					let update = await stream.Recv();
					this.setState({
						info: update.info,
					});
				} catch (err) {
					console.error(`Failed to connect to module: ${err}`);
				}

			}}>Connect</button>
		</div>
		return <div id={openerID}>
			<Module client={this.state.client} info={this.state.info} />
		</div>
	}
}

export default ModuleOpener;