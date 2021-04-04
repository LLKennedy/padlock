import React from "react";

import Module from "./lib/Module"
import { ApplicationConnectRequest, AuthHello, AuthToken, ExposedPadlockClient, ModuleInfo } from "@llkennedy/padlock-api";
import { LoadServerConfig } from "./conf/server";
import "./ModuleOpener.css";

const serverConfig = LoadServerConfig();

const openerID = "padlock-module-opener"
const containerID = "padlock-module-opener-container"
const labelID = "padlock-module-opener-label"
const inputID = "padlock-module-opener-input"
const buttonID = "padlock-module-opener-button"
const titleID = "padlock-module-opener-title"

export interface Props {

}

export class State {
	client: ExposedPadlockClient = new ExposedPadlockClient(serverConfig.addressAndPort);
	selectedModule: string = serverConfig.defaultModule;
	auth?: AuthToken;
	info?: ModuleInfo;
	connecting: boolean = false;
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
		return <div id={openerID}>
			<h1 id={titleID}>Padlock PKCS#11</h1>
			<div id={containerID}>
				{this.state.info === undefined ?
					this.state.connecting ? "Connecting..." :
						[<label key={0} id={labelID}>Module Path</label>,
						<input key={1} id={inputID} value={this.state.selectedModule} onChange={e => this.setState({ selectedModule: e.target.value })}></input>,
						<button key={2} id={buttonID} onClick={async () => {
							this.setState({
								connecting: true
							})
							try {
								let req = new ApplicationConnectRequest();
								req.auth = this.state.auth;
								req.module = this.state.selectedModule;
								let stream = await this.state.client.ApplicationConnect(req);
								let update = await stream.Recv();
								this.setState({
									info: update.info,
								});
							} catch (err) {
								console.error(`Failed to connect to module: ${err}`);
								window.alert(`Failed to connect to module: ${err}`)
							} finally {
								this.setState({
									connecting: false
								})
							}

						}}>Connect</button>]
					: <Module client={this.state.client} info={this.state.info} auth={this.state.auth} module={this.state.selectedModule} />
				}
			</div>
		</div>
	}
}

export default ModuleOpener;