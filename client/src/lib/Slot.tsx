import Client from "./Client";
import React from "react";
import { P11Object, SessionID, SessionListObjectsRequest } from "@llkennedy/padlock-api";
import { EOFError, ServerStream } from "@llkennedy/mercury";
import { sleep } from "@llkennedy/sleep.js";

export interface Props {
	client: Client
	session: SessionID;
	label: string;
	description: string;
}

export class State {
	objects: P11Object[] = [];
}

export class Slot extends React.Component<Props, State> {
	constructor(props: Props) {
		super(props);
		let state = new State();
		this.state = state;
	}
	async componentDidMount() {
		let objsStream: ServerStream<SessionListObjectsRequest, P11Object>
		try {
			let req = new SessionListObjectsRequest();
			req.id = this.props.session;
			req.template = [];
			objsStream = await this.props.client.SessionListObjects(req);
		} catch (err) {
			const errString = `Failed to list objects in slot: ${err}`;
			console.error(errString);
			alert(errString);
			return;
		}
		while (true) {
			let obj: P11Object;
			try {
				obj = await objsStream.Recv();
			} catch (err) {
				if (err instanceof EOFError) {
					return;
				}
				const errString = `Failed to retrieve object from slot: ${err}`;
				console.error(errString);
				alert(errString);
				return;
			}
			let objsCopy = [...this.state.objects];
			objsCopy.push(obj);
			this.setState({
				objects: objsCopy
			});
			await sleep(100);
		}
	}
	render() {
		return <div style={{
			display: "inline-flex",
			flexDirection: "column"
		}}>
			<h2>{this.props.label} - {this.props.description}</h2>
			{this.state.objects.length <= 0 ? null : <table>
				<tbody>
					<tr>
						<th>Label</th>
						<th></th>
					</tr>
					{this.state.objects.map((val, i) => {
						return <tr>
							<td>{val.label}</td>
							<td><button onClick={async () => {

							}}>View</button></td>
						</tr>
					})}
				</tbody>
			</table>}
		</div>

	}
}

export default Slot;