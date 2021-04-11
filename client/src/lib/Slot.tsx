import Client from "./Client";
import React from "react";
import { P11Object, SessionID, SessionListObjectsRequest } from "@llkennedy/padlock-api";
import { EOFError, ServerStream } from "@llkennedy/mercury";
import { sleep } from "@llkennedy/sleep.js";
import { P11Object as ReactP11Object } from "./P11Object";

type styleNames = "container" | "inner-container" | "column" | "table" | "heading";

const styles: ReadonlyMap<styleNames, React.CSSProperties> = new Map<styleNames, React.CSSProperties>([
	["container", {
		display: "inline-flex",
		flexDirection: "column",
		background: "none",
		flexGrow: 1,
		flexShrink: 1,
	}],
	["inner-container", {
		display: "inline-flex",
		flexDirection: "row",
		background: "none",
		justifyItems: "stretch",
		flexBasis: "200px",
		flexGrow: 1,
		flexShrink: 1,
	}],
	["column", {
		display: "inline-flex",
		flexDirection: "column",
		flexGrow: 1,
		flexShrink: 1,
		flexBasis: "200px",
		padding: "3pt 3pt",
		border: "2pt solid blue",
		margin: "3pt 3pt",
	}],
	["heading", {
		margin: "0 0"
	}],
	["table", {
		margin: "3pt 0",
		textAlign: "left"
	}]
]);

export interface Props {
	client: Client
	session: SessionID;
	label: string;
	description: string;
}

export class State {
	objects: P11Object[] = [];
	selectedObject?: P11Object;
	loadingObject: boolean = false;
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
		return <div style={styles.get("container")}>
			<div style={styles.get("inner-container")}>
				<div key={this.props.description + "2"} style={styles.get("column")}>
					<h2 style={styles.get("heading")}>{this.props.label} - {this.props.description}</h2>
					{this.state.objects.length <= 0 ? null : <table style={styles.get("table")}>
						<tbody >
							<tr >
								<th>Label</th>
								<th>Controls</th>
							</tr>
							{this.state.objects.map((val, i) => {
								return <tr>
									<td>{val.label}</td>
									<td>
										<button onClick={async () => {
											this.setState({
												loadingObject: true
											})
										}}>
											View
										</button>
										<button onClick={async () => {

										}}>
											Delete
										</button>
									</td>
								</tr>
							})}
						</tbody>
					</table>}
				</div>
				<div key={this.props.description + "3"} style={styles.get("column")}>
					{this.state.loadingObject ? "Loading..." : this.state.selectedObject === undefined ? "View an object for more information" : <ReactP11Object client={this.props.client} />}
				</div>
			</div>
			<div style={styles.get("column")}>
				<h2 style={styles.get("heading")}>Actions</h2>
			</div>
		</div>

	}
}

export default Slot;