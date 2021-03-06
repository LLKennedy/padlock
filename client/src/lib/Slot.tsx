import Client from "./Client";
import React from "react";
import { AttributeType, ObjectDestroyObjectRequest, ObjectID, ObjectListAttributeValuesRequest, ObjectListAttributeValuesUpdate, P11Object, SessionID, SessionListObjectsRequest } from "@llkennedy/padlock-api";
import { EOFError, ServerStream } from "@llkennedy/mercury";
import { sleep } from "@llkennedy/sleep.js";
import { P11Object as ReactP11Object } from "./P11Object";
import { GenerateKey, GenerateKeyProps } from "./actions/GenerateKey";
import { InjectKey, InjectKeyProps } from "./actions/InjectKey";
import { CopyObject, CopyObjectProps } from "./actions/CopyObject";
import { ExtractKey, ExtractKeyProps } from "./actions/ExtractKey";
import { DeriveKey, DeriveKeyProps } from "./actions/DeriveKey";
import { EncryptData, EncryptDataProps } from "./actions/EncryptData";
import { DecryptData, DecryptDataProps } from "./actions/DecryptData";

type styleNames = "container" | "inner-container" | "column" | "table" | "heading" | "actions" | "object-row" | "selected-action";

const styles: ReadonlyMap<styleNames, React.CSSProperties> = new Map<styleNames, React.CSSProperties>([
	["container", {
		display: "inline-flex",
		flexDirection: "column",
		background: "none",
		flexGrow: 1,
		flexShrink: 1,
		width: "100%",
		height: "100%",
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
		alignItems: "center",
		flexGrow: 1,
		flexShrink: 1,
		flexBasis: "200px",
		padding: "3pt 3pt",
		border: "2pt solid blue",
		margin: "3pt 3pt",
	}],
	["actions", {
		display: "block",
		flexDirection: "column",
		alignItems: "left",
		justifyItems: "left",
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
		textAlign: "left",
		width: "100%",
		borderCollapse: "collapse"
	}],
	["object-row", {
		border: "0.5pt solid rebeccapurple"
	}],
	["selected-action", {
		background: "rgb(23, 59, 23)"
	}]
]);

export interface Props {
	client: Client
	session: SessionID;
	label: string;
	description: string;
	logout(): void;
}

export class State {
	objects: P11Object[] = [];
	selectedObject?: P11Object;
	loadingObject: boolean = false;
	selectedObjectKeyType?: Uint8Array;
	actionState?: GenerateKeyProps | InjectKeyProps | CopyObjectProps | ExtractKeyProps | DeriveKeyProps | EncryptDataProps | DecryptDataProps;
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
							<tr style={styles.get("object-row")}>
								<th>Label</th>
								<th>Controls</th>
							</tr>
							{this.state.objects.map((val, i) => {
								return <tr key={`slot-object-${i}`} style={styles.get("object-row")}>
									<td>{val.label}</td>
									<td>
										<button onClick={async () => {
											this.setState({
												loadingObject: true
											})
											let req = new ObjectListAttributeValuesRequest();
											let objID = new ObjectID();
											objID.sessionId = this.props.session;
											objID.objectId = val.uuid;
											req.objectId = objID;
											req.requestedAttributes = [
												AttributeType.CKA_KEY_TYPE,
											];
											let stream: ServerStream<ObjectListAttributeValuesRequest, ObjectListAttributeValuesUpdate>;
											try {
												stream = await this.props.client.ObjectListAttributeValues(req);
											} catch (err) {
												this.setState({
													loadingObject: false
												})
												const errString = `Failed to retrieve object attributes: ${err}`;
												console.error(errString);
												alert(errString);
												return;
											}
											let keyType = new Uint8Array();
											try {
												let attr = await stream.Recv();
												if (attr.attribute === undefined) {
													throw new Error("not found");
												}
												keyType = attr.attribute.value ?? new Uint8Array();
												await stream.Recv();
											} catch (err) {
												if (!(err instanceof EOFError)) {
													this.setState({
														loadingObject: false
													})
													const errString = `Failed to retrieve object from slot: ${err}`;
													console.error(errString);
													alert(errString);
													return;
												}
											}
											this.setState({
												selectedObject: val,
												selectedObjectKeyType: keyType,
												loadingObject: false
											})
										}}>
											View
										</button>
										<button onClick={async () => {
											// TODO: edit attribute as endpoint
											window.alert("Editing attributes of existing objects is not yet implemented, check back later")
										}}>
											Edit
										</button>
										<button onClick={async () => {
											if (window.confirm(`Are you sure you want to delete this object with label "${val.label}"? This object will not be recoverable!`)) {
												let req = new ObjectDestroyObjectRequest();
												req.objectId = new ObjectID();
												req.objectId.objectId = val.uuid;
												req.objectId.sessionId = this.props.session;
												let objsCopy: P11Object[] = [];
												for (let obj of this.state.objects) {
													if (obj.uuid !== val.uuid) {
														objsCopy.push(obj);
													}
												}
												this.setState({
													loadingObject: true
												})
												try {
													await this.props.client.DestroyObject(req);
													this.setState({
														selectedObject: undefined,
														selectedObjectKeyType: undefined,
														objects: objsCopy
													})
												} catch (err) {
													const errString = `Failed to delete object: ${err}`;
													console.error(errString);
													alert(errString);
													return;
												} finally {
													this.setState({
														loadingObject: false
													})
												}
											}
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
					{this.state.loadingObject ? "Loading..." : this.state.selectedObject === undefined ? "View an object for more information" : <ReactP11Object client={this.props.client} obj={this.state.selectedObject} session={this.props.session} type={this.state.selectedObjectKeyType ?? new Uint8Array()} />}
				</div>
			</div>
			<div style={styles.get("actions")}>
				<h2 style={styles.get("heading")}>Actions</h2>
				<div>
					<button onClick={async () => {
						try {
							await this.props.client.SessionLogout(this.props.session);
						} catch (err) {
							const errString = `Failed to log out of session: ${err}`;
							console.error(errString);
							alert(errString);
						}
						this.props.logout();
					}}>Logout</button>
					<button onClick={async () => {
						this.setState({
							actionState: undefined,
						})
					}}>
						Clear Action
					</button>
				</div>
				<button onClick={async () => this.setState({ actionState: new GenerateKeyProps(this.props.client, this.props.session, this.state.objects) })} style={this.state.actionState instanceof GenerateKeyProps ? styles.get("selected-action") : undefined}>Generate</button>
				<button onClick={async () => this.setState({ actionState: new InjectKeyProps(this.props.client, this.props.session, this.state.objects) })} style={this.state.actionState instanceof InjectKeyProps ? styles.get("selected-action") : undefined}>Inject</button>
				<button onClick={async () => this.setState({ actionState: new CopyObjectProps(this.props.client, this.props.session, this.state.objects) })} style={this.state.actionState instanceof CopyObjectProps ? styles.get("selected-action") : undefined}>Copy</button>
				<button onClick={async () => this.setState({ actionState: new ExtractKeyProps(this.props.client, this.props.session, this.state.objects) })} style={this.state.actionState instanceof ExtractKeyProps ? styles.get("selected-action") : undefined}>Extract</button>
				<button onClick={async () => this.setState({ actionState: new DeriveKeyProps(this.props.client, this.props.session, this.state.objects) })} style={this.state.actionState instanceof DeriveKeyProps ? styles.get("selected-action") : undefined}>Derive</button>
				<button onClick={async () => this.setState({ actionState: new EncryptDataProps(this.props.client, this.props.session, this.state.objects) })} style={this.state.actionState instanceof EncryptDataProps ? styles.get("selected-action") : undefined}>Encrypt</button>
				<button onClick={async () => this.setState({ actionState: new DecryptDataProps(this.props.client, this.props.session, this.state.objects) })} style={this.state.actionState instanceof DecryptDataProps ? styles.get("selected-action") : undefined}>Decrypt</button>
				{
					(() => {
						if (this.state.actionState instanceof GenerateKeyProps) {
							return <GenerateKey client={this.state.actionState.client} session={this.state.actionState.session} objects={this.state.objects} />;
						}
						else if (this.state.actionState instanceof InjectKeyProps) {
							return <InjectKey client={this.state.actionState.client} session={this.state.actionState.session} objects={this.state.objects} />;
						}
						else if (this.state.actionState instanceof CopyObjectProps) {
							return <CopyObject client={this.state.actionState.client} session={this.state.actionState.session} objects={this.state.objects} />;
						}
						else if (this.state.actionState instanceof ExtractKeyProps) {
							return <ExtractKey client={this.state.actionState.client} session={this.state.actionState.session} objects={this.state.objects} />;
						}
						else if (this.state.actionState instanceof DeriveKeyProps) {
							return <DeriveKey client={this.state.actionState.client} session={this.state.actionState.session} objects={this.state.objects} />;
						}
						else if (this.state.actionState instanceof EncryptDataProps) {
							return <EncryptData client={this.state.actionState.client} session={this.state.actionState.session} objects={this.state.objects} />;
						}
						else if (this.state.actionState instanceof DecryptDataProps) {
							return <DecryptData client={this.state.actionState.client} session={this.state.actionState.session} objects={this.state.objects} />;
						}
						else {
							return null;
						}
					})()
				}
			</div>
		</div>

	}
}

export default Slot;