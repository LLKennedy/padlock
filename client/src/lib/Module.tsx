import Client from "./Client";
import React from "react";
import { AuthToken, ModuleInfo, ModuleListSlotsRequest, SessionCloseRequest, SessionID, SessionLoginRequest, SlotID, SlotInfo, SlotOpenSessionRequest } from "@llkennedy/padlock-api";
import Slot from "./Slot";

export interface Props {
	client: Client;
	info: ModuleInfo;
	module: string;
	auth?: AuthToken;
}

export class State {
	slots?: SlotInfo[];
	session?: SessionID;
	slotID?: SlotID;
	selectedSlot?: number;
	selectedLabel: string = "";
	selectedDescription: string = "";
	pins?: ReadonlyMap<number, string> = new Map<number, string>();
	keepalive?: NodeJS.Timeout;
}

export class Module extends React.Component<Props, State> {
	constructor(props: Props) {
		super(props);
		let state = new State();
		state.keepalive = setInterval(async () => {
			if (this.state.session !== undefined) {
				try {
					await this.props.client.SessionKeepAlive(this.state.session);
				} catch (err) {
					const errString = `Failed to keep session alive: ${err}`;
					console.error(errString);
					alert(errString);
				}
			}
		}, 10000);
		this.state = state;
	}
	async componentDidMount() {
		try {
			let req = new ModuleListSlotsRequest();
			req.module = this.props.module;
			req.auth = this.props.auth;
			let res = await this.props.client.ModuleListSlots(req);
			this.setState({
				slots: res.slots
			});
		} catch (err) {
			const errString = `Failed to list slots: ${err}`;
			console.error(errString);
			alert(errString);
		}
	}
	async componentWillUnmount() {
		if (this.state.session !== undefined) {
			let req = new SessionCloseRequest();
			req.id = this.state.session;
			try {
				await this.props.client.SessionClose(req);
			} catch (err) {
				const errString = `Failed to close session: ${err}`;
				console.error(errString);
				alert(errString);
			}
			if (this.state.keepalive !== undefined) clearInterval(this.state.keepalive);
		}
		this.setState({
			slots: undefined,
			session: undefined,
			pins: undefined,
			selectedSlot: undefined,
			slotID: undefined,
		})
	}
	render() {
		if (this.state.session !== undefined && this.state.slotID !== undefined) {
			return <Slot client={this.props.client} session={this.state.session} label={this.state.selectedLabel} description={this.state.selectedDescription} logout={() => {
				this.setState({
					session: undefined,
					slotID: undefined,
					selectedSlot: undefined,
					selectedLabel: "",
					selectedDescription: "",
				});
			}} />
		}
		return <div>
			{(this.state.slots?.length ?? 0) === 0 ? "Listing slots..." :
				<table>
					<tbody>
						<tr>
							<th>ID</th>
							<th>Description</th>
							<th>Label</th>
							<th></th>
							<th>PIN</th>
						</tr>
						{this.state.slots?.map((val, i) => {
							return <tr key={i}>
								<td>{val.id}</td>
								<td>{val.slotDescription}</td>
								<td>{val.tokenInfo?.label}</td>
								<td><button onClick={async e => {
									try {
										let req = new SlotOpenSessionRequest();
										let slotID = new SlotID();
										slotID.auth = this.props.auth;
										slotID.module = this.props.module;
										slotID.slot = val.id;
										req.id = slotID;
										req.writeSession = true; // TODO: allow choice here
										let sessionStream = await this.props.client.SlotOpenSession(req);
										let session = await sessionStream.Recv();
										let sessionID = new SessionID();
										sessionID.uuid = session.uuid;
										sessionID.auth = this.props.auth;
										let loginReq = new SessionLoginRequest();
										loginReq.id = sessionID;
										loginReq.loginAsSecurityOfficer = false; // TODO: allow choice here
										loginReq.pin = this.state.pins?.get(val.id ?? 0) ?? ""; // TODO: input modal
										await this.props.client.SessionLogin(loginReq);
										this.setState({
											session: sessionID,
											slotID: slotID,
											selectedSlot: val.id,
											selectedLabel: val.tokenInfo?.label ?? "",
											selectedDescription: val.slotDescription ?? ""
										});
									} catch (err) {
										const errString = `Failed to log into slot: ${err}`;
										console.error(errString);
										alert(errString);
									}
								}}>Login</button></td>
								<td><input type="password" onChange={e => {
									let mapCopy = new Map<number, string>();
									for (let [id, pin] of this.state.pins ?? new Map<number, string>()) {
										mapCopy.set(id, pin);
									}
									mapCopy.set(val.id ?? 0, e.target.value);
									this.setState({
										pins: mapCopy
									})
								}} /></td>
							</tr>
						})}
					</tbody>
				</table>
			}
		</div>
	}
}

export default Module;