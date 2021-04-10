import Client from "./Client";
import React from "react";
import { AuthToken, ModuleInfo, ModuleListSlotsRequest, SessionID, SessionLoginRequest, SlotID, SlotInfo, SlotOpenSessionRequest } from "@llkennedy/padlock-api";
import Slot from "./Slot"
import ReactModal from "react-modal";
import P11Object from "./P11Object"

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
	openModal: boolean = false;
	selectedSlot?: number;
	pin: string = "";
}

export class Module extends React.Component<Props, State> {
	constructor(props: Props) {
		super(props);
		this.state = new State();
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
	render() {
		if (this.state.session !== undefined && this.state.slotID !== undefined) {
			return <Slot client={this.props.client} />
		}
		return <div>
			<table>
				<tbody>
					<tr>
						<th>ID</th>
						<th>Description</th>
						<th>Label</th>
						<th></th>
					</tr>
					{this.state.slots?.map((val, i) => {
						return <tr key={i}>
							<td>{val.id}</td>
							<td>{val.slotDescription}</td>
							<td>{val.tokenInfo?.label}</td>
							<td><button onClick={async e => {
								this.setState({ openModal: true, selectedSlot: val.id })
							}}>Login</button></td>
						</tr>
					})}
				</tbody>
			</table>
			<ReactModal isOpen={this.state.openModal} onAfterClose={async () => {
				this.setState({
					openModal: false
				})
				try {
					let req = new SlotOpenSessionRequest();
					let slotID = new SlotID();
					slotID.auth = this.props.auth;
					slotID.module = this.props.module;
					slotID.slot = this.state.selectedSlot;
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
					loginReq.pin = this.state.pin; // TODO: input modal
					await this.props.client.SessionLogin(loginReq);
					this.setState({
						session: sessionID,
						slotID: slotID,
					});
				} catch (err) {
					const errString = `Failed to log into slot: ${err}`;
					console.error(errString);
					alert(errString);
				}
			}}>
				<label>PIN:</label>
				<input onChange={e => this.setState({
					pin: e.target.value
				})} />
				<button type="submit">Login</button>
			</ReactModal>
		</div>
	}
}

export default Module;