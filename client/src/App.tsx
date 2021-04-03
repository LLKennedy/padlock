import React from 'react';
import logo from './logo.svg';
import './App.css';

import * as padlockpb from "@llkennedy/padlock-api";
import axios from 'axios';

const modulePath = `D:\\\\Downloads\\\\SecurityServerEvaluation-V4.40.0.2\\\\Software\\\\Windows\\\\x86-64\\\\Crypto_APIs\\\\PKCS11_R3\\\\lib\\\\cs_pkcs11_R3.dll`;

async function test() {
	let client = new padlockpb.ExposedPadlockClient("localhost:6298", true, axios);
	const token = await client.Hello(new padlockpb.AuthHello());
	let connectReq = new padlockpb.ApplicationConnectRequest();
	connectReq.auth = token;
	connectReq.module = modulePath;
	const appStream = await client.ApplicationConnect(connectReq);
	const modules = await appStream.Recv();
	console.log(JSON.stringify(modules.info))
	let listSlotsReq = new padlockpb.ModuleListSlotsRequest();
	listSlotsReq.auth = token;
	listSlotsReq.module = modulePath;
	let modulesList = await client.ModuleListSlots(listSlotsReq);
	console.log(`Slot count: ${modulesList.slots?.length ?? 0}`)
	if (modulesList.slots !== undefined && modulesList.slots.length > 0) {
		let slot = modulesList.slots[0];
		let slotID = new padlockpb.SlotID();
		slotID.auth = token;
		slotID.module = modulePath;
		slotID.slot = slot.id;
		let mechReq = new padlockpb.SlotListMechanismsRequest();
		mechReq.id = slotID;
		let mechs = await client.SlotListMechanisms(mechReq);
		console.log(`Mechanism count: ${mechs.mechanisms?.length ?? 0}`);
		let openSessReq = new padlockpb.SlotOpenSessionRequest();
		openSessReq.id = slotID;
		openSessReq.writeSession = true;
		let sessionChan = await client.SlotOpenSession(openSessReq);
		let update = await sessionChan.Recv();
		if (update.uuid === undefined) {
			throw new Error("No uuid in first update")
		}
		let sessionUUID = update.uuid;
		let sessionID = new padlockpb.SessionID();
		sessionID.auth = token;
		sessionID.uuid = sessionUUID;
		let loginReq = new padlockpb.SessionLoginRequest();
		loginReq.id = sessionID;
		loginReq.pin = "1234";
		loginReq.loginAsSecurityOfficer = false;
		await client.SessionLogin(loginReq);
		console.log("logged in")
		let listObjectsReq = new padlockpb.SessionListObjectsRequest();
		listObjectsReq.id = sessionID;
		listObjectsReq.template = undefined;
		let objStream = await client.SessionListObjects(listObjectsReq);
		while (true) {
			let nextObj = await objStream.Recv();
			console.log(`New object: ${nextObj.uuid}=${nextObj.label}`)
		}
	}
}

test().catch(err => {
	console.error(err)
})

function App() {
	return (
		<div className="App">
			<header className="App-header">
				<img src={logo} className="App-logo" alt="logo" />
				<p>
					Edit <code>src/App.tsx</code> and save to reload.
				</p>
				<a
					className="App-link"
					href="https://reactjs.org"
					target="_blank"
					rel="noopener noreferrer"
				>
					Learn React
				</a>
			</header>
		</div>
	);
}

export default App;
