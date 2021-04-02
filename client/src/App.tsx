import React from 'react';
import logo from './logo.svg';
import './App.css';

import { AuthHello, ExposedPadlockClient, ApplicationConnectRequest } from "@llkennedy/padlock-api";
import axios from 'axios';

async function test() {
  let client = new ExposedPadlockClient("localhost:6298", true, axios);
  const token = await client.Hello(new AuthHello());
  let connectReq = new ApplicationConnectRequest();
  connectReq.auth = token;
  connectReq.module = `D:\\Downloads\\SecurityServerEvaluation-V4.40.0.2\\Software\\Windows\\x86-64\\Crypto_APIs\\PKCS11_R3\\lib\\cs_pkcs11_R3.dll`;
  const appStream = await client.ApplicationConnect(connectReq);
  const modules = await appStream.Recv();
  console.log(JSON.stringify(modules.info))
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
