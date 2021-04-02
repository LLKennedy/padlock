import React from 'react';
import logo from './logo.svg';
import './App.css';

import { AuthHello, ExposedPadlockClient } from "@llkennedy/padlock-api";
import axios from 'axios';

let client = new ExposedPadlockClient("localhost:6298", true, axios);
client.Hello(new AuthHello()).then(token => {
  console.log("token: " + token.data?.toString())
}).catch(err => {
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
