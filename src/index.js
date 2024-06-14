import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';
import { FronteggProvider } from '@frontegg/react';
import './index.css';

const contextOptions = {
  baseUrl: 'https://app-cdgzsn9z94iw.frontegg.com',
  clientId: 'fb425a85-43ec-49c6-a709-b298455dc728'
};

const authOptions = {
 // keepSessionAlive: true // Uncomment this in order to maintain the session alive
};

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <FronteggProvider 
  contextOptions={contextOptions} 
  hostedLoginBox={true}
  authOptions={authOptions}>
    <App />
  </FronteggProvider >,
  document.getElementById('root')
);


// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
