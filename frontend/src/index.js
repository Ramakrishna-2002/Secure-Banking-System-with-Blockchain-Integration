import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

console.log("Mounting React app");

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);