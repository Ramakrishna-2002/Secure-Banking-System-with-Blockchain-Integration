import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Route, Routes, Link, Navigate } from 'react-router-dom';
import { ethers } from 'ethers';
import './App.css';
import Blockchain from './components/Blockchain';
import NewTransaction from './components/NewTransaction';
import Mine from './components/Mine';
import Login from './components/Login';
import Dashboard from './components/Dashboard';

function App() {
  const [account, setAccount] = useState(null);
  const [token, setToken] = useState(null);
  const [balance, setBalance] = useState(null);

  useEffect(() => {
    connectWallet();
  }, []);

  useEffect(() => {
    if (account) {
      fetchBalance();
    }
  }, [account]);

  const connectWallet = async () => {
    if (typeof window.ethereum !== 'undefined') {
      try {
        await window.ethereum.request({ method: 'eth_requestAccounts' });
        const provider = new ethers.providers.Web3Provider(window.ethereum);
        const signer = provider.getSigner();
        const address = await signer.getAddress();
        setAccount(address);
      } catch (error) {
        console.error("Failed to connect to MetaMask", error);
      }
    } else {
      console.log('Please install MetaMask!');
    }
  };

  const fetchBalance = async () => {
    if (account) {
      try {
        const provider = new ethers.providers.Web3Provider(window.ethereum);
        const balance = await provider.getBalance(account);
        setBalance(ethers.utils.formatEther(balance));
      } catch (error) {
        console.error("Failed to fetch balance", error);
      }
    }
  };

  if (!token) {
    return <Login setToken={setToken} />;
  }

  return (
    <Router>
      <div className="container">
        <header className="header">
          <h1>Blockchain App</h1>
        </header>
        <nav className="nav">
          <ul>
            <li><Link to="/dashboard">Dashboard</Link></li>
            <li><Link to="/blockchain">Blockchain</Link></li>
            <li><Link to="/transaction">New Transaction</Link></li>
            <li><Link to="/mine">Mine</Link></li>
          </ul>
        </nav>
        
        {account ? (
          <p className="account-info">Connected Account: {account}</p>
        ) : (
          <button className="button connect-button" onClick={connectWallet}>Connect MetaMask</button>
        )}

        <main>
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" />} />
            <Route path="/dashboard" element={<Dashboard account={account} balance={balance} />} />
            <Route path="/blockchain" element={<Blockchain />} />
            <Route path="/transaction" element={<NewTransaction account={account} />} />
            <Route path="/mine" element={<Mine account={account} />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;