import React from 'react';
import { Link } from 'react-router-dom';
import './Dashboard.css';

function Dashboard({ account, balance }) {
  return (
    // <div className="dashboard">
    //   <h2>Dashboard</h2>
    //   {account ? (
    //     <div>
    //       <p>Connected Account: {account}</p>
    //       <p>Current Balance: {balance} ETH</p>
    //     </div>
    //   ) : (
    //     <p>Please connect your wallet to view account details.</p>
    //   )}
    //   <div className="dashboard-buttons">
    //     <Link to="/blockchain" className="button">View Blockchain</Link>
    //     <Link to="/transaction" className="button">New Transaction</Link>
    //     <Link to="/mine" className="button">Mine</Link>
    //   </div>
    // </div>

    <div className="container-1">
      <h2 className="container-title">Dashboard</h2>
      <div className="gradient-cards">
        <div className="card">
          <div className="container-card bg-green-box">
            
            <p className="card-title">Account Information</p>
            {account ? (
              <>
                <p className="card-description">Connected Account: {account}</p>
                <p className="card-description">Current Balance: {balance} ETH</p>
              </>
            ) : (
              <p className="card-description">Please connect your wallet to view account details.</p>
            )}
          </div>
        </div>
        <div className="card">
          <div className="container-card bg-blue-box">
           
            <p className="card-title">Quick Actions</p>
            <div className="dashboard-buttons">
              <Link to="/blockchain" className="button">View Blockchain</Link>
              <Link to="/transaction" className="button">New Transaction</Link>
              <Link to="/mine" className="button">Mine</Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;