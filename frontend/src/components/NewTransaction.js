import React, { useState } from 'react';
import axios from 'axios';
import { ethers } from 'ethers';

function NewTransaction({ account }) {
  const [recipient, setRecipient] = useState('');
  const [amount, setAmount] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!account) {
      alert('Please connect MetaMask first');
      return;
    }

    try {
      const provider = new ethers.providers.Web3Provider(window.ethereum);
      const signer = provider.getSigner();
      
      const message = `${account}${recipient}${amount}`;
      const signature = await signer.signMessage(message);

      const response = await axios.post('http://localhost:5000/transactions/new', {
        sender: account,
        recipient,
        amount: parseFloat(amount),
        signature
      });

      alert(response.data.message);
    } catch (error) {
      console.error('Error creating transaction', error);
      alert('Error creating transaction');
    }
  };

  return (
    <div className="new-transaction">
      <h2>New Transaction</h2>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Recipient:</label>
          <input type="text" value={recipient} onChange={(e) => setRecipient(e.target.value)} required />
        </div>
        <div className="form-group">
          <label>Amount:</label>
          <input type="number" value={amount} onChange={(e) => setAmount(e.target.value)} required />
        </div>
        <button type="submit" className="button">Create Transaction</button>
      </form>
    </div>
  );
}

export default NewTransaction;