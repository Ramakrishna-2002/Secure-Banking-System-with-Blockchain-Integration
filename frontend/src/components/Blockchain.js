import React, { useState, useEffect } from 'react';
import axios from 'axios';

function Blockchain() {
  const [chain, setChain] = useState([]);

  useEffect(() => {
    fetchChain();
  }, []);

  const fetchChain = async () => {
    try {
      const response = await axios.get('http://localhost:5000/chain');
      setChain(response.data.chain);
    } catch (error) {
      console.error("Failed to fetch blockchain", error);
    }
  };

  return (
    <div className="blockchain">
      <h2>Blockchain</h2>
      {chain.length === 0 ? (
        <p>Loading blockchain data...</p>
      ) : (
        chain.map((block, index) => (
          <div className="block" key={index}>
            <h3>Block {block.index}</h3>
            <p>Timestamp: {new Date(block.timestamp * 1000).toLocaleString()}</p>
            <p>Proof: {block.proof}</p>
            <p>Previous Hash: {block.previous_hash}</p>
            <h4>Transactions:</h4>
            <ul>
              {block.transactions.map((transaction, tIndex) => (
                <li className="transaction" key={tIndex}>
                  From: {transaction.sender}, To: {transaction.recipient}, Amount: {transaction.amount}
                </li>
              ))}
            </ul>
          </div>
        ))
      )}
    </div>
  );
}

export default Blockchain;