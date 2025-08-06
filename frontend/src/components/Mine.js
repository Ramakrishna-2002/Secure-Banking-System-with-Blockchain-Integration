import React from 'react';
import axios from 'axios';

function Mine({ account }) {
  const handleMine = async () => {
    if (!account) {
      alert('Please connect MetaMask first');
      return;
    }

    try {
      const response = await axios.get(`http://localhost:5000/mine?address=${account}`);
      alert(`Block mined: ${JSON.stringify(response.data)}`);
    } catch (error) {
      console.error('Error mining block', error);
      alert('Error mining block');
    }
  };

  return (
    <div className="mining-section">
      <h2>Mine a New Block</h2>
      <button className="button mine-button" onClick={handleMine}>Mine</button>
    </div>
  );
}

export default Mine;