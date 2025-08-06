import React, { useState } from 'react';
import axios from 'axios';
import './Login.css';

function Login({ setToken }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLogin, setIsLogin] = useState(true);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const url = isLogin ? 'http://localhost:5000/login' : 'http://localhost:5000/signup';

    try {
      const response = await axios.post(url, { username, password });
      if (isLogin) {
        setToken(response.data.token);
      } else {
        alert('Signup successful! Please login.');
        setIsLogin(true);
      }
    } catch (error) {
      console.error('Error during authentication', error);
      alert('Authentication failed');
    }
  };

  return (
    <div className="auth-form">
      <h2>{isLogin ? 'Login' : 'Signup'}</h2>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Username:</label>
          <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} required />
        </div>
        <div className="form-group">
          <label>Password:</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        </div>
        <button type="submit" className="button">{isLogin ? 'Login' : 'Signup'}</button>
        <p onClick={() => setIsLogin(!isLogin)}>
          {isLogin ? 'No account? Signup here.' : 'Already have an account? Login here.'}
        </p>
      </form>
    </div>
  );
}

export default Login;
