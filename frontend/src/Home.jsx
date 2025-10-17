import React from 'react';
import { useNavigate } from 'react-router-dom';
import './Home.css';

// Import images
import phishingIcon from './icons/ChatGPT Image May 22, 2025, 02_25_40 PM.png';
import malwareIcon from './icons/ChatGPT Image May 22, 2025, 02_34_44 PM.png';

function Home() {
  const navigate = useNavigate();

  const handleClick = () => {
    navigate('/predict');
  };

  return (
    <div className="home-container">
      <h1>Protect Yourself Online with AI</h1>
      <p>Detect phishing, malware, and malicious URLs instantly using AI technology.</p>
      <button onClick={handleClick}>Get Started</button>
        <h1>Features</h1>
      <div className="features">
        
        <div className="feature-box">
          <img src={phishingIcon} alt="Phishing Icon" />
          <h3>Phishing Detection</h3>
          <p>Identify fake websites that steal your data</p>
        </div>
        <div className="feature-box">
          <img src={malwareIcon} alt="Malware Icon" />
          <h3>Malware Scanner</h3>
          <p>Analyze websites for harmful software</p>
        </div>
        <div className="feature-box">
          <img src={phishingIcon} alt="URL Icon" />
          <h3>URL Reputation</h3>
          <p>Know the trust level of any link you click</p>
        </div>
      </div>
    </div>
  );
}

export default Home;
