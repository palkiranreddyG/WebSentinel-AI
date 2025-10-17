import React, { useState } from 'react';
import './ThreatDetector.css';

const ThreatDetector = () => {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showResult, setShowResult] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setResult(null);
    setError('');
    setLoading(true);

    try {
      const response = await fetch('http://127.0.0.1:5000/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) throw new Error('Failed to fetch');
      const data = await response.json();
      setResult(data);
      setShowResult(true);
    } catch (err) {
      setError('Failed to connect to the server: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleBack = () => {
    setShowResult(false);
    setUrl('');
    setResult(null);
    setError('');
  };

  return (
    <div className="threat-detector-container">
      <div className="card">
        {!showResult ? (
          <>
            <h1 className="title">🛡️ AI Threat Detector</h1>
            <h2 className="title1">🌐 Got a suspicious link? Paste it here to reveal the truth.</h2>
            <form onSubmit={handleSubmit} className="form">
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter a URL (e.g., https://example.com)"
                className="input-box"
              />
              <button type="submit" className="submit-button">
                🚀 Check URL
              </button>
            </form>
            {loading && <p className="loading">Analyzing...</p>}
            {error && <p className="error">❌ {error}</p>}
          </>
        ) : (
          <div className="result">
            <h2>📊 Results for: {result.url}</h2>
            <p><strong>Domain:</strong> {result.domain}</p>
            <p><strong>Risk Probability:</strong> {result.probability}</p>
            <p><strong>Verdict:</strong> {result.verdict}</p>
            <p><strong>Features Detected:</strong> {result.features_detected}/{result.total_features}</p>
            <p><strong>Reasons:</strong> {result.reasons}</p>
            <p><strong>Domain Age:</strong> {result.domain_age}</p>
            <p><strong>HTTP Status Code:</strong> {result.http_status}</p>
            <p><strong>SPF/DMARC Record:</strong> {result.spf_dmarc}</p>
            <p><strong>Free Hosted Content:</strong> {result.free_hosted}</p>
            <p><strong>Parked Domain:</strong> {result.parked_domain}</p>
            <button onClick={handleBack} className="back-button">🔙 Back</button>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatDetector;
