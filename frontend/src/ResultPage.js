import React, { useEffect, useState } from 'react';
import './ResultPage.css';

const ResultPage = () => {
    const [result, setResult] = useState(null);

    useEffect(() => {
        const storedResult = sessionStorage.getItem('threatResult');
        if (storedResult) {
            setResult(JSON.parse(storedResult));
            sessionStorage.removeItem('threatResult');
        }
    }, []);

    if (!result) {
        return (
            <div className="result-page-container">
                <div className="card">
                    <p>No result available.</p>
                </div>
            </div>
        );
    }

    return (
        <div className="result-page-container">
            <div className="card">
                <h2 className="title">🔍 Analysis Results</h2>
                <div className="result">
                    <p>🔗 <strong>URL:</strong> {result.url}</p>
                    <p>📈 <strong>Risk Probability:</strong> {result.probability}</p>
                    <p>📢 <strong>Verdict:</strong> {result.verdict}</p>
                    <p>🧠 <strong>Features Detected:</strong> {result.features_detected}/{result.total_features}</p>
                    {result.reasons && <p>📝 <strong>Reasons:</strong> {result.reasons}</p>}
                    <p>🌐 <strong>Domain:</strong> {result.domain}</p>
                    <p>📅 <strong>Domain Age:</strong> {result.domain_age}</p>
                    <p>📡 <strong>HTTP Status Code:</strong> {result.http_status}</p>
                    <p>🔒 <strong>SPF/DMARC Record:</strong> {result.spf_dmarc}</p>
                    <p>🏠 <strong>Free Hosted Content:</strong> {result.free_hosted}</p>
                    <p>🅿️ <strong>Parked Domain:</strong> {result.parked_domain}</p>
                </div>
            </div>
        </div>
    );
};

export default ResultPage;
