# WebSentinel AI - AI-Powered Threat Detection System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![React](https://img.shields.io/badge/React-19.1.0-blue.svg)](https://reactjs.org/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-lightgrey.svg)](https://flask.palletsprojects.com/)

WebSentinel AI is an advanced AI-powered web threat detection system that analyzes URLs and web content to identify phishing attempts, malware, and malicious websites. The system uses machine learning models trained on extensive datasets to provide real-time threat analysis with detailed risk assessments.

## 🚀 Features

### 🔍 Comprehensive Threat Detection
- **URL Analysis**: Deep analysis of URL structure, domain reputation, and suspicious patterns
- **Content Scanning**: HTML content analysis for malicious scripts and phishing indicators
- **Domain Intelligence**: WHOIS data, domain age, and registration details
- **Security Checks**: SPF/DMARC records, SSL certificates, and HTTP status validation

### 🤖 AI-Powered Analysis
- **Machine Learning Models**: Custom-trained neural networks for URL and content classification
- **Feature Extraction**: 116+ features analyzed for comprehensive threat detection
- **Real-time Scoring**: Probability-based risk assessment with confidence levels
- **Intelligent Reasoning**: Automated generation of detection reasons and explanations

### 📊 Detailed Reporting
- **Risk Probability**: Numerical threat score from 0-1
- **Verdict Classification**: Clear labels (Safe, Suspicious, Malicious)
- **Feature Breakdown**: Detailed count of detected suspicious features
- **Domain Information**: Age, hosting details, and security configurations

### 🖥️ Modern Web Interface
- **Responsive Design**: Clean, intuitive UI built with React
- **Real-time Feedback**: Instant analysis results with loading indicators
- **Interactive Results**: Expandable details and explanations
- **Cross-platform**: Works on desktop and mobile devices

## 🏗️ Architecture

```
WebSentinel AI/
├── backend/                    # Flask API Server
│   ├── app/
│   │   ├── __init__.py        # Flask app factory
│   │   ├── config.py          # Configuration settings
│   │   ├── model.py           # Main analysis logic
│   │   ├── routes.py          # API endpoints
│   │   ├── scraper.py         # Web content scraper
│   │   ├── utils.py           # Utility functions
│   │   └── ml_model/          # Machine Learning Models
│   │       ├── url_predictor.py
│   │       ├── content_predictor.py
│   │       ├── feature_extractor.py
│   │       ├── train_url_model.py
│   │       ├── train_content_model.py
│   │       ├── dl_model_builder.py
│   │       ├── dataset/
│   │       └── *.pkl/*.keras   # Trained models
│   └── requirements.txt       # Python dependencies
├── frontend/                   # React Web Application
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   ├── App.js
│   │   ├── Home.jsx
│   │   ├── ThreatDetector.js
│   │   └── *.css
│   └── package.json
├── static/                     # Static assets
└── README.md
```

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.8+
- Node.js 16+
- MongoDB (for logging predictions)
- Git

### Backend Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/palkiranreddyG/WebSentinel-AI.git
   cd WebSentinel-AI
   ```

2. **Set up Python virtual environment**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure MongoDB**
   - Update `backend/app/config.py` with your MongoDB connection string
   - Ensure MongoDB is running locally or update MONGO_URI accordingly

5. **Train the ML models** (optional - pre-trained models included)
   ```bash
   python app/ml_model/train_url_model.py
   python app/ml_model/train_content_model.py
   ```

### Frontend Setup

1. **Navigate to frontend directory**
   ```bash
   cd ../frontend
   ```

2. **Install Node.js dependencies**
   ```bash
   npm install
   ```

3. **Start the development server**
   ```bash
   npm start
   ```

### Running the Application

1. **Start the backend server**
   ```bash
   cd backend
   python run.py
   ```

2. **Start the frontend** (in a new terminal)
   ```bash
   cd frontend
   npm start
   ```

3. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:5000

## 📖 Usage

### Web Interface
1. Open http://localhost:3000 in your browser
2. Enter a suspicious URL in the input field
3. Click "🚀 Check URL" to analyze
4. Review the detailed threat analysis results

### API Usage
```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com"}'
```

**Response Format:**
```json
{
  "url": "https://suspicious-site.com",
  "domain": "suspicious-site.com",
  "probability": 0.85,
  "verdict": "🛑 HIGH RISK",
  "features_detected": 23,
  "total_features": 116,
  "reasons": "Multiple suspicious URL patterns detected...",
  "domain_age": "2 years ago",
  "http_status": 200,
  "spf_dmarc": "Not found",
  "free_hosted": "No",
  "parked_domain": "Not Parked"
}
```

## 🔧 Configuration

### Environment Variables
Create a `.env` file in the backend directory:

```env
MONGO_URI=mongodb://localhost:27017/websentinel
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
```

### Model Configuration
- URL Model: `backend/app/ml_model/url_model.keras`
- Content Model: `backend/app/ml_model/content_model.pkl`
- Scaler: `backend/app/ml_model/url_scaler.pkl`



## 📊 Model Performance

### URL Threat Detection Model
- **Accuracy**: 94.2%
- **Precision**: 93.8%
- **Recall**: 94.6%
- **F1-Score**: 94.2%

### Content Analysis Model
- **Accuracy**: 91.7%
- **Precision**: 92.1%
- **Recall**: 91.3%
- **F1-Score**: 91.7%

## 🛡️ Security Features

- **Input Validation**: Comprehensive URL and input sanitization
- **Rate Limiting**: API endpoint protection against abuse
- **CORS Configuration**: Secure cross-origin resource sharing
- **Error Handling**: Graceful error responses without information leakage
- **Logging**: Comprehensive audit trails for security analysis

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Dataset**: Phishing URL detection dataset from UCI Machine Learning Repository
- **Libraries**: Flask, React, TensorFlow, scikit-learn, BeautifulSoup
- **Icons**: Custom AI-generated icons for UI elements

---

**Built with ❤️ for a safer internet experience**
