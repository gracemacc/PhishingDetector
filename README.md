# Phishing Email Detector 🛡️

A professional web application that analyzes suspicious email files (.eml format) to detect phishing attempts. Built with Flask and featuring a modern, responsive UI, this tool provides detailed risk assessments with visual reports showing threat levels, detected indicators, and safety recommendations.

![Phishing Email Detector Demo](https://via.placeholder.com/800x400/2563eb/ffffff?text=Phishing+Email+Detector+Demo)

## 🌟 Features

### Core Functionality
- **📧 Multi-format Support**: Accepts `.eml`, `.msg`, and `.txt` files
- **📊 Risk Scoring**: 0-100 point-based scoring system with color-coded visualization
- **🔍 Comprehensive Analysis**: Checks headers, sender, content, links, and attachments
- **🌐 External API Integration**: Google Safe Browsing and VirusTotal for URL reputation
- **⚡ Real-time Analysis**: Progress indicators and fast processing
- **📱 Responsive Design**: Works perfectly on desktop and mobile devices

### Detection Categories
- **Header Spoofing**: SPF/DKIM/DMARC authentication, display name mismatches
- **Sender Anomalies**: Typosquatting detection, free email abuse
- **Urgency Language**: Threat keywords, pressure tactics
- **Body Red Flags**: Credential requests, generic greetings, threats
- **Suspicious Links**: Shortened URLs, reputation checks
- **Dangerous Attachments**: Executable files, suspicious naming

### Professional UI
- **Modern Design**: Clean, professional interface inspired by security tools
- **Visual Risk Gauge**: Animated circular progress indicator
- **Detailed Reports**: Expandable threat breakdown with clear explanations
- **Export Instructions**: Step-by-step guides for major email clients

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- pip package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/phishing-email-detector.git
   cd phishing-email-detector
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env file with your API keys
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Open in browser**
   Navigate to `http://localhost:5000`

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the root directory:

```bash
# Flask Configuration
SECRET_KEY=your-secret-key-here
FLASK_ENV=development

# API Keys (Optional - will work without but with reduced functionality)
GOOGLE_SAFE_BROWSING_API_KEY=your-google-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key

# Security Settings
MAX_FILE_SIZE=10485760  # 10MB in bytes
SESSION_TIMEOUT=3600    # 1 hour
```

### Getting API Keys

#### Google Safe Browsing API
1. Visit [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable the Safe Browsing API
4. Create credentials (API key)
5. Add the key to your `.env` file

#### VirusTotal API
1. Visit [VirusTotal](https://www.virustotal.com/)
2. Sign up for a free account
3. Go to your profile → API key
4. Copy the key to your `.env` file

## 📊 Scoring System

Our point-based scoring system evaluates emails across multiple categories:

| Category | Max Points | Key Indicators |
|----------|------------|----------------|
| Header Spoofing | 40 | SPF/DKIM failures, display name mismatches |
| Sender Anomalies | 20 | Typosquatting, free email abuse |
| Urgency Language | 15 | Threat keywords, pressure tactics |
| Body Red Flags | 15 | Credential requests, generic greetings |
| Suspicious Links | 30 | Shortened URLs, malicious reputation |
| Dangerous Attachments | 25 | Executable files, suspicious names |

### Risk Levels
- **🟢 0-30**: Low Risk (Safe) - Email appears legitimate
- **🟡 31-60**: Medium Risk (Suspicious) - Manual review recommended
- **🔴 61-100**: High Risk (Phishing) - Strong indicators of malicious intent

## 🛠️ Technical Architecture

### Backend
- **Framework**: Flask 2.3 with Python 3.9+
- **Email Parsing**: Python built-in `email` module + BeautifulSoup4
- **Security**: Input validation, file size limits, MIME type checking
- **Caching**: In-memory URL reputation caching (Redis-ready)

### Frontend
- **Framework**: HTML5 + CSS3 + Vanilla JavaScript
- **Styling**: Bootstrap 5 with custom CSS
- **Icons**: Font Awesome 6
- **Charts**: Custom CSS animations (Chart.js ready)

### External Integrations
- **Google Safe Browsing API**: URL reputation checking
- **VirusTotal API**: Multi-engine URL scanning
- **Rate Limiting**: Built-in request queuing and delays

## 🐳 Docker Deployment

### Using Docker

1. **Build the image**
   ```bash
   docker build -t phishing-detector .
   ```

2. **Run the container**
   ```bash
   docker run -d -p 5000:5000 --env-file .env phishing-detector
   ```

### Docker Compose

```yaml
version: '3.8'
services:
  phishing-detector:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
      - SECRET_KEY=${SECRET_KEY}
      - GOOGLE_SAFE_BROWSING_API_KEY=${GOOGLE_SAFE_BROWSING_API_KEY}
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
    restart: unless-stopped
```

## ☁️ Cloud Deployment

### Render (Recommended)

1. Fork this repository
2. Create a new Web Service on [Render](https://render.com/)
3. Connect your GitHub repository
4. Set environment variables in Render dashboard
5. Deploy!

### Heroku

1. Install Heroku CLI
2. Create a new app: `heroku create your-app-name`
3. Set environment variables: `heroku config:set SECRET_KEY=your-secret-key`
4. Deploy: `git push heroku main`

### Railway

1. Connect your GitHub repository to [Railway](https://railway.app/)
2. Set environment variables in Railway dashboard
3. Deploy automatically on push

## 🧪 Testing

### Sample Phishing Email

Create a `.eml` file with this content to test:

```
From: PayPal Security <security@paypaI.com>
To: user@example.com
Subject: Urgent: Verify your account now or it will be suspended!
Date: Mon, 22 Dec 2024 10:00:00 +0000

Dear Customer,

Your PayPal account has been temporarily restricted due to suspicious activity. 
You must verify your identity immediately or your account will be permanently suspended.

Click here to verify: http://bit.ly/verify-paypal-account

This is your final notice. Act now to prevent account closure.

Best regards,
PayPal Security Team
```

### Expected Results
- **Risk Score**: 70-85 (High Risk)
- **Verdict**: Likely Phishing
- **Key Findings**:
  - Typosquatting domain (paypaI.com vs paypal.com)
  - Urgency language and threats
  - Shortened suspicious URL
  - Generic greeting

## 🔒 Security Considerations

### Input Validation
- File size limits (10MB max)
- MIME type verification
- Content sanitization
- Path traversal protection

### API Security
- Environment variable protection
- Rate limiting on external APIs
- Request timeouts (30s max)
- Error message sanitization

### File Handling
- No attachment execution
- Temporary file cleanup
- Memory usage limits
- Content-type validation

## 🎯 Use Cases

### Personal Security
- Verify suspicious emails before clicking links
- Check forwarded emails from friends/family
- Analyze phishing attempts for reporting

### Corporate Security
- Employee security awareness training
- Incident response and analysis
- Security team workflow integration

### Educational Purposes
- Cybersecurity course demonstrations
- Phishing awareness workshops
- Security research and analysis

## 📈 Future Enhancements

### Machine Learning Integration
- NLP-based content analysis
- Behavioral pattern recognition
- Adaptive scoring algorithms

### Advanced Features
- Email thread analysis
- Attachment sandboxing
- Integration with SIEM systems
- API for automated workflows

### UI Improvements
- Dark mode support
- Exportable PDF reports
- Historical analysis dashboard
- Real-time collaboration

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes and add tests
4. Commit: `git commit -m 'Add amazing feature'`
5. Push: `git push origin feature/amazing-feature`
6. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Google Safe Browsing API** for URL reputation data
- **VirusTotal** for multi-engine scanning
- **Bootstrap** for responsive UI framework
- **Flask** for lightweight web framework
- **Font Awesome** for beautiful icons

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/phishing-email-detector/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/phishing-email-detector/discussions)
- **Email**: your.email@example.com

---

**⚠️ Disclaimer**: This tool is for educational and awareness purposes. Always verify suspicious emails through official channels and report phishing attempts to appropriate authorities.

**🛡️ Stay Safe**: Never click suspicious links or download attachments from unknown senders. When in doubt, verify directly with the supposed sender through official channels.