# 🏦 MANS Bank - Intelligent Banking Platform with AI Threat Detection

> A modern digital banking application featuring an advanced AI-powered cybersecurity defense system

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://choosealicense.com/licenses/mit/)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org/)
[![Flask](https://img.shields.io/badge/Flask-3.1+-black.svg)](https://flask.palletsprojects.com/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)

## 📋 Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [CyberGuardAI](#cyberguardai-threat-detection-system)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Learning Outcomes](#learning-outcomes)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

MANS Bank is a comprehensive digital banking platform built as an educational project to demonstrate modern web development practices and advanced cybersecurity concepts. The project showcases a full-stack application with dual backend implementations (Python Flask and Node.js/TypeScript) and features an intelligent threat detection system powered by AI.

## ✨ Key Features

### Banking Features
- 🔐 **Secure Authentication** - Session-based auth with bcrypt password hashing
- 💳 **Account Management** - Real-time balance tracking and transaction history
- 💰 **Transaction Processing** - Send/receive money, view detailed transaction logs
- 📊 **User Dashboard** - Intuitive interface for managing finances

### Admin Features
- 👥 **User Management** - Add funds, block/unblock users, account administration
- 📈 **Analytics Dashboard** - Real-time statistics and system health monitoring
- 🔍 **Security Monitoring** - Login attempt tracking and security event logging
- 🛡️ **CyberGuardAI** - Advanced threat detection and analysis system

### Security Features
- 🤖 **AI-Powered Threat Detection** - 11 comprehensive threat detection algorithms
- 🔒 **Brute Force Protection** - Automatic detection and blocking of suspicious login attempts
- 📝 **Security Event Logging** - Complete audit trail of security-related activities
- ⚠️ **Real-time Alerts** - Instant notifications for detected threats

## 🛡️ CyberGuardAI Threat Detection System

The crown jewel of this project is **CyberGuardAI**, an advanced security system that detects and analyzes cybersecurity threats using both pattern-matching algorithms and optional AI enhancement.

### Detected Threat Types (11 Categories)

| Threat Type | Severity | Example Attack |
|-------------|----------|----------------|
| SQL Injection | High | `' OR 1=1 --` |
| XSS (Cross-Site Scripting) | High | `<script>alert('XSS')</script>` |
| Command Injection | Critical | `; rm -rf /` |
| Path Traversal | High | `../../etc/passwd` |
| LDAP Injection | High | `*)(uid=*))(` |
| XXE (XML External Entity) | Critical | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| NoSQL Injection | High | `{"$ne": null}` |
| SSRF | Critical | `http://localhost/admin` |
| Header Injection | Medium | `\r\nSet-Cookie: admin=true` |
| Email Injection | Medium | `\nbcc:attacker@evil.com` |
| Malicious File Upload | High | `malware.php` |

### How It Works

```
User Input → Local Pattern Detection (11 detectors) → Threat Classification
                         ↓
              Optional: AI Analysis (Groq API)
                         ↓
              Severity Assessment + Recommendations
                         ↓
              Logging & Dashboard Visualization
```

**Dual-Layer Protection:**
1. **Local Detection** - Regex-based pattern matching (works offline)
2. **AI Enhancement** - Groq API with Llama 3.3 70B for context-aware analysis (optional)

## 🛠️ Tech Stack

### Backend
- **Python Flask** - RESTful API server with comprehensive security middleware
- **Node.js/TypeScript** - Alternative Express.js implementation
- **Flask-CORS** - Cross-origin resource sharing support
- **Werkzeug** - Password hashing and security utilities

### Frontend
- **Vanilla JavaScript** - No framework dependencies, pure ES6+
- **HTML5/CSS3** - Modern, responsive design
- **Google Fonts** - Inter & Space Grotesk typography

### AI/ML
- **Groq API** - Advanced threat analysis and classification using Llama 3.3 70B
- **Pattern Recognition** - 200+ regex patterns for threat detection

### Security
- **Session Management** - HTTP-only cookies with secure flags
- **Password Hashing** - Industry-standard bcrypt implementation
- **CSRF Protection** - Cross-site request forgery prevention
- **Input Validation** - Comprehensive sanitization and validation

## 📦 Installation

### Prerequisites
- Python 3.11 or higher
- Node.js 20 or higher
- npm or yarn package manager

### Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/mrvoidx/Intelligent-Fake-Banking-Platform-with-AI-Threat-Detection.git
cd Intelligent-Fake-Banking-Platform-with-AI-Threat-Detection
```

2. **Install dependencies**
```bash
npm install
```

3. **Start the development server**
```bash
npm run dev
```

4. **Access the application**
```
http://localhost:5000
```

### Optional: Enable AI Features

Get a free Groq API key from [Groq Console](https://console.groq.com)

```bash
export GROQ_API_KEY="your-api-key-here"
npm run dev
```

## 🚀 Usage Guide

### For Regular Users

1. **Sign Up**: Navigate to `/signup.html` and create an account
2. **Login**: Access your dashboard at `/dashboard.html`
3. **View Transactions**: Monitor your account activity and balance
4. **Logout**: Securely end your session

### For Administrators

1. **Login** with admin credentials:
   - Email: `admin@mans.bank`
   - Password: `admin123`

2. **Access Admin Dashboard**: Navigate to `/admin-dashboard.html`

3. **Manage Users**: Add funds, block accounts, or delete users

4. **Monitor Security**: View login attempts and security events

5. **Test CyberGuardAI**: Analyze text for security threats

## 🧪 Testing

### Quick Security Test

1. Login as admin and navigate to **CyberGuardAI**
2. Try these test inputs:

**SQL Injection:**
```sql
' OR 1=1 --
```

**XSS Attack:**
```html
<script>alert('XSS')</script>
```

**Command Injection:**
```bash
; cat /etc/passwd
```

**Expected Result:** Each should be detected with severity level and explanation

### Comprehensive Testing

See [THREAT_TESTING_GUIDE.md](THREAT_TESTING_GUIDE.md) for 44 detailed test cases covering all threat types.

### Unit Testing (Future)
```bash
# Python tests
pytest tests/

# JavaScript tests
npm test
```

## 📁 Project Structure

```
Intelligent-Fake-Banking-Platform-with-AI-Threat-Detection/
├── server.py                      # Python Flask backend
├── server/
│   └── index-dev.ts              # Node.js/TypeScript backend
├── *.html                         # Frontend pages
│   ├── index.html                # Landing page
│   ├── login.html                # Login page
│   ├── signup.html               # Registration page
│   ├── dashboard.html            # User dashboard
│   └── admin-dashboard.html      # Admin control panel
├── *.js                          # Frontend scripts
│   ├── script.js                 # Landing page logic
│   ├── auth.js                   # Authentication handler
│   ├── dashboard.js              # User dashboard logic
│   └── admin-dashboard.js        # Admin panel + CyberGuardAI
├── styles.css                    # Global styles
├── THREAT_TESTING_GUIDE.md       # Comprehensive testing documentation
├── replit.md                     # Technical documentation
└── README.md                     # This file
```

## 📚 Learning Outcomes

This project demonstrates proficiency in:

### Web Development
✅ Full-stack application architecture  
✅ RESTful API design and implementation  
✅ Session management and authentication  
✅ Responsive UI/UX design principles  
✅ State management without frameworks  

### Cybersecurity
✅ OWASP Top 10 vulnerabilities  
✅ Threat detection algorithms  
✅ Security event logging and monitoring  
✅ Input validation and sanitization  
✅ Secure coding practices  

### Software Engineering
✅ Clean code principles  
✅ Dual backend implementation (Python & Node.js)  
✅ Error handling and logging  
✅ Documentation and code comments  
✅ Version control with Git  

### AI/ML Integration
✅ API integration with Groq  
✅ Prompt engineering for security analysis  
✅ Fallback strategies for offline operation  
✅ AI-enhanced decision making  

## 🔮 Future Enhancements

### Planned Features
- [ ] **Database Integration** - PostgreSQL for persistent data storage
- [ ] **Real-time Notifications** - WebSocket-based live updates
- [ ] **Two-Factor Authentication** - Enhanced security with TOTP
- [ ] **Transaction Export** - PDF/CSV download functionality
- [ ] **Mobile App** - React Native mobile application
- [ ] **Machine Learning** - Train custom threat detection models
- [ ] **API Rate Limiting** - Protect against abuse
- [ ] **Comprehensive Testing** - Unit and integration test coverage

### Advanced Security Features
- [ ] **Behavioral Analytics** - Detect anomalous user behavior
- [ ] **Threat Intelligence Feed** - Real-time CVE database integration
- [ ] **Automated Response** - Auto-block on critical threats
- [ ] **Security Dashboard** - Enhanced visualization with charts
- [ ] **Compliance Reporting** - Generate security audit reports

## 🤝 Contributing

Contributions are welcome! This is an educational project and feedback helps improve it.

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Coding Standards
- Follow existing code style and formatting
- Add comments for complex logic
- Update documentation for new features
- Test thoroughly before submitting

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.


## 🙏 Acknowledgments

- **OWASP** - For comprehensive security guidelines and vulnerability documentation
- **Groq AI** - For providing free AI API access for educational purposes
- **Flask Community** - For excellent documentation and support
- **Replit** - For providing a development environment and hosting platform

---

### 📊 Project Stats

- **Lines of Code**: ~4,500+
- **Development Time**: 21 days
- **Threat Patterns**: 200+
- **Test Cases**: 44
- **Languages**: Python, TypeScript, JavaScript, HTML, CSS

---

<div align="center">

**⭐ If you find this project useful, please consider giving it a star!**

Made with ❤️ for learning and cybersecurity education

</div>
