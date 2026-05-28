# Advanced Cyber Threat Detection & Response Framework

A comprehensive, real-time cybersecurity platform for detecting, analyzing, and responding to security threats with AI-powered insights and automated incident management.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.3%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## ✨ Features

### 🔍 **Real-Time Threat Detection**
- Live threat monitoring with WebSocket updates
- Multiple threat classification (Malware, DDoS, SQL Injection, XSS, Brute Force, etc.)
- AI-powered threat analysis using Google Gemini API
- Confidence scoring and severity assessment

### 📊 **Advanced Analytics Dashboard**
- Real-time metrics and statistics
- Interactive charts (threat trends, severity distribution, threat types)
- System health monitoring (CPU, Memory, Network, Disk)
- Custom reporting and data export

### 🛡️ **Incident Management**
- Create and track security incidents
- Automated incident response workflows
- Incident assignment and status tracking
- Mitigation steps and impact assessment documentation

### 🔐 **User Management & Authentication**
- JWT-based authentication with role-based access control
- Three user roles: Admin, Analyst, Viewer
- User activity tracking and audit logging
- Secure session management

### 🌍 **Geolocation & Network Intelligence**
- IP geolocation mapping with Leaflet.js
- Threat origin visualization
- Network topology mapping
- Top attacker identification

### 📋 **Comprehensive Reporting**
- Multi-format export (PDF, CSV, JSON, HTML)
- Customizable report generation
- Daily, weekly, monthly, and custom reports
- Threat summaries and trends analysis

### 🎨 **Modern Dark/Light UI**
- Responsive Bootstrap 5 design
- Dark mode and light mode themes
- Mobile-friendly interface
- Real-time notification system

### 🤖 **AI-Powered Features**
- Google Gemini AI integration for threat analysis
- Automated threat classification
- Intelligent mitigation recommendations
- Threat pattern recognition

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip
- SQLite (or PostgreSQL for production)
- Node.js (optional, for front-end tools)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/threat-detection-framework.git
cd threat-detection-framework
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r backend/requirements.txt
```

4. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your settings
```

5. **Initialize database**
```bash
cd backend
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

6. **Run the application**
```bash
python app.py
```

The application will be available at `http://localhost:5000`

### Default Credentials
- **Username:** admin
- **Password:** admin

⚠️ **Important:** Change these credentials in production!

---

## 📖 Usage Guide

### Dashboard
- View real-time threat statistics
- Monitor system health metrics
- Track recent threats and alerts
- Access quick action tools

### Threat Intelligence
- Search and filter detected threats
- View detailed threat analysis
- Create incidents from threats
- Block threat source IPs

### Incident Management
- Create new incidents
- Assign incidents to analysts
- Track incident status (Open → In Progress → Resolved)
- Document mitigation steps and impact

### Analytics & Reports
- Generate custom reports
- Export data in multiple formats
- Analyze threat trends
- Create threat summaries

### Settings
- Configure user accounts and roles
- Manage API keys and integrations
- Set alert preferences
- Configure system settings

---

## 🏗️ Architecture

### Backend
- **Framework:** Flask with Flask-SocketIO
- **Database:** SQLAlchemy ORM (SQLite/PostgreSQL)
- **Authentication:** JWT tokens with role-based access
- **AI Integration:** Google Gemini API
- **Real-time:** WebSocket for live updates

### Frontend
- **Framework:** Vanilla JavaScript (no build required)
- **UI Library:** Bootstrap 5 + Custom CSS
- **Charts:** Chart.js
- **Maps:** Leaflet.js
- **Real-time:** Socket.IO client

### Database Models
- `User` - User accounts and authentication
- `Threat` - Detected security threats
- `Alert` - Security alerts triggered
- `Incident` - Security incidents and responses
- `Playbook` - Incident response playbooks
- `Report` - Generated reports and exports
- `Notification` - User notifications
- `SystemMetrics` - System performance data
- `GeoLocation` - IP geolocation data

---

## 🔌 API Endpoints

### Authentication
- `POST /api/auth/login` - Login and get JWT token

### Threats
- `GET /api/threats` - List all threats
- `GET /api/threats/<id>` - Get threat details
- `GET /api/threats/recent` - Get recent threats
- `GET /api/threats/stats` - Get threat statistics
- `POST /api/threats/<id>/block` - Block threat source IP

### Incidents
- `GET /api/incidents` - List incidents
- `POST /api/incidents` - Create incident
- `PUT /api/incidents/<id>` - Update incident
- `GET /api/incidents/<id>` - Get incident details

### Analytics
- `GET /api/analytics/threat-trends` - Threat trend data
- `GET /api/analytics/severity-distribution` - Severity distribution
- `GET /api/analytics/threat-types` - Threat types statistics

### System
- `GET /api/system/metrics` - Current system metrics
- `POST /api/monitoring/start` - Start threat monitoring
- `POST /api/monitoring/stop` - Stop threat monitoring

### Reports
- `POST /api/reports/generate` - Generate report
- `GET /api/reports` - List generated reports

---

## 🔧 Configuration

### Environment Variables
See `.env.example` for all available configuration options.

**Key settings:**
```env
FLASK_ENV=development
DEBUG=False
PORT=5000
DATABASE_URL=sqlite:///threat_detection.db
GEMINI_API_KEY=your-api-key
MAIL_SERVER=smtp.gmail.com
```

### Database
By default, SQLite is used. For production, configure PostgreSQL:
```env
DATABASE_URL=postgresql://username:password@localhost/threatdb
```

---

## 🔒 Security Features

- ✅ JWT token-based authentication
- ✅ Password hashing with bcrypt
- ✅ HTTPS/TLS ready
- ✅ CORS protection
- ✅ SQL injection protection (SQLAlchemy ORM)
- ✅ XSS protection
- ✅ CSRF tokens for forms
- ✅ Role-based access control
- ✅ Audit logging

---

## 📦 Deployment

### Docker
```bash
docker build -t threat-detection .
docker run -p 5000:5000 threat-detection
```

### Docker Compose
```bash
docker-compose up -d
```

### Production (Gunicorn + Nginx)
```bash
gunicorn --workers 4 --bind 0.0.0.0:5000 app:app
```

---

## 🧪 Testing

Run tests:
```bash
pytest tests/
```

---

## 📝 File Structure

```
threat-detection-framework/
├── backend/
│   ├── app.py                 # Main Flask application
│   ├── config.py              # Configuration settings
│   ├── requirements.txt        # Python dependencies
│   ├── database/
│   │   └── models.py          # Database models
│   ├── utils/
│   │   ├── threat_detector.py
│   │   ├── threat_classifier.py
│   │   ├── data_analyzer.py
│   │   └── gemini_analyzer.py
│   ├── static/
│   │   ├── css/
│   │   │   ├── style.css
│   │   │   └── bootstrap-custom.css
│   │   └── js/
│   │       ├── main.js
│   │       └── app.js
│   └── templates/
│       ├── index.html
│       ├── dashboard.html
│       └── login.html
├── .env.example               # Environment variables template
├── docker-compose.yml         # Docker Compose configuration
├── Dockerfile                 # Docker configuration
└── README.md                  # This file
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📋 Roadmap

- [ ] Machine learning model for advanced threat prediction
- [ ] Multi-tenancy support
- [ ] Mobile app (React Native)
- [ ] Kubernetes deployment ready
- [ ] Elasticsearch integration for log analysis
- [ ] GraphQL API support
- [ ] Advanced threat hunting features
- [ ] MITRE ATT&CK mapping
- [ ] Honeypot integration
- [ ] Blockchain-based audit logs

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🆘 Support

For issues, questions, or suggestions:
- Create an issue on GitHub
- Contact the development team
- Check documentation at `/docs`

---

## 👥 Team

- **Security Lead:** Your Name
- **Lead Developer:** Your Name
- **DevOps:** Your Name

---

## 🙏 Acknowledgments

- Google Gemini API for AI threat analysis
- Flask and Flask-SocketIO communities
- Chart.js for beautiful visualizations
- Leaflet.js for mapping capabilities

---

## ⭐ Show Your Support

Give a ⭐️ if this project helped you!

---

**Last Updated:** May 28, 2026
**Version:** 1.0.0
