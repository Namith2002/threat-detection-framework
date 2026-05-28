# Installation & Setup Guide

## Quick Installation Steps

### Step 1: Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### Step 2: Environment Configuration

Create a `.env` file in the root directory:

```bash
cp .env.example .env
```

Edit `.env` with your settings:
```env
FLASK_ENV=development
DEBUG=True
PORT=5000
SECRET_KEY=your-secret-key
JWT_SECRET=your-jwt-secret
DATABASE_URL=sqlite:///threat_detection.db
GEMINI_API_KEY=your-gemini-api-key
```

### Step 3: Initialize Database

```bash
cd backend
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

This creates:
- Default admin user (username: admin, password: admin)
- Default analyst user (username: analyst, password: analyst)
- All database tables

### Step 4: Run the Application

```bash
python app.py
```

The app will be available at: `http://localhost:5000`

---

## Default Login Credentials

| Role | Username | Password |
|------|----------|----------|
| Admin | admin | admin |
| Analyst | analyst | analyst |

⚠️ **IMPORTANT:** Change these credentials in production!

---

## Features Overview

### 🔐 Authentication
- JWT token-based authentication
- Role-based access control (Admin, Analyst, Viewer)
- Secure password hashing

### 📊 Dashboard
- Real-time threat statistics
- System health monitoring
- Recent threat display
- Interactive charts

### 🔍 Threat Intelligence
- Advanced threat search and filtering
- Detailed threat analysis
- AI-powered insights (Gemini)
- Threat source blocking

### 🛡️ Incident Management
- Create and track incidents
- Assign incidents to analysts
- Track incident status
- Document mitigation steps

### 📋 Analytics & Reports
- Custom report generation
- Multi-format export (PDF, CSV, JSON, HTML)
- Threat trend analysis
- Severity distribution charts

### 🌍 Geolocation Map
- Threat origin visualization
- Network topology mapping
- Top attacker identification

### 👥 User Management
- Create/edit/delete users
- Role-based permissions
- User activity tracking

### ⚙️ Settings
- System configuration
- Alert preferences
- API integration
- Theme settings (Dark/Light)

---

## API Usage Examples

### Login
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin"}'
```

Response:
```json
{
  "success": true,
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin",
    "email": "admin@threatdetection.local"
  }
}
```

### Get Recent Threats
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:5000/api/threats/recent?limit=10
```

### Create Incident
```bash
curl -X POST http://localhost:5000/api/incidents \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Suspicious Login Attempt",
    "description": "Multiple failed login attempts detected",
    "severity": 7,
    "threat_type": "brute_force"
  }'
```

### Get System Metrics
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:5000/api/system/metrics
```

---

## Database Structure

### Key Tables

**Users**
- `id`, `user_id`, `username`, `email`, `password_hash`, `role`, `is_active`, `last_login`

**Threats**
- `id`, `threat_id`, `source_ip`, `destination_ip`, `threat_type`, `severity`, `confidence`, `detected_at`

**Incidents**
- `id`, `incident_id`, `title`, `description`, `status`, `severity`, `assigned_to_id`, `created_by_id`

**Alerts**
- `id`, `alert_id`, `threat_id`, `alert_type`, `message`, `severity`, `resolved`, `created_at`

**Reports**
- `id`, `report_id`, `title`, `report_type`, `generated_by_id`, `file_format`, `generated_at`

**Notifications**
- `id`, `notification_id`, `user_id`, `title`, `message`, `is_read`, `created_at`

---

## WebSocket Events

### Client to Server
- `request_threat_update` - Request latest threats
- `start_monitoring` - Start threat monitoring
- `stop_monitoring` - Stop threat monitoring
- `get_system_status` - Get system status

### Server to Client
- `threat_detected` - New threat detected
- `metrics_update` - System metrics updated
- `alert_triggered` - Alert triggered
- `monitoring_status` - Monitoring status changed

---

## Configuration Details

### GEMINI_API_KEY
Get your API key from: https://ai.google.dev/
- Required for AI-powered threat analysis
- Used for intelligent recommendations

### MAIL Configuration
For email alerts, configure SMTP:
```env
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### DATABASE_URL
- SQLite (default): `sqlite:///threat_detection.db`
- PostgreSQL: `postgresql://user:password@localhost/dbname`
- MySQL: `mysql+pymysql://user:password@localhost/dbname`

---

## Troubleshooting

### Port Already in Use
```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux/Mac
lsof -i :5000
kill -9 <PID>
```

### Database Issues
```bash
# Reset database
rm threat_detection.db
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

### Authentication Fails
- Ensure `.env` file is in the root directory
- Check that `SECRET_KEY` and `JWT_SECRET` are set
- Database users table is populated

### Threats Not Appearing
- Check if monitoring is started (button in dashboard)
- Verify threat detector is working
- Check logs for errors

---

## Performance Optimization

### For Production
1. Use PostgreSQL instead of SQLite
2. Enable caching (Redis)
3. Use Gunicorn with multiple workers
4. Set up Nginx reverse proxy
5. Enable GZIP compression
6. Use CDN for static files

### Recommended Production Setup
```bash
gunicorn --workers 4 --worker-class eventlet \
  --bind 0.0.0.0:5000 \
  --log-level info \
  app:app
```

---

## Security Checklist

- [ ] Change default admin password
- [ ] Set `DEBUG = False` in production
- [ ] Use HTTPS/TLS
- [ ] Configure CORS properly
- [ ] Set strong `SECRET_KEY` and `JWT_SECRET`
- [ ] Enable database authentication
- [ ] Set up firewall rules
- [ ] Enable audit logging
- [ ] Regular backups
- [ ] Keep dependencies updated

---

## Deployment Options

### Docker
```bash
docker build -t threat-detection .
docker run -p 5000:5000 -e FLASK_ENV=production threat-detection
```

### Docker Compose
```bash
docker-compose up -d
```

### Cloud Platforms
- AWS: Use EC2 + RDS
- Azure: Use App Service + Azure SQL
- GCP: Use Cloud Run + Cloud SQL
- Heroku: Push to Heroku Git

---

## Support & Troubleshooting

For issues:
1. Check the logs: `logs/threat_detection.log`
2. Review the documentation
3. Check GitHub issues
4. Contact support team

---

## Next Steps

1. **Change default passwords** for security
2. **Configure Gemini API key** for AI features
3. **Set up email notifications** (optional)
4. **Integrate with Slack** (optional)
5. **Configure database backups**
6. **Set up monitoring** (Prometheus, Grafana)

---

**Version:** 1.0.0
**Last Updated:** May 28, 2026
