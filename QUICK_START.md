# Quick Start Guide

## 🚀 Get Started in 5 Minutes

### 1️⃣ Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2️⃣ Configure Environment
```bash
cd ..
cp .env.example .env
```

Edit `.env`:
```env
FLASK_ENV=development
DEBUG=True
PORT=5000
SECRET_KEY=dev-secret-key
JWT_SECRET=dev-jwt-secret
```

### 3️⃣ Initialize Database
```bash
cd backend
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

### 4️⃣ Run Application
```bash
python app.py
```

### 5️⃣ Access Dashboard
Open browser: `http://localhost:5000/login`

**Default Login:**
- Username: `admin`
- Password: `admin`

---

## 🎯 Main Features

| Feature | URL | Access |
|---------|-----|--------|
| Dashboard | `/dashboard` | All Users |
| Threats | `/dashboard#threats` | Analyst+ |
| Incidents | `/dashboard#incidents` | Analyst+ |
| Analytics | `/dashboard#analytics` | Analyst+ |
| Map | `/dashboard#map` | Analyst+ |
| Reports | `/dashboard#reports` | Analyst+ |
| Settings | `/admin` | Admin |

---

## 📱 Key Pages

### Dashboard (`/dashboard`)
- Real-time threat stats
- System health metrics
- Recent threats
- Interactive charts
- Quick action buttons

### Login Page (`/login`)
- JWT token authentication
- Default credentials
- Session management
- Error handling

### Admin Panel (`/admin`)
- User management
- System settings
- Theme preferences
- Audit logs

---

## 🔑 API Quick Reference

### Login
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

Response:
```json
{
  "success": true,
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {...}
}
```

### Get Threats
```bash
curl http://localhost:5000/api/threats/recent \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Create Incident
```bash
curl -X POST http://localhost:5000/api/incidents \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"Test","severity":7}'
```

---

## 🔐 Users & Roles

### Admin
- Full system access
- User management
- Settings control
- Monitoring control

### Analyst
- View threats
- Manage incidents
- Generate reports
- Block threats

### Viewer
- View only
- No modifications
- Read-only access

---

## 🛠️ Common Commands

### Check Running Process
```bash
# Windows
netstat -ano | findstr :5000

# Linux/Mac
lsof -i :5000
```

### Reset Database
```bash
rm backend/threat_detection.db
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

### Change Admin Password
```bash
python -c "
from app import app, db
from database.models import User
app.app_context().push()
user = User.query.filter_by(username='admin').first()
user.set_password('newpassword')
db.session.commit()
"
```

### View Logs
```bash
tail -f logs/threat_detection.log
```

---

## 🧪 Testing the System

### 1. Login
- Go to http://localhost:5000/login
- Use admin / admin

### 2. View Dashboard
- Check real-time metrics
- Verify charts load

### 3. Start Monitoring
- Click "Start" button
- Observe threat updates

### 4. Create Incident
- Go to Incidents tab
- Fill form and create

### 5. Generate Report
- Go to Reports tab
- Select format and generate

---

## ⚙️ Configuration Options

### .env Variables
```env
# Flask
FLASK_ENV=development
DEBUG=True
PORT=5000

# Security
SECRET_KEY=your-secret-key
JWT_SECRET=your-jwt-secret

# Database
DATABASE_URL=sqlite:///threat_detection.db

# AI
GEMINI_API_KEY=your-api-key

# Email (Optional)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=email@gmail.com
MAIL_PASSWORD=app-password

# Theme
THEME=dark
```

---

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Change PORT in .env to 5001, 5002, etc.
```

### Database Error
```bash
# Reset database
rm backend/threat_detection.db
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

### Import Error
```bash
# Reinstall dependencies
pip install -r backend/requirements.txt --force-reinstall
```

### Can't Login
- Check .env file exists
- Verify database created
- Check browser console for errors

---

## 📚 Documentation

- **Full Docs:** See `README_ENHANCED.md`
- **Setup Guide:** See `INSTALLATION_GUIDE.md`
- **Architecture:** See `IMPLEMENTATION_SUMMARY.md`
- **File Structure:** See `FILE_STRUCTURE.md`

---

## 🎨 UI Themes

### Toggle Theme
- Click moon icon in navbar
- Or use JavaScript console:
```javascript
toggleTheme()
```

### Available Themes
- Light mode (blue accent)
- Dark mode (dark blue accent)

---

## 🔄 Real-Time Features

### WebSocket Events
```javascript
// Threat detected
socket.on('threat_detected', (threat) => {
  console.log('New threat:', threat);
});

// Metrics updated
socket.on('metrics_update', (metrics) => {
  console.log('New metrics:', metrics);
});

// Alert triggered
socket.on('alert_triggered', (alert) => {
  console.log('Alert:', alert);
});
```

---

## 📊 Database Models

**11 Tables:**
1. users - User accounts
2. threats - Detected threats
3. alerts - Security alerts
4. incidents - Incidents
5. playbooks - Response playbooks
6. notifications - Notifications
7. reports - Generated reports
8. system_metrics - Performance data
9. network_flows - Network traffic
10. geolocations - IP locations
11. incident_responses - Response tracking

---

## 🚀 Production Deployment

### Using Gunicorn
```bash
pip install gunicorn
gunicorn --workers 4 --bind 0.0.0.0:5000 app:app
```

### Using Docker
```bash
docker build -t threat-detection .
docker run -p 5000:5000 threat-detection
```

### Using Docker Compose
```bash
docker-compose up -d
```

---

## 🔒 Security Checklist

- [ ] Change default admin password
- [ ] Change SECRET_KEY and JWT_SECRET
- [ ] Set DEBUG=False in production
- [ ] Use HTTPS/TLS
- [ ] Configure CORS properly
- [ ] Set up database backups
- [ ] Enable audit logging
- [ ] Configure firewall rules

---

## 📞 Need Help?

1. Check logs: `logs/threat_detection.log`
2. Review docs: See documentation files
3. Check console: Browser F12 for JS errors
4. Verify config: Check .env file

---

## ✅ You're All Set!

Your threat detection framework is ready to use. 

**Next steps:**
1. Explore the dashboard
2. Create test incidents
3. Configure email alerts
4. Integrate with your systems
5. Set up monitoring

**Happy threat hunting! 🔍**

---

*Version: 1.0.0*  
*Last Updated: May 28, 2026*
