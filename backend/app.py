"""
Real-Time Automated Cyber Threat Classification and Detection Framework
Advanced Python Backend - Flask with WebSocket support for real-time threat processing
Enhanced with authentication, incident management, and reporting
"""

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, login_required, current_user
import logging
from datetime import datetime, timedelta
import json
import threading
import os
import uuid
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

import jwt
from functools import wraps

# Import custom modules
from utils.threat_detector import ThreatDetector
from utils.threat_classifier import ThreatClassifier
from utils.data_analyzer import DataAnalyzer
from utils.gemini_analyzer import GeminiThreatAnalyzer
from database.models import (
    db, Threat, Alert, SystemMetrics, NetworkFlow, IncidentResponse,
    User, Incident, Playbook, Notification, GeoLocation, Report
)
from config import Config

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize extensions
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize threat detection components
threat_detector = ThreatDetector()
threat_classifier = ThreatClassifier(gemini_api_key=app.config.get('GEMINI_API_KEY', ''))
data_analyzer = DataAnalyzer()
gemini_analyzer = GeminiThreatAnalyzer(
    api_key=app.config.get('GEMINI_API_KEY', ''),
    model=app.config.get('GEMINI_MODEL', 'gemini-pro')
)

# Global variables for monitoring
active_connections = {}
monitoring_active = False
monitoring_thread = None


# ============= User Loader =============
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ============= JWT Token Verification =============
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Invalid token format'}), 401
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['JWT_SECRET'], algorithms=[app.config['JWT_ALGORITHM']])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated


# ============= Threat Monitor Thread =============
class ThreatMonitor(threading.Thread):
    """Background thread for continuous threat monitoring"""
    
    def __init__(self, app, socketio):
        super().__init__(daemon=True)
        self.app = app
        self.socketio = socketio
        self.running = True
    
    def run(self):
        """Continuous threat detection loop"""
        with self.app.app_context():
            while self.running:
                try:
                    threats = threat_detector.detect_threats()
                    
                    if threats:
                        for threat in threats:
                            existing_threat = Threat.query.filter_by(threat_id=threat.get('id')).first()
                            if existing_threat:
                                continue
                            
                            classification = threat_classifier.classify(threat)
                            
                            threat_record = Threat(
                                threat_id=threat.get('id'),
                                source_ip=threat.get('source_ip'),
                                destination_ip=threat.get('destination_ip'),
                                threat_type=classification.get('type'),
                                severity=classification.get('severity'),
                                confidence=classification.get('confidence'),
                                payload=json.dumps(threat),
                                detected_at=datetime.utcnow()
                            )
                            db.session.add(threat_record)
                            
                            if classification.get('severity') >= 7:
                                alert = Alert(
                                    threat_id=threat_record.id,
                                    alert_type='CRITICAL_THREAT',
                                    message=f"Critical {classification.get('type')} from {threat.get('source_ip')}",
                                    created_at=datetime.utcnow()
                                )
                                db.session.add(alert)
                            
                            db.session.commit()
                            
                            self.socketio.emit('threat_detected', threat_record.to_dict())
                    
                    metrics = threat_detector.get_system_metrics()
                    system_metrics = SystemMetrics(
                        cpu_usage=metrics.get('cpu'),
                        memory_usage=metrics.get('memory'),
                        network_traffic=metrics.get('network_traffic'),
                        active_threats=Threat.query.filter(
                            Threat.detected_at > datetime.utcnow() - timedelta(hours=1)
                        ).count(),
                        recorded_at=datetime.utcnow()
                    )
                    db.session.add(system_metrics)
                    db.session.commit()
                    
                    self.socketio.emit('metrics_update', {
                        'cpu_usage': metrics.get('cpu'),
                        'memory_usage': metrics.get('memory'),
                        'network_traffic': metrics.get('network_traffic'),
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Error in threat monitoring: {str(e)}")
                
                import time
                time.sleep(5)


# ============= Authentication Routes =============
@app.route('/', methods=['GET'])
def index():
    """Redirect root to login"""
    return redirect(url_for('login'))


@app.route('/favicon.ico')
def favicon():
    """Silence favicon.ico 404s"""
    return '', 204


@app.route('/login', methods=['GET'])
def login():
    """Serve login page"""
    return render_template('login.html')


@app.route('/admin', methods=['GET'])
def admin():
    """Serve admin page"""
    return render_template('admin.html')


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """Authenticate user and return JWT token"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Missing credentials'}), 400
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'success': False, 'message': 'User account is inactive'}), 403
    
    # Generate JWT token
    payload = {
        'user_id': user.id,
        'username': user.username,
        'role': user.role,
        'exp': datetime.utcnow() + timedelta(hours=app.config['JWT_EXPIRY_HOURS'])
    }
    token = jwt.encode(payload, app.config['JWT_SECRET'], algorithm=app.config['JWT_ALGORITHM'])
    
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'token': token,
        'user': user.to_dict()
    }), 200


@app.route('/dashboard', methods=['GET'])
def dashboard():
    """Serve dashboard"""
    return render_template('dashboard.html')


# ============= User Management Routes =============
@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    """Get all users"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    users = User.query.all()
    return jsonify([u.to_dict() for u in users])


@app.route('/api/users', methods=['POST'])
@token_required
def create_user(current_user):
    """Create a new user"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    username = data.get('username')
    email = data.get('email')
    full_name = data.get('full_name')
    role = data.get('role', 'viewer')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already exists'}), 400
        
    new_user = User(
        username=username,
        email=email,
        full_name=full_name,
        role=role,
        is_active=True
    )
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'success': True, 'user': new_user.to_dict()}), 201


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, user_id):
    """Delete a user"""
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
        
    user = User.query.get(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
        
    if user.username == 'admin':
        return jsonify({'success': False, 'message': 'Cannot delete default admin user'}), 400
        
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True, 'message': 'User deleted successfully'})


# ============= Threat Routes =============
@app.route('/api/threats', methods=['GET'])
@token_required
def get_threats(current_user):
    """Get all detected threats with filtering"""
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    severity = request.args.get('severity', None)
    threat_type = request.args.get('type', None)
    ip = request.args.get('ip', None)
    
    query = Threat.query.filter(Threat.threat_type != 'unknown')
    
    if severity:
        query = query.filter(Threat.severity >= int(severity))
    
    if threat_type:
        query = query.filter(Threat.threat_type == threat_type)
        
    if ip:
        query = query.filter((Threat.source_ip.contains(ip)) | (Threat.destination_ip.contains(ip)))
    
    threats = query.order_by(Threat.detected_at.desc()).paginate(page=page, per_page=limit)
    
    return jsonify({
        'total': threats.total,
        'pages': threats.pages,
        'threats': [t.to_dict() for t in threats.items]
    })


@app.route('/api/threats/<int:threat_id>', methods=['GET'])
@token_required
def get_threat_details(current_user, threat_id):
    """Get detailed threat information"""
    threat = Threat.query.get(threat_id)
    if not threat:
        return jsonify({'error': 'Threat not found'}), 404
    
    return jsonify(threat.to_dict())


@app.route('/api/threats/recent', methods=['GET'])
@token_required
def get_recent_threats(current_user):
    """Get recent threats"""
    limit = request.args.get('limit', 10, type=int)
    threats = Threat.query.filter(
        Threat.threat_type != 'unknown'
    ).order_by(Threat.detected_at.desc()).limit(limit).all()
    
    return jsonify([t.to_dict() for t in threats])


@app.route('/api/threats/<int:threat_id>/block', methods=['POST'])
@token_required
def block_threat(current_user, threat_id):
    """Block threat source IP"""
    threat = Threat.query.get(threat_id)
    if not threat:
        return jsonify({'error': 'Threat not found'}), 404
    
    # Create incident response
    response = IncidentResponse(
        threat_id=threat_id,
        response_type='BLOCK_IP',
        status='PENDING',
        details=f'Block IP: {threat.source_ip}'
    )
    db.session.add(response)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Threat source blocked'})


@app.route('/api/threats/stats', methods=['GET'])
@token_required
def get_threat_stats(current_user):
    """Get threat statistics"""
    hour_ago = datetime.utcnow() - timedelta(hours=1)
    day_ago = datetime.utcnow() - timedelta(days=1)
    
    daily_count = Threat.query.filter(
        Threat.detected_at > day_ago,
        Threat.threat_type != 'unknown'
    ).count()
    
    critical_count = Threat.query.filter(
        Threat.severity >= 8,
        Threat.detected_at > day_ago,
        Threat.threat_type != 'unknown'
    ).count()
    
    alert_count = Alert.query.filter(
        Alert.created_at > day_ago
    ).count()
    
    # Extra statistics for key metric cards
    total_threats = Threat.query.filter(Threat.threat_type != 'unknown').count()
    
    avg_sev_query = db.session.query(db.func.avg(Threat.severity)).filter(Threat.threat_type != 'unknown').scalar()
    avg_severity = round(float(avg_sev_query), 2) if avg_sev_query is not None else 0.0
    
    avg_conf_query = db.session.query(db.func.avg(Threat.confidence)).filter(Threat.threat_type != 'unknown').scalar()
    avg_confidence = round(float(avg_conf_query), 2) if avg_conf_query is not None else 0.0
    
    incident_count = Incident.query.filter(Incident.status != 'RESOLVED').count()
    
    return jsonify({
        'daily_count': daily_count,
        'critical_count': critical_count,
        'alert_count': alert_count,
        'total_threats': total_threats,
        'avg_severity': avg_severity,
        'avg_confidence': avg_confidence,
        'incident_count': incident_count
    })


# ============= Incidents Routes =============
@app.route('/api/incidents', methods=['GET'])
@token_required
def get_incidents(current_user):
    """Get all incidents"""
    status = request.args.get('status', None)
    limit = request.args.get('limit', 20, type=int)
    
    query = Incident.query
    if status:
        query = query.filter_by(status=status)
    
    incidents = query.order_by(Incident.created_at.desc()).limit(limit).all()
    return jsonify([i.to_dict() for i in incidents])


@app.route('/api/incidents', methods=['POST'])
@token_required
def create_incident(current_user):
    """Create new incident"""
    data = request.json
    
    incident = Incident(
        title=data.get('title'),
        description=data.get('description', ''),
        severity=data.get('severity', 5),
        threat_type=data.get('threat_type', ''),
        created_by_id=current_user.id,
        status='OPEN'
    )
    db.session.add(incident)
    db.session.commit()
    
    # Create notification
    notification = Notification(
        user_id=current_user.id,
        title='Incident Created',
        message=f'New incident: {incident.title}',
        notification_type='incident_created'
    )
    db.session.add(notification)
    db.session.commit()
    
    return jsonify({'success': True, 'incident': incident.to_dict()}), 201


@app.route('/api/incidents/<int:incident_id>', methods=['PUT'])
@token_required
def update_incident(current_user, incident_id):
    """Update incident"""
    incident = Incident.query.get(incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404
    
    data = request.json
    incident.title = data.get('title', incident.title)
    incident.description = data.get('description', incident.description)
    incident.status = data.get('status', incident.status)
    incident.severity = data.get('severity', incident.severity)
    incident.updated_at = datetime.utcnow()
    
    if incident.status == 'RESOLVED':
        incident.resolved_at = datetime.utcnow()
    
    db.session.commit()
    
    return jsonify({'success': True, 'incident': incident.to_dict()})


# ============= Analytics Routes =============
@app.route('/api/analytics/threat-trends', methods=['GET'])
@token_required
def get_threat_trends(current_user):
    """Get threat trend data for charts"""
    hours = request.args.get('hours', 24, type=int)
    labels = []
    values = []
    
    for i in range(hours):
        hour_start = datetime.utcnow() - timedelta(hours=hours - i)
        hour_end = hour_start + timedelta(hours=1)
        
        count = Threat.query.filter(
            Threat.detected_at >= hour_start,
            Threat.detected_at < hour_end,
            Threat.threat_type != 'unknown'
        ).count()
        
        labels.append(hour_start.strftime('%H:%M'))
        values.append(count)
    
    return jsonify({'labels': labels, 'values': values})


@app.route('/api/analytics/severity-distribution', methods=['GET'])
@token_required
def get_severity_distribution(current_user):
    """Get severity distribution"""
    day_ago = datetime.utcnow() - timedelta(days=1)
    
    severities = db.session.query(
        Threat.severity,
        db.func.count(Threat.id)
    ).filter(
        Threat.detected_at > day_ago,
        Threat.threat_type != 'unknown'
    ).group_by(Threat.severity).all()
    
    labels = ['Critical', 'High', 'Medium', 'Low']
    values = [0, 0, 0, 0]
    colors = ['#dc2626', '#f59e0b', '#f97316', '#3b82f6']
    
    for severity, count in severities:
        if severity >= 8:
            values[0] += count
        elif severity >= 6:
            values[1] += count
        elif severity >= 4:
            values[2] += count
        else:
            values[3] += count
    
    return jsonify({
        'labels': labels,
        'values': values,
        'colors': colors
    })


@app.route('/api/analytics/threat-types', methods=['GET'])
@token_required
def get_threat_types(current_user):
    """Get threat types distribution"""
    day_ago = datetime.utcnow() - timedelta(days=1)
    
    threat_types = db.session.query(
        Threat.threat_type,
        db.func.count(Threat.id)
    ).filter(
        Threat.detected_at > day_ago,
        Threat.threat_type != 'unknown'
    ).group_by(Threat.threat_type).order_by(
        db.func.count(Threat.id).desc()
    ).limit(10).all()
    
    labels = [t[0] for t in threat_types]
    values = [t[1] for t in threat_types]
    
    return jsonify({
        'labels': labels,
        'values': values
    })


# ============= System Routes =============
@app.route('/api/system/metrics', methods=['GET'])
@token_required
def get_system_metrics(current_user):
    """Get current system metrics"""
    metrics = threat_detector.get_system_metrics()
    
    return jsonify({
        'cpu_usage': metrics.get('cpu', 0),
        'memory_usage': metrics.get('memory', 0),
        'network_traffic': metrics.get('network_traffic', 0),
        'disk_usage': metrics.get('disk', 0),
        'timestamp': datetime.utcnow().isoformat()
    })


@app.route('/api/monitoring/start', methods=['POST'])
@token_required
def start_monitoring(current_user):
    """Start threat monitoring"""
    global monitoring_active, monitoring_thread
    
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    if not monitoring_active:
        monitoring_active = True
        monitoring_thread = ThreatMonitor(app, socketio)
        monitoring_thread.start()
        logger.info("Monitoring started by user " + current_user.username)
    
    return jsonify({'success': True, 'status': {'active': monitoring_active}})


@app.route('/api/monitoring/stop', methods=['POST'])
@token_required
def stop_monitoring(current_user):
    """Stop threat monitoring"""
    global monitoring_active, monitoring_thread
    
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    if monitoring_active and monitoring_thread:
        monitoring_active = False
        monitoring_thread.running = False
        logger.info("Monitoring stopped by user " + current_user.username)
    
    return jsonify({'success': True, 'status': {'active': monitoring_active}})


# ============= Reports Routes =============
@app.route('/api/reports/generate', methods=['POST'])
@token_required
def generate_report(current_user):
    """Generate report"""
    data = request.json
    report_type = data.get('report_type', 'daily')
    export_format = data.get('export_format', 'pdf')
    start_date_str = data.get('start_date')
    end_date_str = data.get('end_date')
    
    start_date = datetime.strptime(start_date_str, '%Y-%m-%d') if start_date_str else (datetime.utcnow() - timedelta(days=1))
    end_date = datetime.strptime(end_date_str, '%Y-%m-%d') if end_date_str else datetime.utcnow()
    
    # Create report record
    report = Report(
        title=f'{report_type.capitalize()} Report',
        report_type=report_type,
        generated_by_id=current_user.id,
        start_date=start_date,
        end_date=end_date,
        file_format=export_format,
        content=json.dumps({
            'total_threats': Threat.query.filter(Threat.detected_at >= start_date, Threat.detected_at <= end_date, Threat.threat_type != 'unknown').count(),
            'critical_threats': Threat.query.filter(Threat.severity >= 8, Threat.detected_at >= start_date, Threat.detected_at <= end_date, Threat.threat_type != 'unknown').count(),
            'protocol_breakdown': {}
        })
    )
    db.session.add(report)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'report': report.to_dict(),
        'message': 'Report generated successfully'
    }), 201


@app.route('/api/reports', methods=['GET'])
@token_required
def get_reports(current_user):
    """Get all reports"""
    reports = Report.query.order_by(Report.generated_at.desc()).all()
    return jsonify([r.to_dict() for r in reports])


@app.route('/api/reports/<int:report_id>/download', methods=['GET'])
@token_required
def download_report(current_user, report_id):
    """Download a report"""
    report = Report.query.get(report_id)
    if not report:
        return jsonify({'error': 'Report not found'}), 404
        
    report_data = {
        'report_id': report.report_id,
        'title': report.title,
        'type': report.report_type,
        'generated_by': report.generated_by.username if report.generated_by else 'admin',
        'generated_at': report.generated_at.isoformat(),
        'start_date': report.start_date.isoformat(),
        'end_date': report.end_date.isoformat(),
        'content': json.loads(report.content or '{}')
    }
    
    response_content = json.dumps(report_data, indent=4)
    from flask import make_response
    response = make_response(response_content)
    response.headers['Content-Disposition'] = f'attachment; filename=report_{report_id}.json'
    response.headers['Content-Type'] = 'application/json'
    return response


# ============= Analytics & Geolocation Routes =============
@app.route('/api/analytics/top-ips', methods=['GET'])
@token_required
def get_top_ips(current_user):
    """Get top attacker source IPs"""
    results = db.session.query(
        Threat.source_ip,
        db.func.count(Threat.id).label('count'),
        db.func.max(Threat.severity).label('max_severity')
    ).filter(
        Threat.threat_type != 'unknown'
    ).group_by(Threat.source_ip).order_by(db.func.count(Threat.id).desc()).limit(5).all()
    
    return jsonify([{
        'ip': r[0],
        'count': r[1],
        'max_severity': r[2]
    } for r in results])


@app.route('/api/analytics/overview', methods=['GET'])
@token_required
def get_analytics_overview(current_user):
    """Get high level threat overview statistics"""
    total_threats = Threat.query.filter(Threat.threat_type != 'unknown').count()
    resolved_incidents = Incident.query.filter_by(status='RESOLVED').count()
    total_incidents = Incident.query.count()
    resolution_rate = round((resolved_incidents / total_incidents * 100), 1) if total_incidents > 0 else 100.0
    
    threat_types_count = db.session.query(
        Threat.threat_type,
        db.func.count(Threat.id)
    ).filter(
        Threat.threat_type != 'unknown'
    ).group_by(Threat.threat_type).all()
    
    breakdown = {t[0]: t[1] for t in threat_types_count}
    
    return jsonify({
        'total_threats': total_threats,
        'resolution_rate': resolution_rate,
        'breakdown': breakdown
    })


@app.route('/api/analytics/time-of-day', methods=['GET'])
@token_required
def get_analytics_time_of_day(current_user):
    """Get threat distribution by hour of day"""
    results = db.session.query(
        db.func.strftime('%H', Threat.detected_at).label('hour'),
        db.func.count(Threat.id).label('count')
    ).filter(
        Threat.threat_type != 'unknown'
    ).group_by('hour').all()
    
    hours_dict = {str(i).zfill(2): 0 for i in range(24)}
    for hour, count in results:
        if hour in hours_dict:
            hours_dict[hour] = count
            
    labels = [f"{h}:00" for h in sorted(hours_dict.keys())]
    values = [hours_dict[h] for h in sorted(hours_dict.keys())]
    
    return jsonify({
        'labels': labels,
        'values': values
    })


@app.route('/api/analytics/geolocation', methods=['GET'])
@token_required
def get_geolocation_markers(current_user):
    """Get threat geolocation coordinate markers"""
    geos = GeoLocation.query.all()
    return jsonify([g.to_dict() for g in geos])


@app.route('/api/analytics/origins', methods=['GET'])
@token_required
def get_threat_origins(current_user):
    """Get threat origins summary by country"""
    results = db.session.query(
        GeoLocation.country,
        db.func.sum(GeoLocation.threat_count).label('total_count')
    ).group_by(GeoLocation.country).order_by(db.func.sum(GeoLocation.threat_count).desc()).all()
    
    total = sum([r[1] for r in results]) if results else 0
    
    return jsonify([{
        'country': r[0],
        'count': r[1],
        'percentage': round((r[1] / total * 100), 1) if total > 0 else 0
    } for r in results])


def seed_initial_data():
    """Seed the database with rich, realistic cybersecurity threat data if empty"""
    existing_count = GeoLocation.query.count()
    if existing_count >= 20:
        return
        
    logger.info("Clearing old data and seeding initial threat detection data for all countries...")
    # Clear old data to overwrite with full global set
    GeoLocation.query.delete()
    Threat.query.delete()
    Alert.query.delete()
    Incident.query.delete()
    Report.query.delete()
    db.session.commit()
    
    admin_user = User.query.filter_by(username='admin').first()
    admin_id = admin_user.id if admin_user else 1
    
    geolocs = [
        GeoLocation(ip_address='198.51.100.42', country='United States', city='New York', latitude=40.7128, longitude=-74.0060, isp='DigitalOcean LLC', threat_count=15, is_malicious=True),
        GeoLocation(ip_address='185.220.101.5', country='Germany', city='Berlin', latitude=52.5200, longitude=13.4050, isp='Tor Exit Node Provider', threat_count=12, is_malicious=True),
        GeoLocation(ip_address='103.245.236.1', country='China', city='Beijing', latitude=39.9042, longitude=116.4074, isp='China Telecom', threat_count=22, is_malicious=True),
        GeoLocation(ip_address='45.227.254.10', country='Russia', city='Moscow', latitude=55.7558, longitude=37.6173, isp='VDSina Server Provider', threat_count=18, is_malicious=True),
        GeoLocation(ip_address='186.208.52.12', country='Brazil', city='Sao Paulo', latitude=-23.5505, longitude=-46.6333, isp='Vivo Brazil', threat_count=9, is_malicious=True),
        GeoLocation(ip_address='82.165.15.4', country='United Kingdom', city='London', latitude=51.5074, longitude=-0.1278, isp='British Telecom', threat_count=8, is_malicious=True),
        GeoLocation(ip_address='195.154.122.3', country='France', city='Paris', latitude=48.8566, longitude=2.3522, isp='Scaleway SAS', threat_count=6, is_malicious=True),
        GeoLocation(ip_address='103.21.141.2', country='India', city='Mumbai', latitude=19.0760, longitude=72.8777, isp='Reliance Jio Infocomm', threat_count=25, is_malicious=True),
        GeoLocation(ip_address='210.140.10.5', country='Japan', city='Tokyo', latitude=35.6762, longitude=139.6503, isp='NTT Communications', threat_count=14, is_malicious=True),
        GeoLocation(ip_address='139.130.4.5', country='Australia', city='Sydney', latitude=-33.8688, longitude=151.2093, isp='Telstra Corporation', threat_count=5, is_malicious=True),
        GeoLocation(ip_address='198.103.238.30', country='Canada', city='Toronto', latitude=43.6532, longitude=-79.3832, isp='Rogers Cable', threat_count=7, is_malicious=True),
        GeoLocation(ip_address='196.25.255.3', country='South Africa', city='Johannesburg', latitude=-26.2041, longitude=28.0473, isp='Telkom SA', threat_count=9, is_malicious=True),
        GeoLocation(ip_address='102.89.1.4', country='Nigeria', city='Lagos', latitude=6.5244, longitude=3.3792, isp='MTN Nigeria', threat_count=11, is_malicious=True),
        GeoLocation(ip_address='197.34.1.5', country='Egypt', city='Cairo', latitude=30.0444, longitude=31.2357, isp='Telecom Egypt', threat_count=8, is_malicious=True),
        GeoLocation(ip_address='201.175.1.2', country='Mexico', city='Mexico City', latitude=19.4326, longitude=-99.1332, isp='Uninet SA', threat_count=13, is_malicious=True),
        GeoLocation(ip_address='200.45.1.5', country='Argentina', city='Buenos Aires', latitude=-34.6037, longitude=-58.3816, isp='Telecom Argentina', threat_count=10, is_malicious=True),
        GeoLocation(ip_address='37.224.1.2', country='Saudi Arabia', city='Riyadh', latitude=24.7136, longitude=46.6753, isp='STC Saudi Arabia', threat_count=16, is_malicious=True),
        GeoLocation(ip_address='80.58.61.4', country='Spain', city='Madrid', latitude=40.4168, longitude=-3.7038, isp='Telefonica de Espana', threat_count=11, is_malicious=True),
        GeoLocation(ip_address='151.1.1.2', country='Italy', city='Rome', latitude=41.9028, longitude=12.4964, isp='Telecom Italia', threat_count=9, is_malicious=True),
        GeoLocation(ip_address='211.234.1.4', country='South Korea', city='Seoul', latitude=37.5665, longitude=126.9780, isp='SK Broadband', threat_count=17, is_malicious=True),
        GeoLocation(ip_address='103.24.4.5', country='Singapore', city='Singapore', latitude=1.3521, longitude=103.8198, isp='Singtel Optus', threat_count=12, is_malicious=True),
        GeoLocation(ip_address='82.197.196.5', country='Netherlands', city='Amsterdam', latitude=52.3676, longitude=4.9041, isp='KPN B.V.', threat_count=14, is_malicious=True),
        GeoLocation(ip_address='193.140.1.2', country='Turkey', city='Istanbul', latitude=41.0082, longitude=28.9784, isp='Turk Telekom', threat_count=13, is_malicious=True),
        GeoLocation(ip_address='194.44.1.4', country='Ukraine', city='Kyiv', latitude=50.4501, longitude=30.5234, isp='Ukrtelecom JSC', threat_count=10, is_malicious=True),
        GeoLocation(ip_address='103.92.100.5', country='India', city='Bangalore', latitude=12.9716, longitude=77.5946, isp='ACT Fibernet', threat_count=15, is_malicious=True),
        GeoLocation(ip_address='113.160.1.4', country='Vietnam', city='Hanoi', latitude=21.0285, longitude=105.8542, isp='Viettel Group', threat_count=8, is_malicious=True),
        GeoLocation(ip_address='190.248.1.5', country='Colombia', city='Bogota', latitude=4.7110, longitude=-74.0721, isp='Claro Colombia', threat_count=7, is_malicious=True),
        GeoLocation(ip_address='197.248.1.4', country='Kenya', city='Nairobi', latitude=-1.2921, longitude=36.8219, isp='Safaricom PLC', threat_count=6, is_malicious=True),
    ]
    for gl in geolocs:
        db.session.add(gl)
    db.session.commit()
    
    import random
    threat_types = ['malware', 'ddos', 'sqli', 'xss', 'brute_force']
    ips = [gl.ip_address for gl in geolocs]
    protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS']
    
    now = datetime.utcnow()
    for i in range(120):
        t_type = random.choice(threat_types)
        src_ip = random.choice(ips)
        dest_ip = '10.0.0.15'
        sev = random.randint(3, 10)
        conf = round(random.uniform(0.5, 0.99), 2)
        time_offset = random.randint(0, 1440)
        detected_time = now - timedelta(minutes=time_offset)
        
        threat = Threat(
            threat_id=str(uuid.uuid4()),
            source_ip=src_ip,
            destination_ip=dest_ip,
            source_port=random.randint(1024, 65535),
            destination_port=80 if t_type in ['sqli', 'xss'] else (443 if t_type=='ddos' else 22),
            threat_type=t_type,
            severity=sev,
            confidence=conf,
            payload=json.dumps({"request": f"GET /index.php?q={t_type}", "headers": "User-Agent: Mozilla/5.0"}),
            protocol=random.choice(protocols),
            analyzed=True,
            mitigation_applied=sev >= 8,
            detected_at=detected_time
        )
        db.session.add(threat)
    db.session.commit()
    
    high_threats = Threat.query.filter(Threat.severity >= 8).limit(10).all()
    for ht in high_threats:
        alert = Alert(
            threat_id=ht.id,
            alert_type='CRITICAL_THREAT',
            message=f"Critical {ht.threat_type} detected from {ht.source_ip}",
            severity=ht.severity,
            resolved=random.choice([True, False]),
            created_at=ht.detected_at
        )
        db.session.add(alert)
    db.session.commit()
    
    incident_types = ['DDoS Mitigation Pool', 'SQLi Attack Investigation', 'Malware Outbreak Quarantine']
    for idx, title in enumerate(incident_types):
        incident = Incident(
            title=title,
            description=f"Automated incident generated for investigation of threat type.",
            status=random.choice(['OPEN', 'IN_PROGRESS', 'RESOLVED']),
            severity=random.choice([6, 8, 9]),
            threat_type=random.choice(threat_types),
            created_by_id=admin_id,
            created_at=now - timedelta(hours=random.randint(1, 12))
        )
        db.session.add(incident)
    db.session.commit()
    
    report = Report(
        title="Weekly Cyber Threat Analysis",
        report_type="weekly",
        generated_by_id=admin_id,
        start_date=now - timedelta(days=7),
        end_date=now,
        content=json.dumps({"total_threats": 120, "critical_threats": 35, "top_attack_vector": "SQL Injection"}),
        file_format="pdf",
        generated_at=now - timedelta(days=2)
    )
    db.session.add(report)
    db.session.commit()
    logger.info("Successfully seeded threat detection data for all countries!")


# ============= Database Initialization =============
@app.before_request
def create_tables():
    """Create database tables if they don't exist"""
    db.create_all()
    
    # Create default admin user if it doesn't exist
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@threatdetection.local',
            full_name='Administrator',
            role='admin',
            is_active=True
        )
        admin.set_password('admin')
        db.session.add(admin)
        
        analyst = User(
            username='analyst',
            email='analyst@threatdetection.local',
            full_name='Security Analyst',
            role='analyst',
            is_active=True
        )
        analyst.set_password('analyst')
        db.session.add(analyst)
        
        db.session.commit()
        logger.info("Default users created")
        
    seed_initial_data()


# ============= Main Entry Point =============
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=os.getenv('FLASK_ENV') == 'development',
        allow_unsafe_werkzeug=True
    )
