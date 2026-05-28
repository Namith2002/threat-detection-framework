"""
Database models for threat detection framework
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class Threat(db.Model):
    """Model for detected threats"""
    __tablename__ = 'threats'
    
    id = db.Column(db.Integer, primary_key=True)
    threat_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_ip = db.Column(db.String(45), nullable=False, index=True)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    threat_type = db.Column(db.String(100), nullable=False, default='unknown', index=True)  # Malware, DDoS, SQLi, etc.
    severity = db.Column(db.Integer, nullable=False, default=5)  # 1-10 scale
    confidence = db.Column(db.Float, nullable=False, default=0.0)  # 0.0-1.0
    payload = db.Column(db.Text)  # Raw threat data as JSON
    protocol = db.Column(db.String(20))  # TCP, UDP, ICMP, etc.
    analyzed = db.Column(db.Boolean, default=False)
    mitigation_applied = db.Column(db.Boolean, default=False)
    detected_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    alerts = db.relationship('Alert', backref='threat', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'threat_id': self.threat_id,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'protocol': self.protocol,
            'analyzed': self.analyzed,
            'detected_at': self.detected_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Threat {self.threat_id}: {self.threat_type} ({self.severity}/10)>'


class Alert(db.Model):
    """Model for security alerts"""
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    threat_id = db.Column(db.Integer, db.ForeignKey('threats.id'), nullable=False)
    alert_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    alert_type = db.Column(db.String(100), nullable=False)  # CRITICAL_THREAT, ANOMALY, etc.
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.Integer, default=5)
    resolved = db.Column(db.Boolean, default=False)
    resolution_notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    resolved_at = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'threat_id': self.threat_id,
            'alert_type': self.alert_type,
            'message': self.message,
            'severity': self.severity,
            'resolved': self.resolved,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Alert {self.alert_id}: {self.alert_type}>'


class SystemMetrics(db.Model):
    """Model for system performance metrics"""
    __tablename__ = 'system_metrics'
    
    id = db.Column(db.Integer, primary_key=True)
    cpu_usage = db.Column(db.Float, default=0.0)  # percentage
    memory_usage = db.Column(db.Float, default=0.0)  # percentage
    network_traffic = db.Column(db.Float, default=0.0)  # bytes per second
    disk_usage = db.Column(db.Float, default=0.0)  # percentage
    active_threats = db.Column(db.Integer, default=0)
    threat_processing_rate = db.Column(db.Float, default=0.0)  # threats per second
    recorded_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'cpu_usage': self.cpu_usage,
            'memory_usage': self.memory_usage,
            'network_traffic': self.network_traffic,
            'disk_usage': self.disk_usage,
            'active_threats': self.active_threats,
            'threat_processing_rate': self.threat_processing_rate,
            'recorded_at': self.recorded_at.isoformat()
        }
    
    def __repr__(self):
        return f'<SystemMetrics CPU:{self.cpu_usage}% Memory:{self.memory_usage}%>'


class NetworkFlow(db.Model):
    """Model for network flow data"""
    __tablename__ = 'network_flows'
    
    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_ip = db.Column(db.String(45), nullable=False, index=True)
    source_port = db.Column(db.Integer, nullable=False)
    destination_port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), nullable=False)
    packet_count = db.Column(db.Integer, default=0)
    byte_count = db.Column(db.Integer, default=0)
    duration = db.Column(db.Float, default=0.0)  # seconds
    anomaly_score = db.Column(db.Float, default=0.0)
    is_anomaly = db.Column(db.Boolean, default=False)
    first_seen = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'anomaly_score': self.anomaly_score,
            'is_anomaly': self.is_anomaly,
            'first_seen': self.first_seen.isoformat()
        }
    
    def __repr__(self):
        return f'<NetworkFlow {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}>'


class IncidentResponse(db.Model):
    """Model for incident response tracking"""
    __tablename__ = 'incident_responses'
    
    id = db.Column(db.Integer, primary_key=True)
    threat_id = db.Column(db.Integer, db.ForeignKey('threats.id'), nullable=False)
    response_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    response_type = db.Column(db.String(100))  # BLOCK_IP, RATE_LIMIT, ISOLATE, etc.
    status = db.Column(db.String(20), default='PENDING')  # PENDING, ACTIVE, COMPLETED, FAILED
    details = db.Column(db.Text)
    effectiveness = db.Column(db.Float)  # How effective was the response (0-1)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    def to_dict(self):
        return {
            'id': self.id,
            'response_id': self.response_id,
            'threat_id': self.threat_id,
            'response_type': self.response_type,
            'status': self.status,
            'effectiveness': self.effectiveness,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<IncidentResponse {self.response_id}: {self.response_type} ({self.status})>'


class User(db.Model):
    """Model for system users"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(120))
    role = db.Column(db.String(50), default='analyst')  # admin, analyst, viewer
    is_active = db.Column(db.Boolean, default=True)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships - explicitly specify foreign_keys to avoid ambiguity
    # When a user creates an incident, they are referenced by created_by_id
    incidents_created = db.relationship('Incident', foreign_keys='Incident.created_by_id', backref='created_by_user', lazy=True)
    # When an incident is assigned to a user, they are referenced by assigned_to_id
    incidents_assigned = db.relationship('Incident', foreign_keys='Incident.assigned_to_id', backref='assigned_to_user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


class Incident(db.Model):
    """Model for security incidents"""
    __tablename__ = 'incidents'
    
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default='OPEN')  # OPEN, IN_PROGRESS, RESOLVED, CLOSED
    severity = db.Column(db.Integer, default=5)  # 1-10
    threat_type = db.Column(db.String(100))
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    mitigation_steps = db.Column(db.Text)
    impact_assessment = db.Column(db.Text)
    
    def to_dict(self):
        return {
            'id': self.id,
            'incident_id': self.incident_id,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'severity': self.severity,
            'threat_type': self.threat_type,
            'assigned_to': self.assigned_to_user.username if self.assigned_to_user else None,
            'created_by': self.created_by_user.username if self.created_by_user else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Incident {self.incident_id}: {self.title} ({self.status})>'


class Playbook(db.Model):
    """Model for incident response playbooks"""
    __tablename__ = 'playbooks'
    
    id = db.Column(db.Integer, primary_key=True)
    playbook_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    threat_type = db.Column(db.String(100))  # Malware, DDoS, SQLi, etc.
    steps = db.Column(db.Text)  # JSON array of steps
    is_active = db.Column(db.Boolean, default=True)
    automation_level = db.Column(db.String(50), default='manual')  # manual, semi-auto, auto
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'playbook_id': self.playbook_id,
            'name': self.name,
            'description': self.description,
            'threat_type': self.threat_type,
            'is_active': self.is_active,
            'automation_level': self.automation_level,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Playbook {self.name}: {self.threat_type}>'


class Notification(db.Model):
    """Model for system notifications"""
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    notification_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    notification_type = db.Column(db.String(50))  # threat_detected, incident_created, alert, etc.
    severity = db.Column(db.String(20), default='info')  # critical, high, medium, low, info
    is_read = db.Column(db.Boolean, default=False)
    action_url = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True)
    read_at = db.Column(db.DateTime)
    
    # Relationships
    user = db.relationship('User', backref='notifications')
    
    def to_dict(self):
        return {
            'id': self.id,
            'notification_id': self.notification_id,
            'title': self.title,
            'message': self.message,
            'notification_type': self.notification_type,
            'severity': self.severity,
            'is_read': self.is_read,
            'action_url': self.action_url,
            'created_at': self.created_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Notification {self.notification_id}: {self.title}>'


class GeoLocation(db.Model):
    """Model for IP geolocation data"""
    __tablename__ = 'geolocations'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    isp = db.Column(db.String(200))
    threat_count = db.Column(db.Integer, default=0)
    is_malicious = db.Column(db.Boolean, default=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'country': self.country,
            'city': self.city,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'isp': self.isp,
            'threat_count': self.threat_count,
            'is_malicious': self.is_malicious
        }
    
    def __repr__(self):
        return f'<GeoLocation {self.ip_address} ({self.country})>'


class Report(db.Model):
    """Model for generated reports"""
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(200), nullable=False)
    report_type = db.Column(db.String(100))  # daily, weekly, monthly, custom, threat_summary
    generated_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    content = db.Column(db.Text)  # JSON report data
    file_path = db.Column(db.String(255))  # Path to exported file (PDF, CSV, etc.)
    file_format = db.Column(db.String(20), default='pdf')  # pdf, csv, json, html
    generated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    generated_by = db.relationship('User')
    
    def to_dict(self):
        return {
            'id': self.id,
            'report_id': self.report_id,
            'title': self.title,
            'report_type': self.report_type,
            'generated_by': self.generated_by.username if self.generated_by else None,
            'start_date': self.start_date.isoformat(),
            'end_date': self.end_date.isoformat(),
            'file_format': self.file_format,
            'generated_at': self.generated_at.isoformat()
        }
    
    def __repr__(self):
        return f'<Report {self.report_id}: {self.title}>'
