"""
Database models for threat detection framework
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import uuid

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
