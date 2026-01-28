"""
Real-Time Automated Cyber Threat Classification and Detection Framework
Advanced Python Backend - Flask with WebSocket support for real-time threat processing
"""

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
import logging
from datetime import datetime, timedelta
import json
import threading
import os
from dotenv import load_dotenv

# Import custom modules
from .utils.threat_detector import ThreatDetector
from .utils.threat_classifier import ThreatClassifier
from .utils.data_analyzer import DataAnalyzer
from .utils.gemini_analyzer import GeminiThreatAnalyzer
from .database.models import db, Threat, Alert, SystemMetrics
from .config import Config

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize Gemini analyzer
gemini_analyzer = GeminiThreatAnalyzer(
    api_key=app.config.get('GEMINI_API_KEY', ''),
    model=app.config.get('GEMINI_MODEL', 'gemini-pro')
)

# Initialize extensions
db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

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

# Global variables for monitoring
active_connections = {}
monitoring_active = False
monitoring_thread = None


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
                    # Simulate real-time threat detection from network data
                    threats = threat_detector.detect_threats()
                    
                    if threats:
                        for threat in threats:
                            # Check if threat already exists
                            existing_threat = Threat.query.filter_by(threat_id=threat.get('id')).first()
                            if existing_threat:
                                continue  # Skip if already in database
                            
                            # Classify threat
                            classification = threat_classifier.classify(threat)
                            
                            # Create threat record
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
                            
                            # Create alert if critical
                            if classification.get('severity') >= 7:
                                alert = Alert(
                                    threat_id=threat_record.id,
                                    alert_type='CRITICAL_THREAT',
                                    message=f"Critical {classification.get('type')} detected from {threat.get('source_ip')}",
                                    created_at=datetime.utcnow()
                                )
                                db.session.add(alert)
                            
                            db.session.commit()
                            
                            # Broadcast to connected clients
                            self.socketio.emit('threat_detected', {
                                'threat_id': threat_record.id,
                                'source_ip': threat.get('source_ip'),
                                'destination_ip': threat.get('destination_ip'),
                                'threat_type': classification.get('type'),
                                'severity': classification.get('severity'),
                                'confidence': classification.get('confidence'),
                                'timestamp': datetime.utcnow().isoformat()
                            })
                    
                    # Update system metrics
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
                    
                    # Broadcast metrics
                    self.socketio.emit('system_metrics', {
                        'cpu_usage': metrics.get('cpu'),
                        'memory_usage': metrics.get('memory'),
                        'network_traffic': metrics.get('network_traffic'),
                        'timestamp': datetime.utcnow().isoformat()
                    })
                    
                except Exception as e:
                    db.session.rollback()  # Rollback any failed transaction
                    logger.error(f"Error in threat monitoring: {str(e)}")
                
                # Check every 5 seconds
                import time
                time.sleep(5)


# ============= API Routes =============

@app.route('/', methods=['GET'])
def index():
    """Serve main dashboard"""
    return render_template('index.html')


@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get all detected threats with optional filtering (excludes unknown threats)"""
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity', None)
    threat_type = request.args.get('type', None)
    
    query = Threat.query.filter(Threat.threat_type != 'unknown')  # Exclude unknown threats
    
    if severity:
        query = query.filter(Threat.severity >= int(severity))
    
    if threat_type:
        query = query.filter(Threat.threat_type == threat_type)
    
    threats = query.order_by(Threat.detected_at.desc()).paginate(page=page, per_page=20)
    
    return jsonify({
        'total': threats.total,
        'pages': threats.pages,
        'current_page': page,
        'threats': [{
            'id': t.id,
            'threat_id': t.threat_id,
            'source_ip': t.source_ip,
            'destination_ip': t.destination_ip,
            'threat_type': t.threat_type,
            'severity': t.severity,
            'confidence': t.confidence,
            'detected_at': t.detected_at.isoformat()
        } for t in threats.items]
    })


@app.route('/api/threats/<int:threat_id>', methods=['GET'])
def get_threat_details(threat_id):
    """Get detailed information about a specific threat"""
    threat = Threat.query.get(threat_id)
    
    if not threat:
        return jsonify({'error': 'Threat not found'}), 404
    
    return jsonify({
        'id': threat.id,
        'threat_id': threat.threat_id,
        'source_ip': threat.source_ip,
        'destination_ip': threat.destination_ip,
        'threat_type': threat.threat_type,
        'severity': threat.severity,
        'confidence': threat.confidence,
        'payload': json.loads(threat.payload) if threat.payload else {},
        'detected_at': threat.detected_at.isoformat(),
        'analyzed': threat.analyzed
    })


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get recent alerts"""
    page = request.args.get('page', 1, type=int)
    alerts = Alert.query.order_by(Alert.created_at.desc()).paginate(page=page, per_page=20)
    
    return jsonify({
        'total': alerts.total,
        'pages': alerts.pages,
        'alerts': [{
            'id': a.id,
            'threat_id': a.threat_id,
            'alert_type': a.alert_type,
            'message': a.message,
            'created_at': a.created_at.isoformat()
        } for a in alerts.items]
    })


@app.route('/api/analytics/dashboard', methods=['GET'])
def get_dashboard_analytics():
    """Get dashboard analytics data"""
    hour_ago = datetime.utcnow() - timedelta(hours=1)
    day_ago = datetime.utcnow() - timedelta(days=1)
    
    recent_threats = Threat.query.filter(
        Threat.detected_at > hour_ago,
        Threat.threat_type != 'unknown'  # Exclude unknown threats
    ).count()
    daily_threats = Threat.query.filter(
        Threat.detected_at > day_ago,
        Threat.threat_type != 'unknown'  # Exclude unknown threats
    ).count()
    
    threat_types = db.session.query(
        Threat.threat_type,
        db.func.count(Threat.id)
    ).filter(
        Threat.detected_at > day_ago,
        Threat.threat_type != 'unknown'  # Exclude unknown threats
    ).group_by(Threat.threat_type).all()
    
    severity_distribution = db.session.query(
        Threat.severity,
        db.func.count(Threat.id)
    ).filter(
        Threat.detected_at > day_ago,
        Threat.threat_type != 'unknown'  # Exclude unknown threats
    ).group_by(Threat.severity).all()
    
    critical_threats = Threat.query.filter(
        Threat.severity >= 8,
        Threat.detected_at > day_ago,
        Threat.threat_type != 'unknown'  # Exclude unknown threats
    ).count()
    
    latest_metrics = SystemMetrics.query.order_by(
        SystemMetrics.recorded_at.desc()
    ).first()
    
    return jsonify({
        'recent_threats_1h': recent_threats,
        'daily_threats': daily_threats,
        'critical_threats': critical_threats,
        'threat_types': [{'type': t[0], 'count': t[1]} for t in threat_types],
        'severity_distribution': [{'severity': s[0], 'count': s[1]} for s in severity_distribution],
        'system_metrics': {
            'cpu': latest_metrics.cpu_usage if latest_metrics else 0,
            'memory': latest_metrics.memory_usage if latest_metrics else 0,
            'network_traffic': latest_metrics.network_traffic if latest_metrics else 0
        }
    })


@app.route('/api/analytics/timeline', methods=['GET'])
def get_timeline_analytics():
    """Get threats over time for timeline visualization"""
    hours = request.args.get('hours', 24, type=int)
    start_time = datetime.utcnow() - timedelta(hours=hours)
    
    threats_per_hour = []
    for i in range(hours):
        hour_start = start_time + timedelta(hours=i)
        hour_end = hour_start + timedelta(hours=1)
        
        count = Threat.query.filter(
            Threat.detected_at >= hour_start,
            Threat.detected_at < hour_end,
            Threat.threat_type != 'unknown'  # Exclude unknown threats
        ).count()
        
        threats_per_hour.append({
            'timestamp': hour_start.isoformat(),
            'count': count
        })
    
    return jsonify({'timeline': threats_per_hour})


@app.route('/api/threats/analyze', methods=['POST'])
def analyze_threat():
    """Analyze a custom threat payload with AI enhancement"""
    data = request.json
    payload = data.get('payload')
    
    if not payload:
        return jsonify({'error': 'No payload provided'}), 400
    
    # Perform standard analysis
    analysis = data_analyzer.analyze(payload)
    classification = threat_classifier.classify(payload)
    
    # Get AI-enhanced analysis from Gemini
    threat_data = {
        'payload': payload,
        'source_ip': data.get('source_ip', 'N/A'),
        'destination_ip': data.get('destination_ip', 'N/A'),
        'detected_at': datetime.utcnow().isoformat()
    }
    
    ai_analysis = gemini_analyzer.analyze_threat(threat_data)
    
    # Get mitigation strategies from Gemini
    mitigations = gemini_analyzer.get_mitigation_strategies(
        classification.get('type'),
        threat_data
    )
    
    return jsonify({
        'analysis': analysis,
        'classification': classification,
        'ai_enhanced': {
            'gemini_analysis': ai_analysis,
            'mitigation_strategies': mitigations
        }
    })


@app.route('/api/threats/mass-check', methods=['POST'])
def mass_check_threats():
    """Mass check multiple threat payloads"""
    data = request.json
    payloads = data.get('payloads', [])
    
    results = []
    for payload in payloads:
        classification = threat_classifier.classify(payload)
        results.append(classification)
    
    return jsonify({
        'total': len(results),
        'results': results
    })


@app.route('/api/config', methods=['GET'])
def get_config():
    """Get application configuration"""
    return jsonify({
        'app_name': 'Cyber Threat Detection Framework',
        'version': '1.0.0',
        'monitoring_enabled': monitoring_active,
        'database': app.config.get('SQLALCHEMY_DATABASE_URI').split('://')[0],
        'websocket_enabled': True
    })


# ============= WebSocket Events =============

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    sid = request.sid
    active_connections[sid] = {
        'connected_at': datetime.utcnow(),
        'last_ping': datetime.utcnow()
    }
    logger.info(f"Client connected: {sid}")
    emit('connection_response', {'data': 'Connected to threat detection server'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    sid = request.sid
    if sid in active_connections:
        del active_connections[sid]
    logger.info(f"Client disconnected: {sid}")


@socketio.on('request_threat_update')
def handle_threat_update_request():
    """Handle client request for threat updates"""
    recent_threats = Threat.query.order_by(
        Threat.detected_at.desc()
    ).limit(10).all()
    
    threats_data = [{
        'id': t.id,
        'threat_id': t.threat_id,
        'source_ip': t.source_ip,
        'destination_ip': t.destination_ip,
        'threat_type': t.threat_type,
        'severity': t.severity,
        'detected_at': t.detected_at.isoformat()
    } for t in recent_threats]
    
    emit('threat_update', {'threats': threats_data})


@socketio.on('start_monitoring')
def handle_start_monitoring():
    """Start real-time threat monitoring"""
    global monitoring_active, monitoring_thread
    
    if not monitoring_active:
        monitoring_active = True
        monitoring_thread = ThreatMonitor(app, socketio)
        monitoring_thread.start()
        logger.info("Threat monitoring started")
        emit('monitoring_status', {'status': 'started'})


@socketio.on('stop_monitoring')
def handle_stop_monitoring():
    """Stop real-time threat monitoring"""
    global monitoring_active, monitoring_thread
    
    if monitoring_active and monitoring_thread:
        monitoring_active = False
        monitoring_thread.running = False
        logger.info("Threat monitoring stopped")
        emit('monitoring_status', {'status': 'stopped'})


@socketio.on('get_system_status')
def handle_system_status():
    """Get current system status"""
    metrics = threat_detector.get_system_metrics()
    active_threat_count = Threat.query.filter(
        Threat.detected_at > datetime.utcnow() - timedelta(hours=1)
    ).count()
    
    emit('system_status', {
        'cpu_usage': metrics.get('cpu'),
        'memory_usage': metrics.get('memory'),
        'network_traffic': metrics.get('network_traffic'),
        'active_threats': active_threat_count,
        'connected_clients': len(active_connections),
        'monitoring_active': monitoring_active
    })


@app.route('/api/threats/<int:threat_id>/ai-report', methods=['GET'])
def get_ai_threat_report(threat_id):
    """Get AI-enhanced threat report using Gemini"""
    threat = Threat.query.get(threat_id)
    
    if not threat:
        return jsonify({'error': 'Threat not found'}), 404
    
    # Prepare threat data
    threat_data = {
        'id': threat.id,
        'threat_id': threat.threat_id,
        'source_ip': threat.source_ip,
        'destination_ip': threat.destination_ip,
        'severity': threat.severity,
        'payload': json.loads(threat.payload) if threat.payload else {},
        'detected_at': threat.detected_at.isoformat()
    }
    
    # Classification info
    classification = {
        'type': threat.threat_type,
        'severity': threat.severity,
        'confidence': threat.confidence
    }
    
    # Generate AI report
    report = gemini_analyzer.generate_threat_report(threat_data, classification)
    
    return jsonify(report)


@app.route('/api/threats/ai-batch-analyze', methods=['POST'])
def ai_batch_analyze_threats():
    """Batch analyze threats with Gemini AI"""
    data = request.json
    threat_ids = data.get('threat_ids', [])
    
    if not threat_ids:
        return jsonify({'error': 'No threat IDs provided'}), 400
    
    threats = Threat.query.filter(Threat.id.in_(threat_ids)).all()
    
    if not threats:
        return jsonify({'error': 'No threats found'}), 404
    
    threat_data_list = []
    for threat in threats:
        threat_data_list.append({
            'id': threat.id,
            'threat_id': threat.threat_id,
            'source_ip': threat.source_ip,
            'destination_ip': threat.destination_ip,
            'severity': threat.severity,
            'type': threat.threat_type,
            'payload': json.loads(threat.payload) if threat.payload else {},
            'detected_at': threat.detected_at.isoformat()
        })
    
    # Batch analyze with Gemini
    analyses = gemini_analyzer.batch_analyze_threats(threat_data_list)
    
    return jsonify({
        'total': len(analyses),
        'analyses': analyses
    })


# ============= Error Handlers =============

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500


# ============= Database Initialization =============

with app.app_context():
    db.create_all()
    logger.info("Database tables created successfully")


# ============= Application Entry Point =============

if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    logger.info(f"Starting Threat Detection Framework (Debug: {debug_mode})")
    socketio.run(app, host='0.0.0.0', port=5000, debug=debug_mode)
