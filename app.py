from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from sniffer import start_sniffing, sniffer
from analyzer import analyzer
from threading import Lock
import datetime
import csv
import os
import logging
from logger import LOG_FILE

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# Constants
MAX_STORED_PACKETS = 1000  # Maximum packets to keep in memory

# Global storage
packet_store = []
packet_store_lock = Lock()

@app.route('/')
def index():
    """Serve the main dashboard"""
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    """API endpoint to get current statistics"""
    try:
        stats = sniffer.get_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': 'Failed to get statistics'}), 500

@app.route('/api/packets')
def get_packets():
    """API endpoint to get recent packets"""
    try:
        count = request.args.get('count', 100, type=int)
        packets = sniffer.get_recent_packets(count)
        return jsonify(packets)
    except Exception as e:
        logger.error(f"Error getting packets: {e}")
        return jsonify({'error': 'Failed to get packets'}), 500

@app.route('/api/suspicious_ips')
def get_suspicious_ips():
    """API endpoint to get suspicious IPs"""
    try:
        suspicious_ips = analyzer.get_suspicious_ips()
        return jsonify(suspicious_ips)
    except Exception as e:
        logger.error(f"Error getting suspicious IPs: {e}")
        return jsonify({'error': 'Failed to get suspicious IPs'}), 500

@app.route('/api/blacklist', methods=['GET', 'POST'])
def manage_blacklist():
    """API endpoint to manage blacklist"""
    if request.method == 'GET':
        try:
            # Return current blacklist
            return jsonify(list(analyzer.blacklist))
        except Exception as e:
            logger.error(f"Error getting blacklist: {e}")
            return jsonify({'error': 'Failed to get blacklist'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            entry = data.get('entry', '').strip()
            
            if not entry:
                return jsonify({'error': 'Entry cannot be empty'}), 400
            
            success = analyzer.add_to_blacklist(entry)
            if success:
                return jsonify({'message': f'Added {entry} to blacklist'}), 200
            else:
                return jsonify({'error': 'Failed to add entry to blacklist'}), 500
                
        except Exception as e:
            logger.error(f"Error adding to blacklist: {e}")
            return jsonify({'error': 'Failed to add to blacklist'}), 500

@app.route('/api/clear_ip_frequency', methods=['POST'])
def clear_ip_frequency():
    """API endpoint to clear IP frequency data"""
    try:
        analyzer.clear_ip_frequency()
        return jsonify({'message': 'IP frequency data cleared'}), 200
    except Exception as e:
        logger.error(f"Error clearing IP frequency: {e}")
        return jsonify({'error': 'Failed to clear IP frequency data'}), 500

def load_previous_logs():
    """Load previous log entries from CSV file"""
    try:
        if not os.path.exists(LOG_FILE):
            return []
            
        with open(LOG_FILE, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            logs = []
            for row in reader:
                # Convert CSV row to packet format
                packet_data = {
                    'timestamp': row.get('Timestamp', ''),
                    'src_ip': row.get('Source IP', ''),
                    'dst_ip': row.get('Destination IP', ''),
                    'src_port': row.get('Source Port', ''),
                    'dst_port': row.get('Destination Port', ''),
                    'protocol': row.get('Protocol', ''),
                    'location': row.get('Location', ''),
                    'alert': row.get('Alert', ''),
                    'size': int(row.get('Size', 0)) if row.get('Size', '').isdigit() else 0
                }
                logs.append(packet_data)
            return logs[-100:]  # Return last 100 packets
    except Exception as e:
        logger.error(f"Error loading previous logs: {e}")
        return []

def background_thread():
    """Send periodic server stats and cleanup tasks"""
    while True:
        try:
            socketio.sleep(30)  # Wait 30 seconds
            
            # Send server statistics
            with packet_store_lock:
                server_stats = {
                    'total_stored_packets': len(packet_store),
                    'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
                    'uptime': sniffer.get_stats().get('uptime_seconds', 0)
                }
                socketio.emit('server_stats', server_stats)
            
            # Cleanup old data periodically (every 5 minutes)
            current_time = datetime.datetime.now()
            if hasattr(background_thread, 'last_cleanup'):
                time_diff = (current_time - background_thread.last_cleanup).total_seconds()
                if time_diff > 300:  # 5 minutes
                    cleanup_old_data()
                    background_thread.last_cleanup = current_time
            else:
                background_thread.last_cleanup = current_time
                
        except Exception as e:
            logger.error(f"Error in background thread: {e}")

def cleanup_old_data():
    """Cleanup old packet data to prevent memory issues"""
    try:
        with packet_store_lock:
            if len(packet_store) > MAX_STORED_PACKETS:
                # Keep only the most recent packets
                packet_store[:] = packet_store[-MAX_STORED_PACKETS:]
                logger.info(f"Cleaned up packet store, now contains {len(packet_store)} packets")
                
        # Optionally clear very old IP frequency data
        # analyzer.clear_ip_frequency()  # Uncomment if you want to clear periodically
        
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    try:
        logger.info(f"Client connected: {request.sid}")
        
        # Send connection confirmation
        emit('connection_status', {'status': 'connected'})
        
        # Send previous logs first
        previous_logs = load_previous_logs()
        for log in previous_logs:
            emit('packet', log)
        
        # Send current stored packets
        with packet_store_lock:
            for packet in packet_store[-100:]:  # Send last 100 packets
                emit('packet', packet)
        
        # Send current statistics
        stats = sniffer.get_stats()
        emit('server_stats', stats)
        
        # Send current IP counts
        ip_stats = analyzer.get_ip_stats()
        emit('ip_counts', ip_stats)
        
    except Exception as e:
        logger.error(f"Error handling client connection: {e}")

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('request_stats')
def handle_stats_request():
    """Handle request for current statistics"""
    try:
        stats = sniffer.get_stats()
        emit('server_stats', stats)
    except Exception as e:
        logger.error(f"Error handling stats request: {e}")

@socketio.on('request_ip_counts')
def handle_ip_counts_request():
    """Handle request for IP count statistics"""
    try:
        ip_stats = analyzer.get_ip_stats()
        emit('ip_counts', ip_stats)
    except Exception as e:
        logger.error(f"Error handling IP counts request: {e}")

@socketio.on('add_to_blacklist')
def handle_add_to_blacklist(data):
    """Handle request to add entry to blacklist"""
    try:
        entry = data.get('entry', '').strip()
        if entry:
            success = analyzer.add_to_blacklist(entry)
            if success:
                emit('blacklist_updated', {'message': f'Added {entry} to blacklist'})
            else:
                emit('error', {'message': 'Failed to add entry to blacklist'})
        else:
            emit('error', {'message': 'Entry cannot be empty'})
    except Exception as e:
        logger.error(f"Error adding to blacklist: {e}")
        emit('error', {'message': 'Error adding to blacklist'})

@socketio.on('clear_ip_frequency')
def handle_clear_ip_frequency():
    """Handle request to clear IP frequency data"""
    try:
        analyzer.clear_ip_frequency()
        emit('ip_frequency_cleared', {'message': 'IP frequency data cleared'})
    except Exception as e:
        logger.error(f"Error clearing IP frequency: {e}")
        emit('error', {'message': 'Error clearing IP frequency data'})

def create_app():
    """Application factory"""
    return app

if __name__ == '__main__':
    try:
        # Load previous logs for initial display
        previous_logs = load_previous_logs()
        logger.info(f"Loaded {len(previous_logs)} previous log entries")
        
        # Start background tasks
        socketio.start_background_task(start_sniffing, socketio, packet_store, packet_store_lock, MAX_STORED_PACKETS)
        socketio.start_background_task(background_thread)
        
        logger.info("Starting Network Security Monitor...")
        logger.info("Dashboard will be available at: http://localhost:5000")
        logger.info("Make sure to run as administrator for packet capture!")
        
        # Run the application
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=5000, 
            debug=False,  # Set to False in production
            allow_unsafe_werkzeug=True
        )
        
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sniffer.stop_sniffing()
    except Exception as e:
        logger.error(f"Error starting application: {e}")
        raise