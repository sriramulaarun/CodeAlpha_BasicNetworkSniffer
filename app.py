import os
from flask import Flask, jsonify, request, render_template
from sniffer import NetworkSniffer

app = Flask(__name__)

# Initialize the global sniffer instance
sniffer = NetworkSniffer(max_buffer_size=1000)

@app.route('/')
def index():
    """Serves the main SOC Dashboard interface."""
    return render_template('index.html')

@app.route('/api/start', methods=['POST'])
def start_capture():
    """Endpoint to start packet capturing thread."""
    success = sniffer.start()
    status = sniffer.get_status()
    return jsonify({
        "success": success,
        "message": "Sniffing capture started." if success else "Capture already running or failed to start.",
        "status": status
    })

@app.route('/api/stop', methods=['POST'])
def stop_capture():
    """Endpoint to stop packet capturing thread."""
    success = sniffer.stop()
    status = sniffer.get_status()
    return jsonify({
        "success": success,
        "message": "Sniffing capture stopped." if success else "Capture already stopped.",
        "status": status
    })

@app.route('/api/clear', methods=['POST'])
def clear_logs():
    """Endpoint to clear captured logs and metrics."""
    success = sniffer.clear()
    return jsonify({
        "success": success,
        "message": "Dashboard statistics and packet logs cleared."
    })

@app.route('/api/status', methods=['GET'])
def get_status():
    """Endpoint to retrieve system state and capture mode."""
    status = sniffer.get_status()
    # Merge stats into status for simple unified frontend calls
    status["stats"] = sniffer.get_stats()
    return jsonify(status)

@app.route('/api/packets', methods=['GET'])
def get_packets():
    """
    Endpoint to retrieve captured packets.
    Query Parameters:
      - since_id (int): Fetch only packets created after this packet ID.
      - limit (int): Maximum number of packets to return (defaults to 100).
    """
    since_id = request.args.get('since_id', default=None)
    limit = request.args.get('limit', default=100, type=int)
    
    # Restrict limit sizes to prevent memory strain
    if limit > 500:
        limit = 500
        
    packets = sniffer.get_packets(since_id=since_id, limit=limit)
    return jsonify({
        "count": len(packets),
        "packets": packets
    })

if __name__ == '__main__':
    import os
    # Bind to 0.0.0.0 for external routing (required for cloud deploy like Railway/Render)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
